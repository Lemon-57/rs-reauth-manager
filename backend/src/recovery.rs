//! 校验同一用户的工作区恢复凭据，停用调度后以精确版本写回原账号
use crate::{
    detail,
    host::{admin, fault, now},
    require_idle, settings,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use gateway_plugin_sdk::{
    PluginFault,
    call::host::{AuthCredential, AuthSaveRequest, AuthSaveResult},
    client::HostClient,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const AUTH: &str = "https://api.openai.com/auth";
const IDENTITY_ERROR: &str = "工作区授权身份校验失败，未更改账号或提交凭据";

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, PluginFault> {
    value[key]
        .as_str()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 32768
                && !s.chars().any(|c| c.is_control() || c.is_whitespace())
        })
        .ok_or_else(|| fault(IDENTITY_ERROR))
}

fn claims(token: &str) -> Result<Value, PluginFault> {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(fault(IDENTITY_ERROR));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| fault(IDENTITY_ERROR))?;
    let claims: Value = serde_json::from_slice(&bytes).map_err(|_| fault(IDENTITY_ERROR))?;
    // 私有 TLS 交换结果的字段投影，不宣称为 JWT 签名校验
    let expires = claims["exp"]
        .as_u64()
        .filter(|exp| *exp > now() / 1000 + 30 && *exp < 253402300799)
        .ok_or_else(|| fault(IDENTITY_ERROR))?;
    if !claims.is_object() || expires.checked_mul(1000).is_none() {
        return Err(fault(IDENTITY_ERROR));
    }
    Ok(claims)
}

fn validate(output: &Value, original: &Value) -> Result<(Value, Value), PluginFault> {
    let workspace = text(output, "workspaceId")?;
    let user = text(original, "userId")?;
    let email = text(original, "email")?;
    let forced = output["event"] == "forced_workspace" && output["administratorConfirmed"] == true;
    if (!forced
        && (output["event"] != "free_fallback" || output["originalWorkspaceUnavailable"] != true))
        || output["originalWorkspaceId"] != original["accountId"]
        || workspace == text(original, "accountId")?
    {
        return Err(fault(IDENTITY_ERROR));
    }
    text(&output["tokens"], "refresh_token")?;
    let identity = claims(text(&output["tokens"], "id_token")?)?;
    let access = claims(text(&output["tokens"], "access_token")?)?;
    text(&identity, "sub")?;
    let token_email = identity["email"]
        .as_str()
        .or_else(|| identity["https://api.openai.com/profile"]["email"].as_str())
        .ok_or_else(|| fault(IDENTITY_ERROR))?;
    if !token_email.eq_ignore_ascii_case(email) {
        return Err(fault(IDENTITY_ERROR));
    }
    for token in [&identity, &access] {
        let auth = &token[AUTH];
        if auth["chatgpt_account_id"] != workspace
            || auth["chatgpt_user_id"]
                .as_str()
                .or_else(|| auth["user_id"].as_str())
                != Some(user)
            || !auth["chatgpt_plan_type"]
                .as_str()
                .is_some_and(|p| !p.trim().is_empty() && (forced || p.eq_ignore_ascii_case("free")))
        {
            return Err(fault(IDENTITY_ERROR));
        }
    }
    if identity["sub"] != access["sub"]
        || identity[AUTH]["chatgpt_plan_type"] != access[AUTH]["chatgpt_plan_type"]
    {
        return Err(fault(IDENTITY_ERROR));
    }
    Ok((identity, access))
}

async fn auth_call<T: DeserializeOwned>(
    host: &HostClient,
    method: &str,
    data: &impl Serialize,
    message: &str,
) -> Result<T, PluginFault> {
    let payload = serde_json::to_vec(data).map_err(|_| fault(message))?;
    let reply = host
        .call(method, json!({}), payload)
        .await
        .map_err(|_| fault(message))?;
    serde_json::from_slice(&reply.payload).map_err(|_| fault(message))
}

fn unchanged(a: &Value, snapshot: &Value, expected: &Value) -> Result<(), PluginFault> {
    require_idle(a)?;
    if settings(a) != *expected || a["_credentialRevision"] != snapshot["credentialRevision"] {
        return Err(fault(
            "登录期间账号配置或凭据发生变化，已停止工作区授权写回",
        ));
    }
    Ok(())
}

pub async fn commit(
    host: &HostClient,
    id: &str,
    snapshot: &Value,
    output: &Value,
) -> Result<(), PluginFault> {
    let original = &snapshot["settings"];
    let (identity, access) = validate(output, original)?;
    let current = detail(host, id).await?;
    unchanged(&current, snapshot, original)?;
    let credential: AuthCredential = auth_call(
        host,
        "host.auth.get",
        &json!({"account_id": id}),
        "原账号凭据读取失败，未提交工作区授权",
    )
    .await?;
    let mut facts = credential.facts;
    if credential.account_id != id
        || credential.provider_id != "openai"
        || Some(credential.credential_revision) != snapshot["credentialRevision"].as_u64()
        || facts.authentication_kind != "oauth"
        || facts.name != original["name"]
        || facts.email.as_deref() != original["email"].as_str()
        || facts.upstream_user_id.as_deref() != original["userId"].as_str()
        || facts.upstream_account_id.as_deref() != original["accountId"].as_str()
        || facts.plan_type.as_deref() != original["planType"].as_str()
        || facts.material.get("schema_version") != Some(&json!(1))
        || facts
            .material
            .get("installation_id")
            .and_then(Value::as_str)
            .is_none()
        || facts
            .material
            .get("principal")
            .and_then(|p| p["oauth_subject"].as_str())
            .is_some_and(|sub| identity["sub"] != sub)
    {
        return Err(fault(IDENTITY_ERROR));
    }
    for key in ["access_token", "refresh_token", "id_token"] {
        facts
            .material
            .insert(key.into(), output["tokens"][key].clone());
    }
    facts.material.insert(
        "principal".into(),
        json!({"oauth_subject":identity["sub"],"poid":null}),
    );
    facts.upstream_account_id = output["workspaceId"].as_str().map(str::to_owned);
    let plan = text(&identity[AUTH], "chatgpt_plan_type")?.to_ascii_lowercase();
    facts.plan_type = Some(plan.clone());
    facts.has_refresh_token = true;
    facts.access_token_expires_at_ms = access["exp"].as_i64().and_then(|exp| exp.checked_mul(1000));
    facts.next_refresh_at_ms = None;
    // 读取凭据后再次校验，先停止调度再变更工作区身份
    unchanged(&detail(host, id).await?, snapshot, original)?;
    if original["enabled"] != false {
        admin(
            host,
            "POST",
            "/api/admin/accounts/batch-update",
            Some(json!({"accountIds":[id],"enabled":false})),
        )
        .await
        .map_err(|_| fault("停止调度结果待核对，尚未提交工作区授权，请检查原账号"))?;
    }
    let result = async {
        let mut disabled = original.clone();
        disabled["enabled"] = json!(false);
        unchanged(&detail(host, id).await?, snapshot, &disabled)?;
        let result: AuthSaveResult = auth_call(
            host,
            "host.auth.save",
            &AuthSaveRequest::Replace {
                account_id: id.into(),
                credential_revision: credential.credential_revision,
                facts,
            },
            "工作区授权提交结果不确定",
        )
        .await?;
        if result.account_id != id || result.credential_revision <= credential.credential_revision {
            return Err(fault("工作区授权写回版本未确认"));
        }
        let after = detail(host, id).await?;
        let mut expected = disabled;
        expected["accountId"] = output["workspaceId"].clone();
        expected["planType"] = json!(plan);
        if settings(&after) != expected
            || after["_credentialRevision"] != result.credential_revision
            || after["status"] != "normal"
            || after["hasRefreshToken"] != true
        {
            return Err(fault("工作区授权写回后的账号状态未确认"));
        }
        let saved: AuthCredential = auth_call(
            host,
            "host.auth.get",
            &json!({"account_id":id}),
            "工作区授权凭据读回失败",
        )
        .await?;
        if saved.account_id != id
            || saved.provider_id != "openai"
            || saved.credential_revision != result.credential_revision
            || saved.facts.plan_type.as_deref() != Some(plan.as_str())
            || saved.facts.upstream_account_id.as_deref() != output["workspaceId"].as_str()
            || saved.facts.upstream_user_id.as_deref() != original["userId"].as_str()
            || ["access_token", "refresh_token", "id_token"]
                .iter()
                .any(|k| saved.facts.material.get(*k) != output["tokens"].get(*k))
        {
            return Err(fault("工作区授权凭据写回未确认"));
        }
        Ok(())
    }
    .await;
    result.map_err(|_: PluginFault| {
        fault("已执行停止调度，但工作区授权写回未确认，请人工核对；不会自动重试")
    })
}
