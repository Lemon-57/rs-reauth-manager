//! 只读核验 RS 已保存的授权身份与工作区，不交换或保存 RT
use crate::host::{fault, now};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use gateway_plugin_sdk::{PluginFault, call::host::AuthCredential, client::HostClient};
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

pub(crate) fn claims(token: &str) -> Result<Value, PluginFault> {
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

pub(crate) fn validate(output: &Value, original: &Value) -> Result<(Value, Value), PluginFault> {
    let workspace = text(output, "workspaceId")?;
    let user = text(original, "userId")?;
    let email = text(original, "email")?;
    let same = output["event"] == "same_workspace";
    let forced = output["event"] == "forced_workspace" && output["administratorConfirmed"] == true;
    let forced_free = output["event"] == "forced_free" && output["administratorConfirmed"] == true;
    let upgraded = output["event"] == "team_upgrade"
        && output["uniqueTeamConfirmed"] == true
        && original["planType"]
            .as_str()
            .is_some_and(|p| p.trim().eq_ignore_ascii_case("free"));
    if (!same
        && !forced
        && !forced_free
        && !upgraded
        && (output["event"] != "free_fallback" || output["originalWorkspaceUnavailable"] != true))
        || output["originalWorkspaceId"] != original["accountId"]
        || (same && workspace != text(original, "accountId")?)
        || (!same
            && workspace == text(original, "accountId")?
            && !(forced_free
                && original["planType"]
                    .as_str()
                    .is_some_and(|p| p.trim().eq_ignore_ascii_case("free"))))
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
            || !auth["chatgpt_plan_type"].as_str().is_some_and(|p| {
                !p.trim().is_empty()
                    && ((same
                        && original["planType"]
                            .as_str()
                            .is_some_and(|old| p.trim().eq_ignore_ascii_case(old.trim())))
                        || (!same
                            && (forced
                                || (upgraded
                                    && matches!(
                                        p.to_ascii_lowercase().as_str(),
                                        "team" | "business"
                                    ))
                                || (!upgraded && p.eq_ignore_ascii_case("free")))))
            })
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

pub async fn credential(host: &HostClient, id: &str) -> Result<AuthCredential, PluginFault> {
    let reply = host
        .call(
            "host.auth.get",
            json!({}),
            serde_json::to_vec(&json!({"account_id":id})).map_err(|_| fault("凭据请求无效"))?,
        )
        .await
        .map_err(|_| fault("RS 已保存凭据读取失败"))?;
    let value: AuthCredential =
        serde_json::from_slice(&reply.payload).map_err(|_| fault("RS 已保存凭据格式无效"))?;
    if value.account_id != id || value.provider_id != "openai" {
        return Err(fault("RS 已保存凭据账号不一致"));
    }
    Ok(value)
}

pub fn tokens(credential: &AuthCredential) -> Value {
    json!({"access_token":credential.facts.material.get("access_token"),"refresh_token":credential.facts.material.get("refresh_token"),"id_token":credential.facts.material.get("id_token")})
}

pub fn subject(credential: &AuthCredential) -> Result<String, PluginFault> {
    if let Some(subject) = credential
        .facts
        .material
        .get("principal")
        .and_then(|p| p["oauth_subject"].as_str())
        .filter(|s| !s.is_empty())
    {
        return Ok(subject.into());
    }
    // 旧存量凭据的过期 JWT 仅用于重建原绑定，不作为可用授权，也不跳过新令牌核验
    let mut subjects = Vec::new();
    for key in ["id_token", "access_token"] {
        let token = credential
            .facts
            .material
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 32768)
            .ok_or_else(|| fault("原账号主体无法从已保存凭据确认"))?;
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(fault("原账号主体无法从已保存凭据确认"));
        }
        let raw = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| fault("原账号主体参考格式无效"))?;
        let value: Value =
            serde_json::from_slice(&raw).map_err(|_| fault("原账号主体参考格式无效"))?;
        let auth = &value[AUTH];
        if auth["chatgpt_user_id"]
            .as_str()
            .or_else(|| auth["user_id"].as_str())
            != credential.facts.upstream_user_id.as_deref()
            || auth["chatgpt_account_id"].as_str()
                != credential.facts.upstream_account_id.as_deref()
        {
            return Err(fault("原账号已存主体与用户或工作区不一致"));
        }
        if key == "id_token" {
            let email = value["email"]
                .as_str()
                .or_else(|| value["https://api.openai.com/profile"]["email"].as_str());
            if !email
                .zip(credential.facts.email.as_deref())
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                return Err(fault("原账号已存主体邮箱不一致"));
            }
        }
        let sub = value["sub"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_whitespace))
            .ok_or_else(|| fault("原账号主体参考缺失"))?;
        subjects.push(sub.to_owned());
    }
    if subjects[0] != subjects[1] {
        return Err(fault("原账号 ID 与访问令牌主体不一致"));
    }
    Ok(subjects.remove(0))
}
