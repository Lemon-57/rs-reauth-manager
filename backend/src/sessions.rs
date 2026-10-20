//! 在已验证的新授权上退出其他设备，暂停调度后才向上游发送撤销请求
use crate::{
    detail,
    host::{admin, fault},
    proxy, recovery, require_idle, settings,
};
use gateway_plugin_sdk::{PluginFault, call::host::AuthCredential, client::HostClient};
use serde_json::{Value, json};

pub async fn prepare(
    host: &HostClient,
    id: &str,
    device: &Value,
    previous: &Value,
    _result: &Value,
) -> Result<(Value, Value), PluginFault> {
    let device = device
        .as_str()
        .filter(|v| uuid::Uuid::parse_str(v).is_ok())
        .ok_or_else(|| fault("本次设备标识未确认，未登出其他设备"))?;
    let current = detail(host, id).await?;
    let mut expected = previous
        .get("postAuthorizationSettings")
        .unwrap_or(&previous["settings"])
        .clone();
    if settings(&current) != expected {
        return Err(fault("新授权写回后账号配置发生变化，未登出其他设备"));
    }
    require_idle(&current)?;
    let revision = current["_credentialRevision"].clone();
    let reply = host
        .call(
            "host.auth.get",
            json!({}),
            serde_json::to_vec(&json!({"account_id":id})).map_err(|_| fault("凭据请求无效"))?,
        )
        .await
        .map_err(|_| fault("新授权读取失败，未登出其他设备"))?;
    let credential: AuthCredential =
        serde_json::from_slice(&reply.payload).map_err(|_| fault("新授权格式无效"))?;
    let stored_subject = recovery::subject(&credential)?;
    let facts = credential.facts;
    let tokens = json!({"access_token":facts.material.get("access_token"),"refresh_token":facts.material.get("refresh_token"),"id_token":facts.material.get("id_token")});
    let check = json!({"event":"same_workspace","workspaceId":current["accountId"],"originalWorkspaceId":current["accountId"],"tokens":tokens});
    let (identity, _) = recovery::validate(&check, &expected)?;
    if credential.account_id != id
        || credential.provider_id != "openai"
        || Some(credential.credential_revision) != revision.as_u64()
        || facts.authentication_kind != "oauth"
        || facts.upstream_user_id.as_deref() != current["userId"].as_str()
        || facts.upstream_account_id.as_deref() != current["accountId"].as_str()
        || facts.email.as_deref() != current["email"].as_str()
        || Some(stored_subject.as_str()) != identity["sub"].as_str()
    {
        return Err(fault("新授权身份或凭据版本不一致，未登出其他设备"));
    }
    let endpoint = proxy(host, &current).await?;
    let latest = detail(host, id).await?;
    require_idle(&latest)?;
    if settings(&latest) != expected || latest["_credentialRevision"] != revision {
        return Err(fault("账号配置或授权已变化，未登出其他设备"));
    }
    let resume = previous
        .get("resumeAfterCleanup")
        .and_then(Value::as_bool)
        .unwrap_or(current["enabled"] == true);
    if current["enabled"] == true {
        admin(
            host,
            "POST",
            "/api/admin/accounts/batch-update",
            Some(json!({"accountIds":[id],"enabled":false})),
        )
        .await
        .map_err(|_| fault("暂停调度结果不确定，未登出其他设备，请核对账号启停状态"))?;
    }
    expected["enabled"] = json!(false);
    let paused = detail(host, id).await?;
    if settings(&paused) != expected
        || paused["_credentialRevision"] != revision
        || require_idle(&paused).is_err()
    {
        return Err(fault(
            "暂停后仍有在途请求或配置变化，未登出其他设备；请核对暂停状态",
        ));
    }
    let input = json!({"action":"cleanup_sessions","tokens":{"access_token":tokens["access_token"],"id_token":tokens["id_token"]},"email":current["email"],"userId":current["userId"],"accountId":current["accountId"],"planType":current["planType"],"deviceId":device,"proxy":endpoint});
    let snapshot = json!({"phase":"cleanup","cleanupPrepared":true,"resumeEnabled":resume,"settings":expected,"credentialRevision":revision,"deviceId":device});
    Ok((input, snapshot))
}

pub async fn refresh(
    host: &HostClient,
    id: &str,
    snapshot: &Value,
    result: &Value,
) -> Result<(Value, Value), PluginFault> {
    if result["event"] != "sessions_cleaned"
        || result["otherSessionsRevoked"] != true
        || result["revokedCount"].as_u64().is_none_or(|n| n > 1000)
        || result["retainedSessionId"]
            .as_str()
            .is_none_or(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_whitespace))
    {
        return Err(fault(
            "其他设备退出或本次 RT 刷新未确认，账号保持暂停，请人工核对",
        ));
    }
    let current = detail(host, id).await?;
    require_idle(&current)?;
    if settings(&current) != snapshot["settings"]
        || current["_credentialRevision"] != snapshot["credentialRevision"]
    {
        return Err(fault("RT 原生刷新前配置或凭据变化，账号保持暂停"));
    }
    let before = recovery::credential(host, id).await?;
    let old_tokens = recovery::tokens(&before);
    let old_check = json!({"event":"same_workspace","workspaceId":current["accountId"],"originalWorkspaceId":current["accountId"],"tokens":old_tokens});
    let (old_identity, _) = recovery::validate(&old_check, &snapshot["settings"])?;
    admin(
        host,
        "POST",
        "/api/admin/accounts/refresh",
        Some(json!({"accountId":id})),
    )
    .await
    .map_err(|e| {
        fault(&format!(
            "RS 原生 RT 刷新未确认：{}，账号保持暂停，不自动重放",
            e.message
        ))
    })?;
    let after = detail(host, id).await?;
    let renewed = recovery::credential(host, id).await?;
    if settings(&after) != snapshot["settings"]
        || after["_credentialRevision"].as_u64() != Some(before.credential_revision + 1)
        || renewed.credential_revision != before.credential_revision + 1
    {
        return Err(fault("原生 RT 刷新保存或精确版本未确认，账号保持暂停"));
    }
    let check = json!({"event":"same_workspace","workspaceId":after["accountId"],"originalWorkspaceId":after["accountId"],"tokens":recovery::tokens(&renewed)});
    let (identity, _) = recovery::validate(&check, &snapshot["settings"])?;
    if identity["sub"] != old_identity["sub"] {
        return Err(fault("原生 RT 刷新后的主体变化，账号保持暂停"));
    }
    let tokens = recovery::tokens(&renewed);
    let input = json!({"action":"verify_sessions","tokens":{"access_token":tokens["access_token"],"id_token":tokens["id_token"]},"email":after["email"],"userId":after["userId"],"accountId":after["accountId"],"planType":after["planType"],"deviceId":snapshot["deviceId"],"proxy":proxy(host,&after).await?,"expectedSessionId":result["retainedSessionId"]});
    let mut next = snapshot.clone();
    next["phase"] = json!("verify");
    next["credentialRevision"] = json!(renewed.credential_revision);
    Ok((input, next))
}

pub async fn finish(
    host: &HostClient,
    id: &str,
    snapshot: &Value,
    result: &Value,
) -> Result<(), PluginFault> {
    if result["event"] != "sessions_verified"
        || result["otherSessionsRevoked"] != true
        || result["currentSessionRetained"] != true
    {
        return Err(fault("RS 原生刷新后的设备目录未确认，账号保持暂停"));
    }
    crate::native::restore(
        host,
        id,
        &snapshot["settings"],
        snapshot["credentialRevision"]
            .as_u64()
            .ok_or_else(|| fault("最终核验版本缺失"))?,
        snapshot["resumeEnabled"] == true,
    )
    .await
}
