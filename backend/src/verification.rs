//! 通过 RS 原生接口核验已保存的 RT 与轮换结果，确认后恢复调度
use crate::{
    detail,
    host::{admin, fault},
    native, recovery, require_idle, settings,
};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde_json::{Value, json};

pub async fn finish(host: &HostClient, id: &str, snapshot: &Value) -> Result<(), PluginFault> {
    let expected = &snapshot["postAuthorizationSettings"];
    let revision = snapshot["authorizedCredentialRevision"]
        .as_u64()
        .ok_or_else(|| fault("原生保存的精确凭据版本缺失，账号保持暂停"))?;
    let current = detail(host, id).await?;
    require_idle(&current)?;
    if settings(&current) != *expected
        || current["enabled"] != false
        || current["_credentialRevision"].as_u64() != Some(revision)
    {
        return Err(fault("原生 RT 验证前配置或凭据版本变化，账号保持暂停"));
    }
    let before = recovery::credential(host, id).await?;
    if before.credential_revision != revision {
        return Err(fault("原生 RT 验证前凭据版本变化，账号保持暂停"));
    }
    let check = json!({"event":"same_workspace","workspaceId":current["accountId"],"originalWorkspaceId":current["accountId"],"tokens":recovery::tokens(&before)});
    let (identity, _) = recovery::validate(&check, expected)?;
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
    require_idle(&after)?;
    let saved = recovery::credential(host, id).await?;
    if settings(&after) != *expected
        || after["_credentialRevision"].as_u64() != Some(revision + 1)
        || saved.credential_revision != revision + 1
    {
        return Err(fault("原生 RT 刷新保存或精确版本未确认，账号保持暂停"));
    }
    let check = json!({"event":"same_workspace","workspaceId":after["accountId"],"originalWorkspaceId":after["accountId"],"tokens":recovery::tokens(&saved)});
    let (renewed, _) = recovery::validate(&check, expected)?;
    if renewed["sub"] != identity["sub"] {
        return Err(fault("原生 RT 刷新后的主体变化，账号保持暂停"));
    }
    native::restore(
        host,
        id,
        expected,
        saved.credential_revision,
        snapshot["resumeEnabled"] == true,
    )
    .await
}
