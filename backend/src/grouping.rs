//! 已核验的 Team 授权统一移入 GPT Pro，先确认凭据及空闲状态再单独更新分组
use crate::{
    detail,
    host::{admin, fault},
    recovery, require_idle, settings,
};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde_json::{Value, json};

pub fn team(settings: &Value) -> bool {
    settings["planType"]
        .as_str()
        .is_some_and(|p| matches!(p.trim().to_ascii_lowercase().as_str(), "team" | "business"))
}

async fn destination(host: &HostClient) -> Result<String, PluginFault> {
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut total = None;
    for page in 1..=100 {
        let data = admin(
            host,
            "GET",
            &format!("/api/admin/account-groups/options?page={page}&pageSize=100"),
            None,
        )
        .await?;
        let items = data["items"]
            .as_array()
            .ok_or_else(|| fault("GPT Pro 分组目录格式无效，账号保持暂停"))?;
        if items.len() > 100 {
            return Err(fault("分组分页大小无效，账号保持暂停"));
        }
        if let Some(count) = data["page"]["total"].as_u64() {
            if total.is_some_and(|old| old != count) {
                return Err(fault("分组目录在读取期间变化，请核对后重试"));
            }
            total = Some(count);
        }
        for group in items {
            let id = group["id"]
                .as_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| fault("分组身份无效"))?;
            if !seen.insert(id.to_owned()) {
                return Err(fault("分组目录存在重复分页"));
            }
            rows.push(group.clone());
        }
        if items.len() < 100 {
            if total.is_some_and(|count| count != rows.len() as u64) {
                return Err(fault("分组目录不完整，未修改分组"));
            }
            let matches: Vec<_> = rows.iter().filter(|g| g["name"] == "GPT Pro").collect();
            if matches.len() != 1 || matches[0]["enabled"] != true {
                return Err(fault("GPT Pro 分组不存在、重名或已停用，账号保持暂停"));
            }
            return Ok(matches[0]["id"]
                .as_str()
                .ok_or_else(|| fault("GPT Pro 分组身份无效"))?
                .into());
        }
    }
    Err(fault("分组目录超过读取上限，未修改分组"))
}

pub async fn assign(
    host: &HostClient,
    id: &str,
    expected: &Value,
    revision: u64,
) -> Result<Value, PluginFault> {
    if !team(expected) {
        return Ok(expected.clone());
    }
    let before = detail(host, id).await?;
    require_idle(&before)?;
    if settings(&before) != *expected || before["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault("移入 GPT Pro 前账号配置或凭据变化，未修改分组"));
    }
    let credential = recovery::credential(host, id).await?;
    if credential.credential_revision != revision {
        return Err(fault("移入 GPT Pro 前凭据版本未确认"));
    }
    recovery::validate(
        &json!({"event":"same_workspace","workspaceId":before["accountId"],"originalWorkspaceId":before["accountId"],"tokens":recovery::tokens(&credential)}),
        expected,
    )?;
    let group_id = destination(host).await?;
    let existing = before["groups"]
        .as_array()
        .ok_or_else(|| fault("当前账号分组格式无效"))?;
    if existing.len() == 1
        && existing[0]["id"] == group_id
        && existing[0]["name"] == "GPT Pro"
        && existing[0]["enabled"] == true
    {
        return Ok(expected.clone());
    }
    // 分组是本次明确授权的唯一设置变更，不重复登录、不刷新或替换凭据
    admin(
        host,
        "POST",
        "/api/admin/accounts/batch-update",
        Some(json!({"accountIds":[id],"groupIds":[group_id]})),
    )
    .await
    .map_err(|_| fault("移入 GPT Pro 的结果未确认，请读取账号核对，不会自动重放"))?;
    let after = detail(host, id).await?;
    let renewed = recovery::credential(host, id).await?;
    let groups = after["groups"]
        .as_array()
        .ok_or_else(|| fault("GPT Pro 分组读回格式无效"))?;
    let mut actual = settings(&after);
    actual["groups"] = expected["groups"].clone();
    if groups.len() != 1
        || groups[0]["id"] != group_id
        || groups[0]["name"] != "GPT Pro"
        || groups[0]["enabled"] != true
        || actual != *expected
        || after["_credentialRevision"].as_u64() != Some(revision)
        || renewed.credential_revision != revision
        || renewed.facts.material != credential.facts.material
    {
        return Err(fault("GPT Pro 分组或账号配置、凭据读回未确认，请人工核对"));
    }
    let mut result = expected.clone();
    result["groups"] = after["groups"].clone();
    Ok(result)
}
