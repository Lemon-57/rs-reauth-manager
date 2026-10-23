//! 授权后按已核验套餐归组，先确认凭据及空闲状态再单独更新分组
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

pub fn free_in_pro(settings: &Value) -> bool {
    settings["planType"]
        .as_str()
        .is_some_and(|p| p.trim().eq_ignore_ascii_case("free"))
        && settings["groups"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|g| g["name"] == "GPT Pro"))
}

fn target(settings: &Value) -> Option<&'static str> {
    if team(settings) {
        Some("GPT Pro")
    } else if free_in_pro(settings) {
        Some("Free Wait")
    } else {
        None
    }
}

fn membership(existing: &[Value], name: &str, id: &str) -> Result<Vec<String>, PluginFault> {
    let mut ids = Vec::new();
    if name == "Free Wait" {
        for group in existing.iter().filter(|g| g["name"] != "GPT Pro") {
            let value = group["id"]
                .as_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| fault("原分组身份无效，未修改分组"))?;
            if !ids.iter().any(|old| old == value) {
                ids.push(value.to_owned());
            }
        }
    }
    if !ids.iter().any(|old| old == id) {
        ids.push(id.to_owned());
    }
    Ok(ids)
}

async fn destination(host: &HostClient, name: &str) -> Result<String, PluginFault> {
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
            let matches: Vec<_> = rows.iter().filter(|g| g["name"] == name).collect();
            if matches.len() != 1 || matches[0]["enabled"] != true {
                return Err(fault(&format!(
                    "{name} 分组不存在、重名或已停用，账号保持暂停"
                )));
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
    let Some(name) = target(expected) else {
        return Ok(expected.clone());
    };
    let before = detail(host, id).await?;
    require_idle(&before)?;
    if settings(&before) != *expected || before["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault(&format!(
            "移入 {name} 前账号配置或凭据变化，未修改分组"
        )));
    }
    let credential = recovery::credential(host, id).await?;
    if credential.credential_revision != revision {
        return Err(fault(&format!("移入 {name} 前凭据版本未确认")));
    }
    recovery::validate(
        &json!({"event":"same_workspace","workspaceId":before["accountId"],"originalWorkspaceId":before["accountId"],"tokens":recovery::tokens(&credential)}),
        expected,
    )?;
    let group_id = destination(host, name).await?;
    let existing = before["groups"]
        .as_array()
        .ok_or_else(|| fault("当前账号分组格式无效"))?;
    let group_ids = membership(existing, name, &group_id)?;
    let mut current_ids = existing
        .iter()
        .map(|g| g["id"].as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    let mut wanted_ids = group_ids.clone();
    current_ids.sort();
    wanted_ids.sort();
    if current_ids == wanted_ids {
        return Ok(expected.clone());
    }
    // 目标目录读取期间可能发生其他管理操作，写入前再次核对空闲与精确版本。
    let guard = detail(host, id).await?;
    require_idle(&guard)?;
    if settings(&guard) != *expected || guard["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault("归组前账号配置或凭据变化，未修改分组"));
    }
    // 分组是本次明确授权的唯一设置变更，不重复登录、不刷新或替换凭据
    admin(
        host,
        "POST",
        "/api/admin/accounts/batch-update",
        Some(json!({"accountIds":[id],"groupIds":group_ids})),
    )
    .await
    .map_err(|_| {
        fault(&format!(
            "移入 {name} 的结果未确认，请读取账号核对，不会自动重放"
        ))
    })?;
    let after = detail(host, id).await?;
    let renewed = recovery::credential(host, id).await?;
    let groups = after["groups"]
        .as_array()
        .ok_or_else(|| fault(&format!("{name} 分组读回格式无效")))?;
    let mut actual = settings(&after);
    actual["groups"] = expected["groups"].clone();
    let mut actual_ids = groups
        .iter()
        .map(|g| g["id"].as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    actual_ids.sort();
    if actual_ids != wanted_ids
        || !groups
            .iter()
            .any(|g| g["id"] == group_id && g["name"] == name && g["enabled"] == true)
        || actual != *expected
        || after["_credentialRevision"].as_u64() != Some(revision)
        || renewed.credential_revision != revision
        || renewed.facts.material != credential.facts.material
    {
        return Err(fault(&format!(
            "{name} 分组或账号配置、凭据读回未确认，请人工核对"
        )));
    }
    let mut result = expected.clone();
    result["groups"] = after["groups"].clone();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_free_in_pro_moves_to_wait() {
        for plan in ["free", " Free ", "FREE"] {
            assert_eq!(
                target(&json!({"planType":plan,"groups":[{"id":"p","name":"GPT Pro"}]})),
                Some("Free Wait")
            );
        }
        for name in ["GPT Free", "Free Wait", "GPT Pro other"] {
            assert_eq!(
                target(&json!({"planType":"free","groups":[{"id":"x","name":name}]})),
                None
            );
        }
        assert_eq!(
            target(&json!({"planType":"plus","groups":[{"id":"p","name":"GPT Pro"}]})),
            None
        );
        assert_eq!(
            target(&json!({"planType":"team","groups":[]})),
            Some("GPT Pro")
        );
    }
    #[test]
    fn free_move_preserves_other_groups_and_deduplicates_wait() {
        let groups = vec![
            json!({"id":"p","name":"GPT Pro"}),
            json!({"id":"custom","name":"Custom"}),
            json!({"id":"w","name":"Free Wait"}),
        ];
        assert_eq!(
            membership(&groups, "Free Wait", "w").unwrap(),
            vec!["custom", "w"]
        );
        assert_eq!(membership(&groups, "GPT Pro", "p").unwrap(), vec!["p"]);
    }
}
