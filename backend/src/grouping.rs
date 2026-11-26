//! 授权后按已核验套餐归组，核对凭据版本并读回分组
use crate::{
    detail,
    host::{admin, fault},
    recovery, require_idle, settings,
};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde_json::{Value, json};

impl crate::Manager {
    pub(crate) async fn reconcile_refreshed_free_accounts(&mut self, host: &HostClient) {
        let now = std::time::Instant::now();
        if self.next_refresh_group_check.is_some_and(|next| now < next) {
            return;
        }
        self.next_refresh_group_check = Some(now + std::time::Duration::from_secs(30));
        if admin(
            host,
            "POST",
            "/api/admin/accounts/groups/move-after-refresh",
            Some(json!({
                "provider": "openai",
                "sourceGroup": "GPT Pro",
                "targetGroup": "Free Wait",
                "planType": "free",
            })),
        )
        .await
        .is_err()
        {
            let _ = host
                .call(
                    "host.log",
                    json!({"level":"warn","message":"原生刷新后的 Free 归组暂未确认"}),
                    vec![],
                )
                .await;
        }
    }
}

pub fn team(settings: &Value) -> bool {
    settings["planType"]
        .as_str()
        .is_some_and(crate::plans::team)
}

pub fn free_in_pro(settings: &Value) -> bool {
    settings["planType"]
        .as_str()
        .is_some_and(|p| p.trim().eq_ignore_ascii_case("free"))
        && settings["groups"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|g| g["name"] == "GPT Pro"))
}

pub(crate) fn free_upgrade(original: &Value, verified: &Value) -> bool {
    original["planType"]
        .as_str()
        .is_some_and(|plan| plan.trim().eq_ignore_ascii_case("free"))
        && verified["planType"].as_str().is_some_and(|plan| {
            let plan = plan.trim();
            !plan.is_empty() && !plan.eq_ignore_ascii_case("free")
        })
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

pub(crate) async fn destination(host: &HostClient, name: &str) -> Result<String, PluginFault> {
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
            .ok_or_else(|| fault("分组目录格式无效，未修改分组"))?;
        if items.len() > 100 {
            return Err(fault("分组分页大小无效，未修改分组"));
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
                    "{name} 分组不存在、重名或已停用，未修改分组"
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
    assign_target(host, id, expected, revision, target(expected), Assignment::Standard).await
}

pub(crate) async fn assign_free_upgrade(
    host: &HostClient,
    id: &str,
    expected: &Value,
    revision: u64,
) -> Result<Value, PluginFault> {
    assign_target(host, id, expected, revision, Some("GPT Pro"), Assignment::FreeUpgrade).await
}

pub(crate) async fn assign_mailshop_free_upgrade(
    host: &HostClient,
    id: &str,
    expected: &Value,
    revision: u64,
) -> Result<Value, PluginFault> {
    assign_target(
        host,
        id,
        expected,
        revision,
        Some("GPT Pro"),
        Assignment::MailshopFreeUpgrade,
    )
    .await
}

#[derive(Clone, Copy)]
enum Assignment {
    Standard,
    FreeUpgrade,
    MailshopFreeUpgrade,
}

fn ready_rt(account: &Value) -> bool {
    account["hasRefreshToken"] == true && account["_credentialState"] == "ready"
}

async fn assign_target(
    host: &HostClient,
    id: &str,
    expected: &Value,
    revision: u64,
    name: Option<&str>,
    assignment: Assignment,
) -> Result<Value, PluginFault> {
    let Some(name) = name else {
        return Ok(expected.clone());
    };
    let move_only = !matches!(assignment, Assignment::Standard);
    let mailshop = matches!(assignment, Assignment::MailshopFreeUpgrade);
    let before = detail(host, id).await?;
    if !move_only {
        require_idle(&before)?;
    }
    if settings(&before) != *expected
        || before["_credentialRevision"].as_u64() != Some(revision)
        || (mailshop && !ready_rt(&before))
    {
        return Err(fault(&format!(
            "移入 {name} 前账号配置或凭据变化，未修改分组"
        )));
    }
    let credential = if mailshop {
        None
    } else {
        let credential = recovery::credential(host, id).await?;
        if credential.credential_revision != revision {
            return Err(fault(&format!("移入 {name} 前凭据版本未确认")));
        }
        recovery::validate(
            &json!({"event":"same_workspace","workspaceId":before["accountId"],"originalWorkspaceId":before["accountId"],"tokens":recovery::tokens(&credential)}),
            expected,
        )?;
        Some(credential)
    };
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
    let mut wanted = expected.clone();
    let business = !move_only && expected["planType"].as_str().is_some_and(|p| p.trim().eq_ignore_ascii_case(crate::plans::BUSINESS_PROLITE));
    if business && before["enabled"] != false {
        return Err(fault("团队子类型配置写入前账号未暂停，未修改设置"));
    }
    let update = if business {
        wanted["concurrencyLimit"] = json!(10);
        wanted["weight"] = json!(20);
        wanted["supplier"] = json!("shannian");
        json!({"accountId":id,"name":expected["name"],"notes":expected["notes"],"enabled":false,
            "concurrencyLimit":10,"weight":20,"groupIds":group_ids,
            "modelAccess":expected["modelAccess"],"supplier":"shannian",
            "manualStartsAt":expected["manualStartsAt"],"manualExpiresAt":expected["manualExpiresAt"]})
    } else {
        json!({"accountIds":[id],"groupIds":group_ids})
    };
    if current_ids == wanted_ids && wanted == *expected {
        return Ok(expected.clone());
    }
    // 目标目录读取期间可能发生其他管理操作，写入前再次核对配置与精确版本
    let guard = detail(host, id).await?;
    if !move_only {
        require_idle(&guard)?;
    }
    if settings(&guard) != *expected
        || guard["_credentialRevision"].as_u64() != Some(revision)
        || (mailshop && !ready_rt(&guard))
    {
        return Err(fault("归组前账号配置或凭据变化，未修改分组"));
    }
    // 已核验的团队子类型使用指定并发、权重和供应商，凭据保持
    admin(
        host,
        "POST",
        if business { "/api/admin/accounts/update" } else { "/api/admin/accounts/batch-update" },
        Some(update),
    )
    .await
    .map_err(|_| {
        fault(&format!(
            "移入 {name} 的结果未确认，请读取账号核对，不会自动重放"
        ))
    })?;
    let after = detail(host, id).await?;
    let credential_unchanged = if let Some(credential) = credential {
        let renewed = recovery::credential(host, id).await?;
        renewed.credential_revision == revision && renewed.facts.material == credential.facts.material
    } else {
        ready_rt(&after)
    };
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
        || actual != wanted
        || after["_credentialRevision"].as_u64() != Some(revision)
        || !credential_unchanged
    {
        return Err(fault(&format!(
            "{name} 分组或账号配置、凭据读回未确认，请人工核对"
        )));
    }
    let mut result = wanted;
    result["groups"] = after["groups"].clone();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_verified_non_free_upgrade_qualifies() {
        let free = json!({"planType":" Free "});
        for plan in ["plus", "pro", "prolite", "promax", "go", "team", "business"] {
            let paid = json!({"planType":plan});
            assert!(free_upgrade(&free, &paid));
            assert!(!free_upgrade(&paid, &paid));
        }
        for verified in [json!({}), json!({"planType":"free"}), json!({"planType":" "})] {
            assert!(!free_upgrade(&free, &verified));
        }
    }
    #[test]
    fn only_free_in_pro_moves_to_wait() {
        assert_eq!(target(&json!({"planType":"self_serve_business_prolite","groups":[]})), Some("GPT Pro"));
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
