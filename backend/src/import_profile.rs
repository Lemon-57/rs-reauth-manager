//! 新增导入且已核验为 Pro/ProLite 的账号采用 100/100 调度策略。
use crate::{detail, host::fault, onboarding, recovery, require_idle, settings};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde_json::{Value, json};

pub fn supported(expected: &Value) -> bool {
    expected["planType"]
        .as_str()
        .is_some_and(|plan| matches!(plan.trim().to_ascii_lowercase().as_str(), "pro" | "prolite"))
}

pub async fn apply(
    host: &HostClient,
    transport: &Value,
    id: &str,
    expected: &Value,
    revision: u64,
) -> Result<Value, PluginFault> {
    if !supported(expected) {
        return Ok(expected.clone());
    }
    let prolite = expected["planType"]
        .as_str()
        .is_some_and(|plan| plan.trim().eq_ignore_ascii_case("prolite"));
    let before = detail(host, id).await?;
    require_idle(&before)?;
    if settings(&before) != *expected
        || before["enabled"] != false
        || before["_credentialRevision"].as_u64() != Some(revision)
    {
        return Err(fault("Pro/ProLite 导入配置或凭据变化，账号保持暂停"));
    }
    let credential = recovery::credential(host, id).await?;
    if credential.credential_revision != revision {
        return Err(fault("Pro/ProLite 导入凭据版本未确认，账号保持暂停"));
    }
    recovery::validate(
        &json!({"event":"same_workspace","workspaceId":before["accountId"],"originalWorkspaceId":before["accountId"],"tokens":recovery::tokens(&credential)}),
        expected,
    )?;
    let group = if prolite {
        let proof = onboarding::request(
            host,
            transport,
            "/_management/onboarding/prolite-check",
            json!({"accountId":id,"credentialRevision":revision}),
        )
        .await
        .map_err(|_| {
            fault("ProLite 独立固定 IPv6 未验证，账号保持暂停；不使用共享出口或自动换绑")
        })?;
        if proof["accountId"] != id
            || proof["credentialRevision"].as_u64() != Some(revision)
            || proof["independentIPv6"] != true
        {
            return Err(fault("ProLite 独立 IPv6 回执不一致，账号保持暂停"));
        }
        Some(crate::grouping::destination(host, "GPT Pro").await?)
    } else {
        None
    };
    let guard = detail(host, id).await?;
    require_idle(&guard)?;
    if settings(&guard) != *expected || guard["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault("Pro/ProLite 策略写入前配置或凭据变化，账号保持暂停"));
    }
    let mut update = json!({"accountIds":[id],"concurrencyLimit":100,"weight":100});
    if let Some(group) = &group {
        update["groupIds"] = json!([group]);
    }
    onboarding::request(host, transport, "/api/admin/accounts/batch-update", update).await?;
    let after = detail(host, id).await?;
    let saved = recovery::credential(host, id).await?;
    let mut wanted = expected.clone();
    wanted["concurrencyLimit"] = json!(100);
    wanted["weight"] = json!(100);
    if let Some(group) = group {
        let groups = after["groups"].as_array();
        if !groups.is_some_and(|groups| {
            groups.len() == 1
                && groups[0]["id"] == group
                && groups[0]["name"] == "GPT Pro"
                && groups[0]["enabled"] == true
        }) {
            return Err(fault("ProLite 分组读回未确认，账号保持暂停"));
        }
        wanted["groups"] = after["groups"].clone();
    }
    if settings(&after) != wanted
        || after["_credentialRevision"].as_u64() != Some(revision)
        || saved.credential_revision != revision
        || saved.facts.material != credential.facts.material
    {
        return Err(fault(
            "Pro/ProLite 并发、权重、分组或凭据读回未确认，账号保持暂停",
        ));
    }
    Ok(wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_pro_and_prolite_subscriptions_use_import_profile() {
        for plan in ["pro", "Pro", " PRO ", "prolite", "ProLite", " ProLite "] {
            assert!(supported(&json!({"planType":plan})));
        }
        for plan in [
            "promax",
            "plus",
            "team",
            "business",
            "free",
            "go",
            "prolite-other",
            "pro-other",
            "",
        ] {
            assert!(!supported(&json!({"planType":plan})));
        }
        assert!(!supported(
            &json!({"name":"ProLite","groups":[{"name":"GPT Pro"}]})
        ));
    }
}
