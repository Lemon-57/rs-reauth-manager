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
    if supported(expected) {
        recovery::validate(
            &json!({"event":"same_workspace","workspaceId":before["accountId"],"originalWorkspaceId":before["accountId"],"tokens":recovery::tokens(&credential)}),
            expected,
        )?;
    }
    let proof = onboarding::request(
        host,
        transport,
        "/_management/onboarding/ipv6-check",
        json!({"accountId":id,"credentialRevision":revision}),
    )
    .await
    .map_err(|_| fault("导入账号独立固定 IPv6 未验证，请核对本次预留；不使用共享出口"))?;
    if proof["accountId"] != id
        || proof["credentialRevision"].as_u64() != Some(revision)
        || proof["independentIPv6"] != true
    {
        return Err(fault("导入账号独立 IPv6 回执不一致，请核对本次预留"));
    }
    if !supported(expected) {
        return Ok(expected.clone());
    }
    let group = crate::grouping::destination(host, "GPT Pro").await?;
    let guard = detail(host, id).await?;
    require_idle(&guard)?;
    if settings(&guard) != *expected || guard["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault("Pro/ProLite 策略写入前配置或凭据变化，账号保持暂停"));
    }
    let update = json!({"accountIds":[id],"concurrencyLimit":100,"weight":100,"groupIds":[group]});
    onboarding::request(host, transport, "/api/admin/accounts/batch-update", update).await?;
    let after = detail(host, id).await?;
    let saved = recovery::credential(host, id).await?;
    let mut wanted = expected.clone();
    wanted["concurrencyLimit"] = json!(100);
    wanted["weight"] = json!(100);
    let groups = after["groups"].as_array();
    if !groups.is_some_and(|groups| {
        groups.len() == 1
            && groups[0]["id"] == group
            && groups[0]["name"] == "GPT Pro"
            && groups[0]["enabled"] == true
    }) {
        return Err(fault("Pro/ProLite 分组读回未确认，账号保持暂停"));
    }
    wanted["groups"] = after["groups"].clone();
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
