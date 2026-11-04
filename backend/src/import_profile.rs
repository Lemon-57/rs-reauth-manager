//! 仅新增导入且已核验为 ProLite 的账号采用专用调度策略。
use crate::{detail, host::fault, onboarding, recovery, require_idle, settings};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde_json::{Value, json};

pub fn prolite(expected: &Value) -> bool {
    expected["planType"]
        .as_str()
        .is_some_and(|plan| plan.trim().eq_ignore_ascii_case("prolite"))
}

pub async fn apply(
    host: &HostClient,
    transport: &Value,
    id: &str,
    expected: &Value,
    revision: u64,
) -> Result<Value, PluginFault> {
    if !prolite(expected) {
        return Ok(expected.clone());
    }
    let before = detail(host, id).await?;
    require_idle(&before)?;
    if settings(&before) != *expected
        || before["enabled"] != false
        || before["_credentialRevision"].as_u64() != Some(revision)
    {
        return Err(fault("ProLite 导入配置或凭据变化，账号保持暂停"));
    }
    let credential = recovery::credential(host, id).await?;
    if credential.credential_revision != revision {
        return Err(fault("ProLite 导入凭据版本未确认，账号保持暂停"));
    }
    recovery::validate(
        &json!({"event":"same_workspace","workspaceId":before["accountId"],"originalWorkspaceId":before["accountId"],"tokens":recovery::tokens(&credential)}),
        expected,
    )?;
    let proof = onboarding::request(
        host,
        transport,
        "/_management/onboarding/prolite-check",
        json!({"accountId":id,"credentialRevision":revision}),
    )
    .await
    .map_err(|_| fault("ProLite 独立固定 IPv6 未验证，账号保持暂停；不使用共享出口或自动换绑"))?;
    if proof["accountId"] != id
        || proof["credentialRevision"].as_u64() != Some(revision)
        || proof["independentIPv6"] != true
    {
        return Err(fault("ProLite 独立 IPv6 回执不一致，账号保持暂停"));
    }
    let group = crate::grouping::destination(host, "GPT Pro").await?;
    let guard = detail(host, id).await?;
    require_idle(&guard)?;
    if settings(&guard) != *expected || guard["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault("ProLite 策略写入前配置或凭据变化，账号保持暂停"));
    }
    onboarding::request(
        host,
        transport,
        "/api/admin/accounts/batch-update",
        json!({"accountIds":[id],"concurrencyLimit":50,"weight":100,"groupIds":[group]}),
    )
    .await?;
    let after = detail(host, id).await?;
    let saved = recovery::credential(host, id).await?;
    let mut wanted = expected.clone();
    wanted["concurrencyLimit"] = json!(50);
    wanted["weight"] = json!(100);
    wanted["groups"] = after["groups"].clone();
    let groups = after["groups"].as_array();
    if settings(&after) != wanted
        || !groups.is_some_and(|groups| {
            groups.len() == 1
                && groups[0]["id"] == group
                && groups[0]["name"] == "GPT Pro"
                && groups[0]["enabled"] == true
        })
        || after["_credentialRevision"].as_u64() != Some(revision)
        || saved.credential_revision != revision
        || saved.facts.material != credential.facts.material
    {
        return Err(fault(
            "ProLite 并发、权重、分组或凭据读回未确认，账号保持暂停",
        ));
    }
    Ok(wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_prolite_subscription_uses_import_profile() {
        for plan in ["prolite", "ProLite", " ProLite "] {
            assert!(prolite(&json!({"planType":plan})));
        }
        for plan in [
            "pro",
            "promax",
            "plus",
            "team",
            "business",
            "free",
            "go",
            "prolite-other",
            "",
        ] {
            assert!(!prolite(&json!({"planType":plan})));
        }
        assert!(!prolite(
            &json!({"name":"ProLite","groups":[{"name":"GPT Pro"}]})
        ));
    }
}
