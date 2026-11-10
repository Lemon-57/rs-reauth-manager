//! 导入账号的起止时间、默认身份展示及共享权重策略
use crate::{detail, host::fault, onboarding, recovery, require_idle, settings};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde_json::{Value, json};

pub fn supported(expected: &Value) -> bool {
    expected["planType"].as_str().is_some_and(|plan| {
        matches!(
            plan.trim().to_ascii_lowercase().as_str(),
            "pro" | "prolite" | "self_serve_business_prolite"
        )
    })
}

pub async fn apply(
    host: &HostClient,
    transport: &Value,
    id: &str,
    expected: &Value,
    revision: u64,
    started_at: u64,
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
    let expected = &apply_details(host, transport, id, expected, revision, started_at).await?;
    if !supported(expected) {
        return Ok(expected.clone());
    }
    let (concurrency, weight) = scheduling(expected, &proof)?;
    let group = crate::grouping::destination(host, "GPT Pro").await?;
    let guard = detail(host, id).await?;
    require_idle(&guard)?;
    if settings(&guard) != *expected || guard["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault("Pro/ProLite 策略写入前配置或凭据变化，账号保持暂停"));
    }
    let update = json!({"accountIds":[id],"concurrencyLimit":concurrency,"weight":weight,"groupIds":[group]});
    onboarding::request(host, transport, "/api/admin/accounts/batch-update", update).await?;
    let after = detail(host, id).await?;
    let saved = recovery::credential(host, id).await?;
    let mut wanted = expected.clone();
    wanted["concurrencyLimit"] = json!(concurrency);
    wanted["weight"] = json!(weight);
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

fn import_dates(started_at: u64) -> Result<(String, String), PluginFault> {
    let start = i64::try_from(started_at)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .ok_or_else(|| fault("导入开始时间缺失，账号保持暂停"))?;
    let end = start
        .checked_add_signed(chrono::Duration::days(30))
        .ok_or_else(|| fault("导入到期时间超出范围，账号保持暂停"))?;
    Ok((start.to_rfc3339(), end.to_rfc3339()))
}

pub(crate) async fn apply_details(
    host: &HostClient,
    transport: &Value,
    id: &str,
    expected: &Value,
    revision: u64,
    started_at: u64,
) -> Result<Value, PluginFault> {
    let (start, end) = import_dates(started_at)?;
    let mut wanted = expected.clone();
    wanted["name"] = expected["email"].clone();
    wanted["manualStartsAt"] = json!(start);
    wanted["manualExpiresAt"] = json!(end);
    if crate::plans::team(expected["planType"].as_str().unwrap_or_default())
        && expected["supplier"]
            .as_str()
            .is_none_or(|v| v.trim().is_empty())
    {
        wanted["supplier"] = json!("AI_change_future");
    }
    let guard = detail(host, id).await?;
    require_idle(&guard)?;
    if settings(&guard) != *expected || guard["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault("导入信息写入前账号配置或凭据变化，账号保持暂停"));
    }
    let group_ids: Vec<_> = expected["groups"]
        .as_array()
        .ok_or_else(|| fault("导入分组信息缺失，账号保持暂停"))?
        .iter()
        .map(|g| g["id"].clone())
        .collect();
    let update = json!({
            "accountId":id,"name":wanted["name"],"notes":expected["notes"],"enabled":false,
            "concurrencyLimit":expected["concurrencyLimit"],"weight":expected["weight"],
            "groupIds":group_ids,"modelAccess":expected["modelAccess"],
            "supplier":wanted["supplier"],"manualStartsAt":start,"manualExpiresAt":end
        });
    if transport.is_object() {
        onboarding::request(host, transport, "/api/admin/accounts/update", update).await?;
    } else {
        crate::host::admin(host, "POST", "/api/admin/accounts/update", Some(update)).await?;
    }
    let after = detail(host, id).await?;
    let actual = settings(&after);
    // HTTP 时间统一为 UTC，按时间点比较以接受等价 RFC 3339 表示
    for (key, value) in [("manualStartsAt", &start), ("manualExpiresAt", &end)] {
        let parsed = actual[key]
            .as_str()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok());
        if parsed != chrono::DateTime::parse_from_rfc3339(value).ok() {
            return Err(fault("导入起止时间读回不一致，账号保持暂停"));
        }
        wanted[key] = actual[key].clone();
    }
    if actual != wanted || after["_credentialRevision"].as_u64() != Some(revision) {
        return Err(fault("导入邮箱、供应商或账号配置读回不一致，账号保持暂停"));
    }
    Ok(wanted)
}

fn scheduling(expected: &Value, proof: &Value) -> Result<(u64, u64), PluginFault> {
    if !supported(expected) {
        return Err(fault("导入套餐不适用共享权重策略"));
    }
    let receipt = &proof["importWeight"];
    let ordinal = receipt["ordinal"].as_u64().filter(|n| *n > 0);
    let weight = receipt["weight"]
        .as_u64()
        .filter(|w| (1..=100).contains(w))
        .filter(|w| {
            receipt["timezone"] == "Asia/Shanghai"
                && ordinal.is_some_and(|n| *w == 101u64.saturating_sub(n).max(1))
        })
        .ok_or_else(|| fault("每日共享权重回执无效，账号保持暂停"))?;
    Ok((50, weight))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_expiry_is_exactly_thirty_days_from_the_persisted_start() {
        for date in ["2026-01-31T23:59:59+08:00", "2028-02-01T00:00:00Z"] {
            let start = chrono::DateTime::parse_from_rfc3339(date).unwrap();
            let (a, b) = import_dates(start.timestamp_millis() as u64).unwrap();
            assert_eq!(chrono::DateTime::parse_from_rfc3339(&a).unwrap(), start);
            assert_eq!(
                chrono::DateTime::parse_from_rfc3339(&b).unwrap() - start,
                chrono::Duration::days(30)
            );
        }
        assert!(import_dates(u64::MAX).is_err());
    }

    #[test]
    fn three_import_plans_require_the_same_valid_daily_receipt() {
        for plan in ["pro", "prolite", "self_serve_business_prolite"] {
            let expected = json!({"planType":plan});
            for (ordinal, weight) in [(1, 100), (2, 99), (100, 1), (105, 1)] {
                assert_eq!(scheduling(&expected, &json!({"importWeight":{"weight":weight,"ordinal":ordinal,"timezone":"Asia/Shanghai"}})).unwrap(), (50,weight));
            }
            assert!(scheduling(&expected, &json!({})).is_err());
            for proof in [
                json!({"weight":0,"ordinal":1,"timezone":"Asia/Shanghai"}),
                json!({"weight":100,"ordinal":2,"timezone":"Asia/Shanghai"}),
                json!({"weight":99,"ordinal":2,"timezone":"UTC"}),
                json!({"weight":100,"ordinal":0,"timezone":"Asia/Shanghai"}),
                json!({"weight":"99","ordinal":2,"timezone":"Asia/Shanghai"}),
            ] {
                assert!(scheduling(&expected, &json!({"importWeight":proof})).is_err());
            }
        }
        assert!(
            scheduling(
                &json!({"planType":"team"}),
                &json!({"importWeight":{"weight":100,"ordinal":1,"timezone":"Asia/Shanghai"}})
            )
            .is_err()
        );
    }

    #[test]
    fn only_exact_pro_and_prolite_subscriptions_use_import_profile() {
        for plan in [
            "pro",
            "Pro",
            " PRO ",
            "prolite",
            "ProLite",
            " ProLite ",
            "self_serve_business_prolite",
        ] {
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
