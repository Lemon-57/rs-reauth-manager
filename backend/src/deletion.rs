//! 通过原生管理接口删除所选账号并核对实际移除结果
use crate::{
    host::{admin, fault},
    rows,
};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    account_ids: Vec<String>,
}

fn ids(payload: &[u8]) -> Result<Vec<String>, PluginFault> {
    let request: Request = serde_json::from_slice(payload).map_err(|_| fault("删除参数无效"))?;
    if request.account_ids.is_empty()
        || request.account_ids.len() > 100
        || request.account_ids.iter().collect::<BTreeSet<_>>().len() != request.account_ids.len()
        || request.account_ids.iter().any(|id| {
            id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        })
    {
        return Err(fault("每次删除需选择 1 至 100 个不同的账号"));
    }
    Ok(request.account_ids)
}

fn response_matches(result: &Value, ids: &[String]) -> bool {
    result["deletedCount"].as_u64() == Some(ids.len() as u64)
        && result["accountIds"].as_array().is_some_and(|values| {
            values.len() == ids.len()
                && values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    == ids.iter().map(String::as_str).collect::<BTreeSet<_>>()
        })
}

pub async fn remove(host: &HostClient, payload: &[u8]) -> Result<Vec<String>, PluginFault> {
    let ids = ids(payload)?;
    let before = rows(host).await?;
    let accounts = before["accounts"]
        .as_array()
        .ok_or_else(|| fault("账号目录无效"))?;
    if ids
        .iter()
        .any(|id| !accounts.iter().any(|a| a["id"] == *id))
    {
        return Err(fault("所选账号已不存在或不属于插件账号列表，请刷新后重试"));
    }
    let result = admin(
        host,
        "POST",
        "/api/admin/accounts/delete",
        Some(json!({"provider":"openai","accountIds":ids})),
    )
    .await
    .map_err(|error| {
        fault(&format!(
            "删除结果未确认，请刷新账号列表核对；不会自动重复删除。{}",
            error.message
        ))
    })?;
    if !response_matches(&result, &ids) {
        return Err(fault(
            "RS 返回的删除账号或数量不匹配，请刷新核对；不会自动重复删除",
        ));
    }
    let after = rows(host)
        .await
        .map_err(|_| fault("RS 已返回删除成功，但目录回读失败，请刷新核对；不会自动重复删除"))?;
    if after["accounts"]
        .as_array()
        .is_none_or(|accounts| accounts.iter().any(|a| ids.iter().any(|id| a["id"] == *id)))
    {
        return Err(fault(
            "删除已提交，但仍有账号未确认移除，请刷新核对；不会自动重复删除",
        ));
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_is_bounded_unique_and_has_no_confirmation_field() {
        assert_eq!(
            ids(br#"{"accountIds":["acct_one","acct_two"]}"#)
                .unwrap()
                .len(),
            2
        );
        for value in [
            json!({"accountIds":[]}),
            json!({"accountIds":["a","a"]}),
            json!({"accountIds":["../other"]}),
            json!({"accountIds":[""]}),
            json!({"accountIds":["a"],"confirmation":"anything"}),
            json!({"accountIds":(0..101).map(|i| format!("acct_{i}")).collect::<Vec<_>>()}),
        ] {
            assert!(ids(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn native_success_requires_exact_ids_and_count() {
        let ids = vec!["a".into(), "b".into()];
        assert!(response_matches(
            &json!({"deletedCount":2,"accountIds":["b","a"]}),
            &ids
        ));
        for value in [
            json!({"deletedCount":0,"accountIds":["a","b"]}),
            json!({"deletedCount":2,"accountIds":["a","a"]}),
            json!({"deletedCount":2,"accountIds":["a","other"]}),
            json!({"deletedCount":2,"accountIds":["a",null]}),
        ] {
            assert!(!response_matches(&value, &ids));
        }
    }
}
