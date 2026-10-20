//! 异常认证筛选、持久化单次尝试与后台串行排队
use crate::{
    Job, Queue, detail, eligible,
    host::{fault, now},
    notes_valid, require_idle,
};
use gateway_plugin_sdk::{PluginFault, client::HostClient};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const COOLDOWN_MS: u64 = 6 * 60 * 60 * 1000;

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Automation {
    pub enabled: bool,
    pub attempts: BTreeMap<String, Attempt>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attempt {
    at: u64,
    recovered: bool,
    #[serde(default)]
    requires_review: bool,
}

pub fn authentication_failed(a: &Value) -> bool {
    // RS 也将上游拒绝写成 access_token_expired，必须再查凭据终态
    candidate(a)
        && match a["errorReason"].as_str() {
            Some("credential_expired") => true,
            Some("access_token_expired") => a["_credentialState"] == "expired",
            Some("credential_invalid") => a["_credentialState"] == "invalid",
            _ => false,
        }
}
fn candidate(a: &Value) -> bool {
    eligible(a)
        && a["status"] == "error"
        && matches!(
            a["errorReason"].as_str(),
            Some("credential_expired" | "access_token_expired" | "credential_invalid")
        )
}
fn prepared(a: &Value) -> bool {
    candidate(a)
        && (a["enabled"] == true || a["errorReason"] == "credential_invalid")
        && notes_valid(a)
        && a["outboundProxyEndpoint"]
            .as_str()
            .is_some_and(|p| !p.is_empty())
        && ["userId", "accountId", "planType"]
            .iter()
            .all(|k| a[k].as_str().is_some_and(|v| !v.is_empty()))
        && require_idle(a).is_ok()
}

pub fn ready(a: &Value) -> bool {
    prepared(a) && authentication_failed(a)
}

impl Automation {
    pub fn observe(&mut self, accounts: &[Value]) {
        for a in accounts {
            if (a["status"] == "normal"
                || (a["enabled"] == false
                    && a["status"] == "disabled"
                    && a["_credentialState"] == "ready"))
                && a["errorReason"].is_null()
                && let Some(attempt) = a["id"].as_str().and_then(|id| self.attempts.get_mut(id))
                && !attempt.requires_review
            {
                attempt.recovered = true;
            }
        }
    }
    pub fn permitted(&self, id: &str, timestamp: u64) -> bool {
        self.attempts.get(id).is_none_or(|a| {
            !a.requires_review && a.recovered && timestamp.saturating_sub(a.at) >= COOLDOWN_MS
        }) && (self.attempts.contains_key(id) || self.attempts.len() < 1000)
    }
}

pub async fn scan(host: &HostClient, queue: &mut Queue) -> Result<(), PluginFault> {
    let timestamp = now();
    if !queue.automation.enabled {
        return Ok(());
    }
    let mut accounts = crate::directory(host).await?;
    // 保留最新任务的人工核对边界，历史失败不会覆盖较新的人工成功
    let mut seen = std::collections::BTreeSet::new();
    for job in queue
        .jobs
        .iter()
        .rev()
        .filter(|j| seen.insert(j.account_id.clone()))
    {
        if matches!(
            job.status.as_str(),
            "failed" | "review" | "interrupted" | "cancelled"
        ) {
            if !queue.automation.attempts.contains_key(&job.account_id) {
                if queue.automation.attempts.len() >= 1000 {
                    return Err(fault("自动授权尝试记录已满，请人工核对"));
                }
                queue.automation.attempts.insert(
                    job.account_id.clone(),
                    Attempt {
                        at: timestamp,
                        recovered: false,
                        requires_review: true,
                    },
                );
            }
            if matches!(job.status.as_str(), "review" | "interrupted" | "cancelled")
                && let Some(attempt) = queue.automation.attempts.get_mut(&job.account_id)
            {
                attempt.requires_review = true;
            }
        } else if !job.automatic
            && job.status == "success"
            && let Some(attempt) = queue.automation.attempts.get_mut(&job.account_id)
            && job
                .finished_at
                .is_some_and(|finished| finished >= attempt.at)
        {
            attempt.requires_review = false;
        }
    }
    // 暂停不等于凭据已恢复，只为待观察的暂停账号读取原生凭据终态
    for summary in &mut accounts {
        if summary["enabled"] == false
            && summary["status"] == "disabled"
            && let Some(id) = summary["id"].as_str()
            && queue
                .automation
                .attempts
                .get(id)
                .is_some_and(|a| !a.requires_review && !a.recovered)
        {
            *summary = detail(host, id).await?;
        }
    }
    queue.automation.observe(&accounts);
    // 手动队列优先，每次巡检最多加入一个账号
    if queue.jobs.iter().any(Job::active) {
        return Ok(());
    }
    for summary in accounts.iter().filter(|a| prepared(a)) {
        let id = summary["id"]
            .as_str()
            .ok_or_else(|| fault("自动授权账号标识无效"))?;
        if !queue.automation.permitted(id, timestamp) {
            continue;
        }
        let a = detail(host, id).await?;
        if !ready(&a) {
            continue;
        }
        if !crate::control::enabled(host, queue.automation.enabled).await? {
            return Ok(());
        }
        queue.automation.attempts.insert(
            id.into(),
            Attempt {
                at: timestamp,
                recovered: false,
                requires_review: false,
            },
        );
        while queue.jobs.len() >= 200 {
            let Some(index) = queue.jobs.iter().position(|j| !j.active()) else {
                return Err(fault("授权队列已满"));
            };
            queue.jobs.remove(index);
        }
        queue.jobs.push(Job {
            request_id: format!("{}:{id}", uuid::Uuid::new_v4()),
            account_id: id.into(),
            status: "queued".into(),
            step: "queued".into(),
            message: "自动重新授权：已确认凭据失效".into(),
            started_at: None,
            finished_at: None,
            workspace_choices: vec![],
            force_workspace_id: None,
            free_fallback: false,
            automatic: true,
            expected_revision: a["_credentialRevision"].as_u64(),
            logout_others: true,
            cleanup_started: false,
        });
        break;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn only_terminal_credentials_trigger_login() {
        let mut a = json!({"provider":"openai","authenticationKind":"oauth","status":"error","errorReason":"credential_expired"});
        assert!(authentication_failed(&a));
        for reason in [
            "access_token_expired",
            "credential_invalid",
            "account_banned",
            "account_unverified",
            "rate_limited",
            "proxy_error",
            "quota_exceeded",
            "",
        ] {
            a["errorReason"] = json!(reason);
            assert!(!authentication_failed(&a));
        }
    }
    #[test]
    fn access_expiry_requires_terminal_runtime_evidence() {
        let mut a = json!({"provider":"openai","authenticationKind":"oauth","status":"error","errorReason":"access_token_expired"});
        assert!(!authentication_failed(&a));
        for state in ["ready", "unknown", "invalid", "banned", ""] {
            a["_credentialState"] = json!(state);
            assert!(!authentication_failed(&a));
        }
        a["_credentialState"] = json!("expired");
        assert!(authentication_failed(&a));
        a["status"] = json!("normal");
        assert!(!authentication_failed(&a));
    }
    #[test]
    fn invalid_requires_current_runtime_proof_even_when_paused() {
        let mut a = json!({"provider":"openai","authenticationKind":"oauth","status":"error","enabled":false,"errorReason":"credential_invalid"});
        for state in ["ready", "expired", "unknown", "banned", ""] {
            a["_credentialState"] = json!(state);
            assert!(!authentication_failed(&a));
        }
        a["_credentialState"] = json!("invalid");
        assert!(authentication_failed(&a));
        a["status"] = json!("disabled");
        assert!(!authentication_failed(&a));
    }
    #[test]
    fn persistent_latch_requires_recovery_and_cooldown() {
        let mut state = Automation::default();
        state.attempts.insert(
            "a".into(),
            Attempt {
                at: 10,
                recovered: false,
                requires_review: false,
            },
        );
        let encoded = serde_json::to_vec(&state).unwrap();
        let mut state: Automation = serde_json::from_slice(&encoded).unwrap();
        assert!(!state.permitted("a", COOLDOWN_MS + 10));
        state.observe(&[json!({"id":"a","status":"error"})]);
        assert!(!state.permitted("a", COOLDOWN_MS + 10));
        state.observe(&[json!({"id":"a","status":"normal","errorReason":null})]);
        assert!(!state.permitted("a", 11));
        assert!(state.permitted("a", COOLDOWN_MS + 10));
    }
}
