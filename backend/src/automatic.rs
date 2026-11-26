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
const RECOVERY_CHECK_MS: u64 = 5 * 60 * 1000;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_evidence_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_checked_at: Option<u64>,
}

fn uncertain(job: &Job) -> bool {
    job.status == "review"
        || (matches!(job.status.as_str(), "interrupted" | "cancelled")
            && (job.started_at.is_some() || job.cleanup_started || job.new_account))
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
    fn observe_jobs(&mut self, jobs: &[Job], timestamp: u64) -> Result<(), PluginFault> {
        // 保留最新任务的人工核对边界，历史失败不会覆盖较新的人工成功
        let mut seen = std::collections::BTreeSet::new();
        for job in jobs.iter().rev().filter(|j| {
            !j.account_id.is_empty()
                && !(matches!(j.status.as_str(), "interrupted" | "cancelled") && !uncertain(j))
                && seen.insert(j.account_id.clone())
        }) {
            if uncertain(job) || (job.automatic && job.status == "failed") {
                if !self.attempts.contains_key(&job.account_id) {
                    if self.attempts.len() >= 1000 {
                        return Err(fault("自动授权尝试记录已满，请人工核对"));
                    }
                    self.attempts.insert(
                        job.account_id.clone(),
                        Attempt {
                            at: timestamp,
                            recovered: false,
                            requires_review: true,
                            recovery_evidence_at: None,
                            recovery_checked_at: None,
                        },
                    );
                }
                if let Some(attempt) = self.attempts.get_mut(&job.account_id)
                    && attempt.recovery_evidence_at.is_none_or(|recovered| {
                        job.finished_at.is_none_or(|finished| finished >= recovered)
                    })
                {
                    if uncertain(job) {
                        attempt.requires_review = true;
                    }
                    attempt.recovered = false;
                    attempt.at = attempt.at.max(job.finished_at.unwrap_or(timestamp));
                }
            } else if !job.automatic
                && job.status == "success"
                && let Some(attempt) = self.attempts.get_mut(&job.account_id)
                && job
                    .finished_at
                    .is_some_and(|finished| finished >= attempt.at)
            {
                attempt.requires_review = false;
                attempt.recovery_evidence_at = job.finished_at;
            }
        }
        Ok(())
    }
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

    fn observe_success(&mut self, id: &str, records: &Value, timestamp: u64) {
        let Some(attempt) = self.attempts.get_mut(id) else {
            return;
        };
        let Some(items) = records["items"].as_array() else {
            return;
        };
        // HTTP 200、最近使用时间及其他账号的成功都不能证明本账号已恢复。
        let evidence = items
            .iter()
            .filter(|item| {
                item["accountId"] == id
                    && item["provider"] == "openai"
                    && item["logicalOutcome"] == "succeeded"
            })
            .filter_map(|item| {
                chrono::DateTime::parse_from_rfc3339(item["createdAt"].as_str()?)
                    .ok()
                    .and_then(|time| u64::try_from(time.timestamp_millis()).ok())
            })
            .filter(|at| *at > attempt.at && *at <= timestamp)
            .max();
        if let Some(at) = evidence {
            attempt.recovered = true;
            attempt.requires_review = false;
            attempt.recovery_evidence_at = Some(at);
        }
    }
}

async fn observe_recovery(
    host: &HostClient,
    queue: &mut Queue,
    accounts: &[Value],
    timestamp: u64,
) {
    // 每轮最多两次只读查询；失败保持原保护，避免重复扫描给业务增加负担。
    let mut checked = 0;
    for a in accounts.iter().filter(|a| prepared(a)) {
        let Some(id) = a["id"].as_str() else { continue };
        let Some(attempt) = queue.automation.attempts.get_mut(id) else {
            continue;
        };
        if (!attempt.requires_review && attempt.recovered)
            || timestamp.saturating_sub(attempt.at) < COOLDOWN_MS
            || attempt
                .recovery_checked_at
                .is_some_and(|at| timestamp.saturating_sub(at) < RECOVERY_CHECK_MS)
        {
            continue;
        }
        attempt.recovery_checked_at = Some(timestamp);
        let start = attempt
            .at
            .max(timestamp.saturating_sub(7 * 24 * 60 * 60 * 1000));
        let Some(start) = chrono::DateTime::from_timestamp_millis(start as i64) else {
            continue;
        };
        let Some(end) = chrono::DateTime::from_timestamp_millis(timestamp as i64) else {
            continue;
        };
        let Some(name) = a["name"].as_str() else {
            continue;
        };
        let path = crate::host::query(
            "/api/admin/usage/records",
            &[
                ("accountName", name),
                ("provider", "openai"),
                ("status", "success"),
                ("currentPage", "1"),
                ("pageSize", "20"),
                ("startTime", &start.to_rfc3339()),
                ("endTime", &end.to_rfc3339()),
            ],
        );
        if let Ok(records) = crate::admin(host, "GET", &path, None).await {
            queue.automation.observe_success(id, &records, timestamp);
        }
        checked += 1;
        if checked >= 2 {
            break;
        }
    }
}

pub fn status(a: &Value, queue: &Queue, timestamp: u64) -> Option<Value> {
    if a["status"] != "error" {
        return None;
    }
    let id = a["id"].as_str()?;
    let (code, label, message) = if !queue.automation.enabled {
        (
            "off",
            "自动授权已关闭",
            "开启后会检查原生凭据状态并按顺序处理",
        )
    } else if let Some(attempt) = queue.automation.attempts.get(id)
        && attempt.requires_review
    {
        (
            "review",
            "历史授权待核对",
            "历史授权结果未确认；确认本账号之后成功处理过请求才会解除旧保护，否则需手动核对",
        )
    } else if let Some(attempt) = queue.automation.attempts.get(id)
        && !attempt.recovered
    {
        (
            "attempted",
            "自动尝试已结束",
            "本次异常已经自动尝试，失败后停止；开关切换或刷新不会重复登录",
        )
    } else if let Some(attempt) = queue.automation.attempts.get(id)
        && timestamp.saturating_sub(attempt.at) < COOLDOWN_MS
    {
        (
            "cooldown",
            "自动授权冷却中",
            "已确认恢复，距上次自动尝试满 6 小时后才会处理新的失效",
        )
    } else if !notes_valid(a) {
        (
            "notes",
            "授权资料待补全",
            "账号备注格式或 2FA 密钥未通过校验",
        )
    } else if a["outboundProxyEndpoint"]
        .as_str()
        .is_none_or(str::is_empty)
    {
        (
            "proxy",
            "固定代理待核对",
            "账号未绑定固定代理，无法自动授权",
        )
    } else if !candidate(a) {
        (
            "ineligible",
            "异常需人工处理",
            "当前异常并非可自动处理的凭据失效",
        )
    } else if require_idle(a).is_err() {
        (
            "busy",
            "等待请求结束",
            "账号仍有在途请求或并发状态未知，空闲后再检查",
        )
    } else if a["enabled"] != true && a["errorReason"] != "credential_invalid" {
        (
            "paused",
            "保留手动停用",
            "已停用账号仅在原生凭据明确 invalid 时纳入自动授权",
        )
    } else {
        (
            "pending",
            "等待自动检查",
            "后台依次核对原生凭据终态、身份和工作区；手动队列优先",
        )
    };
    Some(serde_json::json!({"code":code,"label":label,"message":message}))
}

pub async fn scan(host: &HostClient, queue: &mut Queue) -> Result<(), PluginFault> {
    let timestamp = now();
    if !queue.automation.enabled {
        return Ok(());
    }
    let mut accounts = crate::directory(host).await?;
    queue.automation.observe_jobs(&queue.jobs, timestamp)?;
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
    if queue.has_active() {
        return Ok(());
    }
    observe_recovery(host, queue, &accounts, timestamp).await;
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
                recovery_evidence_at: None,
                recovery_checked_at: None,
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
            logout_others: false,
            cleanup_started: false,
            new_account: false,
            import_info: None,
            implementation_version: None,
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
                recovery_evidence_at: None,
                recovery_checked_at: None,
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
    #[test]
    fn manual_failure_does_not_consume_the_single_automatic_attempt() {
        let mut state = Automation::default();
        let mut job = Job::queued("manual", "a".into());
        job.finish("failed", "登录失败");
        state.observe_jobs(&[job.clone()], 10).unwrap();
        assert!(state.permitted("a", 10));
        state.attempts.insert(
            "a".into(),
            Attempt {
                at: 11,
                recovered: false,
                requires_review: false,
                recovery_evidence_at: None,
                recovery_checked_at: None,
            },
        );
        job.automatic = true;
        state.observe_jobs(&[job], 12).unwrap();
        assert!(!state.permitted("a", COOLDOWN_MS + 12));
        let restored: Automation =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(!restored.permitted("a", COOLDOWN_MS * 2));
    }
    #[test]
    fn uncertain_manual_results_still_require_review() {
        for status in ["review", "interrupted", "cancelled"] {
            let mut state = Automation::default();
            let mut job = Job::queued("manual", "a".into());
            job.started_at = Some(5);
            job.finish(status, "结果待核对");
            state.observe_jobs(&[job], 10).unwrap();
            assert!(!state.permitted("a", COOLDOWN_MS * 2));
        }
    }
    #[test]
    fn never_started_cancellation_does_not_block_the_first_automatic_attempt() {
        for status in ["cancelled", "interrupted"] {
            let mut state = Automation::default();
            let mut job = Job::queued("manual", "a".into());
            job.finish(status, "尚未开始登录");
            state.observe_jobs(&[job], 10).unwrap();
            assert!(state.permitted("a", COOLDOWN_MS * 2));
        }
    }
    #[test]
    fn only_a_later_success_for_the_same_account_clears_the_old_review() {
        let mut state: Automation = serde_json::from_value(json!({"enabled":true,"attempts":{"a":{"at":10,"recovered":false,"requiresReview":true}}})).unwrap();
        let timestamp = COOLDOWN_MS * 2;
        for item in [
            json!({"accountId":"other","provider":"openai","logicalOutcome":"succeeded","createdAt":"1970-01-01T00:00:01Z"}),
            json!({"accountId":"a","provider":"openai","logicalOutcome":"failed","statusCode":200,"createdAt":"1970-01-01T00:00:01Z"}),
            json!({"accountId":"a","provider":"openai","logicalOutcome":"running","createdAt":"1970-01-01T00:00:01Z"}),
            json!({"accountId":"a","provider":"openai","logicalOutcome":"succeeded","createdAt":"1970-01-01T00:00:00Z"}),
            json!({"accountId":"a","provider":"openai","logicalOutcome":"succeeded","createdAt":"2099-01-01T00:00:00Z"}),
        ] {
            state.observe_success("a", &json!({"items":[item]}), timestamp);
            assert!(!state.permitted("a", timestamp));
        }
        state.observe_success("a", &json!({"items":[{"accountId":"a","provider":"openai","logicalOutcome":"succeeded","createdAt":"1970-01-01T00:00:01Z"}]}), timestamp);
        assert!(state.permitted("a", timestamp));
        let mut old = Job::queued("old", "a".into());
        old.started_at = Some(20);
        old.finish("review", "原生结果未知");
        old.finished_at = Some(500);
        state.observe_jobs(&[old.clone()], timestamp).unwrap();
        assert!(
            state.permitted("a", timestamp),
            "Old history must not restore a reconciled latch"
        );
        old.finished_at = Some(2000);
        state.observe_jobs(&[old], timestamp).unwrap();
        assert!(
            !state.permitted("a", timestamp),
            "A newer uncertain operation still requires review"
        );
        let restored: Automation =
            serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
        assert!(!restored.permitted("a", timestamp));
    }
}
