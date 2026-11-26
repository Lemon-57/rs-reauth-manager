//! 管理接口、授权队列与宿主生命周期的组合

mod automatic;
mod control;
mod deletion;
mod diagnostics;
mod executor;
mod grouping;
mod host;
mod import_profile;
mod native;
mod onboarding;
mod plans;
mod recovery;
mod verification;
mod worker;

use gateway_plugin_sdk::{
    Manifest, PluginFault,
    call::management::*,
    client::{
        Empty, HostClient, PluginBuilder, PluginSession, SessionConfig, SessionError, TypedCall,
        TypedReply, methods,
    },
};
use host::{admin, fault, now, query};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportInfo {
    line: usize,
    email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rt_update: Option<bool>,
    // Non-secret idempotency key; never persist login inputs or native tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_start_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rt_fallback_reason: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Job {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    import_info: Option<ImportInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    implementation_version: Option<String>,
    request_id: String,
    account_id: String,
    status: String,
    step: String,
    message: String,
    started_at: Option<u64>,
    finished_at: Option<u64>,
    #[serde(default)]
    workspace_choices: Vec<WorkspaceChoice>,
    #[serde(default)]
    force_workspace_id: Option<String>,
    #[serde(default)]
    free_fallback: bool,
    #[serde(default)]
    automatic: bool,
    #[serde(default)]
    expected_revision: Option<u64>,
    #[serde(default)]
    logout_others: bool,
    #[serde(default)]
    cleanup_started: bool,
    #[serde(default)]
    new_account: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct WorkspaceChoice {
    id: String,
}
impl Job {
    fn active(&self) -> bool {
        matches!(self.status.as_str(), "queued" | "running")
    }
    fn finish(&mut self, status: &str, message: &str) {
        self.status = status.into();
        self.message = message.into();
        self.step = status.into();
        self.finished_at = Some(now());
    }
    fn finish_without_mailshop_rt(&mut self, message: &str) {
        self.finish("review", message);
        self.step = "mailshop_no_rt".into();
    }
    fn permits_mailshop_retry(&self) -> bool {
        if self.new_account
            || self.import_info.is_some()
            || self.force_workspace_id.is_some()
            || self.free_fallback
            || self.cleanup_started
        {
            return false;
        }
        match self.status.as_str() {
            "failed" => {
                self.step == "login_rejected" || legacy_mailshop_login_failure(&self.message)
            }
            "review" => self.step == "mailshop_no_rt" || legacy_mailshop_no_rt(&self.message),
            _ => false,
        }
    }
}
#[derive(Default, Deserialize)]
pub struct Queue {
    jobs: Vec<Job>,
    #[serde(default)]
    automation: automatic::Automation,
    #[serde(default, rename = "pendingBatches")]
    pending_batches: Vec<PendingBatch>,
    #[serde(default, rename = "loginFailureHistory")]
    login_failure_history: std::collections::BTreeMap<String, LoginFailure>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingBatch {
    request_id: String,
    account_ids: std::collections::VecDeque<String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginFailure {
    failed_at: u64,
    manual_success_at: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mailshop_retry: Option<MailshopRetry>,
}
#[derive(Clone, Serialize, Deserialize)]
struct MailshopRetry {
    at: u64,
    allowed: bool,
}
impl Job {
    fn queued(batch: &str, account_id: String) -> Self {
        Self {
            request_id: format!("{batch}:{account_id}"),
            account_id,
            status: "queued".into(),
            step: "queued".into(),
            message: String::new(),
            started_at: None,
            finished_at: None,
            workspace_choices: vec![],
            force_workspace_id: None,
            free_fallback: false,
            automatic: false,
            expected_revision: None,
            logout_others: false,
            cleanup_started: false,
            new_account: false,
            import_info: None,
            implementation_version: None,
        }
    }
}
impl Queue {
    fn login_failure_history(&self) -> std::collections::BTreeMap<String, LoginFailure> {
        let mut history = self.login_failure_history.clone();
        for job in self.jobs.iter().filter(|job| !job.account_id.is_empty()) {
            let Some(at) = job.finished_at else { continue };
            if job.status == "failed" {
                let record = history.entry(job.account_id.clone()).or_default();
                if at > record.failed_at || at == record.failed_at && record.message.is_empty() {
                    record.failed_at = at;
                    record.message = job.message.clone();
                }
            } else if job.status == "success"
                && !job.automatic
                && !job.new_account
                && job.import_info.is_none()
            {
                let record = history.entry(job.account_id.clone()).or_default();
                record.manual_success_at = record.manual_success_at.max(at);
            }
            if job.started_at.is_some() || job.status == "success" {
                let allowed = job.permits_mailshop_retry();
                if allowed
                    || history
                        .get(&job.account_id)
                        .is_some_and(|record| record.mailshop_retry.is_some())
                {
                    let record = history.entry(job.account_id.clone()).or_default();
                    if record
                        .mailshop_retry
                        .as_ref()
                        .is_none_or(|previous| at > previous.at || (at == previous.at && !allowed))
                    {
                        record.mailshop_retry = Some(MailshopRetry { at, allowed });
                    }
                }
            }
        }
        history
    }
    fn permits_mailshop_retry(&self, account_id: &str) -> bool {
        self.login_failure_history
            .get(account_id)
            .is_some_and(|record| {
                record.mailshop_retry.as_ref().is_some_and(|retry| {
                    retry.allowed
                        && retry.at >= record.failed_at
                        && retry.at > record.manual_success_at
                })
            })
    }
    fn login_failures(&self) -> Vec<String> {
        self.login_failure_history()
            .into_iter()
            .filter_map(|(id, record)| (record.failed_at > record.manual_success_at).then_some(id))
            .collect()
    }
    fn login_failure_details(&self) -> std::collections::BTreeMap<String, Value> {
        self.login_failure_history()
            .into_iter()
            .filter(|(_, record)| record.failed_at > record.manual_success_at)
            .map(|(id, record)| {
                let category = diagnostics::login_failure_category(&record.message);
                let message = if record.message.is_empty() {
                    "历史登录失败记录未保存具体原因".to_owned()
                } else {
                    record.message
                };
                (
                    id,
                    json!({"category": category, "message": message, "failedAt": record.failed_at}),
                )
            })
            .collect()
    }
    fn visible_jobs(&self) -> Vec<Job> {
        self.jobs
            .iter()
            .cloned()
            .chain(self.pending_batches.iter().flat_map(|batch| {
                batch
                    .account_ids
                    .iter()
                    .cloned()
                    .map(|id| Job::queued(&batch.request_id, id))
            }))
            .collect()
    }
    fn has_active(&self) -> bool {
        self.jobs.iter().any(Job::active)
            || self
                .pending_batches
                .iter()
                .any(|b| !b.account_ids.is_empty())
    }
    fn account_active(&self, id: &str) -> bool {
        self.jobs.iter().any(|j| j.account_id == id && j.active())
            || self
                .pending_batches
                .iter()
                .any(|b| b.account_ids.iter().any(|a| a == id))
    }
    fn contains_batch(&self, id: &str) -> bool {
        self.pending_batches.iter().any(|b| b.request_id == id)
            || self
                .jobs
                .iter()
                .any(|j| j.request_id.starts_with(&format!("{id}:")))
    }
    fn take_next_pending(&mut self, position: usize) -> Option<usize> {
        while let Some(batch) = self.pending_batches.first_mut() {
            if let Some(id) = batch.account_ids.pop_front() {
                let job = Job::queued(&batch.request_id, id);
                if batch.account_ids.is_empty() {
                    self.pending_batches.remove(0);
                }
                self.jobs.insert(position, job);
                return Some(position);
            }
            self.pending_batches.remove(0);
        }
        None
    }
    fn remove_pending(&mut self, ids: &[String]) {
        for batch in &mut self.pending_batches {
            batch.account_ids.retain(|id| !ids.contains(id));
        }
        self.pending_batches.retain(|b| !b.account_ids.is_empty());
    }
    fn cancel_pending(&mut self, request: Option<&str>) {
        let mut cancelled = Vec::new();
        for batch in &mut self.pending_batches {
            batch.account_ids.retain(|id| {
                let key = format!("{}:{id}", batch.request_id);
                if request.is_none_or(|r| r == key) {
                    let mut job = Job::queued(&batch.request_id, id.clone());
                    job.finish("cancelled", "已取消，尚未开始登录");
                    cancelled.push(job);
                    false
                } else {
                    true
                }
            });
        }
        self.pending_batches.retain(|b| !b.account_ids.is_empty());
        self.jobs.extend(cancelled);
    }
}
impl Serialize for Queue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Queue", 4)?;
        state.serialize_field("jobs", &self.visible_jobs())?;
        state.serialize_field("automation", &self.automation)?;
        state.serialize_field("loginFailures", &self.login_failures())?;
        state.serialize_field("loginFailureDetails", &self.login_failure_details())?;
        state.end()
    }
}
struct Manager {
    imports: std::collections::VecDeque<onboarding::Pending>,
    protected_management_url: String,
    mailshop_rt_api_key: Option<String>,
    mailshop_rt_emails: Option<Vec<String>>,
    mailcom_key: Option<String>,
    runtime: worker::Runtime,
    worker: Option<worker::Worker>,
    recovered: bool,
    next_refresh_group_check: Option<std::time::Instant>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Submit {
    account_ids: Vec<String>,
    request_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cancel {
    request_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ForceSubmit {
    source_request_id: String,
    workspace_id: String,
    request_id: String,
    confirmation: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FreeFallbackSubmit {
    source_request_id: String,
    request_id: String,
    confirmation: String,
}

fn workspace_choices(output: &Value) -> Vec<WorkspaceChoice> {
    let Some(items) = output["workspaces"].as_array() else {
        return vec![];
    };
    if items.len() > 30 {
        return vec![];
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut choices = vec![];
    for item in items {
        let Some(id) = item["id"].as_str() else {
            return vec![];
        };
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || !seen.insert(id)
        {
            return vec![];
        }
        choices.push(WorkspaceChoice { id: id.into() });
    }
    choices
}

fn registration() -> ManagementRegistration {
    ManagementRegistration {
        routes: [
            ("GET", "api/accounts"),
            ("GET", "api/jobs"),
            ("GET", "api/executor"),
            ("POST", "api/standby"),
            ("POST", "api/submit"),
            ("POST", "api/import"),
            ("POST", "api/import-line"),
            ("POST", "api/automation"),
            ("POST", "api/cancel"),
            ("POST", "api/delete"),
            ("POST", "api/tick"),
            ("POST", "api/runtime-check"),
            ("POST", "api/force-submit"),
            ("POST", "api/free-fallback"),
        ]
        .into_iter()
        .map(|(m, p)| ManagementRoute {
            method: m.into(),
            path: p.into(),
            request_content_types: if m == "GET" {
                vec![]
            } else {
                vec!["application/json".into()]
            },
            response_content_types: vec!["application/json".into()],
        })
        .collect(),
        resources: ["web/index.html", "web/app.js", "web/app.css"]
            .into_iter()
            .map(|p| ManagementResource {
                path: p.into(),
                public: false,
            })
            .collect(),
        pages: vec![ManagementPage {
            id: "reauth-manager".into(),
            title: "账号重新授权".into(),
            description: Some("登录与授权记录".into()),
            entry: "web/index.html".into(),
            icon: None,
        }],
        callbacks: vec![],
    }
}
fn eligible(a: &Value) -> bool {
    a["provider"] == "openai" && a["authenticationKind"] == "oauth"
}
fn notes_valid(a: &Value) -> bool {
    let Some(notes) = a["notes"].as_str() else {
        return false;
    };
    let parts: Vec<_> = notes.trim().split("----").collect();
    matches!(parts.len(), 3 | 4)
        && a["email"]
            .as_str()
            .is_some_and(|email| parts[0].trim().eq_ignore_ascii_case(email))
        && !parts[1].is_empty()
        && parts[2..].iter().all(|part| !part.trim().is_empty())
        && !notes.chars().any(char::is_control)
}

fn import_notes_valid(email: &str, notes: &str) -> bool {
    if notes.len() > 2000 || notes.contains(['\r', '\n', '\0']) {
        return false;
    }
    let parts: Vec<_> = notes.trim().split("----").collect();
    if !matches!(parts.len(), 3 | 4)
        || !parts[0].trim().eq_ignore_ascii_case(email.trim())
        || parts[1..].iter().any(|part| part.is_empty())
    {
        return false;
    }
    totp_valid(parts.last().unwrap())
}
fn totp_valid(value: &str) -> bool {
    let secret = value.trim().replace(' ', "").to_ascii_uppercase();
    let core = secret.trim_end_matches('=');
    core.len() >= 16
        && matches!(core.len() % 8, 0 | 2 | 4 | 5 | 7)
        && core.bytes().all(|c| matches!(c, b'A'..=b'Z' | b'2'..=b'7'))
        && (!secret.contains('=') || secret.len() % 8 == 0)
}

fn import_proxy_valid(proxy: &str) -> bool {
    let Ok(url) = url::Url::parse(proxy) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
        && url.host_str().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
}
fn settings(a: &Value) -> Value {
    json!({"id":a["id"],"email":a["email"],"name":a["name"],"enabled":a["enabled"],"notes":a["notes"],"groups":a["groups"],"proxy":a["outboundProxyEndpoint"],"weight":a["weight"],"concurrencyLimit":a["concurrencyLimit"],"modelAccess":a["modelAccess"],"accountId":a["accountId"],"userId":a["userId"],"planType":a["planType"],"supplier":a["supplier"],"manualStartsAt":a["manualStartsAt"],"manualExpiresAt":a["manualExpiresAt"]})
}
fn require_idle(a: &Value) -> Result<(), PluginFault> {
    if a["capacity"]["usedSlots"].as_u64() != Some(0) {
        return Err(fault("账号仍有在途请求或并发状态未知，请空闲后重试"));
    }
    Ok(())
}
async fn detail(host: &HostClient, id: &str) -> Result<Value, PluginFault> {
    let data = admin(
        host,
        "GET",
        &query("/api/admin/accounts/detail", &[("accountId", id)]),
        None,
    )
    .await?;
    let mut a = data["account"].clone();
    if a["id"] != id || !eligible(&a) {
        return Err(fault("该账号不是适用的 OpenAI OAuth 账号"));
    }
    let reply = host
        .call(
            "host.auth.get_runtime",
            json!({}),
            serde_json::to_vec(&json!({"account_id":id})).map_err(|_| fault("账号参数无效"))?,
        )
        .await
        .map_err(|e| e.into_plugin_fault())?;
    let runtime: Value =
        serde_json::from_slice(&reply.payload).map_err(|_| fault("账号凭据版本读取失败"))?;
    if runtime["account_id"] != id
        || runtime["provider_id"] != "openai"
        || !runtime["credential_revision"].is_u64()
    {
        return Err(fault("账号凭据版本匹配失败"));
    }
    a["_credentialRevision"] = runtime["credential_revision"].clone();
    a["_credentialState"] = runtime["credential_state"].clone();
    Ok(a)
}
async fn proxy(host: &HostClient, a: &Value) -> Result<String, PluginFault> {
    // 只在内存中读取单账号完整代理，不保存导出材料
    let id = a["id"].as_str().ok_or_else(|| fault("账号 ID 无效"))?;
    if a["outboundProxyEndpoint"]
        .as_str()
        .is_none_or(str::is_empty)
    {
        return Err(fault("原账号未绑定代理，不会改用直连或其他代理"));
    }
    let data = admin(
        host,
        "GET",
        &query(
            "/api/admin/accounts/export",
            &[("accountIds", id), ("confirm", "export_sensitive_accounts")],
        ),
        None,
    )
    .await?;
    let docs = data["documents"]
        .as_array()
        .ok_or_else(|| fault("账号代理读取失败"))?;
    if docs.len() != 1 || docs[0]["provider"] != "openai" {
        return Err(fault("账号代理读取失败"));
    }
    let accounts = docs[0]["document"]["accounts"]
        .as_array()
        .ok_or_else(|| fault("账号代理读取失败"))?;
    if accounts.len() != 1 || accounts[0]["id"] != id {
        return Err(fault("账号代理匹配失败"));
    }
    let text = accounts[0]["outboundProxyUrl"]
        .as_str()
        .ok_or_else(|| fault("原账号代理信息不可用"))?;
    let url = url::Url::parse(text).map_err(|_| fault("原账号代理格式无效"))?;
    if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h") || url.host_str().is_none()
    {
        return Err(fault("原账号代理协议不受支持"));
    }
    Ok(text.into())
}
async fn directory(host: &HostClient) -> Result<Vec<Value>, PluginFault> {
    let mut accounts = vec![];
    let mut seen = std::collections::BTreeSet::new();
    for page in 1..=100u16 {
        let data = admin(
            host,
            "GET",
            &format!("/api/admin/accounts?provider=openai&page={page}&pageSize=100"),
            None,
        )
        .await?;
        let items = data["items"]
            .as_array()
            .ok_or_else(|| fault("账号列表格式无效"))?;
        if items.len() > 100 {
            return Err(fault("账号分页大小无效"));
        }
        for a in items {
            let id = a["id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| fault("账号目录身份无效"))?;
            if !seen.insert(id.to_owned()) {
                return Err(fault("账号目录存在重复分页"));
            }
            accounts.push(a.clone());
        }
        if items.len() < 100 {
            return Ok(accounts);
        }
    }
    Err(fault("账号超过本次读取上限"))
}
fn account_row(a: &Value, groups: Vec<Value>) -> Value {
    json!({"id":a["id"],"name":a["name"],"email":a["email"],"enabled":a["enabled"],"planType":a["planType"],"status":a["status"],"accessTokenExpiresAt":a["accessTokenExpiresAt"],"proxy":a["outboundProxyEndpoint"],"notesValid":notes_valid(a),"groups":groups,"supplier":a["supplier"],"manualExpiresAt":a["manualExpiresAt"],"manualExpiresAtDisplay":a["manualExpiresAtDisplay"],"usage":{"lastUsedAt":a["usage"]["lastUsedAt"],"lastUsedAtDisplay":a["usage"]["lastUsedAtDisplay"],"lastUsedAtFullDisplay":a["usage"]["lastUsedAtFullDisplay"]}})
}
async fn rows(host: &HostClient) -> Result<Value, PluginFault> {
    let accounts = directory(host).await?;
    let (queue, _) = host::load(host).await?;
    let mut rows = vec![];
    for a in accounts.iter().filter(|a| eligible(a)) {
        let groups = a["groups"]
            .as_array()
            .ok_or_else(|| fault("账号分组格式无效"))?
            .iter()
            .map(
                |group| match (group["id"].as_str(), group["name"].as_str()) {
                    (Some(id), Some(name)) => Ok(json!({"id":id,"name":name})),
                    _ => Err(fault("账号分组格式无效")),
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        let mut row = account_row(a, groups);
        row["automaticStatus"] = automatic::status(a, &queue, now()).unwrap_or(Value::Null);
        rows.push(row);
    }
    Ok(json!({"accounts":rows}))
}
fn protocol_error(code: &str) -> &'static str {
    match code {
        "credentials" => "备注格式、邮箱或 2FA 密钥无效",
        "password" => "邮箱或密码错误，请检查原账号备注",
        "mfa" => "2FA 流程未完成，协议未提供具体原因，不能仅凭此提示判断密钥错误",
        "human" => "上游要求人工验证，请手动完成授权",
        "workspace" => "无法匹配原账号工作区，已停止写回",
        "fallback_identity" => "无法确认同一用户的 Free 工作区，已停止写回",
        "authorization" => "RS 授权链接格式无效，尚未发起账号登录",
        "state" => "OAuth state 校验失败，已停止写回",
        "proxy" => "原账号代理连接失败",
        "limited" => "上游登录限流，请稍后手动重试",
        _ => "协议登录未完成，协议未提供具体失败阶段，未自动重试",
    }
}

fn mailshop_login_failure(output: &Value) -> bool {
    let diagnostic = &output["diagnostic"];
    output["event"] == "error"
        && matches!(
            (
                diagnostic["stage"].as_str(),
                diagnostic["reason"].as_str(),
                diagnostic["httpStatus"].as_u64(),
            ),
            (
                Some("email_verify"),
                Some("email_code_required"),
                Some(200) | None
            ) | (
                Some("password"),
                Some("password_rejected"),
                Some(400 | 401 | 403)
            ) | (
                Some("mfa_verify"),
                Some("mfa_code_invalid" | "mfa_code_expired"),
                Some(400 | 401 | 403 | 409)
            )
        )
}

fn legacy_mailshop_login_failure(message: &str) -> bool {
    const EMAIL_REQUIRED: &str = "邮箱验证码验证：上游要求邮箱验证码，当前任务不支持人工补码续跑";
    message == EMAIL_REQUIRED
        || [
            (EMAIL_REQUIRED, &[200][..]),
            ("密码验证：上游拒绝邮箱或密码", &[400, 401, 403][..]),
            (
                "提交 2FA 动态码：上游明确返回动态码无效",
                &[400, 401, 403, 409][..],
            ),
            (
                "提交 2FA 动态码：上游明确返回动态码已过期",
                &[400, 401, 403, 409][..],
            ),
        ]
        .iter()
        .any(|(reason, statuses)| {
            message.strip_prefix(reason).is_some_and(|suffix| {
                statuses
                    .iter()
                    .any(|status| suffix.starts_with(&format!("（HTTP {status}）")))
            })
        })
}

fn legacy_mailshop_no_rt(message: &str) -> bool {
    message == "Mailshop RT 获取超时或进程退出，未写回，不会自动重试"
        || message
            .strip_prefix("GMX RT 回退：")
            .and_then(|detail| detail.strip_suffix("，未写回；未自动重试"))
            .is_some_and(|detail| {
                [
                    "请求 Mailshop 超时",
                    "Mailshop 连接失败或响应中断",
                    "Mailshop 账号任务失败",
                    "Mailshop 接口返回失败",
                    "Mailshop 请求失败",
                    "Mailshop 请求资料无效",
                    "Mailshop 响应格式无效",
                    "Mailshop 未返回可用的 RT",
                ]
                .iter()
                .any(|reason| detail.starts_with(reason))
            })
}

async fn mailshop_target(
    host: &HostClient,
    account_id: &str,
    snapshot: &Value,
    automatic: bool,
) -> Result<Value, PluginFault> {
    if automatic && !control::enabled(host, true).await? {
        return Err(fault("自动授权已关闭"));
    }
    let account = detail(host, account_id).await?;
    require_idle(&account)?;
    if account["status"] != "error"
        || account["_credentialRevision"].as_u64().is_none()
        || account["_credentialRevision"] != snapshot["credentialRevision"]
        || account["outboundProxyId"] != snapshot["outboundProxyId"]
        || settings(&account) != snapshot["settings"]
        || !account["email"]
            .as_str()
            .and_then(|email| email.rsplit_once('@'))
            .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case("gmx.com"))
        || !["accountId", "userId", "planType", "outboundProxyEndpoint"]
            .iter()
            .all(|field| {
                account[*field]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
            })
        || !notes_valid(&account)
    {
        return Err(fault(
            "原 GMX 账号身份、状态、固定代理或凭据版本不满足 RT 更新条件",
        ));
    }
    let proxy = proxy(host, &account).await?;
    if snapshot["originalProxy"].as_str() != Some(proxy.as_str()) {
        return Err(fault("原 GMX 账号固定代理已变化"));
    }
    Ok(account)
}

impl Manager {
    fn mailshop_enabled_for(&self, account: &Value) -> bool {
        self.mailshop_rt_api_key.is_some()
            && account["status"] == "error"
            && account["email"].as_str().is_some_and(|email| {
                email
                    .rsplit_once('@')
                    .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case("gmx.com"))
                    && self.mailshop_rt_emails.as_ref().is_none_or(|emails| {
                        emails
                            .iter()
                            .any(|allowed| allowed.eq_ignore_ascii_case(email))
                    })
            })
    }

    async fn start_mailshop(
        &mut self,
        account: &Value,
        mut snapshot: Value,
        request_id: String,
    ) -> Result<worker::Worker, PluginFault> {
        let key = self
            .mailshop_rt_api_key
            .as_deref()
            .ok_or_else(|| fault("未配置 Mailshop RT 接口"))?;
        let input = json!({"action":"mailshop_rt","notes":account["notes"],"email":account["email"],"mailshopRtApiKey":key});
        snapshot["mailshopRt"] = json!(true);
        self.runtime
            .start(input, String::new(), snapshot, request_id)
            .await
    }

    async fn recover(&mut self, host: &HostClient) -> Result<(), PluginFault> {
        if self.recovered {
            return Ok(());
        }
        let (mut queue, version) = host::load(host).await?;
        let mut changed = false;
        for job in &mut queue.jobs {
            if job.active() {
                let message = if job.cleanup_started {
                    "历史任务被中断，账号可能已暂停；请核对已保存 RT 与启停状态，不会自动重试"
                } else {
                    "插件进程已重启，原生授权或启停状态可能尚未确认，请先核对账号与提交回执后手动处理"
                };
                job.finish("interrupted", message);
                changed = true;
            }
        }
        if changed {
            host::save(host, &queue, version).await?
        }
        self.recovered = true;
        Ok(())
    }
    async fn tick(&mut self, host: &HostClient) -> Result<(), PluginFault> {
        self.recover(host).await?;
        let (mut queue, mut version) = host::load(host).await?;
        // SDK 取消父调用时会直接丢弃 future，跳过原调用的错误收尾。
        // 此时已持久化的 running 意图可能还在，但准备资料或取出的 worker
        // 已随 future 释放。管理锁保证这里不会与仍在执行的同步阶段重叠。
        // 只收尾无本地 worker 的任务，绝不重新提交未知结果的原生操作。
        let mut orphaned = false;
        for job in &mut queue.jobs {
            if job.status == "running"
                && !self
                    .worker
                    .as_ref()
                    .is_some_and(|worker| worker.request_id == job.request_id)
            {
                job.finish(
                    "review",
                    "后台调用已中断，执行结果未确认；请核对账号、原生授权回执与固定代理，未自动重放",
                );
                orphaned = true;
            }
        }
        if orphaned {
            host::save(host, &queue, version).await?;
            onboarding::prune(self, &queue);
            return Ok(());
        }
        if !queue.automation.enabled {
            let mut cancelled = false;
            for job in &mut queue.jobs {
                if job.automatic && job.status == "queued" {
                    job.finish("cancelled", "已关闭自动授权，尚未开始的自动任务已取消");
                    cancelled = true;
                }
            }
            if cancelled {
                host::save(host, &queue, version).await?;
                return Ok(());
            }
        }
        if let Some(mut current) = self.worker.take() {
            let output = current
                .output
                .lock()
                .map_err(|_| fault("协议结果读取失败"))?
                .result
                .take();
            let position = queue
                .jobs
                .iter()
                .position(|j| j.request_id == current.request_id);
            let Some(position) = position else {
                return Err(fault("任务状态发生冲突，已停止协议进程"));
            };
            let job = &mut queue.jobs[position];
            if let Some(output) = output {
                if current.snapshot["mailshopRt"] == true {
                    let Some(rt) = output["refreshToken"].as_str().filter(|rt| {
                        output["event"] == "mailshop_rt"
                            && !rt.is_empty()
                            && rt.len() <= 32768
                            && rt.bytes().all(|byte| byte.is_ascii_graphic())
                    }) else {
                        job.finish_without_mailshop_rt(&format!(
                            "GMX RT：{}，未写回；未自动重试",
                            diagnostics::mailshop_failure(&output)
                        ));
                        host::save(host, &queue, version).await?;
                        return Ok(());
                    };
                    let result = async {
                        let account = mailshop_target(
                            host,
                            &job.account_id,
                            &current.snapshot,
                            job.automatic,
                        )
                        .await?;
                        let revision = account["_credentialRevision"]
                            .as_u64()
                            .ok_or_else(|| fault("原账号凭据版本不可用"))?;
                        native::replace_rt(
                            host,
                            &account,
                            revision,
                            rt,
                            native::RtReplacementMode::Mailshop,
                        )
                        .await
                    }
                    .await;
                    match result {
                        Ok(true) => job.finish(
                            "success",
                            "RS 已写回 Mailshop RT，已确认移入 GPT Pro 分组，原启停和固定代理保持",
                        ),
                        Ok(false) => job.finish(
                            "success",
                            "RS 已验证并写回 Mailshop RT，套餐与工作区已读回，原启停和固定代理保持",
                        ),
                        Err(error) => {
                            job.finish("review", &format!("GMX RT：{}；未自动重试", error.message))
                        }
                    }
                    host::save(host, &queue, version).await?;
                    return Ok(());
                }
                let login_rejected = mailshop_login_failure(&output);
                if current.snapshot["mailshopEligible"] == true
                    && login_rejected
                    && let Ok(account) =
                        mailshop_target(host, &job.account_id, &current.snapshot, job.automatic)
                            .await
                {
                    job.step = "mailshop_rt".into();
                    job.message = "原生登录失败，正在请求 Mailshop RT".into();
                    let request = job.request_id.clone();
                    host::save(host, &queue, version).await?;
                    let snapshot = std::mem::take(&mut current.snapshot);
                    drop(current);
                    self.worker = Some(self.start_mailshop(&account, snapshot, request).await?);
                    return Ok(());
                }
                if matches!(
                    output["event"].as_str(),
                    Some(
                        "complete"
                            | "free_fallback"
                            | "forced_workspace"
                            | "forced_free"
                            | "team_upgrade"
                            | "workspace_recovered"
                    )
                ) {
                    job.step = "saving".into();
                    current.snapshot["flowId"] = json!(current.flow);
                    match native::complete(host, job, &mut current.snapshot, &output).await {
                        Ok((message, free)) => {
                            if job.new_account {
                                job.account_id = current.snapshot["createdAccountId"]
                                    .as_str()
                                    .ok_or_else(|| fault("新增账号 ID 未确认"))?
                                    .to_owned();
                            }
                            job.finish("success", &message);
                            if free {
                                job.step = "free".into();
                            }
                        }
                        Err(error) => {
                            if job.new_account
                                && let Some(id) = current.snapshot["createdAccountId"].as_str()
                            {
                                job.account_id = id.to_owned();
                            }
                            job.finish("review",&format!("原生授权或归组未确认：{}；请核对账号启停及提交回执，不会自动改走插件换取 RT",error.message));
                        }
                    }
                } else {
                    let code = output["code"].as_str().unwrap_or_default();
                    let fallback = if job.new_account && code == "workspace" {
                        "新账号的工作区选择未完成，未提交 RS 原生授权"
                    } else {
                        protocol_error(code)
                    };
                    let message = diagnostics::message(&output, fallback);
                    job.finish("failed", &message);
                    if output["code"] == "workspace" && job.force_workspace_id.is_none() {
                        job.step = "workspace".into();
                        job.workspace_choices = workspace_choices(&output);
                    } else if login_rejected && current.snapshot["acceptCurrentProfile"] == true {
                        job.step = "login_rejected".into();
                    }
                }
                if job.status == "success" {
                    let id = job.account_id.clone();
                    let success_message = job.message.clone();
                    let success_step = job.step.clone();
                    job.status = "running".into();
                    job.step = "verify_refresh".into();
                    job.finished_at = None;
                    host::save(host, &queue, version).await?;
                    let verified = verification::finish(host, &id, &current.snapshot).await;
                    let (mut latest, version) = host::load(host).await?;
                    match verified {
                        Ok(()) => {
                            let message =
                                format!("{success_message}；本次原生 RT 刷新及保存已确认");
                            latest
                                .jobs
                                .iter_mut()
                                .find(|j| j.request_id == current.request_id)
                                .ok_or_else(|| fault("授权任务记录未确认"))?
                                .finish("success", &message);
                            if success_step == "free" {
                                latest
                                    .jobs
                                    .iter_mut()
                                    .find(|j| j.request_id == current.request_id)
                                    .ok_or_else(|| fault("授权任务记录未确认"))?
                                    .step = "free".into();
                            }
                        }
                        Err(error) => latest
                            .jobs
                            .iter_mut()
                            .find(|j| j.request_id == current.request_id)
                            .ok_or_else(|| fault("授权任务记录未确认"))?
                            .finish(
                                "review",
                                &format!(
                                    "{}；请核对已保存 RT 与账号启停，不会自动重放",
                                    error.message
                                ),
                            ),
                    }
                    host::save(host, &latest, version).await?;
                    return Ok(());
                }
            } else if current.snapshot["mailshopRt"] == true
                && (now().saturating_sub(current.started) > 120000 || {
                    let state = current
                        .output
                        .lock()
                        .map_err(|_| fault("协议结果读取失败"))?;
                    state.drained && state.result.is_none()
                })
            {
                job.finish_without_mailshop_rt(
                    "Mailshop RT 获取超时或进程退出，未写回，不会自动重试",
                );
            } else if now().saturating_sub(current.started) > 420000 {
                let message = if job.cleanup_started {
                    "授权或 RT 验证超时，账号保持暂停，请人工核对，不会自动重试"
                } else {
                    "协议登录超时，未自动重试"
                };
                job.finish(
                    if job.cleanup_started {
                        "review"
                    } else {
                        "failed"
                    },
                    message,
                );
            } else if current
                .child
                .try_wait()
                .map_err(|_| fault("协议进程状态不可用"))?
                .is_some()
            {
                // 子进程退出后继续等待读取协程排空，不能丢掉最后的 RT
                let exhausted = {
                    let data = current
                        .output
                        .lock()
                        .map_err(|_| fault("协议结果读取失败"))?;
                    data.drained && data.result.is_none()
                };
                if exhausted {
                    let message = if job.cleanup_started {
                        "授权进程异常结束，账号保持暂停，请核对已保存 RT 状态"
                    } else {
                        "协议进程已退出，未取得有效回调"
                    };
                    job.finish(
                        if job.cleanup_started {
                            "review"
                        } else {
                            "failed"
                        },
                        message,
                    );
                } else {
                    self.worker = Some(current);
                }
            } else {
                if current.snapshot["mailshopRt"] != true {
                    job.step = current
                        .output
                        .lock()
                        .map_err(|_| fault("协议进度读取失败"))?
                        .step
                        .clone();
                }
                self.worker = Some(current);
            }
            host::save(host, &queue, version).await?;
            return Ok(());
        }
        onboarding::prune(self, &queue);
        if !queue.has_active() {
            self.reconcile_refreshed_free_accounts(host).await;
        }
        if queue.automation.enabled && !queue.has_active() {
            let result = automatic::scan(host, &mut queue).await;
            host::save(host, &queue, version).await?;
            result?;
            // 入队后读取新的状态版本，在本次通知内开始，不等待补偿计时器
            (queue, version) = host::load(host).await?;
        }
        let queued = queue.jobs.iter().position(|job| job.status == "queued");
        let next = match queued {
            Some(position)
                if onboarding::waits_for_authorization_batch(self, &queue, &queue.jobs[position]) =>
            {
                queue.take_next_pending(position).or(Some(position))
            }
            Some(position) => Some(position),
            None => queue.take_next_pending(queue.jobs.len()),
        };
        if let Some(position) = next {
            if onboarding::advance(self, host, &mut queue, version, position).await? {
                return Ok(());
            }
            let retry_mailshop = !queue.jobs[position].automatic
                && queue.permits_mailshop_retry(&queue.jobs[position].account_id);
            let job = &mut queue.jobs[position];
            let starting_request_id = job.request_id.clone();
            job.status = "running".into();
            job.step = "preparing".into();
            if job.import_info.is_none() {
                job.started_at = Some(now());
            } else {
                job.started_at.get_or_insert_with(now);
            }
            job.implementation_version = Some(env!("CARGO_PKG_VERSION").into());
            // 凭据发送前先持久化意图，中断任务不自动恢复
            host::save(host, &queue, version).await?;
            let result=async {
                self.runtime.prepare().await?;
                let job=&queue.jobs[position];
                native::reconcile_saved_team(host, job).await?;
                let a=detail(host,&job.account_id).await?;
                require_idle(&a)?;
                if job.expected_revision.is_some_and(|revision| a["_credentialRevision"].as_u64() != Some(revision)) { return Err(fault("导入后凭据版本已变化，未重新登录")); }
                if job.automatic && (!control::enabled(host, queue.automation.enabled).await? || !automatic::ready(&a) || job.expected_revision != a["_credentialRevision"].as_u64()) {
                    return Err(fault("自动授权条件或账号版本已变化，未发起登录，不会自动重试"))
                }
                if !notes_valid(&a){return Err(fault("备注须为与原账号邮箱一致的 邮箱----密码----2FA 或 邮箱----密码----邮箱密码----2FA"))}
                let proxy=proxy(host,&a).await?;
                let recover_workspace = recovery::missing_workspace(&settings(&a)) && job.force_workspace_id.is_none() && !job.free_fallback;
                if recover_workspace { let old = recovery::credential(host, &job.account_id).await?; if Some(old.credential_revision) != a["_credentialRevision"].as_u64() { return Err(fault("补齐工作区前凭据版本变化，未发起登录")); } recovery::validate_existing_binding(&recovery::tokens(&old), &settings(&a))?; }
                let accept_current_profile = !job.new_account && job.import_info.is_none()
                    && job.force_workspace_id.is_none() && !job.free_fallback && !recover_workspace;
                let mut snapshot=json!({"settings":settings(&a),"credentialRevision":a["_credentialRevision"],"recoverWorkspace":recover_workspace,"acceptCurrentProfile":accept_current_profile});
                if accept_current_profile && self.mailshop_enabled_for(&a) {
                    snapshot["mailshopEligible"] = json!(true);
                    snapshot["outboundProxyId"] = a["outboundProxyId"].clone();
                    snapshot["originalProxy"] = json!(&proxy);
                    if retry_mailshop {
                        let account = mailshop_target(host, &job.account_id, &snapshot, false).await?;
                        let (mut latest, version) = host::load(host).await?;
                        let pending = latest.jobs.iter_mut().find(|item| {
                            item.request_id == job.request_id && item.status == "running" && item.step == "preparing"
                        })
                            .ok_or_else(|| fault("授权任务记录未确认"))?;
                        pending.step = "mailshop_rt".into();
                        pending.message = "根据上次失败记录，本次直接请求 Mailshop RT".into();
                        host::save(host, &latest, version).await?;
                        return self.start_mailshop(&account, snapshot, job.request_id.clone()).await;
                    }
                }
                let start=admin(host,"POST","/api/admin/accounts/oauth/start",Some(json!({"provider":"openai","name":a["name"],"accountId":a["id"]}))).await?;
                let flow=start["flowId"].as_str().ok_or_else(||fault("RS 授权流程无效"))?.to_owned();
                let input=json!({"notes":a["notes"],"email":a["email"],"proxy":proxy,"authorizationUrl":start["authorizationUrl"],"accountId":a["accountId"],"userId":a["userId"],"planType":a["planType"],"forceWorkspaceId":job.force_workspace_id,"forceFree":job.free_fallback,"automatic":job.automatic,"recoverWorkspace":recover_workspace,"acceptCurrentProfile":accept_current_profile,"mailcomKey":self.mailcom_key.clone()});
                self.runtime.start(input,flow,snapshot,job.request_id.clone()).await
            }.await;
            match result {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => {
                    let (mut latest, version) = host::load(host).await?;
                    latest
                        .jobs
                        .iter_mut()
                        .find(|j| j.request_id == starting_request_id)
                        .ok_or_else(|| fault("授权任务记录未确认"))?
                        .finish("failed", &error.message);
                    host::save(host, &latest, version).await?;
                }
            }
        }
        Ok(())
    }
}
async fn handle(
    manager: &mut Manager,
    call: TypedCall<ManagementRequest>,
) -> Result<Value, PluginFault> {
    if !call.request.query.is_empty()
        || call.payload.len()
            > if call.request.path == "api/submit" {
                2097152
            } else if call.request.path == "api/import-line" {
                524288
            } else {
                16384
            }
    {
        return Err(fault("插件请求参数无效"));
    }
    if call.request.method == "GET" {
        if !call.payload.is_empty() {
            return Err(fault("查询不能包含正文"));
        }
        return match call.request.path.as_str() {
            "api/accounts" => rows(&call.host).await,
            "api/jobs" => Ok(serde_json::to_value(host::load(&call.host).await?.0)
                .map_err(|_| fault("任务编码失败"))?),
            _ => Err(fault("路由不存在")),
        };
    }
    if call.request.method != "POST" {
        return Err(fault("请求方法不支持"));
    }
    manager.recover(&call.host).await?;
    if call.request.path == "api/runtime-check" {
        if call.payload != b"{}" {
            return Err(fault("请求格式无效"));
        }
        manager.runtime.prepare().await?;
        return Ok(json!({"ready":true}));
    }
    if call.request.path == "api/import-line" {
        return onboarding::submit(manager, &call).await;
    }
    if call.request.path == "api/import" {
        return onboarding::submit_legacy(manager, &call).await;
    }
    let (mut queue, version) = host::load(&call.host).await?;
    match call.request.path.as_str() {
        "api/delete" => {
            let ids = deletion::remove(&call.host, &call.payload).await?;
            let removed = queue
                .jobs
                .iter()
                .filter(|j| ids.contains(&j.account_id))
                .map(|j| j.request_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if manager
                .worker
                .as_ref()
                .is_some_and(|w| removed.contains(w.request_id.as_str()))
            {
                manager.worker.take();
            }
            queue.jobs.retain(|j| !ids.contains(&j.account_id));
            queue
                .login_failure_history
                .retain(|id, _| !ids.contains(id));
            queue.remove_pending(&ids);
            host::save(&call.host, &queue, version).await.map_err(|_| {
                fault("账号已从 RS 网关删除，但插件任务列表同步失败，请刷新核对；不会自动重复删除")
            })?;
            return Ok(json!({"deletedAccountIds":ids,"jobs":queue.visible_jobs()}));
        }
        "api/submit" => {
            let request: Submit =
                serde_json::from_slice(&call.payload).map_err(|_| fault("提交格式无效"))?;
            if request.account_ids.is_empty() {
                return Err(fault("请选择要重新授权的账号"));
            }
            if uuid::Uuid::parse_str(&request.request_id).is_err()
                || request
                    .account_ids
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != request.account_ids.len()
                || request.account_ids.iter().any(|id| {
                    id.is_empty()
                        || id.len() > 128
                        || !id
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                })
            {
                return Err(fault("账号或请求标识无效"));
            }
            if queue.contains_batch(&request.request_id) {
                return Ok(json!({"jobs":queue.visible_jobs()}));
            }
            if request
                .account_ids
                .iter()
                .any(|id| queue.account_active(id))
            {
                return Err(fault("选择的账号已有进行中的任务"));
            }
            let mut completed = queue.jobs.iter().filter(|job| !job.active()).count();
            queue.jobs.retain(|job| {
                if !job.active() && completed > 100 {
                    completed -= 1;
                    false
                } else {
                    true
                }
            });
            queue.pending_batches.push(PendingBatch {
                request_id: request.request_id,
                account_ids: request.account_ids.into(),
            });
        }
        "api/force-submit" => {
            let request: ForceSubmit =
                serde_json::from_slice(&call.payload).map_err(|_| fault("强制授权参数无效"))?;
            if request.confirmation != "replace_workspace_and_disable"
                || uuid::Uuid::parse_str(&request.request_id).is_err()
            {
                return Err(fault("必须由管理员确认工作区替换并停止调度"));
            }
            let source = queue
                .jobs
                .iter()
                .find(|j| j.request_id == request.source_request_id)
                .cloned()
                .ok_or_else(|| fault("原失败任务已失效，请重新检测"))?;
            let key = format!("{}:{}", request.request_id, source.account_id);
            if queue.jobs.iter().any(|j| j.request_id == key) {
                return Ok(json!({"jobs":queue.visible_jobs()}));
            }
            if source.status != "failed"
                || source.step != "workspace"
                || !source
                    .workspace_choices
                    .iter()
                    .any(|w| w.id == request.workspace_id)
                || queue
                    .jobs
                    .iter()
                    .rev()
                    .find(|j| j.account_id == source.account_id)
                    .is_none_or(|j| j.request_id != source.request_id)
                || queue.jobs.iter().filter(|j| j.active()).count() >= 100
            {
                return Err(fault("工作区选择或原任务已变化，请重新检测"));
            }
            let account = detail(&call.host, &source.account_id).await?;
            require_idle(&account)?;
            if account["accountId"] == request.workspace_id
                || account["userId"].as_str().is_none_or(str::is_empty)
            {
                return Err(fault("原账号身份不完整或无需强制替换"));
            }
            let mut completed = queue.jobs.iter().filter(|job| !job.active()).count();
            queue.jobs.retain(|job| {
                if !job.active() && completed > 100 {
                    completed -= 1;
                    false
                } else {
                    true
                }
            });
            queue.jobs.push(Job {
                request_id: key,
                account_id: source.account_id,
                status: "queued".into(),
                step: "queued".into(),
                message: "管理员已确认替换工作区并停止调度".into(),
                started_at: None,
                finished_at: None,
                workspace_choices: vec![],
                force_workspace_id: Some(request.workspace_id),
                free_fallback: false,
                automatic: false,
                expected_revision: None,
                logout_others: false,
                cleanup_started: false,
                new_account: false,
                import_info: None,
                implementation_version: None,
            });
        }
        "api/free-fallback" => {
            let request: FreeFallbackSubmit =
                serde_json::from_slice(&call.payload).map_err(|_| fault("退回 Free 参数无效"))?;
            if request.confirmation != "fallback_free_and_disable"
                || uuid::Uuid::parse_str(&request.request_id).is_err()
            {
                return Err(fault("必须由管理员确认退回 Free 并停止调度"));
            }
            let source = queue
                .jobs
                .iter()
                .find(|j| j.request_id == request.source_request_id)
                .cloned()
                .ok_or_else(|| fault("原失败任务已失效，请重新检测"))?;
            let key = format!("{}:{}", request.request_id, source.account_id);
            if queue.jobs.iter().any(|j| j.request_id == key) {
                return Ok(json!({"jobs":queue.visible_jobs()}));
            }
            if source.status != "failed"
                || source.step != "workspace"
                || !source.workspace_choices.is_empty()
                || queue
                    .jobs
                    .iter()
                    .rev()
                    .find(|j| j.account_id == source.account_id)
                    .is_none_or(|j| j.request_id != source.request_id)
                || queue.jobs.iter().filter(|j| j.active()).count() >= 100
            {
                return Err(fault("只能对没有候选工作区的最新失败任务执行退回 Free"));
            }
            let account = detail(&call.host, &source.account_id).await?;
            require_idle(&account)?;
            if account["userId"].as_str().is_none_or(str::is_empty) {
                return Err(fault("原账号身份不完整，不能退回 Free"));
            }
            queue.jobs.push(Job {
                request_id: key,
                account_id: source.account_id,
                status: "queued".into(),
                step: "queued".into(),
                message: "管理员已确认退回同一用户 Free 并停止调度".into(),
                started_at: None,
                finished_at: None,
                workspace_choices: vec![],
                force_workspace_id: None,
                free_fallback: true,
                automatic: false,
                expected_revision: None,
                logout_others: false,
                cleanup_started: false,
                new_account: false,
                import_info: None,
                implementation_version: None,
            });
        }
        "api/cancel" => {
            let request: Cancel =
                serde_json::from_slice(&call.payload).map_err(|_| fault("取消参数无效"))?;
            if request.request_id.is_none() {
                control::set(&call.host, false).await?;
                queue.automation.enabled = false;
            }
            queue.cancel_pending(request.request_id.as_deref());
            for job in &mut queue.jobs {
                if job.active()
                    && request
                        .request_id
                        .as_ref()
                        .is_none_or(|id| id == &job.request_id)
                {
                    let message = if job.cleanup_started {
                        "历史任务已取消，账号可能已暂停；请人工核对已保存授权，不会自动重放"
                    } else {
                        "已取消，不会重新提交授权回调"
                    };
                    job.finish("cancelled", message);
                    if manager
                        .worker
                        .as_ref()
                        .is_some_and(|w| w.request_id == job.request_id)
                    {
                        manager.worker.take();
                    }
                }
            }
        }
        _ => return Err(fault("路由不存在")),
    }
    if call.request.path == "api/submit" {
        host::save_with_limit(&call.host, &queue, version, 240 * 1024).await?;
    } else {
        host::save(&call.host, &queue, version).await?;
    }
    onboarding::prune(manager, &queue);
    Ok(json!({"jobs":queue.visible_jobs()}))
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = PluginSession::accept(
        tokio::io::stdin(),
        tokio::io::stdout(),
        SessionConfig::default(),
    )
    .await?;
    let manifest = Manifest::from_author_slice(include_bytes!("../../plugin.json"))?;
    if session.handshake().plugin_id != manifest.plugin_id()?
        || session.handshake().contributes != manifest.contributes
    {
        return Err(SessionError::Handshake.into());
    }
    let manager = Arc::new(Mutex::new(Manager {
        imports: std::collections::VecDeque::new(),
        protected_management_url: session.handshake().configuration["protectedManagementUrl"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        mailshop_rt_api_key: session.handshake().configuration["mailshopRtApiKey"]
            .as_str()
            .map(str::to_owned),
        mailshop_rt_emails: session.handshake().configuration["mailshopRtEmails"]
            .as_array()
            .map(|emails| {
                emails
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            }),
        mailcom_key: session.handshake().configuration["mailcomKey"]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        runtime: worker::Runtime::new(),
        worker: None,
        recovered: false,
        next_refresh_group_check: None,
    }));
    let background = Arc::clone(&manager);
    let shutdown = Arc::clone(&manager);
    let controls = Arc::new(Mutex::new(()));
    let executor = executor::Executor::new();
    let background_executor = Arc::clone(&executor);
    let plugin = PluginBuilder::from_json(include_bytes!("../../plugin.json"))?
        .management(registration(), move |call| {
            let manager = Arc::clone(&manager);
            let controls = Arc::clone(&controls);
            let executor = Arc::clone(&executor);
            async move {
                let result = if call.request.path == "api/accounts"
                    && call.request.method == "GET"
                    && call.payload.is_empty()
                    && call.request.query.is_empty()
                {
                    rows(&call.host).await
                } else if call.request.path == "api/tick" {
                    // Browser requests may be cancelled when a frame closes. Native
                    // operations belong to the independent maintenance lifecycle.
                    if call.request.method == "POST" && call.payload == b"{}"
                        && call.request.query.is_empty() {
                        Ok(json!({"ok":true,"background":true}))
                    } else {
                        Err(fault("请求格式无效"))
                    }
                } else if call.request.path == "api/executor"
                    && call.request.method == "GET"
                    && call.payload.is_empty()
                    && call.request.query.is_empty()
                {
                    executor.status(&call.host).await
                } else if call.request.path == "api/automation" || call.request.path == "api/jobs" {
                    let _control = controls.lock().await;
                    control::handle(call).await
                } else {
                    let mut manager = manager.lock().await;
                    if call.request.method == "GET" {
                        handle(&mut manager, call).await
                    } else if call.request.path == "api/standby"
                        && call.payload == b"{}"
                        && call.request.query.is_empty()
                    {
                        if manager.worker.is_some() || !manager.imports.is_empty() {
                            Err(fault("本宿主仍有授权工作，不能交接执行权"))
                        } else {
                            executor.standby(&call.host).await
                        }
                    } else {
                        let host = call.host.clone();
                        let tick = call.request.path == "api/tick";
                        let allow_idle_takeover = matches!(
                            call.request.path.as_str(),
                            "api/import-line" | "api/import" | "api/submit"
                        );
                        let result = executor
                            .run(&host, allow_idle_takeover, handle(&mut manager, call))
                            .await;
                        if manager.worker.is_none() && manager.imports.is_empty() {
                            // Do not leave an idle 120-second lease that makes
                            // the current formal entry appear to be on another host.
                            let _ = executor.release(&host).await;
                        }
                        match result {
                            Ok(Some(value)) => Ok(value),
                            other => {
                                // 无效管理参数不能终止本宿主已有的授权工作
                                if matches!(&other, Ok(None))
                                    || matches!(&other, Err(error) if tick || error.code == gateway_plugin_sdk::ErrorCode::Conflict)
                                {
                                    manager.worker.take();
                                    manager.imports.clear();
                                    manager.recovered = false;
                                }
                                match other {
                                    Ok(None) if tick => Ok(json!({"ok":true,"standby":true})),
                                    Ok(None) => Err(fault(
                                        "授权由另一宿主处理，请从当前正式入口操作；状态仍可读取",
                                    )),
                                    Err(error) => Err(error),
                                    _ => unreachable!(),
                                }
                            }
                        }
                    }
                };
                let (status, value) = match result {
                    Ok(value) => (200, value),
                    Err(error) => (400, json!({"error":{"message":error.message}})),
                };
                Ok(TypedReply::new(ManagementResponse {
                    status,
                    content_type: "application/json".into(),
                    headers: vec![],
                })
                .with_payload(serde_json::to_vec(&value).map_err(|_| fault("响应编码失败"))?))
            }
        })?
        .on(methods::RECONCILE, move |call| {
            let manager = Arc::clone(&background);
            let executor = Arc::clone(&background_executor);
            async move {
                if let Ok(mut manager) = manager.try_lock() {
                    let result = executor.run(&call.host, false, manager.tick(&call.host)).await;
                    if !matches!(&result, Ok(Some(()))) {
                        manager.worker.take();
                        manager.imports.clear();
                        manager.recovered = false;
                    }
                    if manager.worker.is_none() && manager.imports.is_empty() {
                        let _ = executor.release(&call.host).await;
                    }
                    result?;
                }
                Ok(TypedReply::new(Empty {}))
            }
        })?
        .build()?;
    let result = session.run(plugin).await;
    // SDK 生命周期线程可能仍持有处理器，退出前显式回收子进程和运行目录
    let mut manager = shutdown.lock().await;
    if let Some(mut worker) = manager.worker.take() {
        let _ = worker.child.kill().await;
    }
    let cleanup = manager.runtime.cleanup();
    result?;
    cleanup.map_err(|error| std::io::Error::other(error.message))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_failure_survives_history_trimming_and_only_manual_success_clears_it() {
        let mut queue = Queue::default();
        let mut failure = Job::queued("manual", "a".into());
        let reason = "邮箱验证码验证：上游要求邮箱验证码，当前任务不支持人工补码续跑（HTTP 200）";
        failure.finish("failed", reason);
        failure.finished_at = Some(10);
        queue.jobs.push(failure.clone());
        queue = serde_json::from_value(host::queue_value(&queue, 256 * 1024).unwrap()).unwrap();
        queue.jobs.clear();
        assert_eq!(queue.login_failures(), vec!["a"]);
        assert_eq!(
            queue.login_failure_details()["a"]["category"],
            "email_verification"
        );
        assert_eq!(queue.login_failure_details()["a"]["message"], reason);
        let mut success = Job::queued("automatic", "a".into());
        success.finish("success", "自动授权成功");
        success.finished_at = Some(20);
        success.automatic = true;
        queue.jobs.push(success.clone());
        queue = serde_json::from_value(host::queue_value(&queue, 256 * 1024).unwrap()).unwrap();
        assert_eq!(queue.login_failures(), vec!["a"]);
        assert_eq!(queue.login_failure_details()["a"]["message"], reason);
        success.automatic = false;
        success.finished_at = Some(30);
        queue.jobs.push(success);
        queue = serde_json::from_value(host::queue_value(&queue, 256 * 1024).unwrap()).unwrap();
        queue.jobs = vec![failure.clone()];
        assert!(queue.login_failures().is_empty());
        assert!(queue.login_failure_details().is_empty());
        failure.message =
            "提交 2FA 动态码：账号已被封禁或停用，上游拒绝继续登录（HTTP 403）".into();
        failure.finished_at = Some(40);
        queue.jobs.push(failure);
        assert_eq!(queue.login_failures(), vec!["a"]);
        assert_eq!(
            queue.login_failure_details()["a"]["category"],
            "account_banned"
        );
    }

    #[test]
    fn mailshop_retry_evidence_survives_trimming_but_newer_unknown_or_success_blocks_it() {
        let mut queue = Queue::default();
        let mut rejected = Job::queued("first", "account".into());
        rejected.started_at = Some(10);
        rejected.finish("failed", "密码验证：上游拒绝邮箱或密码（HTTP 401）");
        rejected.finished_at = Some(11);
        queue.jobs.push(rejected.clone());
        let mut cancelled = Job::queued("pending", "account".into());
        cancelled.finish("cancelled", "尚未开始登录");
        cancelled.finished_at = Some(12);
        queue.jobs.push(cancelled);
        queue = serde_json::from_value(host::queue_value(&queue, 256 * 1024).unwrap()).unwrap();
        queue.jobs.clear();
        assert!(queue.permits_mailshop_retry("account"));

        for status in ["review", "success", "interrupted"] {
            let mut newer = Job::queued("second", "account".into());
            newer.started_at = Some(13);
            newer.finish(status, "原生写回或处理结果");
            newer.finished_at = Some(14);
            queue.jobs = vec![rejected.clone(), newer];
            let mut saved: Queue =
                serde_json::from_value(host::queue_value(&queue, 256 * 1024).unwrap()).unwrap();
            saved.jobs.clear();
            assert!(!saved.permits_mailshop_retry("account"), "{status}");
        }
        queue
            .login_failure_history
            .get_mut("account")
            .unwrap()
            .manual_success_at = 15;
        assert!(!queue.permits_mailshop_retry("account"));
    }

    #[test]
    fn mailshop_retry_recognizes_only_confirmed_legacy_failures() {
        let mut job = Job::queued("legacy", "account".into());
        job.finish(
            "failed",
            "邮箱验证码验证：上游要求邮箱验证码，当前任务不支持人工补码续跑（HTTP 200）",
        );
        assert!(job.permits_mailshop_retry());
        job.new_account = true;
        assert!(!job.permits_mailshop_retry());
        job.new_account = false;
        job.finish("failed", "密码验证：上游拒绝邮箱或密码（HTTP 429）");
        assert!(!job.permits_mailshop_retry());
        job.finish(
            "review",
            "GMX RT 回退：请求 Mailshop 超时，未写回；未自动重试",
        );
        assert!(job.permits_mailshop_retry());
        job.finish(
            "review",
            "GMX RT 回退：RS 未确认 RT 更新，请核对原账号；未自动重试",
        );
        assert!(!job.permits_mailshop_retry());
    }

    #[test]
    fn old_marks_keep_unknown_causes_and_available_history_fills_them() {
        let mut queue: Queue = serde_json::from_value(
            json!({"jobs":[],"loginFailureHistory":{"a":{"failedAt":10,"manualSuccessAt":0}}}),
        )
        .unwrap();
        assert_eq!(queue.login_failure_details()["a"]["category"], "other");
        assert_eq!(
            queue.login_failure_details()["a"]["message"],
            "历史登录失败记录未保存具体原因"
        );
        let mut failure = Job::queued("legacy", "a".into());
        failure.finish(
            "failed",
            "密码验证：上游拒绝请求，未取得可公开的具体原因（HTTP 403）",
        );
        failure.finished_at = Some(10);
        queue.jobs.push(failure);
        let stored = host::queue_value(&queue, 256 * 1024).unwrap();
        queue = serde_json::from_value(stored).unwrap();
        queue.jobs.clear();
        assert_eq!(queue.login_failure_details()["a"]["category"], "other");
        assert!(
            queue.login_failure_details()["a"]["message"]
                .as_str()
                .unwrap()
                .contains("HTTP 403")
        );
    }

    #[test]
    fn large_failure_batches_retain_causes_within_the_existing_state_budget() {
        let mut queue = Queue::default();
        let reason = "提交 2FA 动态码：账号已被封禁或停用，上游拒绝继续登录（HTTP 403）";
        for index in 0..1001u64 {
            let mut job = Job::queued("batch", format!("acct_{index:032}"));
            job.finish("failed", reason);
            job.finished_at = Some(1794500000000 + index);
            queue.jobs.push(job);
        }
        let stored = host::queue_value(&queue, 256 * 1024).unwrap();
        assert!(serde_json::to_vec(&stored).unwrap().len() <= 256 * 1024);
        queue = serde_json::from_value(stored).unwrap();
        assert!(queue.jobs.len() < 1001);
        assert_eq!(queue.login_failure_details().len(), 1001);
        assert!(queue.login_failure_details().values().all(|detail| detail["message"] == reason && detail["category"] == "account_banned"));
    }

    #[test]
    fn release_uses_current_rpc_and_management_contract() {
        assert_eq!(gateway_plugin_sdk::PROTOCOL_VERSION, 7);
        let source = include_bytes!("../../plugin.json");
        let manifest = Manifest::from_author_slice(source).unwrap();
        assert_eq!(manifest.manifest_version, 2);
        assert_eq!(
            manifest.contributes[&gateway_plugin_sdk::Capability::Management].version,
            2
        );
        assert_eq!(
            manifest.contributes[&gateway_plugin_sdk::Capability::Maintenance].version,
            1
        );
        let mut legacy: Value = serde_json::from_slice(source).unwrap();
        legacy["contributes"]["management"] = json!({"version":1});
        assert!(Manifest::from_author_slice(&serde_json::to_vec(&legacy).unwrap()).is_err());
    }

    #[test]
    fn all_oauth_plans_are_eligible_but_other_credentials_are_not() {
        for plan in [
            json!("free"),
            json!(" Free "),
            json!("plus"),
            json!("pro"),
            json!("team"),
            json!("business"),
            Value::Null,
        ] {
            assert!(eligible(
                &json!({"provider":"openai","authenticationKind":"oauth","planType":plan})
            ));
        }
        assert!(!eligible(
            &json!({"provider":"openai","authenticationKind":"api_key","planType":"free"})
        ));
        assert!(!eligible(
            &json!({"provider":"other","authenticationKind":"oauth","planType":"free"})
        ));
    }
    #[test]
    fn display_fields_use_manual_expiry_and_safe_usage_projection() {
        let a = json!({"id":"synthetic", "supplier":"Vendor A", "manualExpiresAt":"2026-11-21T00:00:00Z", "manualExpiresAtDisplay":"2026-11-21 00:00:00", "accessTokenExpiresAt":"2026-10-28T00:00:00Z", "usage":{"lastUsedAt":"2026-10-27T12:00:00Z", "lastUsedAtDisplay":"3分钟前", "lastUsedAtFullDisplay":"2026-10-27 12:00:00", "secret":"excluded"}, "accessToken":"excluded"});
        let row = account_row(&a, vec![]);
        assert_eq!(row["supplier"], a["supplier"]);
        assert_eq!(row["manualExpiresAt"], a["manualExpiresAt"]);
        assert_ne!(row["manualExpiresAt"], row["accessTokenExpiresAt"]);
        assert_eq!(row["usage"]["lastUsedAtDisplay"], "3分钟前");
        assert!(!row.to_string().contains("excluded"));
        assert!(account_row(&json!({}), vec![])["manualExpiresAt"].is_null());
    }
}
