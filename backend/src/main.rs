//! 管理接口、授权队列与宿主生命周期的组合

mod host;
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
struct Job {
    request_id: String,
    account_id: String,
    status: String,
    step: String,
    message: String,
    started_at: Option<u64>,
    finished_at: Option<u64>,
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
}
#[derive(Default, Serialize, Deserialize)]
pub struct Queue {
    jobs: Vec<Job>,
}
struct Manager {
    runtime: worker::Runtime,
    worker: Option<worker::Worker>,
    recovered: bool,
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

fn registration() -> ManagementRegistration {
    ManagementRegistration {
        routes: [
            ("GET", "api/accounts"),
            ("GET", "api/jobs"),
            ("POST", "api/submit"),
            ("POST", "api/cancel"),
            ("POST", "api/tick"),
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
    a["provider"] == "openai"
        && a["authenticationKind"] == "oauth"
        && !a["planType"]
            .as_str()
            .is_some_and(|plan| plan.trim().eq_ignore_ascii_case("free"))
}
fn notes_valid(a: &Value) -> bool {
    let Some(notes) = a["notes"].as_str() else {
        return false;
    };
    let parts: Vec<_> = notes.trim().split("----").collect();
    parts.len() == 3
        && a["email"]
            .as_str()
            .is_some_and(|email| parts[0].trim().eq_ignore_ascii_case(email))
        && !parts[1].is_empty()
        && !parts[2].trim().is_empty()
        && !notes.contains(['\r', '\n', '\0'])
}
fn settings(a: &Value) -> Value {
    json!({"id":a["id"],"email":a["email"],"name":a["name"],"enabled":a["enabled"],"notes":a["notes"],"groups":a["groups"],"proxy":a["outboundProxyEndpoint"],"weight":a["weight"],"concurrencyLimit":a["concurrencyLimit"],"modelAccess":a["modelAccess"],"accountId":a["accountId"]})
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
        return Err(fault("该账号不是适用的非 Free OpenAI OAuth 账号"));
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
async fn rows(host: &HostClient) -> Result<Value, PluginFault> {
    let mut rows = vec![];
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
        for a in items.iter().filter(|a| eligible(a)) {
            rows.push(json!({"id":a["id"],"name":a["name"],"email":a["email"],"enabled":a["enabled"],"planType":a["planType"],"status":a["status"],"accessTokenExpiresAt":a["accessTokenExpiresAt"],"proxy":a["outboundProxyEndpoint"],"notesValid":notes_valid(a)}));
        }
        if items.len() < 100 {
            return Ok(json!({"accounts":rows}));
        }
    }
    Err(fault("账号超过本次读取上限"))
}
fn protocol_error(code: &str) -> &'static str {
    match code {
        "credentials" => "备注格式、邮箱或 2FA 密钥无效",
        "password" => "邮箱或密码错误，请检查原账号备注",
        "mfa" => "2FA 验证未通过，请检查原账号备注",
        "human" => "上游要求人工验证，请手动完成授权",
        "workspace" => "无法匹配原账号工作区，已停止写回",
        "state" => "OAuth state 校验失败，已停止写回",
        "proxy" => "原账号代理连接失败",
        "limited" => "上游登录限流，请稍后手动重试",
        _ => "协议登录未完成，请检查账号或代理后重试",
    }
}
impl Manager {
    async fn recover(&mut self, host: &HostClient) -> Result<(), PluginFault> {
        if self.recovered {
            return Ok(());
        }
        let (mut queue, version) = host::load(host).await?;
        let mut changed = false;
        for job in &mut queue.jobs {
            if job.active() {
                job.finish("interrupted", "插件进程已重启，请先检查原账号后手动重试");
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
        let (mut queue, version) = host::load(host).await?;
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
                if output["event"] == "complete" {
                    job.step = "saving".into();
                    let result=async {
                        let latest=detail(host,&job.account_id).await?;
                        require_idle(&latest)?;
                        if settings(&latest)!=current.snapshot["settings"] || latest["_credentialRevision"] != current.snapshot["credentialRevision"] {return Err(fault("登录期间账号配置或凭据发生变化，已停止写回"))}
                        let callback=output["callbackUrl"].as_str().ok_or_else(||fault("协议回调格式无效"))?;
                        let done=admin(host,"POST","/api/admin/accounts/oauth/complete",Some(json!({"provider":"openai","flowId":current.flow,"callbackUrl":callback}))).await?;
                        if done["accountId"]!=job.account_id{return Err(fault("RS 写回账号与原账号不一致，请人工核对"))}
                        let after=detail(host,&job.account_id).await?;
                        if settings(&after)!=current.snapshot["settings"]{return Err(fault("授权已提交，但账号配置校验不一致，请人工核对"))}
                        if after["status"]=="error"||!after["hasRefreshToken"].as_bool().unwrap_or(false){return Err(fault("授权已提交，但账号状态尚未恢复，请人工核对"))}
                        Ok::<(),PluginFault>(())
                    }.await;
                    match result {
                        Ok(()) => job.finish("success", "新授权已写回原账号，配置校验通过"),
                        Err(error) => job.finish("review", &error.message),
                    }
                } else {
                    job.finish(
                        "failed",
                        protocol_error(output["code"].as_str().unwrap_or_default()),
                    );
                }
            } else if now().saturating_sub(current.started) > 420000 {
                job.finish("failed", "协议登录超时，未自动重试");
            } else if current
                .child
                .try_wait()
                .map_err(|_| fault("协议进程状态不可用"))?
                .is_some()
            {
                // 子进程退出后，读取协程仍可能在处理最后一行
                if now().saturating_sub(current.started) > 5000 {
                    job.finish("failed", "协议进程已退出，未取得有效回调");
                } else {
                    self.worker = Some(current);
                }
            } else {
                job.step = current
                    .output
                    .lock()
                    .map_err(|_| fault("协议进度读取失败"))?
                    .step
                    .clone();
                self.worker = Some(current);
            }
            host::save(host, &queue, version).await?;
            return Ok(());
        }
        if let Some(position) = queue.jobs.iter().position(|j| j.status == "queued") {
            let job = &mut queue.jobs[position];
            job.status = "running".into();
            job.step = "preparing".into();
            job.started_at = Some(now());
            // 凭据发送前先持久化意图，中断任务不自动恢复
            host::save(host, &queue, version).await?;
            let result=async {
                let job=&queue.jobs[position];let a=detail(host,&job.account_id).await?;
                require_idle(&a)?;
                if !notes_valid(&a){return Err(fault("备注须为与原账号邮箱一致的 邮箱----密码----2FA"))}
                let proxy=proxy(host,&a).await?;
                let start=admin(host,"POST","/api/admin/accounts/oauth/start",Some(json!({"provider":"openai","name":a["name"],"accountId":a["id"]}))).await?;
                let flow=start["flowId"].as_str().ok_or_else(||fault("RS 授权流程无效"))?.to_owned();
                let input=json!({"notes":a["notes"],"email":a["email"],"proxy":proxy,"authorizationUrl":start["authorizationUrl"],"accountId":a["accountId"]});
                self.runtime.start(input,flow,json!({"settings":settings(&a),"credentialRevision":a["_credentialRevision"]}),job.request_id.clone()).await
            }.await;
            match result {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => {
                    let (mut latest, version) = host::load(host).await?;
                    latest.jobs[position].finish("failed", &error.message);
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
    manager.recover(&call.host).await?;
    if !call.request.query.is_empty() || call.payload.len() > 16384 {
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
    if call.request.path == "api/tick" {
        if call.payload != b"{}" {
            return Err(fault("请求格式无效"));
        }
        manager.tick(&call.host).await?;
        return Ok(json!({"ok":true}));
    }
    let (mut queue, version) = host::load(&call.host).await?;
    match call.request.path.as_str() {
        "api/submit" => {
            let request: Submit =
                serde_json::from_slice(&call.payload).map_err(|_| fault("提交格式无效"))?;
            if uuid::Uuid::parse_str(&request.request_id).is_err()
                || request.account_ids.is_empty()
                || request.account_ids.len() > 100
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
            let prefix = format!("{}:", request.request_id);
            if queue
                .jobs
                .iter()
                .any(|job| job.request_id.starts_with(&prefix))
            {
                return Ok(json!({"jobs":queue.jobs}));
            }
            if request
                .account_ids
                .iter()
                .any(|id| queue.jobs.iter().any(|j| j.account_id == *id && j.active()))
            {
                return Err(fault("选择的账号已有进行中的任务"));
            }
            let active = queue.jobs.iter().filter(|j| j.active()).count();
            if active + request.account_ids.len() > 100 {
                return Err(fault("队列最多保留 100 个待处理账号"));
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
            for id in request.account_ids {
                queue.jobs.push(Job {
                    request_id: format!("{}:{id}", request.request_id),
                    account_id: id,
                    status: "queued".into(),
                    step: "queued".into(),
                    message: String::new(),
                    started_at: None,
                    finished_at: None,
                });
            }
        }
        "api/cancel" => {
            let request: Cancel =
                serde_json::from_slice(&call.payload).map_err(|_| fault("取消参数无效"))?;
            for job in &mut queue.jobs {
                if job.active()
                    && request
                        .request_id
                        .as_ref()
                        .is_none_or(|id| id == &job.request_id)
                {
                    job.finish("cancelled", "已取消，不会重新提交授权回调");
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
    host::save(&call.host, &queue, version).await?;
    Ok(json!({"jobs":queue.jobs}))
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
        runtime: worker::Runtime::new(),
        worker: None,
        recovered: false,
    }));
    let background = Arc::clone(&manager);
    let plugin = PluginBuilder::from_json(include_bytes!("../../plugin.json"))?
        .management(registration(), move |call| {
            let manager = Arc::clone(&manager);
            async move {
                let result = handle(&mut *manager.lock().await, call).await;
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
            async move {
                if let Ok(mut manager) = manager.try_lock() {
                    manager.tick(&call.host).await?;
                }
                Ok(TypedReply::new(Empty {}))
            }
        })?
        .build()?;
    session.run(plugin).await?;
    Ok(())
}
