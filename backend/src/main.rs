//! 管理接口、授权队列与宿主生命周期的组合

mod deletion;
mod diagnostics;
mod host;
mod recovery;
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
    #[serde(default)]
    workspace_choices: Vec<WorkspaceChoice>,
    #[serde(default)]
    force_workspace_id: Option<String>,
    #[serde(default)]
    free_fallback: bool,
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
            ("POST", "api/submit"),
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
    parts.len() == 3
        && a["email"]
            .as_str()
            .is_some_and(|email| parts[0].trim().eq_ignore_ascii_case(email))
        && !parts[1].is_empty()
        && !parts[2].trim().is_empty()
        && !notes.contains(['\r', '\n', '\0'])
}
fn settings(a: &Value) -> Value {
    json!({"id":a["id"],"email":a["email"],"name":a["name"],"enabled":a["enabled"],"notes":a["notes"],"groups":a["groups"],"proxy":a["outboundProxyEndpoint"],"weight":a["weight"],"concurrencyLimit":a["concurrencyLimit"],"modelAccess":a["modelAccess"],"accountId":a["accountId"],"userId":a["userId"],"planType":a["planType"]})
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
            rows.push(json!({"id":a["id"],"name":a["name"],"email":a["email"],"enabled":a["enabled"],"planType":a["planType"],"status":a["status"],"accessTokenExpiresAt":a["accessTokenExpiresAt"],"proxy":a["outboundProxyEndpoint"],"notesValid":notes_valid(a),"groups":groups}));
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
                    if job.force_workspace_id.is_some() {
                        job.finish("review", "强制授权返回类型不匹配，未写回");
                        host::save(host, &queue, version).await?;
                        return Ok(());
                    }
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
                } else if output["event"] == "free_fallback"
                    || output["event"] == "forced_workspace"
                    || output["event"] == "forced_free"
                    || output["event"] == "team_upgrade"
                {
                    job.step = "saving".into();
                    let forced = output["event"] == "forced_workspace";
                    let forced_free = output["event"] == "forced_free";
                    let upgraded = output["event"] == "team_upgrade";
                    if (forced
                        && (job.force_workspace_id.as_deref() != output["workspaceId"].as_str()
                            || job.force_workspace_id.is_none()))
                        || (!forced && job.force_workspace_id.is_some())
                        || (forced_free && !job.free_fallback)
                        || (upgraded && job.free_fallback)
                    {
                        job.finish("review", "工作区与管理员确认不一致，未写回");
                        host::save(host, &queue, version).await?;
                        return Ok(());
                    }
                    match recovery::commit(host, &job.account_id, &current.snapshot, &output).await
                    {
                        Ok(()) => {
                            if upgraded {
                                job.finish(
                                    "success",
                                    "已切换到同一用户的唯一 Team 工作区，已开启调度",
                                );
                            } else if forced {
                                job.finish(
                                    "success",
                                    "管理员已确认，其他工作区授权已写回原账号，已停止调度",
                                );
                            } else if forced_free {
                                job.finish(
                                    "success",
                                    "管理员已确认，已退回同一用户的 Free 并停止调度",
                                );
                                job.step = "free".into();
                            } else {
                                job.finish("success", "原工作区已失效，已切回 Free，已停止调度");
                                job.step = "free".into();
                            }
                        }
                        Err(error) => job.finish("review", &error.message),
                    }
                } else {
                    job.finish(
                        "failed",
                        &diagnostics::message(
                            &output,
                            protocol_error(output["code"].as_str().unwrap_or_default()),
                        ),
                    );
                    if output["code"] == "workspace" && job.force_workspace_id.is_none() {
                        job.step = "workspace".into();
                        job.workspace_choices = workspace_choices(&output);
                    }
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
                self.runtime.prepare().await?;
                let job=&queue.jobs[position];let a=detail(host,&job.account_id).await?;
                require_idle(&a)?;
                if !notes_valid(&a){return Err(fault("备注须为与原账号邮箱一致的 邮箱----密码----2FA"))}
                let proxy=proxy(host,&a).await?;
                let start=admin(host,"POST","/api/admin/accounts/oauth/start",Some(json!({"provider":"openai","name":a["name"],"accountId":a["id"]}))).await?;
                let flow=start["flowId"].as_str().ok_or_else(||fault("RS 授权流程无效"))?.to_owned();
                let input=json!({"notes":a["notes"],"email":a["email"],"proxy":proxy,"authorizationUrl":start["authorizationUrl"],"accountId":a["accountId"],"userId":a["userId"],"planType":a["planType"],"forceWorkspaceId":job.force_workspace_id,"forceFree":job.free_fallback});
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
    if call.request.path == "api/runtime-check" {
        if call.payload != b"{}" {
            return Err(fault("请求格式无效"));
        }
        manager.runtime.prepare().await?;
        return Ok(json!({"ready":true}));
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
            host::save(&call.host, &queue, version).await.map_err(|_| {
                fault("账号已从 RS 网关删除，但插件任务列表同步失败，请刷新核对；不会自动重复删除")
            })?;
            return Ok(json!({"deletedAccountIds":ids,"jobs":queue.jobs}));
        }
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
                    workspace_choices: vec![],
                    force_workspace_id: None,
                    free_fallback: false,
                });
            }
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
                return Ok(json!({"jobs":queue.jobs}));
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
                return Ok(json!({"jobs":queue.jobs}));
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
            });
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
    let shutdown = Arc::clone(&manager);
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
    fn release_uses_rpc_v4_and_management_v2_not_a_renamed_legacy_contract() {
        assert_eq!(gateway_plugin_sdk::PROTOCOL_VERSION, 4);
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
}
