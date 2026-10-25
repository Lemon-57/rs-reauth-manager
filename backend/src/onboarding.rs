//! 导入格式校验与本机受保护管理传输，敏感内容仅存于当前调用及工作进程
use crate::{
    ImportInfo, Job, Manager, Queue, detail, directory,
    host::{fault, now},
    import_notes_valid, recovery, require_idle, settings,
};
use gateway_plugin_sdk::{
    PluginFault,
    call::{management::ManagementRequest, middleware::MiddlewareHeader},
    client::{HostClient, TypedCall},
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Submission {
    request_id: String,
    line: String,
    group_ids: Vec<String>,
}

pub struct Input {
    pub email: String,
    pub notes: String,
    pub refresh_token: Option<String>,
}

pub fn parse(line: &str) -> Result<Input, PluginFault> {
    let fields: Vec<_> = line.trim().split("----").collect();
    if !matches!(fields.len(), 3 | 4)
        || fields
            .iter()
            .any(|v| v.is_empty() || v.chars().any(char::is_control))
    {
        return Err(fault(
            "请输入 邮箱----密码----2FA 或 邮箱----密码----2FA----RT",
        ));
    }
    let email = fields[0].trim().to_owned();
    let notes = fields[..3].join("----");
    if email.len() > 254
        || email.chars().any(char::is_whitespace)
        || email.split('@').count() != 2
        || !email
            .split('@')
            .nth(1)
            .is_some_and(|host| host.contains('.'))
        || !import_notes_valid(&email, &notes)
        || fields
            .get(3)
            .is_some_and(|v| v.len() > 32768 || v.chars().any(char::is_whitespace))
    {
        return Err(fault("导入格式或三字段登录资料无效"));
    }
    Ok(Input {
        email,
        notes,
        refresh_token: fields.get(3).map(|v| (*v).to_owned()),
    })
}

fn transport(call: &TypedCall<ManagementRequest>, base: &str) -> Result<Value, PluginFault> {
    let url = url::Url::parse(base).map_err(|_| fault("请先配置本机受保护管理入口"))?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(fault("受保护管理入口必须是带端口的本机回环 HTTP 地址"));
    }
    let headers: Vec<MiddlewareHeader> = call
        .request
        .headers
        .iter()
        .filter(|h| {
            matches!(
                h.name.to_ascii_lowercase().as_str(),
                "cookie" | "authorization" | "x-api-key" | "origin" | "x-csrf-token"
            )
        })
        .cloned()
        .collect();
    if !headers.iter().any(|h| {
        matches!(
            h.name.to_ascii_lowercase().as_str(),
            "cookie" | "authorization" | "x-api-key"
        )
    }) {
        return Err(fault("导入需要原管理员会话认证"));
    }
    Ok(json!({"base":url.as_str().trim_end_matches('/'),"headers":headers}))
}

pub async fn request(
    host: &HostClient,
    transport: &Value,
    path: &str,
    body: Value,
) -> Result<Value, PluginFault> {
    // 仅允许固定管理路径，导入内容不能指定任意 URL
    crate::executor::check(host).await?;
    if !matches!(
        path,
        "/_management/onboarding/start"
            | "/api/admin/accounts/import"
            | "/api/admin/accounts/oauth/complete"
            | "/api/admin/accounts/batch-update"
    ) {
        return Err(fault("导入管理路径无效"));
    }
    let headers: Vec<MiddlewareHeader> = serde_json::from_value(transport["headers"].clone())
        .map_err(|_| fault("导入认证上下文缺失"))?;
    let mut headers: Vec<_> = headers.into_iter().map(|h| (h.name, h.value)).collect();
    headers.push(("content-type".into(), b"application/json".to_vec()));
    let reply = host
        .http(
            gateway_plugin_sdk::call::host::HttpRequest {
                method: "POST".into(),
                url: format!(
                    "{}{}",
                    transport["base"]
                        .as_str()
                        .ok_or_else(|| fault("管理入口缺失"))?,
                    path
                ),
                headers,
            },
            serde_json::to_vec(&body).map_err(|_| fault("导入请求编码失败"))?,
        )
        .await
        .map_err(|_| fault("受保护导入请求结果未确认，请读取账号和任务，勿重复提交"))?;
    let status = reply.status;
    let raw = reply
        .body
        .collect(2 * 1024 * 1024)
        .await
        .map_err(|_| fault("导入回执读取未确认，请核对账号，勿重复提交"))?;
    let result: Value = serde_json::from_slice(&raw)
        .map_err(|_| fault("导入回执格式未确认，请核对账号，勿重复提交"))?;
    if !(200..300).contains(&status) || result["code"] != 200 {
        return Err(fault(&format!(
            "受保护导入未确认（HTTP {status}），请核对账号与任务，未自动重试"
        )));
    }
    result
        .get("data")
        .cloned()
        .ok_or_else(|| fault("导入回执缺少结果"))
}

pub struct Pending {
    request_id: String,
    nonce: String,
    input: Input,
    group_ids: Vec<String>,
    transport: Value,
}

pub fn parse_lines(text: &str) -> Result<Vec<(usize, Input)>, PluginFault> {
    if text.len() > 500 * 1024 {
        return Err(fault("本批内容过长，请拆分提交"));
    }
    let mut entries = Vec::new();
    let mut emails = std::collections::BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let input = parse(line).map_err(|_| {
            fault(&format!(
                "第 {} 行格式无效，请核对三字段或四字段格式",
                index + 1
            ))
        })?;
        if !emails.insert(input.email.to_ascii_lowercase()) {
            return Err(fault(&format!(
                "第 {} 行邮箱在本批次重复，未提交任何账号",
                index + 1
            )));
        }
        entries.push((index + 1, input));
    }
    if entries.is_empty() {
        return Err(fault("请至少输入一行账号"));
    }
    Ok(entries)
}

fn job(request_id: String, line: usize, email: &str) -> Job {
    Job {
        request_id,
        account_id: String::new(),
        status: "queued".into(),
        step: "queued".into(),
        message: format!("第 {line} 行等待导入"),
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
        implementation_version: None,
        import_info: Some(ImportInfo {
            line,
            email: email.into(),
        }),
    }
}

pub fn prune(manager: &mut Manager, queue: &Queue) {
    manager.imports.retain(|p| {
        queue
            .jobs
            .iter()
            .any(|j| j.request_id == p.request_id && j.active())
    });
}

pub async fn submit(
    manager: &mut Manager,
    call: &TypedCall<ManagementRequest>,
) -> Result<Value, PluginFault> {
    let data: Submission =
        serde_json::from_slice(&call.payload).map_err(|_| fault("导入参数无效"))?;
    let entries = parse_lines(&data.line)?;
    if uuid::Uuid::parse_str(&data.request_id).is_err()
        || data.group_ids.len() > 20
        || data.group_ids.iter().any(|v| {
            v.is_empty()
                || v.len() > 128
                || !v
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        })
        || data
            .group_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != data.group_ids.len()
    {
        return Err(fault("导入请求或分组无效"));
    }
    let transport = transport(call, &manager.protected_management_url)?;
    let (mut queue, version) = crate::host::load(&call.host).await?;
    let prefix = format!("{}:import", data.request_id);
    if queue
        .jobs
        .iter()
        .any(|j| j.request_id == prefix || j.request_id.starts_with(&(prefix.clone() + ":")))
    {
        return Ok(json!({"jobs":queue.visible_jobs()}));
    }
    if manager.worker.is_some() || queue.has_active() {
        return Err(fault("已有授权任务进行中，请等待空闲后导入"));
    }
    let rows = directory(&call.host).await?;
    for (line, input) in &entries {
        if rows.iter().any(|a| {
            a["provider"] == "openai"
                && a["email"]
                    .as_str()
                    .is_some_and(|v| v.eq_ignore_ascii_case(&input.email))
        }) {
            return Err(fault(&format!(
                "第 {line} 行账号已存在，保留当前凭据及固定代理，本批未提交"
            )));
        }
    }
    // 整批校验通过后一次持久化非敏感意图，敏感输入仅留在当前进程内存
    let single = entries.len() == 1;
    let mut pending = Vec::new();
    // The history budget must never truncate the new batch or drain an empty
    // queue when the batch itself exceeds 200 rows. Storage is checked by save
    // before any sensitive input is retained or any account operation begins.
    let history_to_keep = 200usize.saturating_sub(entries.len());
    let remove = queue.jobs.len().saturating_sub(history_to_keep);
    queue.jobs.drain(..remove);
    for (line, input) in entries {
        let request_id = if single {
            prefix.clone()
        } else {
            format!("{prefix}:{line}")
        };
        queue.jobs.push(job(request_id.clone(), line, &input.email));
        pending.push(Pending {
            request_id,
            nonce: uuid::Uuid::new_v4().to_string(),
            input,
            group_ids: data.group_ids.clone(),
            transport: transport.clone(),
        });
    }
    crate::host::save(&call.host, &queue, version).await?;
    prune(manager, &queue);
    manager.imports.extend(pending);
    Ok(json!({"jobs":queue.visible_jobs()}))
}

pub async fn advance(manager: &mut Manager, host: &HostClient) -> Result<bool, PluginFault> {
    let (mut queue, version) = crate::host::load(host).await?;
    prune(manager, &queue);
    let Some(job) = queue.jobs.iter_mut().find(|j| j.status == "queued") else {
        return Ok(false);
    };
    if job.import_info.is_none() || !job.account_id.is_empty() {
        return Ok(false);
    }
    let Some(index) = manager
        .imports
        .iter()
        .position(|p| p.request_id == job.request_id)
    else {
        job.finish(
            "interrupted",
            "待导入资料已不在内存，请核对账号后重新提交，未自动重放",
        );
        crate::host::save(host, &queue, version).await?;
        return Ok(true);
    };
    let pending = manager
        .imports
        .remove(index)
        .ok_or_else(|| fault("待导入任务状态冲突"))?;
    job.status = "running".into();
    job.step = "preparing".into();
    job.started_at = Some(now());
    job.implementation_version = Some(env!("CARGO_PKG_VERSION").into());
    crate::host::save(host, &queue, version).await?;
    // 每行只执行一次，结果不确定时只标记本行核对，其他账号沿各自身份继续串行处理
    if let Err(error) = execute(
        manager,
        host,
        &pending.transport,
        &pending,
        &pending.input,
        &pending.request_id,
    )
    .await
    {
        let (mut queue, version) = crate::host::load(host).await?;
        if let Some(job) = queue
            .jobs
            .iter_mut()
            .find(|j| j.request_id == pending.request_id)
        {
            job.finish("review", &error.message);
        }
        crate::host::save(host, &queue, version).await?;
    }
    Ok(true)
}

async fn execute(
    manager: &mut Manager,
    host: &HostClient,
    transport: &Value,
    data: &Pending,
    input: &Input,
    request_id: &str,
) -> Result<(), PluginFault> {
    let config = json!({"enabled":false,"concurrencyLimit":null,"weight":1,"groupIds":data.group_ids,"notes":input.notes,"modelAccess":{"mode":"all","models":[]}});
    if let Some(rt) = &input.refresh_token {
        let result = request(host, transport, "/api/admin/accounts/import", json!({"provider":"openai","data":{"email":input.email,"refreshToken":rt},"settings":config})).await?;
        let ids = result["accountIds"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(|| fault("RT 导入账号回执未确认，请核对目录"))?;
        let id = ids[0]
            .as_str()
            .ok_or_else(|| fault("RT 导入账号 ID 无效"))?;
        let a = detail(host, id).await?;
        let (mut queue, version) = crate::host::load(host).await?;
        let job = queue
            .jobs
            .iter_mut()
            .find(|j| j.request_id == request_id)
            .ok_or_else(|| fault("导入任务缺失"))?;
        job.account_id = id.into();
        crate::host::save(host, &queue, version).await?;
        if !a["email"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case(&input.email))
            || a["notes"] != input.notes
            || a["enabled"] != false
        {
            return Err(fault("RT 导入身份或备注读回不一致，账号保持暂停"));
        }
        require_idle(&a)?;
        let credential = recovery::credential(host, id).await?;
        recovery::validate_binding(&recovery::tokens(&credential), &settings(&a))?;
        if credential.credential_revision != a["_credentialRevision"].as_u64().unwrap_or_default() {
            return Err(fault("RT 导入凭据版本变化，账号保持暂停"));
        }
        match a["planType"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "team" | "business" => {
                recovery::validate(
                    &json!({"event":"same_workspace","workspaceId":a["accountId"],"originalWorkspaceId":a["accountId"],"tokens":recovery::tokens(&credential)}),
                    &settings(&a),
                ).map_err(|_| fault("RT 已保存，但 Team 工作区或套餐声明未确认，账号保持暂停，请核对"))?;
                crate::native::restore(
                    host,
                    id,
                    &settings(&a),
                    credential.credential_revision,
                    true,
                )
                .await?;
                let (mut queue, version) = crate::host::load(host).await?;
                queue
                    .jobs
                    .iter_mut()
                    .find(|j| j.request_id == request_id)
                    .ok_or_else(|| fault("导入任务缺失"))?
                    .finish(
                        "success",
                        "提供的 Team RT 已验证、保存并移入 GPT Pro，已启用，未发起账密登录",
                    );
                crate::host::save(host, &queue, version).await?;
            }
            "free" => {
                // 复用普通手动原生 OAuth 执行器，保持同一账号和固定代理
                let (mut queue, version) = crate::host::load(host).await?;
                let j = queue
                    .jobs
                    .iter_mut()
                    .find(|j| j.request_id == request_id)
                    .ok_or_else(|| fault("导入任务缺失"))?;
                j.expected_revision = a["_credentialRevision"].as_u64();
                j.status = "queued".into();
                j.step = "queued".into();
                j.message = "提供的 RT 为 Free，已保存原账号，等待插件重新授权".into();
                crate::host::save(host, &queue, version).await?;
            }
            _ => {
                return Err(fault(
                    "提供的 RT 套餐既非 Team/Business 也非 Free，已保留暂停，请核对",
                ));
            }
        }
        return Ok(());
    }
    manager.runtime.prepare().await?;
    let start = request(
        host,
        transport,
        "/_management/onboarding/start",
        json!({"email":input.email,"requestId":data.nonce}),
    )
    .await?;
    let flow = start["flowId"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| fault("受保护 OAuth 流程缺失"))?
        .to_owned();
    let proxy = start["outboundProxyUrl"]
        .as_str()
        .filter(|v| crate::import_proxy_valid(v))
        .ok_or_else(|| fault("受保护固定代理缺失，未启动登录"))?;
    let (mut queue, version) = crate::host::load(host).await?;
    queue
        .jobs
        .iter_mut()
        .find(|j| j.request_id == request_id)
        .ok_or_else(|| fault("导入任务缺失"))?
        .new_account = true;
    crate::host::save(host, &queue, version).await?;
    let worker_input = json!({"notes":input.notes,"email":input.email,"proxy":proxy,"authorizationUrl":start["authorizationUrl"],"accountId":"","userId":"","planType":"team","automatic":false,"newAccount":true,"allowFreeNew":true});
    let snapshot = json!({"newAccount":true,"flowId":flow,"proxy":proxy,"email":input.email,"settings":config,"protectedTransport":transport,"allowFreeNew":true});
    manager.worker = Some(
        manager
            .runtime
            .start(worker_input, flow, snapshot, request_id.into())
            .await?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_both_formats_without_putting_rt_in_notes() {
        let three = "fixture@example.com----fixture-password----JBSWY3DPEHPK3PXP";
        let a = parse(three).unwrap();
        assert!(a.refresh_token.is_none());
        assert_eq!(a.notes, three);
        let b = parse(&format!("{three}----fixture-rt")).unwrap();
        assert_eq!(b.notes, three);
        assert_eq!(b.refresh_token.as_deref(), Some("fixture-rt"));
    }
    #[test]
    fn mixed_multiline_preserves_physical_line_numbers_and_rejects_duplicates() {
        let first = "first@example.com----fixture-password----JBSWY3DPEHPK3PXP";
        let second = "second@example.com----fixture-password----JBSWY3DPEHPK3PXP----fixture-rt";
        let entries = parse_lines(&format!("\r\n{first}\r\n\r\n{second}\r\n")).unwrap();
        assert_eq!(entries.iter().map(|e| e.0).collect::<Vec<_>>(), vec![2, 4]);
        assert!(entries[0].1.refresh_token.is_none());
        assert_eq!(entries[1].1.refresh_token.as_deref(), Some("fixture-rt"));
        assert!(parse_lines(&format!("{first}\n{}", first.to_uppercase())).is_err());
        assert!(parse_lines("\r\n \n").is_err());
        assert!(
            parse_lines(&format!("{first}\ninvalid-private-input"))
                .err()
                .unwrap()
                .message
                .contains("第 2 行")
        );
    }
    #[test]
    fn large_batches_preserve_all_rows_and_validate_the_tail() {
        let text = (0..500)
            .map(|n| format!("row{n}@example.com----fixture-password----JBSWY3DPEHPK3PXP"))
            .collect::<Vec<_>>()
            .join("\n");
        let entries = parse_lines(&text).unwrap();
        assert_eq!(entries.len(), 500);
        assert_eq!(entries.last().unwrap().0, 500);
        assert!(
            parse_lines(&format!("{text}\ninvalid"))
                .err()
                .unwrap()
                .message
                .contains("第 501 行")
        );
        assert!(
            parse_lines(&format!(
                "{text}\nROW0@example.com----fixture-password----JBSWY3DPEHPK3PXP"
            ))
            .err()
            .unwrap()
            .message
            .contains("重复")
        );
        assert!(parse_lines(&" ".repeat(500 * 1024 + 1)).is_err());
    }
    #[test]
    fn rejects_partial_multiline_and_ambiguous_input_without_echoing_it() {
        for text in [
            "fixture@example.com----secret",
            "fixture@example.com----secret----bad!",
            "fixture@example.com----secret----JBSWY3DPEHPK3PXP----",
            "fixture@example.com----secret----JBSWY3DPEHPK3PXP----rt----extra",
            "fixture@example.com----secret\nsecret----JBSWY3DPEHPK3PXP",
        ] {
            let error = parse(text).err().expect("invalid input");
            assert!(!error.message.contains("secret"));
        }
    }
}
