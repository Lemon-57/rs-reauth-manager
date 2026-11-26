//! 原生宿主请求与插件私有状态的版本校验

use gateway_plugin_sdk::{
    ErrorCode, PluginFault, SendState,
    call::{
        host::{StateGetResult, StatePutResult},
        middleware::{MiddlewareHeader, http::Version},
    },
    client::{HostClient, HttpBody, HttpFrame, HttpRequest},
};
use serde_json::{Value, json};

pub fn fault(message: &str) -> PluginFault {
    PluginFault::new(ErrorCode::Rejected, message)
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn query(path: &str, pairs: &[(&str, &str)]) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.extend_pairs(pairs.iter().copied());
    format!("{path}?{}", query.finish())
}
pub async fn load(host: &HostClient) -> Result<(crate::Queue, Option<u64>), PluginFault> {
    let reply = host
        .call(
            "host.state.get",
            json!({"namespace":"reauth-manager","key":"queue"}),
            vec![],
        )
        .await
        .map_err(|e| e.into_plugin_fault())?;
    let data: StateGetResult =
        serde_json::from_value(reply.result).map_err(|_| fault("任务状态读取失败"))?;
    let (mut queue, version): (crate::Queue, Option<u64>) = match data.record {
        Some(record) => Ok((
            serde_json::from_value(record.value).map_err(|_| fault("任务状态格式无效"))?,
            Some(record.version),
        )),
        None => Ok((crate::Queue::default(), None)),
    }?;
    queue.login_failure_history = queue.login_failure_history();
    queue.automation.enabled = crate::control::enabled(host, queue.automation.enabled).await?;
    Ok((queue, version))
}
pub async fn save(
    host: &HostClient,
    queue: &crate::Queue,
    version: Option<u64>,
) -> Result<(), PluginFault> {
    save_with_limit(host, queue, version, 256 * 1024).await
}
pub(crate) async fn save_with_limit(
    host: &HostClient,
    queue: &crate::Queue,
    version: Option<u64>,
    limit: usize,
) -> Result<(), PluginFault> {
    crate::executor::check(host).await?;
    let value = queue_value(queue, limit)?;
    let reply = host.call("host.state.put", json!({"namespace":"reauth-manager","key":"queue","value":value,"expected_version":version}), vec![]).await.map_err(|e| e.into_plugin_fault())?;
    let _: StatePutResult =
        serde_json::from_value(reply.result).map_err(|_| fault("任务保存失败"))?;
    Ok(())
}

/// Omit only fields that both current and older readers already default. Keep
/// every active job; discard oldest completed history only when the SDK's
/// 256 KiB record budget requires it. HTTP responses still expose full jobs.
pub(crate) fn queue_value(queue: &crate::Queue, limit: usize) -> Result<Value, PluginFault> {
    let mut value = json!({"jobs": &queue.jobs, "automation": &queue.automation, "pendingBatches": &queue.pending_batches, "loginFailureHistory": queue.login_failure_history()});
    for job in value["jobs"]
        .as_array_mut()
        .ok_or_else(|| fault("任务状态格式无效"))?
    {
        let object = job
            .as_object_mut()
            .ok_or_else(|| fault("任务状态格式无效"))?;
        for key in [
            "startedAt",
            "finishedAt",
            "forceWorkspaceId",
            "expectedRevision",
        ] {
            if object.get(key).is_some_and(Value::is_null) {
                object.remove(key);
            }
        }
        for key in [
            "freeFallback",
            "automatic",
            "logoutOthers",
            "cleanupStarted",
            "newAccount",
        ] {
            if object.get(key) == Some(&json!(false)) {
                object.remove(key);
            }
        }
        if object
            .get("workspaceChoices")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            object.remove("workspaceChoices");
        }
    }
    let mut size = serde_json::to_vec(&value)
        .map_err(|_| fault("任务编码失败"))?
        .len();
    let jobs = value["jobs"]
        .as_array_mut()
        .ok_or_else(|| fault("任务状态格式无效"))?;
    while size > limit {
        let terminal: Vec<_> = jobs
            .iter()
            .enumerate()
            .filter(|(_, j)| !matches!(j["status"].as_str(), Some("queued" | "running")))
            .collect();
        if terminal.len() <= 1 {
            return Err(fault(
                "后台队列状态暂时无法保存，本次任务未提交，请稍后重试",
            ));
        }
        let index = terminal
            .into_iter()
            .min_by_key(|(index, j)| (j["finishedAt"].as_u64().unwrap_or(0), *index))
            .unwrap()
            .0;
        let removed = jobs.remove(index);
        size = size.saturating_sub(
            serde_json::to_vec(&removed)
                .map_err(|_| fault("任务编码失败"))?
                .len()
                + 1,
        );
    }
    Ok(value)
}
pub(crate) const NATIVE_REFRESH_PATH: &str = "/api/admin/accounts/refresh";
const NATIVE_RT_REPLACEMENT_PATH: &str = "/api/admin/accounts/oauth/replace-rt";
const REFRESH_LEASE_BUSY: &str = "令牌刷新繁忙，请稍后重试";

pub(crate) fn is_refresh_lease_busy(error: &PluginFault) -> bool {
    error.code == ErrorCode::Capacity
        && error.send_state == SendState::NotSent
        && error.http_status == Some(409)
        && error.message == REFRESH_LEASE_BUSY
}

async fn admin_http(
    host: &HostClient,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<(u16, Vec<u8>), PluginFault> {
    if method != "GET" {
        crate::executor::check(host).await?;
    }
    let (headers, body) = match body {
        Some(data) => (
            vec![MiddlewareHeader {
                name: "content-type".into(),
                value: b"application/json".to_vec(),
            }],
            HttpBody::from_bytes(serde_json::to_vec(&data).map_err(|_| fault("请求编码失败"))?),
        ),
        None => (vec![], HttpBody::empty()),
    };
    let mut reply = host
        .dispatch_http(HttpRequest {
            settings: Value::Null,
            method: method.into(),
            uri: path.into(),
            version: Version::Http11,
            headers,
            timeout_ms: Some(20000),
            body,
        })
        .await?;
    let mut bytes = Vec::new();
    while let Some(frame) = reply.body.read().await? {
        if let HttpFrame::Data(chunk) = frame {
            if bytes.len() + chunk.len() > 2097152 {
                reply.body.close().await?;
                return Err(fault("宿主响应过大"));
            }
            bytes.extend(chunk);
        }
    }
    Ok((reply.status, bytes))
}

pub(crate) async fn admin_replace_rt(host: &HostClient, body: Value) -> Result<Value, PluginFault> {
    let (status, bytes) = admin_http(host, "POST", NATIVE_RT_REPLACEMENT_PATH, Some(body))
        .await
        .map_err(|_| rt_update_fault(None, None))?;
    let value = serde_json::from_slice::<Value>(&bytes).ok();
    if (200..300).contains(&status)
        && let Some(value) = &value
        && value["code"] == 200
        && let Some(data) = value.get("data")
    {
        return Ok(data.clone());
    }
    Err(rt_update_fault(Some(status), value.as_ref()))
}

fn rt_update_fault(status: Option<u16>, body: Option<&Value>) -> PluginFault {
    let mut summary = match status {
        Some(status) => format!("RS HTTP {status}"),
        None => "无可用的 RS 回执".into(),
    };
    if let (Some(status), Some(body)) = (status, body) {
        let code = body["code"]
            .as_u64()
            .filter(|code| (40000..60000).contains(code));
        if let Some(code) = code {
            summary.push_str(&format!(" / {code}"));
        }
        let diagnostic = &body["diagnostic"];
        if (400..600).contains(&status)
            && code.is_some()
            && body.get("data").is_some_and(Value::is_null)
            && let Some(upstream) = diagnostic["upstreamStatus"]
                .as_u64()
                .filter(|status| (300..600).contains(status))
        {
            summary.push_str(&format!("；上游 HTTP {upstream}"));
            let code = diagnostic["upstreamCode"].as_str().filter(|code| {
                matches!(
                    *code,
                    "access_denied"
                        | "account_deactivated"
                        | "invalid_client"
                        | "invalid_grant"
                        | "invalid_refresh_token"
                        | "invalid_request"
                        | "invalid_request_error"
                        | "invalid_scope"
                        | "invalid_token"
                        | "rate_limit_exceeded"
                        | "refresh_token_expired"
                        | "refresh_token_invalid"
                        | "refresh_token_invalidated"
                        | "refresh_token_reused"
                        | "refresh_token_revoked"
                        | "server_error"
                        | "temporarily_unavailable"
                        | "token_expired"
                        | "token_invalidated"
                        | "token_revoked"
                        | "too_many_requests"
                        | "unauthorized_client"
                        | "unsupported_country_region_territory"
                        | "unsupported_grant_type"
                        | "user_deactivated"
                )
            });
            if let Some(code) = code {
                summary.push_str(&format!(" / {code}"));
            } else {
                summary.push_str("，无可记录的上游错误码");
            }
        } else if status == 502
            && code == Some(50201)
            && body["message"] == "令牌刷新被拒绝，请检查账号授权"
        {
            summary.push_str("；RS 报告上游拒绝，未提供精确状态或错误码");
        }
    }
    fault(&format!(
        "RS 未确认 RT 更新（{summary}），请核对原账号；未自动重试或改用账密登录"
    ))
}

pub async fn admin(
    host: &HostClient,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, PluginFault> {
    let (status, bytes) = admin_http(host, method, path, body).await?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| fault("宿主响应格式无效"))?;
    if !(200..300).contains(&status) || value["code"] != 200 {
        if method == "POST"
            && path == NATIVE_REFRESH_PATH
            && status == 409
            && value["code"] == 40901
            && value["message"] == REFRESH_LEASE_BUSY
        {
            let mut error = PluginFault::new(ErrorCode::Capacity, REFRESH_LEASE_BUSY);
            error.http_status = Some(409);
            return Err(error);
        }
        // 上游正文可能包含凭据或回调，不直接透传到页面
        let code = value["code"].as_u64().unwrap_or_default();
        let reason = match value["message"].as_str().unwrap_or_default() {
            "OpenAI 授权服务暂不可用，请检查出站连接后重试" => {
                "；RS 判定上游授权码交换入口或出站连接不可用"
            }
            "OpenAI 授权状态存储暂不可用，请稍后重试" => {
                "；RS 判定授权状态存储不可用"
            }
            "OpenAI 授权结果未知，请先核对账号状态，不要立即重复提交" => {
                "；RS 判定令牌交换结果未知，不得重放"
            }
            "OpenAI 拒绝了授权码，请重新发起授权" => "；RS 判定授权码被拒绝",
            _ => "",
        };
        return Err(fault(&format!(
            "RS 操作失败（HTTP {} / {}）{}，请检查原账号授权状态",
            status, code, reason
        )));
    }
    value
        .get("data")
        .cloned()
        .ok_or_else(|| fault("宿主响应缺少数据"))
}
