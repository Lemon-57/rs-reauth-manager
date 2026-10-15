//! 原生宿主请求与插件私有状态的版本校验

use gateway_plugin_sdk::{
    ErrorCode, PluginFault,
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
    match data.record {
        Some(record) => Ok((
            serde_json::from_value(record.value).map_err(|_| fault("任务状态格式无效"))?,
            Some(record.version),
        )),
        None => Ok((crate::Queue::default(), None)),
    }
}
pub async fn save(
    host: &HostClient,
    queue: &crate::Queue,
    version: Option<u64>,
) -> Result<(), PluginFault> {
    let reply = host.call("host.state.put", json!({"namespace":"reauth-manager","key":"queue","value":queue,"expected_version":version}), vec![]).await.map_err(|e| e.into_plugin_fault())?;
    let _: StatePutResult =
        serde_json::from_value(reply.result).map_err(|_| fault("任务保存失败"))?;
    Ok(())
}
pub async fn admin(
    host: &HostClient,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, PluginFault> {
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
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| fault("宿主响应格式无效"))?;
    if !(200..300).contains(&reply.status) || value["code"] != 200 {
        // 上游正文可能包含凭据或回调，不直接透传到页面
        let code = value["code"].as_u64().unwrap_or_default();
        return Err(fault(&format!(
            "RS 操作失败（HTTP {} / {}），请检查原账号授权状态",
            reply.status, code
        )));
    }
    value
        .get("data")
        .cloned()
        .ok_or_else(|| fault("宿主响应缺少数据"))
}
