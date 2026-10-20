//! 独立持久化自动开关，控制请求不等待登录与目录扫描锁

use crate::host::fault;
use gateway_plugin_sdk::{
    PluginFault,
    call::host::{StateGetResult, StatePutResult},
    client::HostClient,
};
use serde_json::json;

async fn read(host: &HostClient) -> Result<StateGetResult, PluginFault> {
    let reply = host
        .call(
            "host.state.get",
            json!({"namespace":"reauth-manager","key":"automation-switch"}),
            vec![],
        )
        .await
        .map_err(|e| e.into_plugin_fault())?;
    serde_json::from_value(reply.result).map_err(|_| fault("自动授权开关读取失败"))
}

pub async fn enabled(host: &HostClient, legacy: bool) -> Result<bool, PluginFault> {
    match read(host).await?.record {
        Some(record) => record.value["enabled"]
            .as_bool()
            .ok_or_else(|| fault("自动授权开关格式无效")),
        None => Ok(legacy),
    }
}

pub async fn set(host: &HostClient, enabled: bool) -> Result<(), PluginFault> {
    let current = read(host).await?;
    let reply = host.call("host.state.put", json!({"namespace":"reauth-manager","key":"automation-switch","value":{"enabled":enabled},"expected_version":current.record.map(|r| r.version)}), vec![])
        .await.map_err(|e| e.into_plugin_fault())?;
    let _: StatePutResult =
        serde_json::from_value(reply.result).map_err(|_| fault("自动授权开关保存结果无效"))?;
    Ok(())
}

pub async fn handle(
    call: gateway_plugin_sdk::client::TypedCall<
        gateway_plugin_sdk::call::management::ManagementRequest,
    >,
) -> Result<serde_json::Value, PluginFault> {
    match (call.request.method.as_str(), call.request.path.as_str()) {
        ("GET", "api/jobs") if call.payload.is_empty() => {}
        ("POST", "api/automation") => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Configure {
                enabled: bool,
            }
            let request: Configure =
                serde_json::from_slice(&call.payload).map_err(|_| fault("自动授权设置无效"))?;
            set(&call.host, request.enabled).await?;
        }
        _ => return Err(fault("自动授权控制请求无效")),
    }
    serde_json::to_value(crate::host::load(&call.host).await?.0).map_err(|_| fault("任务编码失败"))
}
