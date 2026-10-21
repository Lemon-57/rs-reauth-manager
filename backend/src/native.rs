//! 所有授权共用 RS 原生完成接口，仅在原生保存后核验及修正工作区元数据
use crate::{
    Job, detail,
    host::{admin, fault},
    recovery, require_idle, settings,
};
use gateway_plugin_sdk::{
    PluginFault,
    call::host::{AuthSaveRequest, AuthSaveResult},
    client::HostClient,
};
use serde_json::{Value, json};

fn final_status_confirmed(status: &Value) -> bool {
    matches!(
        status.as_str(),
        Some("normal" | "disabled" | "quota_exhausted" | "rate_limited")
    )
}

pub async fn restore(
    host: &HostClient,
    id: &str,
    expected: &Value,
    revision: u64,
    enabled: bool,
) -> Result<(), PluginFault> {
    let before = detail(host, id).await?;
    if settings(&before) != *expected
        || before["_credentialRevision"].as_u64() != Some(revision)
        || require_idle(&before).is_err()
    {
        return Err(fault("恢复调度前账号配置、凭据或在途状态变化，请人工核对"));
    }
    if enabled {
        admin(
            host,
            "POST",
            "/api/admin/accounts/batch-update",
            Some(json!({"accountIds":[id],"enabled":true})),
        )
        .await
        .map_err(|_| fault("恢复调度结果不确定，请核对实际启停状态，不会自动重放"))?;
    }
    let after = detail(host, id).await?;
    let mut target = expected.clone();
    target["enabled"] = json!(enabled);
    if settings(&after) != target
        || after["_credentialRevision"].as_u64() != Some(revision)
        || !final_status_confirmed(&after["status"])
    {
        return Err(fault("最终授权配置或调度状态未确认，请人工核对"));
    }
    Ok(())
}

pub async fn complete(
    host: &HostClient,
    job: &Job,
    snapshot: &mut Value,
    output: &Value,
) -> Result<(String, bool), PluginFault> {
    let event = output["event"].as_str().unwrap_or_default();
    let forced = event == "forced_workspace";
    let free = matches!(event, "free_fallback" | "forced_free");
    let team = event == "team_upgrade";
    if !matches!(
        event,
        "complete" | "free_fallback" | "forced_free" | "forced_workspace" | "team_upgrade"
    ) || output.get("tokens").is_some()
        || (job.automatic && event != "complete")
        || (forced
            && (job.force_workspace_id.as_deref() != output["workspaceId"].as_str()
                || output["administratorConfirmed"] != true))
        || (!forced && job.force_workspace_id.is_some())
        || (event == "forced_free"
            && (!job.free_fallback || output["administratorConfirmed"] != true))
        || (team
            && (output["uniqueTeamConfirmed"] != true
                || !snapshot["settings"]["planType"]
                    .as_str()
                    .is_some_and(|p| p.trim().eq_ignore_ascii_case("free"))))
    {
        return Err(fault(
            "授权类型与原账号或管理员确认不一致，未提交原生完成接口",
        ));
    }
    let original = snapshot["settings"].clone();
    if ["email", "userId", "accountId", "planType"]
        .iter()
        .any(|key| original[*key].as_str().is_none_or(|v| v.trim().is_empty()))
    {
        return Err(fault("原账号身份、工作区或套餐不完整，未提交原生完成接口"));
    }
    let current = detail(host, &job.account_id).await?;
    require_idle(&current)?;
    if settings(&current) != original
        || current["_credentialRevision"] != snapshot["credentialRevision"]
    {
        return Err(fault("登录期间账号配置或凭据变化，未提交原生完成接口"));
    }
    if job.automatic && !crate::automatic::ready(&current) {
        return Err(fault("自动授权条件已经变化，未提交原生完成接口"));
    }
    let old = recovery::credential(host, &job.account_id).await?;
    if Some(old.credential_revision) != snapshot["credentialRevision"].as_u64()
        || old.facts.upstream_user_id.as_deref() != original["userId"].as_str()
    {
        return Err(fault("原账号身份或凭据版本未确认，未提交原生完成接口"));
    }
    let old_subject = recovery::subject(&old)?;
    let callback = output["callbackUrl"]
        .as_str()
        .ok_or_else(|| fault("授权码回调缺失，未提交原生完成接口"))?;
    if original["enabled"] == true {
        admin(
            host,
            "POST",
            "/api/admin/accounts/batch-update",
            Some(json!({"accountIds":[job.account_id],"enabled":false})),
        )
        .await
        .map_err(|_| fault("原生授权前暂停结果不确定，请核对账号状态"))?;
    }
    let mut expected = original.clone();
    expected["enabled"] = json!(false);
    let paused = detail(host, &job.account_id).await?;
    require_idle(&paused)?;
    if settings(&paused) != expected
        || paused["_credentialRevision"] != snapshot["credentialRevision"]
    {
        return Err(fault(
            "暂停后账号配置、凭据或在途状态变化，未提交原生完成接口",
        ));
    }
    let done = admin(
        host,
        "POST",
        "/api/admin/accounts/oauth/complete",
        Some(json!({"provider":"openai","flowId":snapshot["flowId"],"callbackUrl":callback})),
    )
    .await
    .map_err(|error| {
        fault(&format!(
            "RS 原生 OAuth 完成接口未确认：{}；账号保持暂停，请先核对提交回执",
            error.message
        ))
    })?;
    if done["accountId"] != job.account_id {
        return Err(fault("原生 OAuth 返回账号不一致，账号保持暂停"));
    }
    let after = detail(host, &job.account_id).await?;
    require_idle(&after)?;
    let mut saved = recovery::credential(host, &job.account_id).await?;
    if settings(&after) != expected
        || after["_credentialRevision"].as_u64() != Some(old.credential_revision + 1)
        || saved.credential_revision != old.credential_revision + 1
    {
        return Err(fault(
            "原生 OAuth 保存后的配置或精确凭据版本未确认，账号保持暂停",
        ));
    }
    let tokens = recovery::tokens(&saved);
    let identity = recovery::claims(
        tokens["id_token"]
            .as_str()
            .ok_or_else(|| fault("原生保存的 ID Token 缺失"))?,
    )?;
    let actual = identity["https://api.openai.com/auth"]["chatgpt_account_id"]
        .as_str()
        .ok_or_else(|| fault("原生授权工作区缺失"))?;
    let selected = output["workspaceId"].as_str().filter(|s| !s.is_empty());
    if (event == "complete" && Some(actual) != original["accountId"].as_str())
        || selected.is_some_and(|s| s != actual)
        || Some(old_subject.as_str()) != identity["sub"].as_str()
    {
        return Err(fault(
            "原生保存的授权主体或工作区不一致，账号保持暂停，未退出设备",
        ));
    }
    let mut checked = output.clone();
    checked["event"] = json!(if event == "complete" {
        "same_workspace"
    } else {
        event
    });
    checked["workspaceId"] = json!(actual);
    checked["originalWorkspaceId"] = original["accountId"].clone();
    checked["tokens"] = tokens;
    let (identity, _) = recovery::validate(&checked, &original)?;
    let plan = identity["https://api.openai.com/auth"]["chatgpt_plan_type"]
        .as_str()
        .ok_or_else(|| fault("原生授权套餐缺失"))?
        .trim()
        .to_ascii_lowercase();
    if event != "complete" {
        let guard = detail(host, &job.account_id).await?;
        require_idle(&guard)?;
        if settings(&guard) != expected
            || guard["_credentialRevision"].as_u64() != Some(saved.credential_revision)
        {
            return Err(fault("工作区元数据写回前配置或凭据变化，账号保持暂停"));
        }
        // 原生已交换并保存 RT，此处仅修正工作区元数据，令牌材料逐字段保持原样
        let native_material = saved.facts.material.clone();
        saved.facts.upstream_account_id = Some(actual.to_owned());
        saved.facts.plan_type = Some(plan.clone());
        saved.facts.material.insert(
            "principal".into(),
            json!({"oauth_subject":identity["sub"],"poid":null}),
        );
        for key in ["access_token", "refresh_token", "id_token"] {
            if saved.facts.material.get(key) != native_material.get(key) {
                return Err(fault("工作区元数据变更不得替换原生令牌"));
            }
        }
        let request = AuthSaveRequest::Replace {
            account_id: job.account_id.clone(),
            credential_revision: saved.credential_revision,
            facts: saved.facts.clone(),
        };
        let reply = host
            .call(
                "host.auth.save",
                json!({}),
                serde_json::to_vec(&request).map_err(|_| fault("工作区元数据请求无效"))?,
            )
            .await
            .map_err(|_| fault("工作区元数据保存结果不确定，账号保持暂停"))?;
        let result: AuthSaveResult = serde_json::from_slice(&reply.payload)
            .map_err(|_| fault("工作区元数据保存结果未确认"))?;
        if result.account_id != job.account_id
            || result.credential_revision != saved.credential_revision + 1
        {
            return Err(fault("工作区元数据凭据版本未确认"));
        }
        saved.credential_revision = result.credential_revision;
        expected["accountId"] = json!(actual);
        expected["planType"] = json!(plan);
        let read = recovery::credential(host, &job.account_id).await?;
        if read.credential_revision != saved.credential_revision
            || serde_json::to_value(read.facts).map_err(|_| fault("元数据校验失败"))?
                != serde_json::to_value(&saved.facts).map_err(|_| fault("元数据校验失败"))?
        {
            return Err(fault("工作区元数据完整读回失败"));
        }
    }
    let verified = detail(host, &job.account_id).await?;
    require_idle(&verified)?;
    if settings(&verified) != expected
        || verified["_credentialRevision"].as_u64() != Some(saved.credential_revision)
    {
        return Err(fault("原生授权最终状态未确认，账号保持暂停"));
    }
    let resume = team || (!free && !forced && original["enabled"] == true);
    snapshot["postAuthorizationSettings"] = expected.clone();
    snapshot["resumeAfterCleanup"] = json!(resume);
    if !job.logout_others {
        restore(
            host,
            &job.account_id,
            &expected,
            saved.credential_revision,
            resume,
        )
        .await?;
    }
    let message = if team {
        "原生授权已切换到唯一 Team 工作区"
    } else if free {
        "原生授权已退回同一用户 Free，已停止调度"
    } else if forced {
        "管理员已确认，原生工作区授权已保存，已停止调度"
    } else {
        "RS 原生 OAuth 已换取、保存 RT，身份及配置已读回确认"
    };
    Ok((message.into(), free))
}

#[cfg(test)]
mod tests {
    use super::final_status_confirmed;
    use serde_json::json;

    #[test]
    fn final_status_accepts_stable_rs_account_states() {
        for status in ["normal", "disabled", "quota_exhausted", "rate_limited"] {
            assert!(final_status_confirmed(&json!(status)));
        }
    }

    #[test]
    fn final_status_rejects_unconfirmed_or_error_states() {
        for status in ["error", "unknown", ""] {
            assert!(!final_status_confirmed(&json!(status)));
        }
        assert!(!final_status_confirmed(&json!(null)));
    }
}
