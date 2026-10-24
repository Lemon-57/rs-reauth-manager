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

fn same_proxy(left: &str, right: &Value) -> bool {
    url::Url::parse(left)
        .ok()
        .zip(right.as_str().and_then(|value| url::Url::parse(value).ok()))
        .is_some_and(|(a, b)| a == b)
}

fn final_status_confirmed(status: &Value) -> bool {
    matches!(
        status.as_str(),
        Some("normal" | "disabled" | "quota_exhausted" | "rate_limited")
    )
}

// 接受原生保存所投影的已验证套餐/工作区，其他控制字段仍逐项一致
fn native_settings_match(actual: &Value, expected: &Value, workspace: &str, plan: &str) -> bool {
    let mut actual = settings(actual);
    for (key, verified) in [("accountId", workspace), ("planType", plan)] {
        if actual[key] != expected[key] && actual[key].as_str() != Some(verified) {
            return false;
        }
        actual[key] = expected[key].clone();
    }
    actual == *expected
}

// 仅在显式手动任务中补齐已保存 Team 凭据的元数据，不登录、不交换或恢复旧 RT
pub async fn reconcile_saved_team(host: &HostClient, job: &Job) -> Result<(), PluginFault> {
    if job.automatic {
        return Ok(());
    }
    let before = detail(host, &job.account_id).await?;
    require_idle(&before)?;
    let original = settings(&before);
    let mut saved = recovery::credential(host, &job.account_id).await?;
    let Ok(identity) = recovery::claims(
        recovery::tokens(&saved)["id_token"]
            .as_str()
            .unwrap_or_default(),
    ) else {
        return Ok(());
    };
    let auth = &identity["https://api.openai.com/auth"];
    let workspace = auth["chatgpt_account_id"].as_str().unwrap_or_default();
    let plan = auth["chatgpt_plan_type"].as_str().unwrap_or_default();
    if !matches!(plan, "team" | "business")
        || workspace.is_empty()
        || (original["accountId"] == workspace
            && original["planType"] == plan
            && saved.facts.upstream_account_id.as_deref() == Some(workspace)
            && saved.facts.plan_type.as_deref() == Some(plan))
    {
        return Ok(());
    }
    if before["enabled"] != false {
        return Err(fault("已保存 Team 工作区待核对，请先暂停账号"));
    }
    let subject = recovery::validate_binding(&recovery::tokens(&saved), &original)?;
    if saved
        .facts
        .material
        .get("principal")
        .and_then(|v| v["oauth_subject"].as_str())
        .is_some_and(|v| v != subject)
    {
        return Err(fault("已保存 Team 凭据主体不一致，未修正元数据"));
    }
    let mut target = original.clone();
    target["accountId"] = json!(workspace);
    target["planType"] = json!(plan);
    recovery::validate(
        &json!({"event":"same_workspace","workspaceId":workspace,"originalWorkspaceId":workspace,"tokens":recovery::tokens(&saved)}),
        &target,
    )?;
    let guard = detail(host, &job.account_id).await?;
    require_idle(&guard)?;
    if settings(&guard) != original
        || guard["_credentialRevision"].as_u64() != Some(saved.credential_revision)
    {
        return Err(fault("补齐 Team 元数据前配置或凭据变化，未写入"));
    }
    saved.facts.upstream_account_id = Some(workspace.to_owned());
    saved.facts.plan_type = Some(plan.to_owned());
    saved.facts.material.insert(
        "principal".into(),
        json!({"oauth_subject":subject,"poid":null}),
    );
    let request = AuthSaveRequest::Replace {
        account_id: job.account_id.clone(),
        credential_revision: saved.credential_revision,
        facts: saved.facts.clone(),
    };
    crate::executor::check(host).await?;
    let reply = host
        .call(
            "host.auth.save",
            json!({}),
            serde_json::to_vec(&request).map_err(|_| fault("Team 元数据请求无效"))?,
        )
        .await
        .map_err(|_| fault("Team 元数据保存未确认，请回读，未重放"))?;
    let result: AuthSaveResult =
        serde_json::from_slice(&reply.payload).map_err(|_| fault("Team 元数据回执未确认"))?;
    let read = recovery::credential(host, &job.account_id).await?;
    let after = detail(host, &job.account_id).await?;
    if result.account_id != job.account_id
        || result.credential_revision != saved.credential_revision + 1
        || read.credential_revision != result.credential_revision
        || settings(&after) != target
        || serde_json::to_value(read.facts).map_err(|_| fault("Team 元数据读回失败"))?
            != serde_json::to_value(saved.facts).map_err(|_| fault("Team 元数据读回失败"))?
    {
        return Err(fault("Team 元数据读回未确认，账号保持暂停"));
    }
    Ok(())
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
    let expected = crate::grouping::assign(host, id, expected, revision).await?;
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
    if snapshot["newAccount"] == true {
        return complete_new_account(host, snapshot, output).await;
    }
    let event = output["event"].as_str().unwrap_or_default();
    let forced = event == "forced_workspace";
    let free = matches!(event, "free_fallback" | "forced_free");
    let team = event == "team_upgrade";
    let recovered = event == "workspace_recovered";
    if !matches!(
        event,
        "complete"
            | "free_fallback"
            | "forced_free"
            | "forced_workspace"
            | "team_upgrade"
            | "workspace_recovered"
    ) || output.get("tokens").is_some()
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
        || (recovered
            && (snapshot["recoverWorkspace"] != true
                || !recovery::missing_workspace(&snapshot["settings"])
                || output["uniqueWorkspaceConfirmed"] != true
                || !matches!(output["selectedPlan"].as_str(), Some("free" | "team"))))
    {
        return Err(fault(
            "授权类型与原账号或管理员确认不一致，未提交原生完成接口",
        ));
    }
    let original = snapshot["settings"].clone();
    if ["email", "userId", "planType"]
        .iter()
        .any(|key| original[*key].as_str().is_none_or(|v| v.trim().is_empty()))
        || (!recovered
            && original["accountId"]
                .as_str()
                .is_none_or(|v| v.trim().is_empty()))
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
    let old = recovery::credential(host, &job.account_id).await?;
    if Some(old.credential_revision) != snapshot["credentialRevision"].as_u64()
        || old.facts.upstream_user_id.as_deref() != original["userId"].as_str()
    {
        return Err(fault("原账号身份或凭据版本未确认，未提交原生完成接口"));
    }
    let old_subject = if recovered {
        recovery::validate_existing_binding(&recovery::tokens(&old), &original)?
    } else if team {
        recovery::subject_for_team_upgrade(&old)?
    } else {
        recovery::subject(&old)?
    };
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
    if after["_credentialRevision"].as_u64() != Some(old.credential_revision + 1)
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
        return Err(fault("原生保存的授权主体或工作区不一致，账号保持暂停"));
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
    if !native_settings_match(&after, &expected, actual, &plan) {
        return Err(fault("原生保存后账号控制配置变化，账号保持暂停"));
    }
    if event != "complete" {
        let guard = detail(host, &job.account_id).await?;
        require_idle(&guard)?;
        if !native_settings_match(&guard, &expected, actual, &plan)
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
        crate::executor::check(host).await?;
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
    if event == "complete" {
        expected["accountId"] = json!(actual);
        expected["planType"] = json!(plan);
    }
    if settings(&verified) != expected
        || verified["_credentialRevision"].as_u64() != Some(saved.credential_revision)
    {
        return Err(fault("原生授权最终状态未确认，账号保持暂停"));
    }
    let expected =
        crate::grouping::assign(host, &job.account_id, &expected, saved.credential_revision)
            .await?;
    let recovered_team = recovered && crate::grouping::team(&expected);
    let free = free || (recovered && !recovered_team);
    let resume = (team || recovered_team || (!free && !forced && original["enabled"] == true))
        && !(job.automatic && original["enabled"] == false);
    snapshot["postAuthorizationSettings"] = expected.clone();
    snapshot["resumeEnabled"] = json!(resume);
    snapshot["authorizedCredentialRevision"] = json!(saved.credential_revision);
    let message = if recovered_team {
        "RS 原生 OAuth 已补齐并验证唯一 Team 工作区"
    } else if team {
        "原生授权已切换到唯一 Team 工作区"
    } else if free {
        "原生授权已退回同一用户 Free，已停止调度"
    } else if forced {
        "管理员已确认，原生工作区授权已保存，已停止调度"
    } else {
        "RS 原生 OAuth 已换取、保存 RT，身份及配置已读回确认"
    };
    let message = if crate::grouping::team(&expected) {
        format!("{message}；已移入 GPT Pro 分组")
    } else if expected["planType"]
        .as_str()
        .is_some_and(|p| p.trim().eq_ignore_ascii_case("free"))
        && original["groups"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|g| g["name"] == "GPT Pro"))
    {
        format!("{message}；已移入 Free Wait 分组")
    } else {
        message.into()
    };
    Ok((message, free))
}

async fn complete_new_account(
    host: &HostClient,
    snapshot: &mut Value,
    output: &Value,
) -> Result<(String, bool), PluginFault> {
    if output["event"] != "complete" || output.get("tokens").is_some() {
        return Err(fault("新增账号必须取得 RS 原生授权回调，未提交完成接口"));
    }
    let callback = output["callbackUrl"]
        .as_str()
        .ok_or_else(|| fault("新增账号授权码回调缺失，未提交原生完成接口"))?;
    let flow = snapshot["flowId"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| fault("新增账号 OAuth flow 缺失"))?;
    let settings = snapshot["settings"].clone();
    let body =
        json!({"provider":"openai","flowId":flow,"callbackUrl":callback,"settings":settings});
    let done = if snapshot["protectedTransport"].is_object() {
        crate::onboarding::request(
            host,
            &snapshot["protectedTransport"],
            "/api/admin/accounts/oauth/complete",
            body,
        )
        .await?
    } else {
        admin(
            host,
            "POST",
            "/api/admin/accounts/oauth/complete",
            Some(body),
        )
        .await?
    };
    let id = done["accountId"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| fault("RS 新增 OAuth 未返回账号 ID"))?;
    let account = detail(host, id).await?;
    if account["provider"] != "openai"
        || account["authenticationKind"] != "oauth"
        || account["enabled"] != false
        || account["email"].as_str().is_none_or(|email| {
            !email.eq_ignore_ascii_case(snapshot["email"].as_str().unwrap_or_default())
        })
        || account["planType"].as_str().is_none_or(|plan| {
            !(matches!(
                plan.trim().to_ascii_lowercase().as_str(),
                "team" | "business"
            ) || (snapshot["allowFreeNew"] == true && plan.trim().eq_ignore_ascii_case("free")))
        })
        || require_idle(&account).is_err()
    {
        return Err(fault("新增账号身份、套餐或停用状态读回不一致"));
    }
    let expected_groups = settings["groupIds"].as_array().cloned().unwrap_or_default();
    let actual_groups = account["groups"]
        .as_array()
        .ok_or_else(|| fault("新增账号分组读回格式无效"))?;
    let mut actual_ids = actual_groups
        .iter()
        .filter_map(|group| group["id"].as_str())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut expected_ids = expected_groups
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    actual_ids.sort_unstable();
    expected_ids.sort_unstable();
    if actual_ids != expected_ids || account["notes"] != settings["notes"] {
        return Err(fault("新增账号分组或三字段备注读回不一致"));
    }
    let credential = recovery::credential(host, id).await?;
    let tokens = recovery::tokens(&credential);
    let check = json!({"event":"same_workspace","workspaceId":account["accountId"],
        "originalWorkspaceId":account["accountId"],"tokens":tokens});
    recovery::validate(&check, &crate::settings(&account))?;
    if credential.credential_revision != account["_credentialRevision"].as_u64().unwrap_or(0)
        || output["workspaceId"] != account["accountId"]
        || !same_proxy(&crate::proxy(host, &account).await?, &snapshot["proxy"])
    {
        return Err(fault("新增账号凭据版本、所选工作区或固定代理不一致"));
    }
    snapshot["createdAccountId"] = json!(id);
    let verified_settings = crate::grouping::assign(
        host,
        id,
        &crate::settings(&account),
        credential.credential_revision,
    )
    .await?;
    snapshot["postAuthorizationSettings"] = verified_settings;
    let team = account["planType"]
        .as_str()
        .is_some_and(|p| matches!(p.to_ascii_lowercase().as_str(), "team" | "business"));
    snapshot["resumeEnabled"] = json!(team);
    snapshot["authorizedCredentialRevision"] = json!(credential.credential_revision);
    Ok((
        if team {
            "RS 原生 OAuth 已创建并保存 Team RT，备注与分组已读回确认".into()
        } else {
            "RS 原生 OAuth 已保存 Free RT，未发现唯一 Team 成员资格，账号保持暂停".into()
        },
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::final_status_confirmed;
    use serde_json::json;

    #[test]
    fn proxy_normalization_preserves_authentication_and_fixed_endpoint() {
        assert!(super::same_proxy(
            "http://fixture:pass@127.0.0.1:21001/",
            &json!("http://fixture:pass@127.0.0.1:21001")
        ));
        assert!(!super::same_proxy(
            "http://fixture:other@127.0.0.1:21001/",
            &json!("http://fixture:pass@127.0.0.1:21001")
        ));
        assert!(!super::same_proxy(
            "http://fixture:pass@127.0.0.1:21002/",
            &json!("http://fixture:pass@127.0.0.1:21001")
        ));
    }

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
