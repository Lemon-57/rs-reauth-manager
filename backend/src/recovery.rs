//! 只读核验 RS 已保存的授权身份与工作区，不交换或保存 RT
use crate::host::{fault, now};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use gateway_plugin_sdk::{PluginFault, call::host::AuthCredential, client::HostClient};
use serde_json::{Value, json};

const AUTH: &str = "https://api.openai.com/auth";
const IDENTITY_ERROR: &str = "授权身份、工作区、套餐或令牌有效期未确认，请核对已保存结果";

pub(crate) fn missing_workspace(original: &Value) -> bool {
    original["planType"]
        .as_str()
        .is_some_and(|p| p.eq_ignore_ascii_case("free"))
        && original["accountId"]
            .as_str()
            .is_none_or(|w| w.trim().is_empty())
}

// 旧 RT 可以没有 ChatGPT 工作区声明；仅用于绑定已有用户，不能据此启用或归组
pub(crate) fn validate_binding(tokens: &Value, original: &Value) -> Result<String, PluginFault> {
    validate_binding_with_expiry(tokens, original, true)
}

// Existing saved credentials establish historical identity only. Fresh OAuth results
// and supplied RT imports still require live tokens through validate_binding/validate.
pub(crate) fn validate_existing_binding(
    tokens: &Value,
    original: &Value,
) -> Result<String, PluginFault> {
    validate_binding_with_expiry(tokens, original, false)
}

fn validate_binding_with_expiry(
    tokens: &Value,
    original: &Value,
    require_fresh: bool,
) -> Result<String, PluginFault> {
    text(tokens, "refresh_token")?;
    let identity = decode_claims(text(tokens, "id_token")?, require_fresh)?;
    let access = decode_claims(text(tokens, "access_token")?, require_fresh)?;
    let email = identity["email"]
        .as_str()
        .or_else(|| identity["https://api.openai.com/profile"]["email"].as_str());
    if !email
        .is_some_and(|e| e.eq_ignore_ascii_case(original["email"].as_str().unwrap_or_default()))
    {
        return Err(fault("已保存 RT 的邮箱身份未确认，账号保持暂停"));
    }
    let user = text(original, "userId")?;
    for c in [&identity, &access] {
        if c[AUTH]["chatgpt_user_id"]
            .as_str()
            .or_else(|| c[AUTH]["user_id"].as_str())
            != Some(user)
        {
            return Err(fault("已保存 RT 的用户身份不一致，账号保持暂停"));
        }
    }
    let subject = text(&identity, "sub")?;
    if access["sub"].as_str() != Some(subject) {
        return Err(fault("已保存 RT 的双令牌主体不一致，账号保持暂停"));
    }
    Ok(subject.to_owned())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, PluginFault> {
    value[key]
        .as_str()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 32768
                && !s.chars().any(|c| c.is_control() || c.is_whitespace())
        })
        .ok_or_else(|| fault(IDENTITY_ERROR))
}

pub(crate) fn claims(token: &str) -> Result<Value, PluginFault> {
    decode_claims(token, true)
}

fn decode_claims(token: &str, require_fresh: bool) -> Result<Value, PluginFault> {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(fault(IDENTITY_ERROR));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| fault(IDENTITY_ERROR))?;
    let claims: Value = serde_json::from_slice(&bytes).map_err(|_| fault(IDENTITY_ERROR))?;
    // 私有 TLS 交换结果的字段投影，不宣称为 JWT 签名校验
    let expires = claims["exp"]
        .as_u64()
        .filter(|exp| {
            *exp > 0 && *exp < 253402300799 && (!require_fresh || *exp > now() / 1000 + 30)
        })
        .ok_or_else(|| fault(IDENTITY_ERROR))?;
    if !claims.is_object() || expires.checked_mul(1000).is_none() {
        return Err(fault(IDENTITY_ERROR));
    }
    Ok(claims)
}

pub(crate) fn validate(output: &Value, original: &Value) -> Result<(Value, Value), PluginFault> {
    let workspace = text(output, "workspaceId")?;
    let user = text(original, "userId")?;
    let email = text(original, "email")?;
    let same = output["event"] == "same_workspace";
    let forced = output["event"] == "forced_workspace" && output["administratorConfirmed"] == true;
    let forced_free = output["event"] == "forced_free" && output["administratorConfirmed"] == true;
    let upgraded = output["event"] == "team_upgrade"
        && output["uniqueTeamConfirmed"] == true
        && original["planType"]
            .as_str()
            .is_some_and(|p| p.trim().eq_ignore_ascii_case("free"));
    let recovered = output["event"] == "workspace_recovered"
        && missing_workspace(original)
        && output["uniqueWorkspaceConfirmed"] == true
        && matches!(output["selectedPlan"].as_str(), Some("free" | "team"));
    if (!same
        && !forced
        && !forced_free
        && !upgraded
        && !recovered
        && (output["event"] != "free_fallback" || output["originalWorkspaceUnavailable"] != true))
        || output["originalWorkspaceId"] != original["accountId"]
        || (same && workspace != text(original, "accountId")?)
        || (!same
            && !recovered
            && workspace == text(original, "accountId")?
            && !upgraded
            && !(forced_free
                && original["planType"]
                    .as_str()
                    .is_some_and(|p| p.trim().eq_ignore_ascii_case("free"))))
    {
        return Err(fault(IDENTITY_ERROR));
    }
    text(&output["tokens"], "refresh_token")?;
    let identity = claims(text(&output["tokens"], "id_token")?)?;
    let access = claims(text(&output["tokens"], "access_token")?)?;
    text(&identity, "sub")?;
    let token_email = identity["email"]
        .as_str()
        .or_else(|| identity["https://api.openai.com/profile"]["email"].as_str())
        .ok_or_else(|| fault(IDENTITY_ERROR))?;
    if !token_email.eq_ignore_ascii_case(email) {
        return Err(fault(IDENTITY_ERROR));
    }
    for token in [&identity, &access] {
        let auth = &token[AUTH];
        if auth["chatgpt_account_id"] != workspace
            || auth["chatgpt_user_id"]
                .as_str()
                .or_else(|| auth["user_id"].as_str())
                != Some(user)
            || !auth["chatgpt_plan_type"].as_str().is_some_and(|p| {
                !p.trim().is_empty()
                    && ((same
                        && original["planType"]
                            .as_str()
                            .is_some_and(|old| p.trim().eq_ignore_ascii_case(old.trim())))
                        || (!same
                            && (forced
                                || (upgraded
                                    && matches!(
                                        p.to_ascii_lowercase().as_str(),
                                        "team" | "business"
                                    ))
                                || (recovered
                                    && if output["selectedPlan"] == "team" {
                                        matches!(
                                            p.to_ascii_lowercase().as_str(),
                                            "team" | "business"
                                        )
                                    } else {
                                        p.eq_ignore_ascii_case("free")
                                    })
                                || (!upgraded && !recovered && p.eq_ignore_ascii_case("free")))))
            })
        {
            return Err(fault(IDENTITY_ERROR));
        }
    }
    if identity["sub"] != access["sub"]
        || identity[AUTH]["chatgpt_plan_type"] != access[AUTH]["chatgpt_plan_type"]
    {
        return Err(fault(IDENTITY_ERROR));
    }
    Ok((identity, access))
}

pub async fn credential(host: &HostClient, id: &str) -> Result<AuthCredential, PluginFault> {
    let reply = host
        .call(
            "host.auth.get",
            json!({}),
            serde_json::to_vec(&json!({"account_id":id})).map_err(|_| fault("凭据请求无效"))?,
        )
        .await
        .map_err(|_| fault("RS 已保存凭据读取失败"))?;
    let value: AuthCredential =
        serde_json::from_slice(&reply.payload).map_err(|_| fault("RS 已保存凭据格式无效"))?;
    if value.account_id != id || value.provider_id != "openai" {
        return Err(fault("RS 已保存凭据账号不一致"));
    }
    Ok(value)
}

pub fn tokens(credential: &AuthCredential) -> Value {
    json!({"access_token":credential.facts.material.get("access_token"),"refresh_token":credential.facts.material.get("refresh_token"),"id_token":credential.facts.material.get("id_token")})
}

pub fn subject(credential: &AuthCredential) -> Result<String, PluginFault> {
    subject_with_workspace_check(credential, true)
}

pub fn subject_for_team_upgrade(credential: &AuthCredential) -> Result<String, PluginFault> {
    subject_with_workspace_check(credential, false)
}

fn subject_with_workspace_check(
    credential: &AuthCredential,
    check_workspace: bool,
) -> Result<String, PluginFault> {
    if let Some(subject) = credential
        .facts
        .material
        .get("principal")
        .and_then(|p| p["oauth_subject"].as_str())
        .filter(|s| !s.is_empty())
    {
        return Ok(subject.into());
    }
    // 旧存量凭据的过期 JWT 仅用于重建原绑定，不作为可用授权，也不跳过新令牌核验
    let mut subjects = Vec::new();
    for key in ["id_token", "access_token"] {
        let token = credential
            .facts
            .material
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 32768)
            .ok_or_else(|| fault("原账号主体无法从已保存凭据确认"))?;
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(fault("原账号主体无法从已保存凭据确认"));
        }
        let raw = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| fault("原账号主体参考格式无效"))?;
        let value: Value =
            serde_json::from_slice(&raw).map_err(|_| fault("原账号主体参考格式无效"))?;
        let auth = &value[AUTH];
        if auth["chatgpt_user_id"]
            .as_str()
            .or_else(|| auth["user_id"].as_str())
            != credential.facts.upstream_user_id.as_deref()
            || (check_workspace
                && auth["chatgpt_account_id"].as_str()
                    != credential.facts.upstream_account_id.as_deref())
        {
            return Err(fault("原账号已存主体与用户或工作区不一致"));
        }
        if key == "id_token" {
            let email = value["email"]
                .as_str()
                .or_else(|| value["https://api.openai.com/profile"]["email"].as_str());
            if !email
                .zip(credential.facts.email.as_deref())
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                return Err(fault("原账号已存主体邮箱不一致"));
            }
        }
        let sub = value["sub"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_whitespace))
            .ok_or_else(|| fault("原账号主体参考缺失"))?;
        subjects.push(sub.to_owned());
    }
    if subjects[0] != subjects[1] {
        return Err(fault("原账号 ID 与访问令牌主体不一致"));
    }
    Ok(subjects.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expired_token(user: &str, subject: &str, email: &str) -> String {
        let value = json!({"email":email,"sub":subject,"exp":1,AUTH:{"user_id":user}});
        format!(
            "fixture.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
        )
    }
    #[test]
    fn expired_saved_credentials_bind_identity_but_cannot_authorize_or_import() {
        let original = json!({"email":"fixture@example.com","userId":"user","planType":"free","accountId":null});
        let old = expired_token("user", "subject", "fixture@example.com");
        let tokens = json!({"id_token":old,"access_token":old,"refresh_token":"fixture-rt"});
        assert_eq!(
            validate_existing_binding(&tokens, &original).unwrap(),
            "subject"
        );
        assert!(validate_binding(&tokens, &original).is_err());
        assert!(claims(&old).is_err());
        assert!(validate(&json!({"event":"workspace_recovered","workspaceId":"workspace","originalWorkspaceId":null,"uniqueWorkspaceConfirmed":true,"selectedPlan":"free","tokens":tokens}), &original).is_err());
        for (user, subject, email) in [
            ("other", "subject", "fixture@example.com"),
            ("user", "other", "fixture@example.com"),
            ("user", "subject", "other@example.com"),
        ] {
            let mut wrong = tokens.clone();
            let key = if email == "other@example.com" {
                "id_token"
            } else {
                "access_token"
            };
            wrong[key] = json!(expired_token(user, subject, email));
            assert!(validate_existing_binding(&wrong, &original).is_err());
        }
        for invalid in ["not-a-token", "fixture.e30.signature"] {
            let mut wrong = tokens.clone();
            wrong["access_token"] = json!(invalid);
            assert!(validate_existing_binding(&wrong, &original).is_err());
        }
    }
    fn token(user: &str, subject: &str) -> String {
        let value = json!({"email":"fixture@example.com","sub":subject,"exp":now()/1000+3600,AUTH:{"user_id":user}});
        format!(
            "fixture.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
        )
    }
    #[test]
    fn unbound_rt_proves_user_only_and_cannot_pass_workspace_validation() {
        let original = json!({"email":"fixture@example.com","userId":"user","planType":"free","accountId":null});
        let tokens = json!({"id_token":token("user","subject"),"access_token":token("user","subject"),"refresh_token":"fixture-rt"});
        assert!(missing_workspace(&original));
        assert_eq!(validate_binding(&tokens, &original).unwrap(), "subject");
        assert!(validate(&json!({"event":"same_workspace","workspaceId":null,"originalWorkspaceId":null,"tokens":tokens}),&original).is_err());
        for (user, sub) in [("wrong-user", "subject"), ("user", "wrong-subject")] {
            let mut changed = tokens.clone();
            changed["access_token"] = json!(token(user, sub));
            assert!(validate_binding(&changed, &original).is_err());
        }
    }
}
