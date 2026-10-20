//! 将协议诊断白名单投影为可公开的中文错误，不透传上游正文
use serde_json::Value;

pub fn message(output: &Value, fallback: &str) -> String {
    let Some(diagnostic) = output.get("diagnostic").filter(|d| d.is_object()) else {
        return fallback.into();
    };
    render(diagnostic, true)
}

fn render(diagnostic: &Value, include_previous: bool) -> String {
    let local_generation = matches!(
        diagnostic["reason"].as_str(),
        Some(
            "mfa_code_unavailable"
                | "mfa_new_code_timeout"
                | "mfa_code_invalid_format"
                | "mfa_generation_failed"
        )
    );
    let stage_key = if local_generation {
        "mfa_generate"
    } else {
        diagnostic["stage"].as_str().unwrap_or_default()
    };
    let stage = match stage_key {
        "authorize" => "获取授权页面",
        "authorize_follow" => "跟随授权页面跳转",
        "account_request" => "调用上游账号接口",
        "login_page" => "打开登录页面",
        "password_page" => "打开密码验证页面",
        "security_token" => "获取登录安全校验令牌",
        "account_selection" => "选择登录账号",
        "profile" => "补充账号资料",
        "phone_send" => "发送手机验证码",
        "phone_verify" => "提交手机验证码",
        "session" => "初始化登录会话",
        "session_lookup" => "读取登录会话及工作区",
        "other_sessions" => "登出其他设备",
        "login" => "提交登录身份",
        "password" => "密码验证",
        "mfa_factor" => "识别 2FA 验证器",
        "mfa_issue" => "创建 2FA 验证挑战",
        "mfa_verify" => "提交 2FA 动态码",
        "mfa_generate" => "本地生成 2FA 动态码",
        "email_send" => "发送邮箱验证码",
        "email_verify" => "邮箱验证码验证",
        "phone" => "手机验证",
        "workspace" => "选择工作区",
        "organization" => "选择组织",
        "consent" => "授权确认",
        "callback" => "校验授权回调",
        "token_exchange" => "交换授权令牌",
        "identity" => "校验授权身份",
        "account" => "检查账号状态",
        "billing" => "检查付款状态",
        _ => "登录协议",
    };
    let reason = match diagnostic["reason"].as_str().unwrap_or_default() {
        "sessions_current_unconfirmed" => "无法唯一确认本次设备，已停止，不使用全部登出",
        "sessions_response_invalid" | "sessions_incomplete" => "设备目录格式异常或不完整，已停止",
        "sessions_request_rejected" => "上游拒绝读取设备目录，已停止",
        "sessions_revoke_unconfirmed" => "其他设备退出结果未确认，可能只完成部分退出",
        "sessions_changed" => "本次会话或设备目录发生变化，已停止",
        "sessions_refresh_unconfirmed" => "本次 RT 刷新未确认",
        "sessions_identity_changed" => "授权身份、工作区或套餐发生变化，未写回",
        "sessions_transport_unconfirmed" => "设备退出或 RT 验证发生传输异常，未自动重放",
        "sessions_proxy_invalid" => "原代理不可用，未回退直连",
        "password_rejected" => "上游拒绝邮箱或密码",
        "account_banned" => "账号已被封禁或停用，上游拒绝继续登录",
        "payment_required" => "上游返回 Payment Required，账号需要付款或订阅状态异常",
        "mfa_secret_missing" => "未提供 2FA 密钥",
        "mfa_factor_missing" => "未找到可用的 TOTP 验证器，不能据此判断密钥错误",
        "mfa_provider_invalid" => "2FA 动态码生成器不可用",
        "mfa_code_unavailable" => "等待可用动态码超时，本轮未向上游提交",
        "mfa_new_code_timeout" => "等待下一轮未使用的动态码超时，本轮未再次提交",
        "mfa_code_invalid_format" => "生成器未返回六位数字，本轮未向上游提交",
        "mfa_generation_failed" => "动态码生成器异常，本轮未向上游提交",
        "mfa_code_invalid" => "上游明确返回动态码无效",
        "mfa_code_expired" => "上游明确返回动态码已过期",
        "mfa_challenge_invalid" => {
            "上游明确返回 2FA 验证挑战状态无效，不等同于密钥错误；已停止沿用该挑战重试，请重新发起授权"
        }
        "login_state_invalid" => "上游明确返回登录步骤状态无效，不能沿用旧登录会话",
        "mfa_conflict" => {
            "动态码已生成并提交，上游返回验证冲突，未明确说明验证码是否错误；未自动重试"
        }
        "mfa_issue_failed" => "上游未成功创建 2FA 验证挑战，并非已确认验证码错误",
        "mfa_code_rejected" => "上游拒绝 2FA 动态码，可能已失效、被使用或与验证器不匹配",
        "mfa_verification_failed" => "2FA 验证流程未完成，未取得明确的验证码拒绝原因",
        "primary_factor_required" => "上游要求先完成密码或邮箱验证，不能只使用 2FA",
        "email_code_required" => "上游要求邮箱验证码，当前任务不支持人工补码续跑",
        "email_send_failed" => "上游未能发送邮箱验证码",
        "email_code_rejected" => "上游拒绝邮箱验证码",
        "email_verification_failed" => "邮箱验证流程未完成",
        "phone_required" => "上游要求手机验证，需要人工完成",
        "phone_verification_failed" => "手机验证未完成，需要人工检查验证状态",
        "profile_required" => "上游要求补充账号资料",
        "security_challenge" => "上游要求浏览器安全验证，需要人工完成",
        "rate_limited" => "上游限制登录频率，不自动重试",
        "request_timeout" => "请求超时，保留原代理，不自动重试",
        "dns_failed" => "域名或代理地址解析失败",
        "tls_failed" => "TLS 连接或证书校验失败",
        "connection_failed" => "连接中断或代理连接失败",
        "transport_failed" => "请求传输异常，未保存原始异常内容",
        "protocol_processing_failed" => "读取或处理该步骤的协议数据时发生内部异常",
        "response_invalid_json" => "该步骤的响应不是有效 JSON，无法继续解析",
        "response_invalid_shape" => "该步骤的 JSON 响应结构不符合协议要求",
        "upstream_unavailable" => "上游服务暂不可用",
        "http_rejected" => "上游拒绝请求，未取得可公开的具体原因",
        "account_selection_failed" => "上游账号选择未完成",
        "callback_missing" => "未取得有效授权回调",
        "callback_hops_exhausted" => "授权跳转达到上限，未取得回调",
        "login_continue_failed" => "上游登录步骤未返回可继续的授权地址",
        "token_exchange_failed" => "授权码换取令牌未成功，未写回",
        "token_redirect_rejected" => {
            "令牌交换接口返回重定向，已拒绝跟随，不向其他地址转发授权码或 PKCE verifier"
        }
        "state_mismatch" => "授权回调 state 校验未通过，未写回",
        "workspace_unmatched" => "无法匹配原账号工作区，已停止写回",
        "workspace_evidence_invalid" => {
            "授权页的工作区数据格式无效、相互冲突或超出数量限制，未自动选择或写回"
        }
        "workspace_selection_failed" => "上游未接受工作区或组织选择，未继续授权或写回",
        "free_workspace_missing" => "授权页面未提供可安全选择的个人 Free 候选工作区，未写回",
        "free_workspace_ambiguous" => {
            "授权页面存在多个候选工作区，无法唯一确定个人 Free 工作区，未自动选择或写回"
        }
        "identity_unconfirmed" => "新授权的同一用户或 Free 工作区校验未通过，未写回",
        _ => "未取得可公开的具体错误，未保存上游原始响应",
    };
    let mut message = format!("{stage}：{reason}");
    if let Some(status) = diagnostic["httpStatus"]
        .as_u64()
        .filter(|v| !local_generation && (100..=599).contains(v))
    {
        message.push_str(&format!("（HTTP {status}）"));
    }
    if let Some(code) = diagnostic["upstreamCode"].as_str().filter(|code| {
        matches!(
            *code,
            "invalid_otp"
                | "invalid_totp"
                | "invalid_code"
                | "invalid_verification_code"
                | "totp_invalid"
                | "otp_expired"
                | "invalid_state"
        )
    }) {
        message.push_str(&format!(" [上游错误码 {code}]"));
    }
    if include_previous
        && local_generation
        && let Some(previous) = diagnostic
            .get("previousVerification")
            .filter(|d| d.is_object() && d["stage"] == "mfa_verify")
    {
        message.push_str(&format!("；此前验证结果：{}", render(previous, false)));
    }
    if include_previous && diagnostic["sessionRestarts"].as_u64() == Some(1) {
        if let Some(previous) = diagnostic.get("previousLogin").filter(|d| d.is_object()) {
            message.push_str(&format!("；首次登录失败：{}", render(previous, false)));
        }
        message.push_str("；已重建一次登录会话，本次仍失败，不再自动重登");
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn renders_only_known_diagnostic_fields() {
        let rendered = message(
            &json!({"diagnostic":{"stage":"mfa_issue","reason":"mfa_issue_failed","httpStatus":403,"raw":"private-body"}}),
            "fallback",
        );
        assert!(rendered.contains("创建 2FA 验证挑战"));
        assert!(rendered.contains("HTTP 403"));
        assert!(!rendered.contains("private-body"));
        assert_eq!(message(&json!({}), "legacy"), "legacy");
    }

    #[test]
    fn untrusted_details_cannot_reach_job_history() {
        let rendered = message(
            &json!({"diagnostic":{"stage":"private-url","reason":"private-secret","httpStatus":"private-header"}}),
            "fallback",
        );
        assert!(!rendered.contains("private-"));
        assert!(!rendered.contains("HTTP"));
        assert!(
            !message(&json!({"diagnostic":{"httpStatus":999999}}), "fallback").contains("HTTP")
        );
    }

    #[test]
    fn separates_local_generation_from_previous_upstream_rejection() {
        let rendered = message(
            &json!({"diagnostic":{
                "stage":"mfa_generate","reason":"mfa_new_code_timeout","httpStatus":null,
                "previousVerification":{"stage":"mfa_verify","reason":"mfa_conflict","httpStatus":409}
            }}),
            "fallback",
        );
        let (local, previous) = rendered.split_once('；').unwrap();
        assert!(local.contains("本轮未再次提交"));
        assert!(!local.contains("HTTP"));
        assert!(previous.contains("动态码已生成并提交"));
        assert!(previous.contains("HTTP 409"));
        assert!(previous.contains("未明确说明验证码是否错误"));
        let legacy = message(
            &json!({"diagnostic":{"stage":"mfa_verify","reason":"mfa_code_unavailable","httpStatus":409}}),
            "fallback",
        );
        assert!(legacy.starts_with("本地生成"));
        assert!(!legacy.contains("HTTP"));
    }

    #[test]
    fn preserves_known_machine_codes_without_exposing_arbitrary_details() {
        let rendered = message(
            &json!({"diagnostic":{
                "stage":"mfa_generate","reason":"mfa_new_code_timeout",
                "previousVerification":{"stage":"mfa_verify","reason":"mfa_code_expired","httpStatus":409,"upstreamCode":"otp_expired","raw":"private-secret",
                    "previousVerification":{"stage":"private-secret"}}
            }}),
            "fallback",
        );
        assert!(rendered.contains("动态码已过期"));
        assert!(rendered.contains("otp_expired"));
        assert!(!rendered.contains("private-secret"));
        let unknown = message(
            &json!({"diagnostic":{"stage":"mfa_verify","reason":"mfa_conflict","httpStatus":409,"upstreamCode":"private-secret"}}),
            "fallback",
        );
        assert!(!unknown.contains("private-secret"));
    }

    #[test]
    fn lookup_and_redirect_errors_do_not_claim_no_free_account() {
        let lookup = message(
            &json!({"diagnostic":{"stage":"session_lookup","reason":"http_rejected","httpStatus":403}}),
            "fallback",
        );
        assert!(lookup.starts_with("读取登录会话及工作区"));
        assert!(lookup.contains("HTTP 403"));
        assert!(!lookup.contains("Free"));
        let redirect = message(
            &json!({"diagnostic":{"stage":"token_exchange","reason":"token_redirect_rejected","httpStatus":307,"location":"private-url"}}),
            "fallback",
        );
        assert!(redirect.contains("已拒绝跟随"));
        assert!(redirect.contains("HTTP 307"));
        assert!(!redirect.contains("private-url"));
    }

    #[test]
    fn restarted_login_renders_both_safe_causes_without_repeating_recovery() {
        let rendered = message(
            &json!({"diagnostic":{
                "stage":"mfa_verify","reason":"rate_limited","httpStatus":429,"sessionRestarts":1,
                "previousLogin":{"stage":"mfa_verify","reason":"mfa_challenge_invalid","httpStatus":409,"upstreamCode":"invalid_state","raw":"private-cookie",
                    "previousLogin":{"raw":"private-secret"},"sessionRestarts":1}
            }}),
            "fallback",
        );
        assert!(rendered.contains("HTTP 429"));
        assert!(rendered.contains("HTTP 409"));
        assert!(rendered.contains("首次登录失败"));
        assert_eq!(rendered.matches("已重建一次登录会话").count(), 1);
        assert!(rendered.contains("不再自动重登"));
        assert!(!rendered.contains("private-"));
        let untrusted = message(
            &json!({"diagnostic":{"sessionRestarts":999,"previousLogin":{"raw":"private-cookie"}}}),
            "fallback",
        );
        assert!(!untrusted.contains("已重建"));
        assert!(!untrusted.contains("private-"));
    }

    #[test]
    fn invalid_challenge_explains_retry_stopped_not_generation_timeout() {
        let rendered = message(
            &json!({"diagnostic":{"stage":"mfa_verify","reason":"mfa_challenge_invalid","httpStatus":409,"upstreamCode":"invalid_state"}}),
            "fallback",
        );
        assert!(rendered.starts_with("提交 2FA 动态码"));
        assert!(rendered.contains("已停止沿用该挑战重试"));
        assert!(rendered.contains("不等同于密钥错误"));
        assert!(rendered.contains("HTTP 409"));
        assert!(rendered.contains("invalid_state"));
        assert!(!rendered.contains("等待下一轮"));
        assert!(!rendered.contains("本地生成"));
    }

    #[test]
    fn distinguishes_missing_and_ambiguous_free_candidates() {
        for (reason, expected) in [
            ("free_workspace_missing", "未提供可安全选择"),
            ("free_workspace_ambiguous", "存在多个候选"),
        ] {
            let rendered = message(
                &json!({"diagnostic":{"stage":"workspace","reason":reason,"httpStatus":200,"raw":"private-cookie"}}),
                "fallback",
            );
            assert!(rendered.starts_with("选择工作区"));
            assert!(rendered.contains(expected));
            assert!(rendered.contains("未写回") || rendered.contains("未自动选择或写回"));
            assert!(rendered.contains("HTTP 200"));
            assert!(!rendered.contains("private-cookie"));
            assert!(!rendered.contains("2FA"));
        }
    }

    #[test]
    fn reports_direct_request_stages_and_parse_errors_without_blames() {
        let parse = message(
            &json!({"diagnostic":{"stage":"token_exchange","reason":"response_invalid_json","httpStatus":200}}),
            "fallback",
        );
        assert!(parse.starts_with("交换授权令牌"));
        assert!(parse.contains("不是有效 JSON"));
        assert!(!parse.contains("代理"));
        let security = message(
            &json!({"diagnostic":{"stage":"security_token","reason":"http_rejected","httpStatus":403}}),
            "fallback",
        );
        assert!(security.starts_with("获取登录安全校验令牌"));
        assert!(security.contains("HTTP 403"));
        let processing = message(
            &json!({"diagnostic":{"stage":"password_page","reason":"protocol_processing_failed","httpStatus":200}}),
            "fallback",
        );
        assert!(processing.starts_with("打开密码验证页面"));
        assert!(processing.contains("内部异常"));
        assert!(!processing.contains("代理"));
    }
}
