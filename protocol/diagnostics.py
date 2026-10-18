"""Project protocol failures into fixed public enums, never raw upstream material."""
import re
from urllib.parse import urlsplit

STAGES = {
    '/oauth/authorize': 'authorize',
    '/api/accounts/authorize/continue': 'login',
    '/api/accounts/password/verify': 'password',
    '/api/accounts/mfa/issue_challenge': 'mfa_issue',
    '/api/accounts/mfa/verify': 'mfa_verify',
    '/api/accounts/email-otp/validate': 'email_verify',
    '/api/accounts/email-otp/send': 'email_send',
    '/api/accounts/passwordless/send-otp': 'email_send',
    '/api/accounts/workspace/select': 'workspace',
    '/api/accounts/organization/select': 'organization',
    '/oauth/token': 'token_exchange',
    '/log-in/password': 'password_page',
    '/log-in': 'login_page',
    '/choose-an-account': 'account_selection',
    '/about-you': 'profile',
    '/api/accounts/create_account': 'profile',
    '/api/accounts/add-phone/send': 'phone_send',
    '/api/accounts/phone-otp/validate': 'phone_verify',
}
REASONS = {
    'account_banned': ('account', 'account_banned'),
    'account_blocked': ('account', 'account_banned'),
    'account_deactivated': ('account', 'account_banned'),
    'account_disabled': ('account', 'account_banned'),
    'account_suspended': ('account', 'account_banned'),
    'access_terminated': ('account', 'account_banned'),
    'user_deactivated': ('account', 'account_banned'),
    'user_suspended': ('account', 'account_banned'),
    'payment_required': ('billing', 'payment_required'),
    'payment required': ('billing', 'payment_required'),
    'invalid_username_or_password': ('password', 'password_rejected'),
    'mfa_totp_secret_required': ('mfa', 'mfa_secret_missing'),
    'mfa_totp_factor_not_available': ('mfa', 'mfa_factor_missing'),
    'mfa_totp_provider_invalid': ('mfa', 'mfa_provider_invalid'),
    'mfa_totp_code_unavailable': ('mfa', 'mfa_code_unavailable'),
    'mfa_totp_verification_failed': ('mfa', 'mfa_verification_failed'),
    'mfa_primary_factor_required': ('human', 'primary_factor_required'),
    'phone_required': ('human', 'phone_required'),
    'add_phone_requires_sms_client': ('human', 'phone_required'),
    'email_otp_requires_mail_client': ('human', 'email_code_required'),
    'email_otp_client_required': ('human', 'email_code_required'),
    'email_otp_provider_required': ('human', 'email_code_required'),
    'email_otp_verification_failed': ('human', 'email_verification_failed'),
    'oauth_cloudflare_challenge': ('human', 'security_challenge'),
    'token_exchange_failed': ('protocol', 'token_exchange_failed'),
    'choose_account_failed': ('protocol', 'account_selection_failed'),
    'about_you_failed': ('human', 'profile_required'),
    'oauth_callback_not_found': ('protocol', 'callback_missing'),
    'oauth_callback_timeout': ('protocol', 'callback_hops_exhausted'),
    'login_continue_failed': ('protocol', 'login_continue_failed'),
    'add_phone_failed': ('human', 'phone_verification_failed'),
    'invalid_state': ('state', 'state_mismatch'),
    'oauth_state_mismatch': ('state', 'state_mismatch'),
    'callback_state_mismatch': ('state', 'state_mismatch'),
    'state': ('state', 'state_mismatch'),
    'workspace': ('workspace', 'workspace_unmatched'),
    'fallback_identity': ('fallback_identity', 'identity_unconfirmed'),
}

MFA_ERRORS = {
    'invalid_otp': 'mfa_code_invalid',
    'invalid_totp': 'mfa_code_invalid',
    'invalid_code': 'mfa_code_invalid',
    'invalid_verification_code': 'mfa_code_invalid',
    'totp_invalid': 'mfa_code_invalid',
    'otp_expired': 'mfa_code_expired',
    'invalid_state': 'mfa_challenge_invalid',
}


def response_mfa_error(response):
    # 只保留已知机器码，不读取或返回可能含敏感内容的 message
    try:
        body = response.json()
    except Exception:
        return None
    error = body.get('error') if isinstance(body, dict) else None
    candidates = [error.get('code'), error.get('type')] if isinstance(error, dict) else [error]
    for code in candidates:
        if isinstance(code, str) and code.lower() in MFA_ERRORS:
            return code.lower()
    return None


def mfa_generation_failure(reason, previous=None):
    if reason not in {'mfa_code_unavailable', 'mfa_new_code_timeout', 'mfa_code_invalid_format', 'mfa_generation_failed'}:
        reason = 'mfa_generation_failed'
    diagnostic = {'stage': 'mfa_generate', 'reason': reason, 'httpStatus': None}
    prior = previous.get('diagnostic') if isinstance(previous, dict) else None
    if isinstance(prior, dict) and prior.get('stage') == 'mfa_verify':
        diagnostic['previousVerification'] = prior
    return {'code': 'mfa', 'diagnostic': diagnostic}


def stage_for_url(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme == 'https' and parsed.netloc == 'sentinel.openai.com' and parsed.path == '/backend-api/sentinel/req':
            return 'security_token'
        if parsed.scheme != 'https' or parsed.netloc != 'auth.openai.com':
            return 'unknown'
        path = parsed.path
        if path in STAGES:
            return STAGES[path]
        if path.startswith('/mfa-challenge'):
            return 'mfa_factor'
        if path in {'/api/accounts/mfa/list', '/api/accounts/mfa/factors'}:
            return 'mfa_factor'
        if path.startswith('/email-verification'):
            return 'email_verify'
        if path.startswith('/add-phone') or path.startswith('/phone-verification'):
            return 'phone'
        if path.startswith('/log-in'):
            return 'login'
        if path.startswith('/sign-in-with-chatgpt/'):
            return 'consent'
        if path.startswith('/api/accounts/'):
            return 'account_request'
        return 'authorize_follow'
    except (TypeError, ValueError):
        pass
    return 'unknown'


def transport_reason(exc):
    # Exception messages can include proxy authentication and authorization URLs.
    code = getattr(exc, 'code', None)
    if code == 28 or isinstance(exc, TimeoutError):
        return 'request_timeout'
    if code in {5, 6}:
        return 'dns_failed'
    if code in {35, 51, 58, 60}:
        return 'tls_failed'
    if code in {7, 56, 97} or isinstance(exc, ConnectionError):
        return 'connection_failed'
    return 'transport_failed'


def describe_failure(result=None, *, attempt=None, exception=None):
    result = result if isinstance(result, dict) else {}
    attempt = attempt if isinstance(attempt, dict) else {}
    reason = result.get('error')
    reason = reason.lower() if isinstance(reason, str) else ''
    status = attempt.get('httpStatus')
    status = status if type(status) is int and 100 <= status <= 599 else None
    stage = attempt.get('stage', 'unknown')
    if not isinstance(stage, str) or stage not in {*STAGES.values(), 'mfa_factor', 'consent', 'phone', 'security_token', 'account_request', 'authorize_follow', 'session', 'unknown'}:
        stage = 'unknown'
    if stage == 'unknown':
        protocol = result.get('oauth_protocol')
        page = protocol.get('last_page_type') if isinstance(protocol, dict) else result.get('page_type')
        stage = {'log-in': 'login_page', 'login_password': 'password', 'mfa-challenge': 'mfa_factor', 'email-verification': 'email_verify', 'workspace': 'workspace', 'organization': 'organization', 'consent': 'consent', 'edge-challenge': 'authorize', 'add-phone': 'phone', 'about-you': 'profile', 'choose-an-account': 'account_selection', 'callback': 'callback'}.get(page, 'unknown') if isinstance(page, str) else 'unknown'
        if stage == 'unknown':
            final_url = protocol.get('final_url') if isinstance(protocol, dict) else result.get('final_url')
            stage = stage_for_url(final_url)
    observed_error = attempt.get('upstreamError')
    if (reason not in REASONS or reason in {'token_exchange_failed', 'login_continue_failed', 'oauth_callback_not_found', 'oauth_callback_timeout', 'mfa_totp_verification_failed'}) and isinstance(observed_error, str) and observed_error in (REASONS.keys() | MFA_ERRORS.keys()):
        reason = observed_error
    # 旧上游会用通用失败覆盖具体 HTTP 原因，优先读取该次响应的已知 MFA 码
    observed_mfa = attempt.get('mfaError')
    if stage in {'mfa_verify', 'mfa_issue'} and isinstance(observed_mfa, str) and observed_mfa in MFA_ERRORS:
        reason = observed_mfa
    if reason == 'mfa_totp_code_unavailable':
        return mfa_generation_failure('mfa_code_unavailable')
    if reason in {'fallback_identity', 'state', 'invalid_state'} and not (reason == 'invalid_state' and stage in {'mfa_verify', 'mfa_issue'}):
        stage = 'identity' if reason == 'fallback_identity' else 'callback'
        if reason in {'fallback_identity', 'state'}:
            status = None
    code, detail = 'protocol', 'upstream_unknown'
    if status == 429 or reason in {'rate_limit_exceeded', 'too_many_requests', 'phone_verification_rate_limited'}:
        code, detail = 'limited', 'rate_limited'
    elif attempt.get('transport') or (exception is not None and transport_reason(exception) != 'transport_failed'):
        safe_transport = attempt.get('transport')
        if not isinstance(safe_transport, str) or safe_transport not in {'request_timeout', 'dns_failed', 'tls_failed', 'connection_failed', 'transport_failed'}:
            safe_transport = 'transport_failed'
        code, detail = 'proxy', transport_reason(exception) if exception is not None else safe_transport
    elif exception is not None:
        detail = 'protocol_processing_failed'
    elif status is not None and 200 <= status < 300 and attempt.get('responseState') in ('invalid_json', 'invalid_shape'):
        detail = 'response_invalid_json' if attempt['responseState'] == 'invalid_json' else 'response_invalid_shape'
    elif reason in {'login_continue_failed', 'token_exchange_failed', 'oauth_callback_not_found', 'oauth_callback_timeout'} and status is not None and status >= 400:
        detail = 'upstream_unavailable' if status >= 500 else 'http_rejected'
    elif stage in {'mfa_verify', 'mfa_issue'} and reason in MFA_ERRORS:
        code, detail = 'mfa', MFA_ERRORS[reason]
    elif reason in REASONS:
        code, detail = REASONS[reason]
    elif re.fullmatch(r'mfa_issue_challenge_http_[1-5][0-9]{2}', reason):
        code, detail = 'mfa', 'mfa_issue_failed'
    elif re.fullmatch(r'mfa_totp_rejected_[1-5][0-9]{2}', reason) and reason != 'mfa_totp_rejected_409':
        code, detail = 'mfa', 'mfa_code_rejected'
    elif re.fullmatch(r'email_otp_rejected_[1-5][0-9]{2}', reason):
        code, detail = 'human', 'email_code_rejected'
    elif re.fullmatch(r'passwordless_send_otp_http_[1-5][0-9]{2}', reason):
        code, detail = 'human', 'email_send_failed'
    elif status == 402:
        code, detail = 'billing', 'payment_required'
    elif (stage == 'mfa_verify' and status == 409) or reason == 'mfa_totp_rejected_409':
        stage = 'mfa_verify'
        code, detail = 'mfa', 'mfa_conflict'
    elif stage == 'mfa_issue':
        code, detail = 'mfa', 'mfa_issue_failed'
    elif stage == 'mfa_verify':
        code, detail = 'mfa', 'mfa_verification_failed'
    elif status is not None and status >= 500:
        detail = 'upstream_unavailable'
    elif status is not None and status >= 400:
        detail = 'http_rejected'
    if re.fullmatch(r'(?:mfa_issue_challenge_http|mfa_totp_rejected|email_otp_rejected)_[1-5][0-9]{2}', reason):
        status = int(reason.rsplit('_', 1)[1])
        if status == 429:
            code, detail = 'limited', 'rate_limited'
    if re.fullmatch(r'passwordless_send_otp_http_[1-5][0-9]{2}', reason):
        status = int(reason.rsplit('_', 1)[1])
        if status == 429:
            code, detail = 'limited', 'rate_limited'
    diagnostic = {'stage': stage, 'reason': detail, 'httpStatus': status}
    if reason in MFA_ERRORS and stage in {'mfa_verify', 'mfa_issue'}:
        diagnostic['upstreamCode'] = reason
    return {'code': code, 'diagnostic': diagnostic}
