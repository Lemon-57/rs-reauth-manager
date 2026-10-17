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
}
REASONS = {
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
    'invalid_state': ('state', 'state_mismatch'),
    'oauth_state_mismatch': ('state', 'state_mismatch'),
    'callback_state_mismatch': ('state', 'state_mismatch'),
    'state': ('state', 'state_mismatch'),
    'workspace': ('workspace', 'workspace_unmatched'),
    'fallback_identity': ('fallback_identity', 'identity_unconfirmed'),
}


def stage_for_url(url):
    try:
        parsed = urlsplit(url)
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
    if not isinstance(stage, str) or stage not in {*STAGES.values(), 'mfa_factor', 'consent', 'phone', 'unknown'}:
        stage = 'unknown'
    if stage == 'unknown':
        protocol = result.get('oauth_protocol')
        page = protocol.get('last_page_type') if isinstance(protocol, dict) else result.get('page_type')
        stage = {'log-in': 'login', 'mfa-challenge': 'mfa_factor', 'email-verification': 'email_verify', 'workspace': 'workspace', 'organization': 'organization', 'consent': 'consent', 'edge-challenge': 'authorize', 'add-phone': 'phone'}.get(page, 'unknown') if isinstance(page, str) else 'unknown'
    if reason in {'fallback_identity', 'state', 'invalid_state'}:
        stage = 'identity' if reason == 'fallback_identity' else 'callback'
    code, detail = 'protocol', 'upstream_unknown'
    if status == 429 or reason in {'rate_limit_exceeded', 'too_many_requests', 'phone_verification_rate_limited'}:
        code, detail = 'limited', 'rate_limited'
    elif exception is not None or attempt.get('transport'):
        safe_transport = attempt.get('transport')
        if not isinstance(safe_transport, str) or safe_transport not in {'request_timeout', 'dns_failed', 'tls_failed', 'connection_failed', 'transport_failed'}:
            safe_transport = 'transport_failed'
        code, detail = 'proxy', transport_reason(exception) if exception is not None else safe_transport
    elif reason in REASONS:
        code, detail = REASONS[reason]
    elif re.fullmatch(r'mfa_issue_challenge_http_[1-5][0-9]{2}', reason):
        code, detail = 'mfa', 'mfa_issue_failed'
    elif re.fullmatch(r'mfa_totp_rejected_[1-5][0-9]{2}', reason):
        code, detail = 'mfa', 'mfa_code_rejected'
    elif re.fullmatch(r'email_otp_rejected_[1-5][0-9]{2}', reason):
        code, detail = 'human', 'email_code_rejected'
    elif reason in {'invalid_otp', 'invalid_totp', 'invalid_code', 'invalid_verification_code', 'otp_expired', 'totp_invalid'} and stage == 'mfa_verify':
        code, detail = 'mfa', 'mfa_code_rejected'
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
    return {'code': code, 'diagnostic': {'stage': stage, 'reason': detail, 'httpStatus': status}}
