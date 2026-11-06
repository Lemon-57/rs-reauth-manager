"""Finite diagnostic vocabulary. Never forward an upstream message or body."""
import json

REASONS = frozenset({'invalid_grant', 'invalid_token', 'refresh_token_expired',
    'refresh_token_reused', 'token_expired', 'token_revoked', 'account_deactivated',
    'user_deactivated', 'invalid_client', 'unauthorized_client', 'access_denied',
    'rate_limit_exceeded', 'too_many_requests', 'refresh_token_invalid',
    'invalid_refresh_token', 'refresh_token_revoked', 'token_invalidated',
    'invalid_request_error'})
CODES = frozenset({'rt_rejected', 'rt_transport_unconfirmed', 'rt_result_unconfirmed',
    'identity_mismatch', 'identity_invalid', 'account_conflict', 'account_busy',
    'proxy_unavailable', 'flow_conflict'})
MESSAGES = {
    'RT identity email does not match expected email; not imported': 'identity_mismatch',
    'RT identity conflicts with the selected email; not imported': 'identity_mismatch',
    'RT returned invalid identity token': 'identity_invalid',
    'Email matches multiple accounts; select an exact account': 'account_conflict',
    'Account must be idle before RT import': 'account_busy',
    '已有账号须先暂停并等待请求自然完成，再更新导入凭据': 'account_busy',
    'Reservation does not belong to this instance': 'proxy_unavailable',
    'Import reservation history mismatch': 'proxy_unavailable',
    'Pool registration unavailable': 'proxy_unavailable',
}


def sanitize(value):
    if (not isinstance(value, dict) or not isinstance(value.get('code'), str)
            or value['code'] not in CODES):
        return None
    result = {'code': value['code']}
    status = value.get('upstreamStatus')
    if type(status) is int and 400 <= status <= 599:
        result['upstreamStatus'] = status
    if isinstance(value.get('reason'), str) and value['reason'] in REASONS:
        result['reason'] = value['reason']
    return result


def from_error(error):
    diagnostic = sanitize(getattr(error, 'diagnostic', None))
    if diagnostic:
        return diagnostic
    code = MESSAGES.get(str(error))
    return {'code': code} if code else None


def rejected(error):
    result = {'code': 'rt_rejected', 'upstreamStatus': error.code}
    try:
        raw = error.read(32769)
        if len(raw) > 32768:
            return sanitize(result)
        body = json.loads(raw)
        item = body.get('error')
        candidates = [body.get('code'), body.get('error_code')]
        if isinstance(item, dict):
            candidates += [item.get('code'), item.get('type')]
        elif isinstance(item, str):
            candidates.append(item)
        for reason in candidates:
            if isinstance(reason, str) and reason in REASONS:
                result['reason'] = reason
                break
    except Exception:
        pass
    return sanitize(result)
