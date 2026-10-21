"""Observe all vendor HTTP entry points without retaining URLs, payloads or secrets."""
from diagnostics import MFA_ERRORS, REASONS, stage_for_url, transport_reason
from urllib.parse import urlsplit
import time


class ObservedSession:
    def __init__(self, session, record, *, recover_initial_page=False, on_initial_retry=None):
        self._session = session
        self._record = record
        self._recover_initial_page = recover_initial_page
        self._on_initial_retry = on_initial_retry
        self._initial_request_seen = False

    def __getattr__(self, name):
        return getattr(self._session, name)

    def _call(self, invoke, url, *, method, **kwargs):
        try:
            parsed = urlsplit(url)
        except (TypeError, ValueError):
            parsed = None
        if parsed and parsed.scheme == 'https' and parsed.netloc == 'auth.openai.com' and parsed.path == '/oauth/token':
            kwargs['allow_redirects'] = False
        attempt = {'stage': stage_for_url(url), 'httpStatus': None}
        self._record(attempt)
        # 仅允许全新登录会话的首个原生授权页 GET 恢复一次，不重放登录或交换请求
        initial_page = self._recover_initial_page and not self._initial_request_seen and method.upper() == 'GET' and parsed and parsed.scheme == 'https' and parsed.netloc == 'auth.openai.com' and parsed.path == '/oauth/authorize'
        self._initial_request_seen = True
        try:
            response = invoke(**kwargs)
            if initial_page and self._initial_challenge(response):
                if self._on_initial_retry:
                    self._on_initial_retry()
                time.sleep(2)
                response = invoke(**kwargs)
                attempt['initialPageRetries'] = 1
        except Exception as exc:
            attempt['transport'] = transport_reason(exc)
            raise
        attempt['httpStatus'] = getattr(response, 'status_code', None)
        try:
            parsed = urlsplit(url)
            json_endpoint = parsed.netloc in {'auth.openai.com', 'sentinel.openai.com'} and (parsed.path.startswith('/api/accounts/') or parsed.path in {'/oauth/token', '/backend-api/sentinel/req'})
        except (TypeError, ValueError):
            json_endpoint = False
        if json_endpoint:
            try:
                body = response.json()
            except Exception:
                attempt['responseState'] = 'invalid_json'
            else:
                if not isinstance(body, dict):
                    attempt['responseState'] = 'invalid_shape'
                else:
                    error = body.get('error')
                    if error and attempt['stage'] in {'workspace', 'organization'}:
                        attempt['hasError'] = True
                    codes = [error.get('code'), error.get('type')] if isinstance(error, dict) else [error]
                    for code in codes:
                        if isinstance(code, str) and code.lower() in (REASONS.keys() | MFA_ERRORS.keys()):
                            attempt['upstreamError'] = code.lower()
                            break
        return response

    @staticmethod
    def _initial_challenge(response):
        if getattr(response, 'status_code', None) != 403:
            return False
        headers = getattr(response, 'headers', {}) or {}
        if headers.get('server', '').lower() != 'cloudflare' and not headers.get('cf-ray'):
            return False
        # 尊重上游要求等待更长的响应，不提前重发，也不接管人工挑战
        if headers.get('retry-after'):
            try:
                if float(headers['retry-after']) > 2:
                    return False
            except (ValueError, TypeError):
                return False
        body = str(getattr(response, 'text', '') or '').lower()
        return any(marker in body for marker in ('just a moment', 'cf-chl-', '/cdn-cgi/challenge-platform/'))

    def request(self, method, url, **kwargs):
        return self._call(lambda **kw: self._session.request(method, url, **kw), url, method=method, **kwargs)

    def get(self, url, **kwargs):
        return self._call(lambda **kw: self._session.get(url, **kw), url, method='GET', **kwargs)

    def post(self, url, **kwargs):
        return self._call(lambda **kw: self._session.post(url, **kw), url, method='POST', **kwargs)
