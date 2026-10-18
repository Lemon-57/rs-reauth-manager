"""Observe all vendor HTTP entry points without retaining URLs, payloads or secrets."""
from diagnostics import MFA_ERRORS, REASONS, stage_for_url, transport_reason
from urllib.parse import urlsplit


class ObservedSession:
    def __init__(self, session, record):
        self._session = session
        self._record = record

    def __getattr__(self, name):
        return getattr(self._session, name)

    def _call(self, invoke, url, **kwargs):
        attempt = {'stage': stage_for_url(url), 'httpStatus': None}
        self._record(attempt)
        try:
            response = invoke(**kwargs)
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
                    codes = [error.get('code'), error.get('type')] if isinstance(error, dict) else [error]
                    for code in codes:
                        if isinstance(code, str) and code.lower() in (REASONS.keys() | MFA_ERRORS.keys()):
                            attempt['upstreamError'] = code.lower()
                            break
        return response

    def request(self, method, url, **kwargs):
        return self._call(lambda **kw: self._session.request(method, url, **kw), url, **kwargs)

    def get(self, url, **kwargs):
        return self._call(lambda **kw: self._session.get(url, **kw), url, **kwargs)

    def post(self, url, **kwargs):
        return self._call(lambda **kw: self._session.post(url, **kw), url, **kwargs)
