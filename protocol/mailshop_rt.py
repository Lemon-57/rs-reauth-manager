"""Exchange one explicit GMX login failure for a Mailshop RT candidate."""

from http.client import HTTPException
import json
import re
import unicodedata
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4


ENDPOINT = 'https://mailshop.closeai.hk/api/user/gpt/codex-rt/run'
LIMIT = 256 * 1024
DELIMITER = '----'
DETAIL_LIMIT = 240
UNSAFE_DETAIL = re.compile(
    r'[<>{}@\\]|----|://|%[0-9a-f]{2}|\b(?:bearer|basic)\s+'
    r'|\b(?:authorization|cookie|password|passwd|api[_ -]?key|(?:access|refresh|id)[_ -]?token|token|secret|otp)\s*[:=]'
    r'|(?:密码|密钥|令牌|验证码)\s*[:=]|(?<!\d)\d{6}(?!\d)'
    r'|\b(?:sk|rt|at|sess)[-_][a-z0-9_./+=-]{8,}|[a-z0-9+/=]{24,}',
    re.IGNORECASE,
)


class MailshopError(Exception):
    def __init__(self, reason, *, http_status=None, api_code=None, detail=None):
        super().__init__(reason)
        self.diagnostic = {'reason': reason}
        if http_status is not None:
            self.diagnostic['httpStatus'] = http_status
        if api_code is not None:
            self.diagnostic['apiCode'] = api_code
        if detail:
            self.diagnostic['detail'] = detail


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_detail(value, private_values):
    if not isinstance(value, str) or not 0 < len(value) <= DETAIL_LIMIT:
        return None
    if any(unicodedata.category(character).startswith('C') for character in value):
        return None
    text = value.strip()
    folded = unicodedata.normalize('NFKC', text).casefold()
    if not folded or folded in {'ok', 'success', '成功', '请求成功', '操作成功'} or UNSAFE_DETAIL.search(folded):
        return None
    for private in private_values:
        protected = unicodedata.normalize('NFKC', private.strip()).casefold()
        if protected and protected in folded:
            return None
    return text


def extract_rt(result, email, task_id, *, http_status=None, private_values=()):
    envelope = result if isinstance(result, dict) else {}
    api_code = envelope.get('code')
    if type(api_code) is not int or not -(2**31) <= api_code < 2**31:
        api_code = None
    private_values = (email, *private_values)

    def error(reason, detail=None):
        return MailshopError(reason, http_status=http_status, api_code=api_code or None,
                             detail=safe_detail(detail, private_values))

    if http_status is not None and not 200 <= http_status < 300:
        raise error('http_rejected', envelope.get('msg') if api_code is not None else None)
    if api_code is None:
        raise error('response_invalid')
    if api_code != 0:
        raise error('api_rejected', envelope.get('msg'))
    success = task_id + '-ok' + DELIMITER
    failure = task_id + '-failed' + DELIMITER
    pending = [envelope.get('data')]
    tokens = set()
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            for line in item.splitlines():
                if line.startswith(failure):
                    returned_email, _, cause = line[len(failure):].partition(DELIMITER)
                    if returned_email.casefold() != email.casefold():
                        raise error('response_invalid')
                    raise error('account_rejected', cause or envelope.get('msg'))
                if line.startswith(success):
                    returned_email, split, token = line[len(success):].partition(DELIMITER)
                    if (returned_email.casefold() != email.casefold() or not split
                            or not 1 <= len(token) <= 32768
                            or not all(33 <= ord(character) <= 126 for character in token)):
                        raise error('response_invalid')
                    tokens.add(token)
    if not tokens:
        raise error('rt_missing', envelope.get('msg'))
    if len(tokens) != 1:
        raise error('response_invalid')
    return tokens.pop()


def fetch_rt(email, password, secret, api_key):
    task_id = f'gmx-reauth-{uuid4().hex}'
    payload = {
        'accounts': [{'email': email, 'password': password, 'twoFASecret': secret}],
        'autoBindPhone': False,
        'outputDelimiter': DELIMITER,
        'successOutputTemplate': task_id + '-ok{split}{email}{split}{refreshToken}',
        'failedOutputTemplate': task_id + '-failed{split}{email}{split}{error}',
        'taskId': task_id,
    }
    request = Request(ENDPOINT, method='POST', data=json.dumps(payload).encode(), headers={
        'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json',
    })
    status = None
    try:
        opener = build_opener(ProxyHandler({}), NoRedirect())
        try:
            response = opener.open(request, timeout=90)
        except HTTPError as failure:
            response = failure
        with response:
            status = response.getcode()
            raw = response.read(LIMIT + 1)
    except (OSError, HTTPException, ValueError) as failure:
        reason = 'timeout' if isinstance(getattr(failure, 'reason', failure), TimeoutError) else 'transport'
        raise MailshopError(reason, http_status=status) from None
    result = None
    if len(raw) <= LIMIT:
        try:
            result = json.loads(raw)
        except (ValueError, RecursionError):
            pass
    return extract_rt(result, email, task_id, http_status=status, private_values=(password, secret, api_key))
