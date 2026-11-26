"""Fetch OpenAI email-verification codes from the Mailcom mailbox API."""

from __future__ import annotations

import hashlib
import html
import json
import re
import time
from html.parser import HTMLParser
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


BASE_URL = 'https://mailcom.yeahzi.app'
LIMIT = 4 * 1024 * 1024
CODE_RE = re.compile(r'(?<!\d)(\d{6})(?!\d)')
URL_RE = re.compile(r'https?://\S+', re.I)
CODE_HINT_RE = re.compile(
    r'(?:verification|verify|log[ -]?in|sign[ -]?in|security|confirmation|one[ -]?time|otp|code|'
    r'验证码|校验码|安全码|确认码)',
    re.I,
)
OPENAI_RE = re.compile(r'(?:openai|chatgpt)', re.I)


class MailcomError(Exception):
    def __init__(self, reason, *, http_status=None, api_code=None):
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.api_code = api_code

    def diagnostic(self):
        result = {'reason': self.reason}
        if self.http_status is not None:
            result['httpStatus'] = self.http_status
        if self.api_code is not None:
            result['apiCode'] = self.api_code
        return result


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {'script', 'style'}:
            self._skip += 1

    def handle_endtag(self, tag):
        if tag.lower() in {'script', 'style'} and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)

    def text(self):
        return re.sub(r'\s+', ' ', ''.join(self.parts)).strip()


def visible_text(value):
    if not isinstance(value, str):
        return ''
    parser = _VisibleText()
    try:
        parser.feed(value)
        return html.unescape(parser.text())
    except Exception:
        return html.unescape(re.sub(r'<[^>]+>', ' ', value))


def mailbox_password(notes, email):
    """Return the mailbox password from a four-field notes line, if present."""
    if not isinstance(notes, str) or not isinstance(email, str):
        return None
    parts = notes.strip().split('----')
    if len(parts) != 4 or parts[0].strip().casefold() != email.strip().casefold():
        return None
    return parts[2].strip() or None


def _message_id(message):
    value = message.get('mailId')
    if isinstance(value, str) and value:
        return value[:256]
    material = '|'.join(str(message.get(key) or '') for key in ('folderId', 'timestamp', 'sender', 'subject'))
    return hashlib.sha256(material.encode('utf-8', 'replace')).hexdigest()


def _normalize(message):
    if not isinstance(message, dict):
        return None
    content = message.get('content')
    subject = message.get('subject')
    sender = message.get('sender')
    timestamp = message.get('timestamp')
    if isinstance(timestamp, str) and timestamp.isdigit():
        timestamp = int(timestamp)
    return {
        'id': _message_id(message),
        'timestamp': timestamp if type(timestamp) is int else 0,
        'folderId': message.get('folderId') if isinstance(message.get('folderId'), str) else '',
        'subject': subject[:1000] if isinstance(subject, str) else '',
        'sender': sender[:1000] if isinstance(sender, str) else '',
        'content': content if isinstance(content, str) else '',
    }


def _is_openai(message):
    haystack = ' '.join((message.get('sender', ''), message.get('subject', ''), message.get('content', '')))
    return bool(OPENAI_RE.search(haystack))


def _code_candidates(text):
    for match in CODE_RE.finditer(text):
        before = text[max(0, match.start() - 100):match.start()]
        after = text[match.end():match.end() + 100]
        context = f'{before}{match.group(0)}{after}'
        if not CODE_HINT_RE.search(context):
            continue
        score = 0
        if CODE_HINT_RE.search(before[-60:]) or CODE_HINT_RE.search(after[:60]):
            score += 5
        if re.search(r'(?:is|code|验证码|校验码)[^0-9]{0,30}$', before, re.I):
            score += 5
        if re.search(r'^(?:[^0-9]{0,30})(?:is your|verification|code|验证码)', after, re.I):
            score += 3
        yield score, match.start(), match.group(1)


def extract_code(message):
    text = visible_text(message.get('content', ''))
    subject = message.get('subject', '')
    text = URL_RE.sub(' ', text)
    subject = URL_RE.sub(' ', subject)
    candidates = list(_code_candidates(text))
    if not candidates:
        # Some messages put the code only in the subject.
        candidates = list(_code_candidates(subject))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], -item[1]))
    return candidates[0][2]


class MailcomClient:
    def __init__(self, email, password, api_key, *, base_url=BASE_URL, limit=5, timeout=45):
        if not isinstance(email, str) or '@' not in email or len(email) > 254:
            raise ValueError('mailcom_email')
        if not isinstance(password, str) or not password or len(password) > 4096:
            raise ValueError('mailcom_password')
        if not isinstance(api_key, str) or not api_key or len(api_key) > 256:
            raise ValueError('mailcom_key')
        parsed = urlsplit(base_url)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            raise ValueError('mailcom_base_url')
        if parsed.scheme != 'https' and parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}:
            raise ValueError('mailcom_base_url')
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('mailcom_limit')
        self.email = email.strip()
        self._password = password
        self._api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.limit = limit
        self.timeout = timeout
        self.manual_resend_error = ''
        self.manual_resend_provider = None
        self.last_error = None

    def _request(self, limit=None, type_='all'):
        body = json.dumps({
            'email': self.email,
            'password': self._password,
            'limit': self.limit if limit is None else limit,
            'type': type_,
        }, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        request = Request(
            self.base_url + '/get',
            method='POST',
            data=body,
            headers={
                'X-Key': self._api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0',
            },
        )
        status = None
        try:
            opener = build_opener(ProxyHandler({}), NoRedirect())
            try:
                response = opener.open(request, timeout=self.timeout)
            except HTTPError as failure:
                response = failure
            with response:
                status = response.getcode()
                raw = response.read(LIMIT + 1)
        except (OSError, HTTPException, ValueError) as failure:
            reason = 'timeout' if isinstance(getattr(failure, 'reason', failure), TimeoutError) else 'transport'
            raise MailcomError(reason, http_status=status) from None
        if len(raw) > LIMIT:
            raise MailcomError('response_invalid', http_status=status)
        try:
            result = json.loads(raw)
        except (ValueError, RecursionError):
            raise MailcomError('response_invalid', http_status=status) from None
        if not isinstance(result, dict):
            raise MailcomError('response_invalid', http_status=status)
        code = result.get('code')
        if type(code) is not int:
            raise MailcomError('response_invalid', http_status=status)
        if not 200 <= status < 300:
            raise MailcomError('http_rejected', http_status=status, api_code=code if code else None)
        if code != 0:
            raise MailcomError('api_rejected', http_status=status, api_code=code)
        data = result.get('data')
        if not isinstance(data, dict):
            raise MailcomError('response_invalid', http_status=status, api_code=code)
        username = data.get('username')
        if isinstance(username, str) and username.strip() and username.strip().casefold() != self.email.casefold():
            raise MailcomError('identity_mismatch', http_status=status, api_code=code)
        messages = data.get('emails')
        if not isinstance(messages, list):
            return []
        result_messages = []
        for message in messages:
            normalized = _normalize(message)
            if normalized is not None:
                result_messages.append(normalized)
        return result_messages

    def messages(self):
        try:
            messages = self._request()
            self.last_error = None
            return messages
        except MailcomError as error:
            self.last_error = error
            raise

    def snapshot_openai_message_ids(self, email=None):
        try:
            return {
                message['id']
                for message in self.messages()
                if _is_openai(message)
            }
        except MailcomError:
            return set()

    def capture_openai_baseline(self, email=None, quiet=False):
        return self.snapshot_openai_message_ids(email)

    def wait_for_new_verification_code(self, email, *, timeout=150, exclude_codes=None, exclude_message_ids=None):
        deadline = time.monotonic() + max(1, int(timeout or 1))
        excluded_codes = set(exclude_codes or ())
        excluded_ids = set(exclude_message_ids or ())
        delays = (2, 3, 5, 8, 13, 21, 34, 55)
        attempt = 0
        while time.monotonic() < deadline:
            try:
                messages = self.messages()
            except MailcomError as error:
                transient = error.reason in {'timeout', 'transport'} or (
                    error.reason == 'http_rejected'
                    and error.http_status in {429, 500, 502, 503, 504}
                )
                if not transient:
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                attempt += 1
                time.sleep(min(5, remaining))
                continue
            for message in messages:
                if message['id'] in excluded_ids or not _is_openai(message):
                    continue
                code = extract_code(message)
                if code and code not in excluded_codes:
                    return code
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            delay = delays[min(attempt, len(delays) - 1)]
            attempt += 1
            time.sleep(min(delay, remaining))
        return None

    def get_latest_verification_code_fallback(self, email, *, exclude_codes=None, exclude_message_ids=None):
        excluded_codes = set(exclude_codes or ())
        try:
            messages = self.messages()
        except MailcomError:
            return None
        for message in sorted(messages, key=lambda item: item['timestamp'], reverse=True):
            if not _is_openai(message):
                continue
            code = extract_code(message)
            if code and code not in excluded_codes:
                return code
        self.last_error = MailcomError('no_code')
        return None
