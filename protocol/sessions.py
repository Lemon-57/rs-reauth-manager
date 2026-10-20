"""Revoke other device sessions through the first-party session manager.

Only opaque session IDs and the explicit current-device marker are consumed.
Neither device records nor credentials belong in diagnostics or persistent jobs.
"""
import uuid
from urllib.parse import urlsplit

from fallback import verify_tokens

BASE = 'https://chatgpt.com/backend-api/accounts/sessions'


class SessionCleanupError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _id(value):
    return isinstance(value, str) and 0 < len(value) <= 512 and not any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in value)


def _json(response):
    if response.status_code != 200:
        raise SessionCleanupError('sessions_request_rejected')
    try:
        body = response.json()
    except Exception:
        raise SessionCleanupError('sessions_response_invalid') from None
    if not isinstance(body, dict) or body.get('error'):
        raise SessionCleanupError('sessions_response_invalid')
    return body


def device_sessions(body):
    # The client renders data.devices. Unknown pagination must never mean complete.
    if not isinstance(body, dict) or body.get('pagination'):
        raise SessionCleanupError('sessions_response_invalid')
    if any(body.get(k) not in (None, False, '') for k in ('has_more', 'hasMore', 'next_cursor', 'nextCursor', 'next_page', 'nextPage')):
        raise SessionCleanupError('sessions_incomplete')
    rows = body.get('devices')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 1000:
        raise SessionCleanupError('sessions_response_invalid')
    if any(k in body and (type(body[k]) is not int or body[k] > len(rows)) for k in ('total', 'total_count', 'totalCount')):
        raise SessionCleanupError('sessions_incomplete')
    current, others, seen = [], [], set()
    for row in rows:
        if not isinstance(row, dict) or type(row.get('is_current_device')) is not bool:
            raise SessionCleanupError('sessions_current_unconfirmed')
        session_id = row.get('session_id')
        if session_id in (None, '') and row['is_current_device'] is False and row.get('is_trusted_device') is True:
            # Signed-out trusted devices are not active sessions; do not untrust them.
            continue
        if not _id(session_id) or session_id in seen:
            raise SessionCleanupError('sessions_response_invalid')
        seen.add(session_id)
        (current if row['is_current_device'] else others).append(session_id)
    if len(current) != 1:
        raise SessionCleanupError('sessions_current_unconfirmed')
    return current[0], set(others)


def cleanup(data, emit):
    from vendor.lib.chatgpt_client import ChatGPTClient
    proxy = urlsplit(data.get('proxy', ''))
    if proxy.scheme not in {'http', 'https', 'socks5', 'socks5h'} or not proxy.hostname:
        raise SessionCleanupError('sessions_proxy_invalid')
    tokens, workspace, plan = verify_tokens(data['tokens'], data['email'], data['userId'], data['accountId'], force=True, require_refresh=False)
    if plan != data['planType'].strip().lower():
        raise SessionCleanupError('sessions_identity_changed')
    try:
        device_id = str(uuid.UUID(data['deviceId']))
    except (KeyError, TypeError, ValueError, AttributeError):
        raise SessionCleanupError('sessions_current_unconfirmed') from None
    chat = ChatGPTClient(proxy=data['proxy'], verbose=False, impersonate='chrome133a')
    chat.device_id = device_id
    chat.session.cookies.set('oai-did', device_id, domain='chatgpt.com')
    headers = {'Authorization': 'Bearer ' + tokens['access_token'], 'Accept': 'application/json',
               'Origin': 'https://chatgpt.com', 'Referer': 'https://chatgpt.com/', 'oai-device-id': device_id}
    try:
        def listing():
            return device_sessions(_json(chat.session.get(BASE, headers=headers, timeout=20, allow_redirects=False)))

        emit('step', step='verify_refresh' if data.get('action') == 'verify_sessions' else 'other_sessions')
        current, others = listing()
        if data.get('action') == 'verify_sessions':
            if current != data.get('expectedSessionId') or others:
                raise SessionCleanupError('sessions_current_unconfirmed')
            emit('sessions_verified', otherSessionsRevoked=True, currentSessionRetained=True)
            return
        revoked = 0
        # Re-read before each mutation: changed current markers or newly appeared
        # sessions must not expand a previously approved operation silently.
        for session_id in sorted(others):
            now_current, remaining = listing()
            if now_current != current or not remaining <= others:
                raise SessionCleanupError('sessions_changed')
            if session_id not in remaining:
                continue
            response = chat.session.post(BASE + '/revoke', json={'session_id': session_id}, headers=headers, timeout=20, allow_redirects=False)
            if response.status_code not in (200, 204):
                raise SessionCleanupError('sessions_revoke_unconfirmed')
            if response.status_code == 200:
                # An empty acknowledgement is allowed; the fresh directory is
                # the semantic proof. Explicit JSON errors still stop the task.
                if getattr(response, 'text', None) != '':
                    _json(response)
            after_current, remaining = listing()
            if after_current != current or session_id in remaining or not remaining <= others:
                raise SessionCleanupError('sessions_revoke_unconfirmed')
            revoked += 1
        after_current, remaining = listing()
        if after_current != current or remaining:
            raise SessionCleanupError('sessions_revoke_unconfirmed')
        emit('sessions_cleaned', workspaceId=workspace, originalWorkspaceId=workspace,
             otherSessionsRevoked=True, revokedCount=revoked, retainedSessionId=current)
    except SessionCleanupError:
        raise
    except Exception:
        raise SessionCleanupError('sessions_transport_unconfirmed') from None
    finally:
        chat.session.close()
