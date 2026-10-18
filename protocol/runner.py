"""Isolated reauth-web login adapter. RS owns PKCE, token exchange and persistence."""
from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import re
import sys
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from diagnostics import describe_failure, mfa_generation_failure, response_mfa_error, retry_action, stage_for_url, transport_reason
from tracing import ObservedSession


def emit(event, **fields):
    sys.__stdout__.write(json.dumps({"event": event, **fields}) + "\n")
    sys.__stdout__.flush()


def parse_notes(notes, email):
    if not isinstance(notes, str) or len(notes) > 2000 or any(c in notes for c in "\r\n\0"):
        raise ValueError("credentials")
    parts = notes.strip().split("----")
    if len(parts) != 3 or parts[0].strip().casefold() != email.strip().casefold() or not parts[1]:
        raise ValueError("credentials")
    secret = parts[2].strip().upper().replace(" ", "")
    if not secret or not base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True):
        raise ValueError("credentials")
    return parts[0].strip(), parts[1], secret


def authorization(url):
    def parse(value):
        if not isinstance(value, str) or not value or len(value) > 16384 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
            raise ValueError("authorization")
        parsed = urlsplit(value)
        params = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=64)
        if parsed.fragment or any(len(values) != 1 for values in params.values()):
            raise ValueError("authorization")
        return parsed, params

    try:
        parsed, params = parse(url)
        # RS wraps the upstream authorize URL in the official desktop entry point.
        if parsed.scheme == "https" and parsed.netloc == "chatgpt.com" and parsed.path == "/codex/desktop-auth":
            url = params.get("authorize_url", [""])[0]
            parsed, params = parse(url)
        if parsed.scheme != "https" or parsed.netloc != "auth.openai.com" or parsed.path != "/oauth/authorize":
            raise ValueError("authorization")
        required = ["state", "redirect_uri", "code_challenge", "client_id", "response_type", "code_challenge_method"]
        if any(not params.get(k, [""])[0] for k in required):
            raise ValueError("authorization")
        if params["response_type"] != ["code"] or params["code_challenge_method"] != ["S256"] or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params["code_challenge"][0]):
            raise ValueError("authorization")
        if any(ord(c) <= 32 or ord(c) == 127 for k in required for c in params[k][0]):
            raise ValueError("authorization")
        redirect = urlsplit(params["redirect_uri"][0])
        if redirect.scheme != "http" or redirect.netloc not in {"localhost:1455", "127.0.0.1:1455"} or redirect.path != "/auth/callback" or redirect.query or redirect.fragment:
            raise ValueError("authorization")
        return url, params["state"][0], redirect
    except (ValueError, TypeError):
        raise ValueError("authorization") from None


def error_code(result):
    return describe_failure(result)['code']


def workspace_ids_from_text(text, original):
    values = []
    for value in re.findall(r'(?i)(?:workspace_id|workspaceId)[^A-Za-z0-9_-]{0,8}([A-Za-z0-9_-]{8,128})', str(text)):
        if value != original and value not in values:
            values.append(value)
    return values


def run(data):
    used_codes = set()
    previous = None
    for attempt in range(2):
        failure = _run_once(data, used_codes)
        if failure is None:
            return
        if attempt == 0 and retry_action(failure) == 'restart_login':
            previous = failure['diagnostic']
            emit('step', step='session_restart')
            continue
        if previous is not None:
            diagnostic = failure.setdefault('diagnostic', describe_failure({'error': failure.get('code')})['diagnostic'])
            if failure.get('code') == 'workspace':
                diagnostic['stage'] = 'workspace'
            diagnostic['sessionRestarts'] = 1
            diagnostic['previousLogin'] = previous
        emit('error', **failure)
        return


def _run_once(data, used_codes):
    email, password, secret = parse_notes(data["notes"], data["email"])
    authorize_url, state, redirect = authorization(data["authorizationUrl"])
    proxy = str(data["proxy"])
    parsed_proxy = urlsplit(proxy)
    if parsed_proxy.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed_proxy.hostname:
        raise ValueError("proxy")
    from vendor.lib.chatgpt_client import ChatGPTClient
    from vendor.lib.oauth_client import OAuthClient
    from totp import TotpMfaClient
    from fallback import WorkspaceUnavailable, free_workspace_candidate, personal_candidate, recover_free, recover_unbound_free, workspace_choices

    target = str(data.get("accountId") or "")
    forced = data.get("forceWorkspaceId")
    forced_free = data.get("forceFree") is True
    if forced is not None and (not isinstance(forced, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", forced) or forced == target):
        raise ValueError("workspace")

    class BoundOAuthClient(OAuthClient):
        bound_workspace = False
        selected_workspace = forced or target
        workspace_candidates = []
        unbound_workspace = False
        last_attempt = None
        failed_authorization = None
        last_mfa_verification = None
        local_mfa_failure = None

        def _oauth_request(self, method, url, **kwargs):
            self.last_attempt = {'stage': stage_for_url(url), 'httpStatus': None}
            if self.last_attempt['stage'] == 'mfa_verify':
                code = kwargs.get('json', {}).get('code')
                if isinstance(code, str) and re.fullmatch(r'\d{6}', code):
                    used_codes.add(code)
            if self.last_attempt['stage'] == 'mfa_issue':
                self.last_mfa_verification = None
            try:
                response = super()._oauth_request(method, url, **kwargs)
            except Exception as exc:
                self.last_attempt['transport'] = transport_reason(exc)
                raise
            self.last_attempt['httpStatus'] = getattr(response, 'status_code', None)
            if self.last_attempt['stage'] in {'mfa_verify', 'mfa_issue'}:
                self.last_attempt['mfaError'] = response_mfa_error(response)
            if self.last_attempt['stage'] == 'mfa_verify':
                self.last_mfa_verification = describe_failure(attempt=self.last_attempt)
            return response

        def _exchange_code_for_tokens(self, *args, **kwargs):
            self.last_attempt = {'stage': 'token_exchange', 'httpStatus': None}
            try:
                tokens = super()._exchange_code_for_tokens(*args, **kwargs)
            except Exception as exc:
                self.last_attempt['transport'] = transport_reason(exc)
                raise
            if not tokens:
                self.failed_authorization = describe_failure({'error': 'token_exchange_failed'}, attempt=self.last_attempt)
            return tokens

        def _remember_workspace(self, value):
            value = str(value or '').strip()
            if re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) and value != target and value not in self.workspace_candidates:
                self.workspace_candidates.append(value)
            return value

        def _extract_workspace_id_from_session(self):
            selected = self.selected_workspace
            if not selected:
                if self.unbound_workspace:
                    selected = free_workspace_candidate(self._decode_oauth_session_cookie(), target)
                    self.selected_workspace = selected
                    return selected
                raise ValueError("workspace")
            session = self._decode_oauth_session_cookie() or {}
            workspaces = session.get("workspaces") or []
            if isinstance(session.get("workspace_id"), str):
                self._remember_workspace(session.get("workspace_id"))
            if isinstance(workspaces, list):
                for item in workspaces:
                    if isinstance(item, dict):
                        self._remember_workspace(item.get("id"))
            if session.get("workspace_id") == selected or any(isinstance(w, dict) and w.get("id") == selected for w in workspaces):
                return selected
            if selected == target:
                try:
                    personal = personal_candidate(session, target)
                except ValueError:
                    return ""
                raise WorkspaceUnavailable(personal)
            return ""

        def _extract_workspace_id_from_html(self, html_text):
            text = str(html_text)
            for value in workspace_ids_from_text(text, target):
                self._remember_workspace(value)
            if self.selected_workspace and self.selected_workspace in text:
                return self._remember_workspace(self.selected_workspace)
            if self.unbound_workspace:
                return ""
            raise ValueError("workspace")

        def _select_workspace_for_callback(self, *args, **kwargs):
            result = super()._select_workspace_for_callback(*args, **kwargs)
            if result and any(result):
                self.bound_workspace = True
            return result

        def workspace_matches(self):
            session = self._decode_oauth_session_cookie() or {}
            ids = [w.get("id") for w in session.get("workspaces", []) if isinstance(w, dict)]
            selected = self.selected_workspace
            return bool(selected) and (self.bound_workspace or session.get("workspace_id") == selected or ids == [selected])

    class ProgressMfa(TotpMfaClient):
        def get_mfa_code(self, timeout=90, exclude_codes=None):
            previous = oauth.last_mfa_verification
            if previous and retry_action(previous) != 'new_code':
                # 只对明确的验证码拒绝换码；其他失败交给外层有界会话恢复。
                oauth.failed_authorization = previous
                return None
            emit("step", step="mfa")
            oauth.local_mfa_failure = None
            exclude_codes = set(exclude_codes or ()) | used_codes
            if exclude_codes:
                timeout = self.period + 5
            try:
                code = super().get_mfa_code(timeout=timeout, exclude_codes=exclude_codes)
            except Exception:
                oauth.local_mfa_failure = mfa_generation_failure('mfa_generation_failed', oauth.last_mfa_verification)
                raise
            if code is None:
                reason = 'mfa_new_code_timeout' if exclude_codes else 'mfa_code_unavailable'
                oauth.local_mfa_failure = mfa_generation_failure(reason, oauth.last_mfa_verification)
            elif not isinstance(code, str) or not re.fullmatch(r'\d{6}', code):
                oauth.local_mfa_failure = mfa_generation_failure('mfa_code_invalid_format', oauth.last_mfa_verification)
            return code

    emit("step", step="session")
    chat = None
    try:
        chat = ChatGPTClient(proxy=proxy, verbose=False, impersonate="chrome133a")
        chat.current_email = email
        oauth = BoundOAuthClient({"oauth_phone_strategy": "sms", "sub2api_oauth_max_hops": 20, "oauth_email_otp_max_attempts": 1, "oauth_email_otp_timeout": 30, "sub2api_oauth_impersonates": "chrome133a", "sub2api_redirect_uri": urlunsplit(redirect)}, proxy=proxy, verbose=False)
        oauth.session.close()
    except Exception as exc:
        if chat is not None:
            try:
                chat.session.close()
            except Exception:
                pass
        return describe_failure(attempt={'stage': 'session', 'httpStatus': None}, exception=exc)
    chat.session = ObservedSession(chat.session, lambda attempt: setattr(oauth, 'last_attempt', attempt))
    oauth.session = chat.session
    try:
        emit("step", step="login")
        def authorize(url, expected):
            oauth.last_attempt = {'stage': 'authorize', 'httpStatus': None}
            oauth.failed_authorization = None
            oauth.last_mfa_verification = None
            oauth.local_mfa_failure = None
            result = oauth.authorize_external_oauth_url(url, chat, expected_state=expected, user_agent=chat.ua, impersonate=chat.impersonate, email=email, password=password, mfa_client=ProgressMfa(secret), max_hops=20)
            if not isinstance(result, dict) or result.get('ok') is not True:
                oauth.failed_authorization = oauth.failed_authorization or oauth.local_mfa_failure or describe_failure(result, attempt=oauth.last_attempt)
            return result

        def fallback(personal):
            if not data.get("userId"):
                raise ValueError("fallback_identity")
            oauth.bound_workspace = False
            tokens = recover_free(oauth, chat, authorize_url, data, personal, authorize)
            emit("free_fallback", workspaceId=personal, originalWorkspaceId=target, originalWorkspaceUnavailable=True, tokens=tokens)

        try:
            if forced_free:
                tokens, workspace = recover_unbound_free(oauth, chat, authorize_url, data, authorize)
                emit("forced_free", workspaceId=workspace, originalWorkspaceId=target, administratorConfirmed=True, tokens=tokens)
                return
            if forced:
                tokens = recover_free(oauth, chat, authorize_url, data, forced, authorize, force=True)
                emit("forced_workspace", workspaceId=forced, originalWorkspaceId=target, administratorConfirmed=True, tokens=tokens)
                return
            try:
                result = authorize(authorize_url, state)
            except WorkspaceUnavailable as unavailable:
                fallback(unavailable.personal_id)
                return
            if not isinstance(result, dict) or not result.get("ok"):
                return oauth.failed_authorization
            if result.get("state") != state or not result.get("code"):
                raise ValueError("state")
            if not oauth.workspace_matches():
                fallback(personal_candidate(oauth._decode_oauth_session_cookie(), target))
                return
            callback = urlunsplit((redirect.scheme, redirect.netloc, redirect.path, urlencode({"state": state, "code": result["code"]}), ""))
            emit("complete", callbackUrl=callback)
        except ValueError as exc:
            if oauth.local_mfa_failure is not None:
                return oauth.local_mfa_failure
            if oauth.failed_authorization is not None:
                return oauth.failed_authorization
            if str(exc) != "workspace":
                return describe_failure({'error': str(exc)}, attempt=oauth.last_attempt, exception=None if str(exc) in {'state', 'fallback_identity', 'free_workspace_missing', 'free_workspace_ambiguous'} else exc)
            choices = workspace_choices(oauth._decode_oauth_session_cookie(), target)
            known = {item["id"] for item in choices}
            for value in getattr(oauth, "workspace_candidates", []):
                if value not in known and len(choices) < 30:
                    choices.append({"id": value})
                    known.add(value)
            return {'code': 'workspace', 'workspaces': choices}
        except Exception as exc:
            return oauth.local_mfa_failure or describe_failure(attempt=oauth.last_attempt, exception=exc)
    finally:
        chat.session.close()


def main():
    logging.disable(logging.CRITICAL)
    parent = os.getppid()
    def watchdog():
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline and os.getppid() == parent:
            time.sleep(1)
        os._exit(0)
    threading.Thread(target=watchdog, daemon=True).start()
    try:
        data = json.loads(sys.stdin.read(16385))
        # Vendored diagnostics must never share the structured protocol pipe.
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            run(data)
    except ValueError as exc:
        code = str(exc)
        if code in {'credentials', 'authorization', 'workspace', 'proxy'}:
            emit('error', code=code)
        else:
            emit('error', **describe_failure({'error': code}))
    except Exception:
        emit("error", code="protocol")


if __name__ == "__main__":
    main()
