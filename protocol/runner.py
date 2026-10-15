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
    reason = str(result.get("error", "")).lower()
    page = str(result.get("page_type", "")).lower()
    if "invalid_username_or_password" in reason:
        return "password"
    if "mfa" in reason or "totp" in reason:
        return "mfa"
    if "429" in reason or "rate_limit" in reason:
        return "limited"
    if any(v in reason + page for v in ("phone", "email_otp", "captcha", "challenge", "primary_factor")):
        return "human"
    return "protocol"


def run(data):
    email, password, secret = parse_notes(data["notes"], data["email"])
    authorize_url, state, redirect = authorization(data["authorizationUrl"])
    proxy = str(data["proxy"])
    parsed_proxy = urlsplit(proxy)
    if parsed_proxy.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed_proxy.hostname:
        raise ValueError("proxy")
    from vendor.lib.chatgpt_client import ChatGPTClient
    from vendor.lib.oauth_client import OAuthClient
    from totp import TotpMfaClient

    target = str(data.get("accountId") or "")

    class BoundOAuthClient(OAuthClient):
        bound_workspace = False

        def _extract_workspace_id_from_session(self):
            if not target:
                raise ValueError("workspace")
            session = self._decode_oauth_session_cookie() or {}
            workspaces = session.get("workspaces") or []
            if session.get("workspace_id") == target or any(isinstance(w, dict) and w.get("id") == target for w in workspaces):
                return target
            return ""

        def _extract_workspace_id_from_html(self, html_text):
            if target and target in str(html_text):
                return target
            raise ValueError("workspace")

        def _select_workspace_for_callback(self, *args, **kwargs):
            result = super()._select_workspace_for_callback(*args, **kwargs)
            if result and any(result):
                self.bound_workspace = True
            return result

        def workspace_matches(self):
            session = self._decode_oauth_session_cookie() or {}
            ids = [w.get("id") for w in session.get("workspaces", []) if isinstance(w, dict)]
            return bool(target) and (self.bound_workspace or session.get("workspace_id") == target or ids == [target])

    class ProgressMfa(TotpMfaClient):
        def get_mfa_code(self, *args, **kwargs):
            emit("step", step="mfa")
            return super().get_mfa_code(*args, **kwargs)

    emit("step", step="session")
    chat = ChatGPTClient(proxy=proxy, verbose=False, impersonate="chrome133a")
    chat.current_email = email
    oauth = BoundOAuthClient({"oauth_phone_strategy": "sms", "sub2api_oauth_max_hops": 20, "oauth_email_otp_max_attempts": 1, "oauth_email_otp_timeout": 30, "sub2api_oauth_impersonates": "chrome133a", "sub2api_redirect_uri": urlunsplit(redirect)}, proxy=proxy, verbose=False)
    oauth.session.close()
    oauth.session = chat.session
    try:
        emit("step", step="login")
        result = oauth.authorize_external_oauth_url(authorize_url, chat, expected_state=state, user_agent=chat.ua, impersonate=chat.impersonate, email=email, password=password, mfa_client=ProgressMfa(secret), max_hops=20)
        if not isinstance(result, dict) or not result.get("ok"):
            emit("error", code=error_code(result if isinstance(result, dict) else {}))
            return
        if result.get("state") != state or not result.get("code"):
            raise ValueError("state")
        if not oauth.workspace_matches():
            raise ValueError("workspace")
        callback = urlunsplit((redirect.scheme, redirect.netloc, redirect.path, urlencode({"state": state, "code": result["code"]}), ""))
        emit("complete", callbackUrl=callback)
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
        emit("error", code=code if code in {"credentials", "authorization", "state", "workspace", "proxy"} else "credentials")
    except Exception:
        emit("error", code="protocol")


if __name__ == "__main__":
    main()
