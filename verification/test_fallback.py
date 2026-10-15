"""Offline guards plus the unmodified vendor's actual PKCE and token-exchange code."""
import base64
import copy
import hashlib
import json
import socket
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "protocol"))
import runner
from fallback import personal_candidate, verify_free_tokens
from test_protocol import EMAIL, SECRET, URL, desktop_url
from requests.cookies import RequestsCookieJar
from vendor.lib import chatgpt_client, oauth_client

AUTH = "https://api.openai.com/auth"


def jwt(payload):
    return "fixture." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".signature"


def tokens():
    payload = {"sub": "original-subject", "email": EMAIL, "exp": int(time.time()) + 3600,
               AUTH: {"chatgpt_account_id": "personal-workspace", "chatgpt_user_id": "original-user", "chatgpt_plan_type": "free"}}
    return {"id_token": jwt(payload), "access_token": jwt(payload), "refresh_token": "fixture-private-rt"}


class FallbackGuards(unittest.TestCase):
    def test_explicit_personal_only_and_original_absent(self):
        for key, value in [("is_personal", True), ("type", "personal"), ("account_type", "individual"), ("kind", "personal")]:
            self.assertEqual(personal_candidate({"workspaces": [{"id": "personal-workspace", key: value}]}, "original-workspace"), "personal-workspace")

    def test_missing_ambiguous_unknown_and_still_available_rejected(self):
        personal = {"id": "personal-workspace", "is_personal": True}
        cases = [None, {}, {"workspaces": []}, {"workspaces": [personal], "workspace_id": "original-workspace"},
                 {"workspaces": [personal, {"id": "original-workspace"}]}, {"workspaces": [{"id": "unknown"}]},
                 {"workspaces": [personal, dict(personal, id="another")]}, {"workspaces": [personal, personal]},
                 {"workspaces": [dict(personal, plan_type="plus")]}, {"workspaces": [personal, None]}]
        for session in cases:
            with self.subTest(session=session), self.assertRaisesRegex(ValueError, "^workspace$"):
                personal_candidate(session, "original-workspace")

    def test_same_user_email_workspace_free_and_live_tokens_required(self):
        original = tokens()
        self.assertEqual(verify_free_tokens(original, EMAIL.upper(), "original-user", "personal-workspace"), original)
        for key in ["id_token", "access_token"]:
            for field, value in [("chatgpt_user_id", "other-user"), ("chatgpt_account_id", "other-workspace"), ("chatgpt_plan_type", "team")]:
                modified = copy.deepcopy(original)
                payload = json.loads(base64.urlsafe_b64decode(modified[key].split('.')[1] + '=='))
                payload[AUTH][field] = value
                modified[key] = jwt(payload)
                with self.subTest(key=key, field=field), self.assertRaisesRegex(ValueError, "^fallback_identity$"):
                    verify_free_tokens(modified, EMAIL, "original-user", "personal-workspace")
        for changes in [{"refresh_token": ""}, {"refresh_token": "private\nrt"}, {"id_token": "not-jwt"}, {"access_token": "x" * 32769}]:
            with self.assertRaisesRegex(ValueError, "^fallback_identity$"):
                verify_free_tokens(original | changes, EMAIL, "original-user", "personal-workspace")

    def test_bad_email_subject_expiry_and_malformed_profile_rejected(self):
        for changes in [{"email": "other@example.com"}, {"sub": 123}, {"exp": 1}, {"exp": True}, {"email": None, "https://api.openai.com/profile": "invalid"}, {AUTH: []}]:
            original = tokens()
            payload = json.loads(base64.urlsafe_b64decode(original["id_token"].split('.')[1] + '=='))
            original["id_token"] = jwt(payload | changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "^fallback_identity$"):
                verify_free_tokens(original, EMAIL, "original-user", "personal-workspace")


class RealVendorFreeRecovery(unittest.TestCase):
    def execute(self, selection_page=False, bad_state=False, bad_tokens=False, user="original-user"):
        messages, calls = [], []
        exchanged = tokens()
        if bad_tokens:
            exchanged["refresh_token"] = ""
        data = {"notes": f"{EMAIL}----fixture-password----{SECRET}", "email": EMAIL,
                "proxy": "http://fixture:pass@127.0.0.1:21001", "authorizationUrl": desktop_url(),
                "accountId": "original-workspace", "userId": user}
        testcase = self

        class Session:
            def __init__(self):
                self.headers = {}
                self.cookies = RequestsCookieJar()
                self.cookies.set("oai-client-auth-session", json.dumps({"workspaces": [{"id": "personal-workspace", "is_personal": True}]}), domain="auth.openai.com")

            def request(self, method, url, **kwargs):
                testcase.assertEqual(method, "GET")
                testcase.assertEqual(urlsplit(url).netloc, "auth.openai.com")
                calls.append((method, url))
                params = parse_qs(urlsplit(url).query)
                if url == URL and selection_page:
                    return types.SimpleNamespace(status_code=200, url="https://auth.openai.com/workspace", headers={}, text="workspaces", json=lambda: {})
                state = "wrong" if bad_state and url != URL else params["state"][0]
                return types.SimpleNamespace(status_code=302, url=url, headers={"Location": f"http://127.0.0.1:1455/auth/callback?state={state}&code=fixture-code"}, text="")

            def post(self, url, **kwargs):
                testcase.assertEqual(url, "https://auth.openai.com/oauth/token")
                testcase.assertEqual(kwargs["data"]["client_id"], "fixture")
                testcase.assertEqual(kwargs["data"]["redirect_uri"], "http://127.0.0.1:1455/auth/callback")
                params = parse_qs(urlsplit(calls[-1][1]).query)
                testcase.assertNotEqual(params["state"], ["fixture"])
                challenge = base64.urlsafe_b64encode(hashlib.sha256(kwargs["data"]["code_verifier"].encode()).digest()).decode().rstrip("=")
                testcase.assertEqual(params["code_challenge"], [challenge])
                testcase.assertNotEqual(challenge, "a" * 43)
                calls.append(("POST", url))
                return types.SimpleNamespace(status_code=200, json=lambda: exchanged)

            def close(self):
                pass

        def session(**kwargs):
            self.assertEqual(kwargs["proxy"], data["proxy"])
            return Session()

        self.messages, self.calls = messages, calls
        with patch.object(chatgpt_client, "create_http_session", side_effect=session), patch.object(oauth_client, "create_http_session", side_effect=session), patch.object(socket, "create_connection", side_effect=AssertionError("Network forbidden")), patch.object(runner, "emit", side_effect=lambda event, **fields: messages.append({"event": event, **fields})):
            runner.run(data)

    def test_direct_callback_recovers_with_fresh_pkce_same_proxy_real_exchange(self):
        self.execute()
        result = self.messages[-1]
        self.assertEqual(result["event"], "free_fallback")
        self.assertEqual(result["workspaceId"], "personal-workspace")
        self.assertEqual(result["originalWorkspaceId"], "original-workspace")
        self.assertIs(result["originalWorkspaceUnavailable"], True)
        self.assertEqual(len(self.calls), 3)
        self.assertNotIn("fixture-private-rt", json.dumps(self.messages[:-1]))
        self.assertFalse(any(message["event"] == "complete" for message in self.messages))

    def test_selection_page_recovers_without_vendor_changes(self):
        self.execute(selection_page=True)
        self.assertEqual(self.messages[-1]["event"], "free_fallback")

    def test_wrong_new_state_never_exchanges_or_emits_tokens(self):
        with self.assertRaisesRegex(ValueError, "^fallback_identity$"):
            self.execute(bad_state=True)
        self.assertFalse(any(call[0] == "POST" for call in self.calls))
        self.assertFalse(any(message["event"] == "free_fallback" for message in self.messages))

    def test_missing_original_identity_prevents_new_authorization(self):
        with self.assertRaisesRegex(ValueError, "^fallback_identity$"):
            self.execute(user="")
        self.assertEqual(len(self.calls), 1)

    def test_incomplete_tokens_never_emit_fallback(self):
        with self.assertRaisesRegex(ValueError, "^fallback_identity$"):
            self.execute(bad_tokens=True)
        self.assertFalse(any(message["event"] == "free_fallback" for message in self.messages))


if __name__ == "__main__":
    unittest.main()
