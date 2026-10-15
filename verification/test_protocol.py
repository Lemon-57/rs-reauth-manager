import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "protocol"))
spec = importlib.util.spec_from_file_location("runner", ROOT / "protocol" / "runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
EMAIL = "fixture@example.com"
URL = "https://auth.openai.com/oauth/authorize?state=fixture&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback&client_id=fixture&code_challenge=fixture"


class Session:
    def close(self):
        pass


class Chat:
    def __init__(self, **kwargs):
        assert kwargs["proxy"] == "http://fixture:pass@127.0.0.1:21001"
        self.session = Session()
        self.ua = "fixture"
        self.impersonate = "chrome133a"


class OAuth:
    cookie = {"workspace_id": "original-workspace"}
    result = {"ok": True, "state": "fixture", "code": "fixture-code"}

    def __init__(self, config, **kwargs):
        self.session = Session()

    def _decode_oauth_session_cookie(self):
        return self.cookie

    def authorize_external_oauth_url(self, *args, **kwargs):
        kwargs["mfa_client"].get_mfa_code(timeout=5)
        return self.result


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.messages = []
        self.data = {"notes": f"{EMAIL}----fixture-password----{SECRET}", "email": EMAIL, "proxy": "http://fixture:pass@127.0.0.1:21001", "authorizationUrl": URL, "accountId": "original-workspace"}
        self.chat = types.ModuleType("vendor.lib.chatgpt_client")
        self.chat.ChatGPTClient = Chat
        self.oauth = types.ModuleType("vendor.lib.oauth_client")
        self.oauth.OAuthClient = OAuth
        OAuth.result = {"ok": True, "state": "fixture", "code": "fixture-code"}
        OAuth.cookie = {"workspace_id": "original-workspace"}

    def run_login(self):
        with patch.dict(sys.modules, {"vendor.lib.chatgpt_client": self.chat, "vendor.lib.oauth_client": self.oauth}), patch.object(runner, "emit", side_effect=lambda event, **kw: self.messages.append({"event": event, **kw})):
            runner.run(self.data)

    def test_notes_exact_format_and_email(self):
        self.assertEqual(runner.parse_notes(self.data["notes"], EMAIL)[0], EMAIL)
        for notes in [self.data["notes"].replace(EMAIL, "other@example.com"), self.data["notes"] + "----extra", "missing", self.data["notes"] + "\nnew"]:
            with self.assertRaises(ValueError):
                runner.parse_notes(notes, EMAIL)

    def test_password_keeps_whitespace(self):
        self.assertEqual(runner.parse_notes(f"{EMAIL}---- space password ----{SECRET}", EMAIL)[1], " space password ")

    def test_mfa_invalid_rejected(self):
        with self.assertRaises(ValueError):
            runner.parse_notes(f"{EMAIL}----fixture----not-base32-!", EMAIL)

    def test_auth_url_trusted_origin(self):
        for url in [URL.replace("auth.openai.com", "untrusted.example"), URL.replace("https:", "http:"), URL + "&state=duplicate", URL.replace("localhost", "evil.example")]:
            with self.assertRaises(ValueError):
                runner.authorization(url)

    def test_login_callback_and_secret_free_progress(self):
        self.run_login()
        self.assertEqual(self.messages[-1]["event"], "complete")
        self.assertIn("state=fixture", self.messages[-1]["callbackUrl"])
        progress = json.dumps(self.messages[:-1])
        for secret in [SECRET, "fixture-password", "fixture:pass", "fixture-code", EMAIL]:
            self.assertNotIn(secret, progress)

    def test_mismatched_state_stops(self):
        OAuth.result["state"] = "wrong"
        with self.assertRaisesRegex(ValueError, "state"):
            self.run_login()

    def test_other_workspace_stops_before_writeback(self):
        OAuth.cookie = {"workspace_id": "other-workspace", "workspaces": [{"id": "other-workspace"}]}
        with self.assertRaisesRegex(ValueError, "workspace"):
            self.run_login()

    def test_ambiguous_workspaces_require_explicit_selection(self):
        OAuth.cookie = {"workspaces": [{"id": "original-workspace"}, {"id": "other-workspace"}]}
        with self.assertRaisesRegex(ValueError, "workspace"):
            self.run_login()

    def test_single_matching_workspace(self):
        OAuth.cookie = {"workspaces": [{"id": "original-workspace"}]}
        self.run_login()
        self.assertEqual(self.messages[-1]["event"], "complete")

    def test_human_verification_not_bypassed(self):
        OAuth.result = {"ok": False, "error": "phone_required"}
        self.run_login()
        self.assertEqual(self.messages[-1], {"event": "error", "code": "human"})

    def test_no_direct_fallback(self):
        self.data["proxy"] = ""
        with self.assertRaisesRegex(ValueError, "proxy"):
            self.run_login()


if __name__ == "__main__":
    unittest.main()
