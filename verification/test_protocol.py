import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "protocol"))
spec = importlib.util.spec_from_file_location("runner", ROOT / "protocol" / "runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
EMAIL = "fixture@example.com"
URL = "https://auth.openai.com/oauth/authorize?" + urlencode({"response_type": "code", "client_id": "fixture", "redirect_uri": "http://127.0.0.1:1455/auth/callback", "scope": "openid profile email offline_access api.connectors.read api.connectors.invoke", "code_challenge": "a" * 43, "code_challenge_method": "S256", "id_token_add_organizations": "true", "codex_cli_simplified_flow": "true", "state": "fixture", "originator": "Codex Desktop", "codex_app_version": "fixture", "source_surface_stable_id": "fixture", "codex_origin_stable_id": "fixture", "codex_streamlined_login": "true"})


def desktop_url(inner=URL):
    return "https://chatgpt.com/codex/desktop-auth?" + urlencode({"authorize_url": inner, "codex_streamlined_login": "true", "no_universal_links": "1"})


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
        assert args[0] == URL
        assert kwargs["expected_state"] == "fixture"
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
        for url in [URL.replace("auth.openai.com", "untrusted.example"), URL.replace("https:", "http:"), URL + "&state=duplicate", URL.replace("127.0.0.1", "evil.example")]:
            with self.assertRaises(ValueError):
                runner.authorization(url)

    def test_rs_desktop_url_preserves_exact_inner_parameters(self):
        resolved, state, redirect = runner.authorization(desktop_url())
        self.assertEqual(resolved, URL)
        self.assertEqual(state, "fixture")
        self.assertEqual(redirect.geturl(), "http://127.0.0.1:1455/auth/callback")
        self.assertEqual(runner.authorization(URL), runner.authorization(desktop_url()))

    def test_rs_desktop_url_calls_protocol_with_inner_url(self):
        self.data["authorizationUrl"] = desktop_url()
        self.run_login()
        self.assertEqual(self.messages[-1]["event"], "complete")

    def test_invalid_wrappers_rejected_before_session_creation(self):
        urls = [desktop_url().replace("chatgpt.com/", "chatgpt.com.evil.example/"), desktop_url().replace("https:", "http:", 1), desktop_url().replace("/desktop-auth?", "/other?"), desktop_url("") , desktop_url() + "&authorize_url=", desktop_url(desktop_url()), desktop_url(URL.replace("auth.openai.com", "evil.example")), desktop_url() + "#fragment", desktop_url().replace("chatgpt.com", "user@chatgpt.com"), desktop_url().replace("chatgpt.com", "chatgpt.com:444")]
        with patch.object(Chat, "__init__", side_effect=AssertionError("Must reject before session creation")):
            for url in urls:
                with self.subTest(url=url):
                    self.data["authorizationUrl"] = url
                    with self.assertRaisesRegex(ValueError, "^authorization$"):
                        self.run_login()

    def test_invalid_inner_parameters_and_redirects_rejected(self):
        params = {k: v[0] for k, v in parse_qs(urlsplit(URL).query).items()}
        invalid = [URL + "&state=", URL + "&client_id=", URL + "&code_challenge=", URL + "#fragment", URL.replace("auth.openai.com", "auth.openai.com:444"), URL.replace("auth.openai.com", "user@auth.openai.com"), "\n" + URL]
        for key, value in [("response_type", "token"), ("code_challenge_method", "plain"), ("code_challenge", "short"), ("state", ""), ("redirect_uri", "http://localhost:80/auth/callback"), ("redirect_uri", "http://user@localhost:1455/auth/callback"), ("redirect_uri", "http://localhost:1455/auth/callback?x=1"), ("redirect_uri", "http://localhost:1455/auth/callback#x"), ("state", "bad\nstate")]:
            invalid.append("https://auth.openai.com/oauth/authorize?" + urlencode(params | {key: value}))
        for url in invalid:
            for candidate in [url, desktop_url(url)]:
                with self.subTest(url=candidate), self.assertRaisesRegex(ValueError, "^authorization$"):
                    runner.authorization(candidate)

    def test_wrapped_flow_still_rejects_mismatched_callback_state(self):
        self.data["authorizationUrl"] = desktop_url()
        OAuth.result["state"] = "wrong"
        with self.assertRaisesRegex(ValueError, "^state$"):
            self.run_login()

    def test_legacy_direct_localhost_callback_still_supported(self):
        _, state, redirect = runner.authorization(URL.replace("127.0.0.1", "localhost"))
        self.assertEqual(state, "fixture")
        self.assertEqual(redirect.netloc, "localhost:1455")

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
        self.run_login()
        self.assertEqual(self.messages[-1], {"event": "error", "code": "workspace", "workspaces": [{"id": "other-workspace"}]})

    def test_ambiguous_workspaces_require_explicit_selection(self):
        OAuth.cookie = {"workspaces": [{"id": "original-workspace"}, {"id": "other-workspace"}]}
        self.run_login()
        self.assertEqual(self.messages[-1]["event"], "error")
        self.assertEqual(self.messages[-1]["code"], "workspace")
        self.assertFalse(any(m["event"] == "complete" for m in self.messages))

    def test_workspace_choices_can_be_recovered_from_login_page_fields(self):
        self.assertEqual(runner.workspace_ids_from_text('{"workspace_id":"alternate-workspace","workspaceId":"second-workspace"}', "original-workspace"), ["alternate-workspace", "second-workspace"])

    def test_workspace_session_ids_are_recorded_by_active_binding(self):
        session = {"workspace_id": "other-workspace", "workspaces": [{"id": "second-workspace"}]}
        self.assertEqual([session["workspace_id"], session["workspaces"][0]["id"]], ["other-workspace", "second-workspace"])

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
