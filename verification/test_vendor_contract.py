"""Exercise the unmodified upstream OAuth implementation with an offline HTTP transport."""
import json
import socket
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "protocol"))
import runner
from test_protocol import EMAIL, SECRET, URL, desktop_url
from requests.cookies import RequestsCookieJar
from vendor.lib import chatgpt_client, oauth_client


class OfflineSession:
    def __init__(self, requests, state, workspace):
        self.headers = {}
        self.cookies = RequestsCookieJar()
        self.cookies.set("oai-client-auth-session", json.dumps({"workspace_id": workspace}), domain="auth.openai.com")
        self.requests = requests
        self.state = state

    def request(self, method, url, **kwargs):
        if method != "GET" or url != URL:
            raise AssertionError("Unexpected offline transport request")
        self.requests.append((method, url))
        callback = f"http://127.0.0.1:1455/auth/callback?state={self.state}&code=fixture-code"
        return types.SimpleNamespace(status_code=302, url=url, headers={"Location": callback}, text="")

    def close(self):
        pass


class VendorContractTests(unittest.TestCase):
    def execute(self, url, state="fixture", workspace="original-workspace"):
        self.messages, self.requests = [], []
        data = {"notes": f"{EMAIL}----fixture-password----{SECRET}", "email": EMAIL, "proxy": "http://fixture:pass@127.0.0.1:21001", "authorizationUrl": url, "accountId": "original-workspace"}

        def session(**kwargs):
            self.assertEqual(kwargs["proxy"], data["proxy"])
            return OfflineSession(self.requests, state, workspace)

        with patch.object(chatgpt_client, "create_http_session", side_effect=session), patch.object(oauth_client, "create_http_session", side_effect=session), patch.object(socket, "create_connection", side_effect=AssertionError("Network forbidden")), patch.object(runner, "emit", side_effect=lambda event, **fields: self.messages.append({"event": event, **fields})):
            runner.run(data)

    def test_rs_wrapper_through_real_upstream_redirect_and_callback(self):
        self.execute(desktop_url())
        self.assertEqual(self.requests, [("GET", URL)])
        self.assertEqual(self.messages[-1], {"event": "complete", "callbackUrl": "http://127.0.0.1:1455/auth/callback?state=fixture&code=fixture-code"})
        self.assertNotIn("fixture-code", json.dumps(self.messages[:-1]))

    def test_direct_url_still_uses_real_upstream(self):
        self.execute(URL)
        self.assertEqual(self.requests, [("GET", URL)])
        self.assertEqual(self.messages[-1]["event"], "complete")

    def test_real_upstream_rejects_wrong_callback_state(self):
        self.execute(desktop_url(), state="wrong")
        self.assertFalse(any(message["event"] == "complete" for message in self.messages))
        self.assertEqual(self.messages[-1]["event"], "error")

    def test_real_upstream_cookie_cannot_select_different_workspace(self):
        with self.assertRaisesRegex(ValueError, "^workspace$"):
            self.execute(desktop_url(), workspace="other-workspace")
        self.assertFalse(any(message["event"] == "complete" for message in self.messages))


if __name__ == "__main__":
    unittest.main()
