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
    def mfa_failure(self, issue_status, verify_status=200):
        messages = []
        data = {'notes': f'{EMAIL}----fixture-password----{SECRET}', 'email': EMAIL, 'proxy': 'http://fixture:pass@127.0.0.1:21001', 'authorizationUrl': URL, 'accountId': 'original-workspace'}
        class Session:
            def __init__(self):
                self.cookies = RequestsCookieJar()
                self.headers = {}
            def close(self):
                pass
            def request(self, method, url, **kwargs):
                if method == 'GET' and url == URL:
                    return types.SimpleNamespace(status_code=302, url=url, headers={'Location':'https://auth.openai.com/mfa-challenge/fixture-factor'}, text='')
                assert method == 'POST'
                assert url in {'https://auth.openai.com/api/accounts/mfa/issue_challenge', 'https://auth.openai.com/api/accounts/mfa/verify'}
                status = issue_status if url.endswith('issue_challenge') else verify_status
                body = {} if status == 200 else {'error': {'code': 'unknown-upstream-code', 'message': 'private-body fixture-password'}}
                return types.SimpleNamespace(status_code=status, url=url, headers={}, text=json.dumps(body), json=lambda:body)
        with patch.object(chatgpt_client, 'create_http_session', side_effect=lambda **kwargs: Session()), patch.object(oauth_client, 'create_http_session', side_effect=lambda **kwargs: Session()), patch.object(oauth_client.OAuthClient, '_resolve_totp_factor', return_value={'id':'fixture-factor', 'factor_type':'totp'}), patch.object(oauth_client.OAuthClient, '_visit_oauth_page'), patch.object(socket, 'create_connection', side_effect=AssertionError('Network forbidden')), patch.object(runner, 'emit', side_effect=lambda event, **fields:messages.append({'event':event, **fields})):
            runner.run(data)
        return messages

    def test_real_mfa_issue_failure_retains_stage_and_status_without_raw_body(self):
        messages = self.mfa_failure(403)
        self.assertEqual(messages[-1]['diagnostic'], {'stage':'mfa_issue', 'reason':'mfa_issue_failed', 'httpStatus':403})
        self.assertNotIn('fixture-password', json.dumps(messages))
        self.assertNotIn('private-body', json.dumps(messages))

    def test_real_mfa_verify_rate_limit_is_not_wrong_secret(self):
        messages = self.mfa_failure(200, 429)
        self.assertEqual(messages[-1]['code'], 'limited')
        self.assertEqual(messages[-1]['diagnostic'], {'stage':'mfa_verify', 'reason':'rate_limited', 'httpStatus':429})

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
        self.execute(desktop_url(), workspace="other-workspace")
        self.assertEqual(self.messages[-1], {"event": "error", "code": "workspace", "workspaces": [{"id": "other-workspace"}]})
        self.assertFalse(any(message["event"] == "complete" for message in self.messages))


if __name__ == "__main__":
    unittest.main()
