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
from fallback import personal_candidate, verify_free_tokens, workspace_choices
from test_protocol import EMAIL, SECRET, URL, desktop_url
from requests.cookies import RequestsCookieJar
from vendor.lib import chatgpt_client, oauth_client
from totp import TotpMfaClient

AUTH = "https://api.openai.com/auth"


def jwt(payload):
    return "fixture." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".signature"


def tokens():
    payload = {"sub": "original-subject", "email": EMAIL, "exp": int(time.time()) + 3600,
               AUTH: {"chatgpt_account_id": "personal-workspace", "chatgpt_user_id": "original-user", "chatgpt_plan_type": "free"}}
    return {"id_token": jwt(payload), "access_token": jwt(payload), "refresh_token": "fixture-private-rt"}


class FallbackGuards(unittest.TestCase):
    def test_workspace_choices_are_bounded_ids_only(self):
        self.assertEqual(workspace_choices({"workspace_id": "other"}, "original-workspace"), [{"id": "other"}])
        self.assertEqual(workspace_choices({"workspaces": [{"id": "original-workspace"}, {"id": "other", "name": "private-name", "token": "private-material"}]}, "original-workspace"), [{"id": "other"}])
        for session in [None, {"workspaces": [{"id": "bad\nvalue"}]}, {"workspaces": [{"id": "x"}, {"id": "x"}]}, {"workspaces": [{"id": str(i)} for i in range(31)]}]:
            self.assertEqual(workspace_choices(session, "original-workspace"), [])

    def test_forced_tokens_allow_other_plan_but_preserve_identity_checks(self):
        value = tokens()
        for key in ["id_token", "access_token"]:
            payload = json.loads(base64.urlsafe_b64decode(value[key].split('.')[1] + '=='))
            payload[AUTH]["chatgpt_plan_type"] = "plus"
            value[key] = jwt(payload)
        self.assertEqual(verify_free_tokens(value, EMAIL, "original-user", "personal-workspace", force=True), value)
        with self.assertRaisesRegex(ValueError, "fallback_identity"):
            verify_free_tokens(value, EMAIL, "original-user", "personal-workspace")
        for email, user, workspace in [("wrong@example.com", "original-user", "personal-workspace"), (EMAIL, "wrong-user", "personal-workspace"), (EMAIL, "original-user", "wrong-workspace")]:
            with self.assertRaisesRegex(ValueError, "fallback_identity"):
                verify_free_tokens(value, email, user, workspace, force=True)
        payload = json.loads(base64.urlsafe_b64decode(value["access_token"].split('.')[1] + '=='))
        value["access_token"] = jwt(payload | {"sub": "different-subject"})
        with self.assertRaisesRegex(ValueError, "fallback_identity"):
            verify_free_tokens(value, EMAIL, "original-user", "personal-workspace", force=True)

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
    def execute(self, selection_page=False, bad_state=False, bad_tokens=False, user="original-user", force=False, token_status=200, token_json_invalid=False, invalid_mfa_once=False):
        messages, calls = [], []
        exchanged = tokens()
        if force:
            for key in ["id_token", "access_token"]:
                payload = json.loads(base64.urlsafe_b64decode(exchanged[key].split('.')[1] + '=='))
                payload[AUTH]["chatgpt_plan_type"] = "team"
                exchanged[key] = jwt(payload)
        if bad_tokens:
            exchanged["refresh_token"] = ""
        data = {"notes": f"{EMAIL}----fixture-password----{SECRET}", "email": EMAIL,
                "proxy": "http://fixture:pass@127.0.0.1:21001", "authorizationUrl": desktop_url(),
                "accountId": "original-workspace", "userId": user}
        if force:
            data["forceWorkspaceId"] = "personal-workspace"
        testcase = self
        recovery_queries = []
        mfa_states = iter([409, 200])

        class Session:
            def __init__(self):
                self.headers = {}
                self.cookies = RequestsCookieJar()
                self.cookies.set("oai-client-auth-session", json.dumps({"workspaces": [{"id": "personal-workspace", "is_personal": True}]}), domain="auth.openai.com")

            def request(self, method, url, **kwargs):
                if invalid_mfa_once and method == 'POST':
                    calls.append((method, url))
                    status = 200 if url.endswith('/issue_challenge') else next(mfa_states)
                    body = {'error': {'code': 'invalid_state'}} if status == 409 else {}
                    if url.endswith('/verify') and status == 200:
                        body = {'continue_url': f'http://127.0.0.1:1455/auth/callback?state={recovery_queries[-1]["state"][0]}&code=fixture-code'}
                    return types.SimpleNamespace(status_code=status, url=url, headers={}, text=json.dumps(body), json=lambda: body)
                testcase.assertEqual(method, "GET")
                testcase.assertEqual(urlsplit(url).netloc, "auth.openai.com")
                calls.append((method, url))
                params = parse_qs(urlsplit(url).query)
                if invalid_mfa_once and url != URL:
                    recovery_queries.append(params)
                    return types.SimpleNamespace(status_code=302, url=url, headers={'Location': 'https://auth.openai.com/mfa-challenge/fixture-factor'}, text='')
                if url == URL and selection_page:
                    return types.SimpleNamespace(status_code=200, url="https://auth.openai.com/workspace", headers={}, text="workspaces", json=lambda: {})
                state = "wrong" if bad_state and url != URL else params["state"][0]
                return types.SimpleNamespace(status_code=302, url=url, headers={"Location": f"http://127.0.0.1:1455/auth/callback?state={state}&code=fixture-code"}, text="")

            def post(self, url, **kwargs):
                testcase.assertEqual(url, "https://auth.openai.com/oauth/token")
                testcase.assertEqual(kwargs["data"]["client_id"], "fixture")
                testcase.assertEqual(kwargs["data"]["redirect_uri"], "http://127.0.0.1:1455/auth/callback")
                params = recovery_queries[-1] if invalid_mfa_once else parse_qs(urlsplit(calls[-1][1]).query)
                testcase.assertNotEqual(params["state"], ["fixture"])
                challenge = base64.urlsafe_b64encode(hashlib.sha256(kwargs["data"]["code_verifier"].encode()).digest()).decode().rstrip("=")
                testcase.assertEqual(params["code_challenge"], [challenge])
                testcase.assertNotEqual(challenge, "a" * 43)
                calls.append(("POST", url))
                def read_json():
                    if token_json_invalid:
                        raise ValueError('private-response')
                    return exchanged
                return types.SimpleNamespace(status_code=token_status, json=read_json, text='private-response')

            def close(self):
                pass

        def session(**kwargs):
            self.assertEqual(kwargs["proxy"], data["proxy"])
            return Session()

        self.messages, self.calls, self.recovery_queries = messages, calls, recovery_queries
        with patch.object(TotpMfaClient, 'get_mfa_code', side_effect=['123456', '234567']), patch.object(oauth_client.OAuthClient, '_resolve_totp_factor', return_value={'id': 'fixture-factor'}), patch.object(oauth_client.OAuthClient, '_visit_oauth_page'), patch.object(chatgpt_client, "create_http_session", side_effect=session), patch.object(oauth_client, "create_http_session", side_effect=session), patch.object(socket, "create_connection", side_effect=AssertionError("Network forbidden")), patch.object(runner, "emit", side_effect=lambda event, **fields: messages.append({"event": event, **fields})):
            runner.run(data)

    def test_free_transition_can_restart_with_fresh_pkce_and_no_stale_failure(self):
        self.execute(invalid_mfa_once=True)
        self.assertEqual(self.messages[-1]['event'], 'free_fallback')
        self.assertEqual(self.messages[-1]['workspaceId'], 'personal-workspace')
        self.assertFalse(any(m['event'] == 'error' for m in self.messages))
        self.assertEqual(len(self.recovery_queries), 2)
        self.assertNotEqual(self.recovery_queries[0]['state'], self.recovery_queries[1]['state'])
        self.assertNotEqual(self.recovery_queries[0]['code_challenge'], self.recovery_queries[1]['code_challenge'])
        self.assertEqual(sum(url.endswith('/oauth/token') for _, url in self.calls), 1)

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

    def test_explicit_forced_workspace_uses_fresh_pkce_and_verified_nonfree_tokens(self):
        self.execute(force=True)
        self.assertEqual(self.messages[-1]["event"], "forced_workspace")
        self.assertEqual(self.messages[-1]["workspaceId"], "personal-workspace")
        self.assertIs(self.messages[-1]["administratorConfirmed"], True)
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn("fixture-private-rt", json.dumps(self.messages[:-1]))

    def test_forced_wrong_state_never_emits_or_exchanges_tokens(self):
        self.execute(force=True, bad_state=True)
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertFalse(any(call[0] == "POST" for call in self.calls))

    def test_wrong_new_state_never_exchanges_or_emits_tokens(self):
        self.execute(bad_state=True)
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertFalse(any(call[0] == "POST" for call in self.calls))
        self.assertFalse(any(message["event"] == "free_fallback" for message in self.messages))

    def test_missing_original_identity_prevents_new_authorization(self):
        self.execute(user="")
        self.assertEqual(self.messages[-1]['code'], 'fallback_identity')
        self.assertEqual(self.messages[-1]['diagnostic']['stage'], 'identity')
        self.assertEqual(len(self.calls), 1)

    def test_incomplete_tokens_never_emit_fallback(self):
        self.execute(bad_tokens=True)
        self.assertEqual(self.messages[-1]['code'], 'fallback_identity')
        self.assertEqual(self.messages[-1]['diagnostic']['stage'], 'identity')
        self.assertIsNone(self.messages[-1]['diagnostic']['httpStatus'])
        self.assertFalse(any(message["event"] == "free_fallback" for message in self.messages))

    def test_direct_token_exchange_retains_actual_http_failure(self):
        self.execute(token_status=503)
        self.assertEqual(self.messages[-1]['diagnostic'], {'stage': 'token_exchange', 'reason': 'upstream_unavailable', 'httpStatus': 503})
        self.assertNotIn('private-response', json.dumps(self.messages))
        self.assertFalse(any(message['event'] == 'free_fallback' for message in self.messages))

    def test_token_exchange_parse_failure_is_not_reported_as_proxy_or_identity(self):
        self.execute(token_json_invalid=True)
        self.assertEqual(self.messages[-1]['diagnostic'], {'stage': 'token_exchange', 'reason': 'response_invalid_json', 'httpStatus': 200})
        self.assertNotIn('private-response', json.dumps(self.messages))


class RealVendorForcedFreeConsent(unittest.TestCase):
    def execute(self, workspaces=None, *, cookie=None, changed_tokens=None, bad_state=False, direct=False, selection_status=302):
        self.messages, self.calls = [], []
        exchanged = changed_tokens or tokens()
        if cookie is None:
            cookie = {'workspaces': workspaces if workspaces is not None else [
                {'id': 'personal-workspace', 'is_personal': True},
            ]}
        data = {'notes': f'{EMAIL}----fixture-password----{SECRET}', 'email': EMAIL,
                'proxy': 'http://fixture:pass@127.0.0.1:21001', 'authorizationUrl': desktop_url(),
                'accountId': 'original-workspace', 'userId': 'original-user', 'forceFree': True}
        testcase = self
        authorization = {}
        consent = 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent'

        def response(url, status, *, location=None, body=None):
            return types.SimpleNamespace(status_code=status, url=url,
                headers={'Location': location} if location else {},
                text=json.dumps(body or {}), json=lambda: body or {})

        def callback():
            state = 'wrong' if bad_state else authorization['state'][0]
            return f'http://127.0.0.1:1455/auth/callback?state={state}&code=fixture-code'

        class Session:
            def __init__(self):
                self.headers = {}
                self.cookies = RequestsCookieJar()
                self.cookies.set('oai-client-auth-session', json.dumps(cookie), domain='auth.openai.com')

            def request(self, method, url, **kwargs):
                testcase.calls.append((method, url))
                if method == 'GET' and urlsplit(url).path == '/oauth/authorize':
                    authorization.update(parse_qs(urlsplit(url).query))
                    return response(url, 302, location=callback() if direct else consent)
                if method == 'GET' and url == consent:
                    return response(url, 200, body={'page': {'type': 'codex_consent'}})
                if method == 'POST' and url == 'https://auth.openai.com/api/accounts/workspace/select':
                    testcase.assertEqual(kwargs['json'], {'workspace_id': 'personal-workspace'})
                    if selection_status != 302:
                        return response(url, selection_status, body={'error': {'code': 'private-error'}})
                    return response(url, 302, location=callback())
                raise AssertionError('Unexpected offline request')

            def post(self, url, **kwargs):
                testcase.assertEqual(url, 'https://auth.openai.com/oauth/token')
                verifier = kwargs['data']['code_verifier']
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
                testcase.assertEqual(authorization['code_challenge'], [challenge])
                testcase.assertNotEqual(challenge, 'a' * 43)
                testcase.assertNotEqual(authorization['state'], ['fixture'])
                testcase.calls.append(('POST', url))
                return response(url, 200, body=exchanged)

            def get(self, url, **kwargs):
                testcase.assertEqual(url, 'https://auth.openai.com/api/accounts/client_auth_session_dump')
                testcase.calls.append(('GET', url))
                return response(url, 200, body=cookie)

            def close(self):
                pass

        def session(**kwargs):
            self.assertEqual(kwargs['proxy'], data['proxy'])
            return Session()

        with patch.object(chatgpt_client, 'create_http_session', side_effect=session), patch.object(oauth_client, 'create_http_session', side_effect=session), patch.object(socket, 'create_connection', side_effect=AssertionError('Network forbidden')), patch.object(runner, 'emit', side_effect=lambda event, **fields: self.messages.append({'event': event, **fields})):
            runner.run(data)

    def assert_no_writeback(self):
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertFalse(any(m['event'] in {'complete', 'free_fallback', 'forced_free', 'forced_workspace'} for m in self.messages))
        for secret in ['fixture-password', SECRET, 'fixture:pass', 'fixture-private-rt', 'fixture-code', 'private-error']:
            self.assertNotIn(secret, json.dumps(self.messages))

    def test_consent_selects_personal_then_verifies_fresh_pkce_and_free_identity(self):
        self.execute()
        self.assertEqual(self.messages[-1]['event'], 'forced_free')
        self.assertEqual(self.messages[-1]['workspaceId'], 'personal-workspace')
        self.assertTrue(self.messages[-1]['administratorConfirmed'])
        self.assertEqual([method for method, _ in self.calls], ['GET', 'GET', 'POST', 'POST'])
        self.assertNotIn('fixture-private-rt', json.dumps(self.messages[:-1]))

    def test_explicit_free_can_select_personal_even_if_original_team_is_listed(self):
        self.execute([{'id': 'original-workspace', 'type': 'team'}, {'id': 'personal-workspace', 'type': 'personal'}])
        self.assertEqual(self.messages[-1]['event'], 'forced_free')

    def test_single_untyped_workspace_still_requires_verified_free_tokens(self):
        self.execute([{'id': 'personal-workspace'}])
        self.assertEqual(self.messages[-1]['event'], 'forced_free')

    def test_unique_workspace_id_cookie_is_supported(self):
        self.execute(cookie={'workspace_id': 'personal-workspace'})
        self.assertEqual(self.messages[-1]['event'], 'forced_free')

    def test_direct_callback_still_requires_identity_without_workspace_selection(self):
        self.execute(cookie={}, direct=True)
        self.assertEqual(self.messages[-1]['event'], 'forced_free')
        self.assertEqual(len(self.calls), 2)

    def test_ambiguous_candidates_do_not_select_first_workspace(self):
        for workspaces in [
            [{'id': 'personal-workspace', 'is_personal': True}, {'id': 'second', 'is_personal': True}],
            [{'id': 'personal-workspace'}, {'id': 'second'}],
        ]:
            with self.subTest(workspaces=workspaces):
                self.execute(workspaces)
                self.assert_no_writeback()
                self.assertEqual(self.messages[-1]['diagnostic']['reason'], 'free_workspace_ambiguous')
                self.assertFalse(any(method == 'POST' for method, _ in self.calls))

    def test_missing_invalid_or_nonfree_workspaces_stop_with_specific_reason(self):
        for cookie, reason in [
            ({}, 'free_workspace_missing'),
            ({'workspaces': []}, 'free_workspace_missing'),
            ({'workspaces': [{'id': 'bad\nvalue'}]}, 'free_workspace_missing'),
            ({'workspaces': [{'id': 'original-workspace', 'is_personal': True}]}, 'free_workspace_missing'),
            ({'workspaces': [{'id': 'personal-workspace', 'type': 'team'}]}, 'free_workspace_missing'),
            ({'workspaces': [{'id': 'personal-workspace', 'type': 'personal', 'plan_type': 'plus'}]}, 'free_workspace_missing'),
            ({'workspaces': [{'id': 'personal-workspace'}, {'id': 'personal-workspace'}]}, 'free_workspace_ambiguous'),
        ]:
            with self.subTest(cookie=cookie):
                self.execute(cookie=cookie)
                self.assert_no_writeback()
                self.assertEqual(self.messages[-1]['diagnostic'], {'stage': 'workspace', 'reason': reason, 'httpStatus': 200})
                self.assertFalse(any(method == 'POST' for method, _ in self.calls))

    def test_wrong_state_never_exchanges_tokens(self):
        self.execute(bad_state=True)
        self.assert_no_writeback()
        self.assertFalse(any(url.endswith('/oauth/token') for _, url in self.calls))

    def test_nonfree_or_other_user_tokens_never_emit_writeback(self):
        for field, value in [('chatgpt_plan_type', 'plus'), ('chatgpt_user_id', 'other-user'), ('chatgpt_account_id', 'original-workspace'), ('chatgpt_account_id', 'another-personal-workspace')]:
            changed = tokens()
            for key in ['id_token', 'access_token']:
                payload = json.loads(base64.urlsafe_b64decode(changed[key].split('.')[1] + '=='))
                payload[AUTH][field] = value
                changed[key] = jwt(payload)
            with self.subTest(field=field):
                self.execute(changed_tokens=changed)
                self.assert_no_writeback()
                self.assertEqual(self.messages[-1]['diagnostic']['reason'], 'identity_unconfirmed')

    def test_workspace_http_failure_retains_actual_stage_and_status(self):
        self.execute(selection_status=403)
        self.assert_no_writeback()
        self.assertEqual(self.messages[-1]['diagnostic'], {'stage': 'workspace', 'reason': 'http_rejected', 'httpStatus': 403})


if __name__ == "__main__":
    unittest.main()
