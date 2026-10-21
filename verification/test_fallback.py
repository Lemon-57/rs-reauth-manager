"""Offline workspace guards and the unmodified upstream authorization-code flow."""
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


class AutomaticWorkspaceTransitions(unittest.TestCase):
    def execute(self, plan='free', workspaces=None, *, html_only=False, token_plan='team', wrong_user=False, page_workspaces=None, automatic=False, token_workspace=None, recorded_workspace=None):
        self.messages, self.calls = [], []
        source = recorded_workspace or ('personal-workspace' if plan == 'free' else 'old-team')
        target = source if automatic else 'new-team' if plan == 'free' else 'personal-workspace'
        workspaces = workspaces if workspaces is not None else [
            {'id': 'personal-workspace', 'type': 'personal', 'plan_type': 'free'},
            *([{'id': 'new-team', 'type': 'team', 'plan_type': 'team'}] if plan == 'free' else []),
        ]
        cookie = {} if html_only else {'workspaces': workspaces}
        data = {'notes': f'{EMAIL}----fixture-password----{SECRET}', 'email': EMAIL, 'proxy': 'http://fixture:pass@127.0.0.1:21001', 'authorizationUrl': desktop_url(), 'accountId': source, 'userId': 'original-user', 'planType': plan, 'automatic': automatic}
        query = {}
        testcase = self
        consent = 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent'
        value = tokens()
        for key in ['access_token', 'id_token']:
            payload = json.loads(base64.urlsafe_b64decode(value[key].split('.')[1] + '=='))
            payload[AUTH].update(chatgpt_account_id=token_workspace or target, chatgpt_plan_type=token_plan, chatgpt_user_id='wrong-user' if wrong_user else 'original-user')
            value[key] = jwt(payload)
        def response(url, status=200, body=None, location=None):
            return types.SimpleNamespace(url=url, status_code=status, headers={'Location': location} if location else {}, text=json.dumps(body or {}), json=lambda: body or {})
        class Session:
            def __init__(self):
                self.headers, self.cookies = {}, RequestsCookieJar()
                self.cookies.set('oai-client-auth-session', json.dumps(cookie), domain='auth.openai.com')
            def close(self):
                pass
            def request(self, method, url, **kwargs):
                testcase.calls.append((method, url, kwargs.get('json')))
                if method == 'GET' and urlsplit(url).path == '/oauth/authorize':
                    query.update(parse_qs(urlsplit(url).query))
                    return response(url, 302, location=consent)
                if method == 'GET' and url == consent:
                    return response(url, body={'workspaces': page_workspaces if page_workspaces is not None else workspaces})
                if method == 'POST' and url.endswith('/workspace/select'):
                    selected = kwargs['json']['workspace_id']
                    testcase.assertIn(selected, {source, target})
                    return response(url, 302, location=f'http://127.0.0.1:1455/auth/callback?state={query["state"][0]}&code=fixture-code')
                raise AssertionError('Unexpected offline request')
            def get(self, url, **kwargs):
                testcase.assertTrue(url.endswith('/client_auth_session_dump'))
                return response(url, 403)
            def post(self, url, **kwargs):
                testcase.assertTrue(url.endswith('/oauth/token'))
                testcase.assertFalse(kwargs['allow_redirects'])
                testcase.assertNotEqual(query['state'], ['fixture'])
                verifier = kwargs['data']['code_verifier']
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
                testcase.assertEqual(query['code_challenge'], [challenge])
                testcase.calls.append(('POST', url, None))
                return response(url, body=value)
        def session(**kwargs):
            self.assertEqual(kwargs['proxy'], data['proxy'])
            return Session()
        with patch.object(chatgpt_client, 'create_http_session', side_effect=session), patch.object(oauth_client, 'create_http_session', side_effect=session), patch.object(socket, 'create_connection', side_effect=AssertionError('Network forbidden')), patch.object(runner, 'emit', side_effect=lambda event, **kw: self.messages.append({'event': event, **kw})):
            runner.run(data)

    def test_free_with_unique_team_returns_native_workspace_callback(self):
        for html_only in [False, True]:
            with self.subTest(html_only=html_only):
                self.execute(html_only=html_only)
                self.assertEqual(self.messages[-1]['event'], 'team_upgrade')
                self.assertEqual(self.messages[-1]['workspaceId'], 'new-team')
                self.assertTrue(self.messages[-1]['uniqueTeamConfirmed'])
                selected = [body['workspace_id'] for _, url, body in self.calls if url.endswith('/workspace/select')]
                self.assertEqual(selected, ['new-team'])

    def test_team_membership_matching_stale_record_is_still_selected_once(self):
        for html_only in [False, True]:
            self.execute(recorded_workspace='new-team', html_only=html_only)
            self.assertEqual(self.messages[-1]['event'], 'team_upgrade')
            self.assertEqual(self.messages[-1]['workspaceId'], 'new-team')
            self.assertEqual([body['workspace_id'] for _, url, body in self.calls if url.endswith('/workspace/select')], ['new-team'])
            self.assertFalse(any(url.endswith('/oauth/token') for _, url, _ in self.calls))

    def test_live_organization_kind_is_verified_as_team_before_upgrade(self):
        workspaces = [
            {'id': 'new-team', 'kind': 'organization'},
            {'id': 'personal-workspace', 'kind': 'personal'},
        ]
        for html_only in [False, True]:
            with self.subTest(html_only=html_only):
                self.execute(workspaces=workspaces, html_only=html_only)
                self.assertEqual(self.messages[-1]['event'], 'team_upgrade')
                self.assertEqual(self.messages[-1]['workspaceId'], 'new-team')
                selected = [body['workspace_id'] for _, url, body in self.calls if url.endswith('/workspace/select')]
                self.assertEqual(selected, ['new-team'])

    def test_organization_authorization_returns_code_for_native_identity_validation(self):
        for plan in ['free','plus','enterprise','team']:
            self.execute(workspaces=[{'id':'new-team','kind':'organization'},{'id':'personal-workspace','kind':'personal'}],html_only=True,token_plan=plan)
            self.assertEqual(self.messages[-1]['event'],'team_upgrade')
            self.assertIn('state=fixture',self.messages[-1]['callbackUrl'])
            self.assertNotIn('tokens',self.messages[-1])
            self.assertFalse(any(url.endswith('/oauth/token') for _,url,_ in self.calls))

    def test_multiple_organizations_require_manual_workspace_choice(self):
        self.execute(html_only=True, workspaces=[
            {'id': 'personal-workspace', 'kind': 'personal'},
            {'id': 'new-team', 'kind': 'organization'},
            {'id': 'second-team', 'kind': 'organization'},
        ])
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertEqual(self.messages[-1]['code'], 'workspace')
        self.assertFalse(any(method == 'POST' for method, _, _ in self.calls))

    def test_conflicting_personal_or_nonteam_organization_is_not_selected(self):
        for fields in [{'is_personal': True}, {'type': 'personal'}, {'plan_type': 'plus'}, {'plan_type': 'enterprise'}]:
            with self.subTest(fields=fields):
                self.execute(html_only=True, workspaces=[
                    {'id': 'personal-workspace', 'kind': 'personal'},
                    {'id': 'new-team', 'kind': 'organization', **fields},
                ])
                self.assertEqual(self.messages[-1]['event'], 'complete')
                self.assertFalse(any(url.endswith('/oauth/token') for _, url, _ in self.calls))

    def test_team_only_free_remaining_automatically_falls_back(self):
        self.execute(plan='team', token_plan='free')
        self.assertEqual(self.messages[-1]['event'], 'free_fallback')
        self.assertEqual(self.messages[-1]['workspaceId'], 'personal-workspace')

    def test_existing_team_remains_bound_even_with_other_teams(self):
        self.execute(plan='team', workspaces=[{'id': 'old-team', 'type': 'team'}, {'id': 'another-team', 'type': 'team'}])
        self.assertEqual(self.messages[-1]['event'], 'complete')
        self.assertFalse(any(url.endswith('/oauth/token') for _, url, _ in self.calls))

    def test_multiple_team_candidates_require_manual_choice(self):
        self.execute(workspaces=[{'id': 'personal-workspace', 'type': 'personal'}, {'id': 'one-team', 'type': 'team'}, {'id': 'two-team', 'type': 'team'}])
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertEqual(self.messages[-1]['code'], 'workspace')
        self.assertEqual({w['id'] for w in self.messages[-1]['workspaces']}, {'one-team', 'two-team'})
        self.assertFalse(any(method == 'POST' for method, _, _ in self.calls))

    def test_cookie_single_team_cannot_override_two_teams_on_current_page(self):
        self.execute(page_workspaces=[{'id': 'new-team', 'type': 'team'}, {'id': 'second-team', 'type': 'team'}])
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertEqual(self.messages[-1]['code'], 'workspace')
        self.assertFalse(any(method == 'POST' for method, _, _ in self.calls))

    def test_cookie_only_original_free_can_still_select_it_on_plain_consent_page(self):
        self.execute(workspaces=[{'id': 'personal-workspace', 'type': 'personal'}], page_workspaces=[])
        self.assertEqual(self.messages[-1]['event'], 'complete')

    def test_conflicting_team_metadata_is_not_accepted_as_unique(self):
        self.execute(page_workspaces=[{'id': 'new-team', 'type': 'personal'}])
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertEqual(self.messages[-1]['diagnostic']['reason'], 'workspace_evidence_invalid')

    def test_free_without_team_keeps_personal_workspace(self):
        self.execute(workspaces=[{'id': 'personal-workspace', 'type': 'personal', 'plan_type': 'free'}])
        self.assertEqual(self.messages[-1]['event'], 'complete')

    def test_unknown_membership_is_not_automatically_promoted(self):
        self.execute(workspaces=[{'id': 'personal-workspace', 'type': 'personal'}, {'id': 'new-team'}])
        self.assertEqual(self.messages[-1]['event'], 'complete')

    def test_team_upgrade_never_accepts_or_exchanges_plugin_tokens(self):
        self.execute(token_plan='free',wrong_user=True)
        self.assertEqual(self.messages[-1]['event'],'team_upgrade')
        self.assertNotIn('tokens',self.messages[-1])
        self.assertFalse(any(url.endswith('/oauth/token') for _,url,_ in self.calls))

    def test_other_team_remaining_does_not_trigger_automatic_free_downgrade(self):
        self.execute(plan='team', token_plan='free', workspaces=[{'id': 'personal-workspace', 'type': 'personal'}, {'id': 'other-team', 'type': 'team'}])
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertEqual(self.messages[-1]['code'], 'workspace')


    def test_unattended_preserves_original_team_and_rs_pkce(self):
        self.execute(plan='team',automatic=True,workspaces=[{'id':'old-team','type':'team'},{'id':'another-team','type':'team'}])
        self.assertEqual(self.messages[-1]['event'],'complete')
        self.assertIn('state=fixture',self.messages[-1]['callbackUrl'])
        self.assertEqual([b['workspace_id'] for _,u,b in self.calls if u.endswith('/workspace/select')],['old-team'])
        self.assertFalse(any(u.endswith('/oauth/token') for _,u,_ in self.calls))

    def test_unattended_free_does_not_upgrade_to_team(self):
        self.execute(plan='free',token_plan='free',automatic=True)
        self.assertEqual(self.messages[-1]['event'],'complete')
        self.assertNotIn('tokens',self.messages[-1])

    def test_unattended_emits_no_credentials_before_native_validation(self):
        self.execute(plan='team',automatic=True,workspaces=[{'id':'old-team','type':'team'}],wrong_user=True)
        self.assertEqual(self.messages[-1]['event'],'complete')
        self.assertNotIn('tokens',self.messages[-1])
        self.assertFalse(any(u.endswith('/oauth/token') for _,u,_ in self.calls))

    def test_unattended_missing_original_workspace_never_downgrades(self):
        self.execute(plan='team', token_plan='free', automatic=True)
        self.assertEqual(self.messages[-1]['event'], 'error')
        self.assertFalse(any(url.endswith('/oauth/token') for _, url, _ in self.calls))


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
                        self.authenticated = True
                        body = {'continue_url': f'http://127.0.0.1:1455/auth/callback?state={recovery_queries[-1]["state"][0]}&code=fixture-code'}
                    return types.SimpleNamespace(status_code=status, url=url, headers={}, text=json.dumps(body), json=lambda: body)
                testcase.assertEqual(method, "GET")
                testcase.assertEqual(urlsplit(url).netloc, "auth.openai.com")
                calls.append((method, url))
                params = parse_qs(urlsplit(url).query)
                if invalid_mfa_once and not getattr(self,'authenticated',False) and sum(m == 'GET' and u == URL for m, u in calls) > 1:
                    recovery_queries.append(params)
                    return types.SimpleNamespace(status_code=302, url=url, headers={'Location': 'https://auth.openai.com/mfa-challenge/fixture-factor'}, text='')
                if url == URL and selection_page and sum(m == 'GET' and u == URL for m, u in calls) == 1:
                    return types.SimpleNamespace(status_code=200, url="https://auth.openai.com/workspace", headers={}, text="workspaces", json=lambda: {})
                state = "wrong" if bad_state else params["state"][0]
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

    def test_free_transition_restart_retains_rs_state_and_pkce(self):
        self.execute(invalid_mfa_once=True)
        self.assertEqual(self.messages[-1]['event'],'free_fallback')
        self.assertTrue(self.recovery_queries)
        for query in self.recovery_queries:
            self.assertEqual(query['state'],['fixture'])
            self.assertEqual(query['code_challenge'],['a'*43])
        self.assertFalse(any(u.endswith('/oauth/token') for _,u in self.calls))

    def test_direct_callback_retains_rs_state_pkce_and_original_proxy(self):
        self.execute()
        self.assertEqual(self.messages[-1]['event'],'free_fallback')
        self.assertEqual(self.messages[-1]['workspaceId'],'personal-workspace')
        self.assertIn('state=fixture',self.messages[-1]['callbackUrl'])
        self.assertNotIn('tokens',self.messages[-1])
        self.assertEqual(len(self.calls),2)
        for _,url in self.calls:
            self.assertEqual(parse_qs(urlsplit(url).query)['code_challenge'],['a'*43])

    def test_selection_page_recovers_without_vendor_changes(self):
        self.execute(selection_page=True)
        self.assertEqual(self.messages[-1]["event"], "free_fallback")

    def test_explicit_forced_workspace_returns_only_the_native_callback(self):
        self.execute(force=True)
        self.assertEqual(self.messages[-1]['event'],'forced_workspace')
        self.assertEqual(self.messages[-1]['workspaceId'],'personal-workspace')
        self.assertTrue(self.messages[-1]['administratorConfirmed'])
        self.assertEqual(len(self.calls),1)
        self.assertNotIn('tokens',self.messages[-1])

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

    def test_plugin_does_not_receive_fallback_tokens(self):
        self.execute(bad_tokens=True)
        self.assertEqual(self.messages[-1]['event'],'free_fallback')
        self.assertNotIn('tokens',self.messages[-1])
        self.assertFalse(any(u.endswith('/oauth/token') for _,u in self.calls))

    def test_plugin_does_not_call_token_service_even_if_it_would_fail(self):
        self.execute(token_status=503)
        self.assertEqual(self.messages[-1]['event'],'free_fallback')
        self.assertFalse(any(u.endswith('/oauth/token') for _,u in self.calls))

    def test_plugin_never_follows_token_redirects(self):
        self.execute(token_status=307)
        self.assertEqual(self.messages[-1]['event'],'free_fallback')
        self.assertFalse(any(u.endswith('/oauth/token') for _,u in self.calls))

    def test_native_exchange_result_is_not_parsed_by_protocol_worker(self):
        self.execute(token_json_invalid=True)
        self.assertEqual(self.messages[-1]['event'],'free_fallback')
        self.assertNotIn('tokens',self.messages[-1])


class RealVendorForcedFreeConsent(unittest.TestCase):
    def execute(self, workspaces=None, *, cookie=None, changed_tokens=None, bad_state=False, direct=False, selection_status=302, html_text=None, dump_status=200, dump_timeout=False, intermediate=False, intermediate_status=200, source_plan=None):
        self.messages, self.calls = [], []
        exchanged = changed_tokens or tokens()
        if cookie is None:
            cookie = {'workspaces': workspaces if workspaces is not None else [
                {'id': 'personal-workspace', 'is_personal': True},
            ]}
        data = {'notes': f'{EMAIL}----fixture-password----{SECRET}', 'email': EMAIL,
                'proxy': 'http://fixture:pass@127.0.0.1:21001', 'authorizationUrl': desktop_url(),
                'accountId': 'original-workspace', 'userId': 'original-user', 'forceFree': True}
        if source_plan is not None:
            data['planType'] = source_plan
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
                    if intermediate:
                        return response(url, 200, body={'continue_url': 'https://auth.openai.com/next-consent'})
                    if html_text is not None:
                        return types.SimpleNamespace(status_code=200, url=url, headers={}, text=html_text, json=lambda: {})
                    return response(url, 200, body={'page': {'type': 'codex_consent'}})
                if method == 'GET' and url == 'https://auth.openai.com/next-consent':
                    if intermediate_status != 200:
                        return response(url, intermediate_status)
                    return types.SimpleNamespace(status_code=200, url=url, headers={}, text=html_text or '{"workspace_id":"personal-workspace"}', json=lambda: {})
                if method == 'POST' and url == 'https://auth.openai.com/api/accounts/workspace/select':
                    testcase.assertEqual(kwargs['json'], {'workspace_id': 'original-workspace' if source_plan == 'free' else 'personal-workspace'})
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
                if dump_timeout:
                    raise TimeoutError('private-proxy')
                return response(url, dump_status, body=cookie if dump_status == 200 else {})

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

    def test_consent_selects_personal_then_returns_rs_native_callback(self):
        self.execute()
        self.assertEqual(self.messages[-1]['event'], 'forced_free')
        self.assertEqual(self.messages[-1]['workspaceId'], 'personal-workspace')
        self.assertTrue(self.messages[-1]['administratorConfirmed'])
        self.assertEqual([method for method, _ in self.calls], ['GET', 'GET', 'POST'])
        self.assertNotIn('fixture-private-rt', json.dumps(self.messages[:-1]))

    def test_explicit_free_verification_can_refresh_same_original_free_workspace(self):
        changed = tokens()
        for key in ['id_token', 'access_token']:
            payload = json.loads(base64.urlsafe_b64decode(changed[key].split('.')[1] + '=='))
            payload[AUTH]['chatgpt_account_id'] = 'original-workspace'
            changed[key] = jwt(payload)
        self.execute([{'id': 'original-workspace', 'type': 'personal', 'plan_type': 'free'}], changed_tokens=changed, source_plan='free')
        self.assertEqual(self.messages[-1]['event'], 'forced_free')
        self.assertEqual(self.messages[-1]['workspaceId'], 'original-workspace')

    def test_cookie_dump_403_does_not_block_html_workspace_fallback(self):
        self.execute(cookie={}, dump_status=403, html_text='<script type="application/json">{"workspace_id":"personal-workspace"}</script>')
        self.assertEqual(self.messages[-1]['event'], 'forced_free')
        self.assertEqual(self.messages[-1]['workspaceId'], 'personal-workspace')
        self.assertEqual(sum(url.endswith('/workspace/select') for _, url in self.calls), 1)

    def test_bootstrap_assignments_do_not_block_real_vendor_free_recovery(self):
        bootstrap = '<script>'+''.join(f'var bootstrap{i}={i};' for i in range(200))+'</script>'
        html = bootstrap+'<script type="application/json">{"workspace_id":"personal-workspace"}</script>'
        self.execute(cookie={}, dump_status=403, html_text=html)
        self.assertEqual(self.messages[-1]['event'], 'forced_free')
        self.assertEqual(self.messages[-1]['workspaceId'], 'personal-workspace')
        self.assertEqual(sum(url.endswith('/workspace/select') for _, url in self.calls), 1)

    def test_cookie_dump_timeout_does_not_block_html_workspace_fallback(self):
        self.execute(cookie={}, dump_timeout=True, html_text='{"workspace_id":"personal-workspace"}')
        self.assertEqual(self.messages[-1]['event'], 'forced_free')

    def test_intermediate_consent_without_ids_can_continue_to_workspace_page(self):
        self.execute(cookie={}, dump_status=403, intermediate=True)
        self.assertEqual(self.messages[-1]['event'], 'forced_free')
        self.assertTrue(any(url.endswith('/next-consent') for _, url in self.calls))

    def test_later_http_failure_is_not_overwritten_by_earlier_dump_failure(self):
        self.execute(cookie={}, dump_status=403, intermediate=True, intermediate_status=429)
        self.assert_no_writeback()
        self.assertEqual(self.messages[-1]['diagnostic']['reason'], 'rate_limited')
        self.assertEqual(self.messages[-1]['diagnostic']['httpStatus'], 429)

    def test_missing_html_and_denied_session_reports_lookup_not_free_absence(self):
        self.execute(cookie={}, dump_status=403, html_text='<html>consent</html>')
        self.assert_no_writeback()
        self.assertEqual(self.messages[-1]['diagnostic'], {'stage': 'session_lookup', 'reason': 'http_rejected', 'httpStatus': 403})

    def test_multiple_html_candidates_are_not_arbitrarily_selected(self):
        self.execute(cookie={}, dump_status=403, html_text='{"workspace_id":"personal-workspace","nested":{"workspace_id":"another-workspace"}}')
        self.assert_no_writeback()
        self.assertEqual(self.messages[-1]['diagnostic']['reason'], 'free_workspace_ambiguous')
        self.assertIsNone(self.messages[-1]['diagnostic']['httpStatus'])
        self.assertFalse(any(url.endswith('/workspace/select') for _, url in self.calls))

    def test_dump_timeout_does_not_mask_local_html_ambiguity(self):
        self.execute(cookie={}, dump_timeout=True, html_text='{"workspace_id":"personal-workspace","nested":{"workspace_id":"another-workspace"}}')
        self.assert_no_writeback()
        self.assertEqual(self.messages[-1]['diagnostic'], {'stage': 'workspace', 'reason': 'free_workspace_ambiguous', 'httpStatus': None})

    def test_referenced_router_metadata_selects_personal_not_first_team(self):
        table = [{'_1': 2}, 'workspaces', [3, 8], {'_4': 5, '_6': 7}, 'id', 'team-workspace', 'type', 'team', {'_4': 9, '_6': 10}, 'personal-workspace', 'personal']
        html = '<script>window.stream.enqueue('+json.dumps(json.dumps(table))+');</script>'
        self.execute(cookie={}, dump_status=403, html_text=html)
        self.assertEqual(self.messages[-1]['event'], 'forced_free')
        self.assertEqual(self.messages[-1]['workspaceId'], 'personal-workspace')

    def test_ambiguous_cookie_cannot_be_bypassed_by_a_single_html_candidate(self):
        self.execute([{'id': 'personal-workspace'}, {'id': 'second'}], html_text='{"workspace_id":"personal-workspace"}')
        self.assert_no_writeback()
        self.assertEqual(self.messages[-1]['diagnostic']['reason'], 'free_workspace_ambiguous')

    def test_html_candidate_returns_native_callback_without_local_token_exchange(self):
        self.execute(cookie={},dump_status=403,html_text='{"workspace_id":"personal-workspace"}')
        self.assertEqual(self.messages[-1]['event'],'forced_free')
        self.assertNotIn('tokens',self.messages[-1])
        self.assertFalse(any(u.endswith('/oauth/token') for _,u in self.calls))

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
        self.assertEqual(len(self.calls), 1)

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
                self.assertEqual(self.messages[-1]['diagnostic'], {'stage': 'workspace', 'reason': reason, 'httpStatus': None})
                self.assertFalse(any(method == 'POST' for method, _ in self.calls))

    def test_wrong_state_never_exchanges_tokens(self):
        self.execute(bad_state=True)
        self.assert_no_writeback()
        self.assertFalse(any(url.endswith('/oauth/token') for _, url in self.calls))

    def test_forced_free_never_carries_locally_exchanged_tokens(self):
        self.execute(changed_tokens=tokens())
        self.assertEqual(self.messages[-1]['event'],'forced_free')
        self.assertNotIn('tokens',self.messages[-1])
        self.assertFalse(any(u.endswith('/oauth/token') for _,u in self.calls))

    def test_workspace_http_failure_retains_actual_stage_and_status(self):
        self.execute(selection_status=403)
        self.assert_no_writeback()
        self.assertEqual(self.messages[-1]['diagnostic'], {'stage': 'workspace', 'reason': 'http_rejected', 'httpStatus': 403})


if __name__ == "__main__":
    unittest.main()
