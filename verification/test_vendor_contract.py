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
from totp import TotpMfaClient


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
    def password_failure(self, first_code, *, next_status=200):
        messages, requests, sessions = [], [], []
        failures = iter([409, next_status])
        data = {'notes': f'{EMAIL}----fixture-password----{SECRET}', 'email': EMAIL,
                'proxy': 'http://fixture:pass@127.0.0.1:21001', 'authorizationUrl': URL, 'accountId': 'original-workspace'}
        class Session:
            def __init__(self):
                self.headers = {}
                self.cookies = RequestsCookieJar()
                self.cookies.set('oai-client-auth-session', json.dumps({'workspace_id': 'original-workspace'}), domain='auth.openai.com')
                self.closed = False
                sessions.append(self)
            def close(self):
                self.closed = True
            def request(self, method, url, **kwargs):
                requests.append((method, url))
                status, body, headers = 200, {}, {}
                if method == 'GET' and url == URL:
                    status, headers = 302, {'Location': 'https://auth.openai.com/log-in'}
                elif url.endswith('/authorize/continue'):
                    body = {'continue_url': 'https://auth.openai.com/log-in/password', 'page': {'type': 'login_password'}}
                elif url.endswith('/password/verify'):
                    status = next(failures)
                    body = {'continue_url': 'http://127.0.0.1:1455/auth/callback?state=fixture&code=fixture-code'} if status == 200 else {'error': {'code': first_code, 'message': 'private-body'}}
                else:
                    raise AssertionError('Unexpected offline request')
                return types.SimpleNamespace(status_code=status, url=url, headers=headers, text=json.dumps(body), json=lambda: body)
        def session(**kwargs):
            self.assertEqual(kwargs['proxy'], data['proxy'])
            return Session()
        with patch.object(chatgpt_client, 'create_http_session', side_effect=session), patch.object(oauth_client, 'create_http_session', side_effect=session), patch.object(oauth_client, 'build_sentinel_token', return_value='fixture-sentinel'), patch.object(oauth_client.OAuthClient, '_visit_oauth_page'), patch.object(socket, 'create_connection', side_effect=AssertionError('Network forbidden')), patch.object(runner, 'emit', side_effect=lambda event, **fields: messages.append({'event': event, **fields})):
            runner.run(data)
        self.password_requests = requests
        self.assertTrue(all(s.closed for s in sessions))
        self.assertNotIn('private-body', json.dumps(messages))
        self.assertNotIn('fixture-password', json.dumps(messages))
        return messages

    def test_password_step_invalid_state_rebuilds_full_login_session_once(self):
        messages = self.password_failure('invalid_state')
        self.assertEqual(messages[-1]['event'], 'complete')
        self.assertEqual(sum(url == URL for _, url in self.password_requests), 2)
        self.assertEqual(sum(url.endswith('/authorize/continue') for _, url in self.password_requests), 2)
        self.assertEqual(sum(m.get('step') == 'session_restart' for m in messages), 1)

    def test_password_rejection_ban_and_ambiguous_conflict_do_not_restart(self):
        for code in ['invalid_username_or_password', 'account_banned', 'unknown-upstream-code']:
            with self.subTest(code=code):
                messages = self.password_failure(code)
                self.assertEqual(messages[-1]['event'], 'error')
                self.assertEqual(sum(url == URL for _, url in self.password_requests), 1)
                self.assertFalse(any(m.get('step') == 'session_restart' for m in messages))

    def test_real_login_reports_direct_security_token_failure_stage(self):
        for failure in ['forbidden', 'invalid_json', 'timeout']:
            with self.subTest(failure=failure):
                messages = []
                class Session:
                    def __init__(self):
                        self.headers = {}
                        self.cookies = RequestsCookieJar()
                    def close(self):
                        pass
                    def request(self, method, url, **kwargs):
                        assert method == 'GET' and url == URL
                        return types.SimpleNamespace(status_code=302, url=url, headers={'Location': 'https://auth.openai.com/log-in'}, text='')
                    def post(self, url, **kwargs):
                        assert url == 'https://sentinel.openai.com/backend-api/sentinel/req'
                        if failure == 'timeout':
                            raise TimeoutError('private-proxy private-code')
                        def read_json():
                            if failure == 'invalid_json':
                                raise ValueError('private-response')
                            return {'error': {'message': 'private-response'}}
                        return types.SimpleNamespace(status_code=200 if failure == 'invalid_json' else 403, json=read_json)
                def sentinel(session, *args, **kwargs):
                    try:
                        session.post('https://sentinel.openai.com/backend-api/sentinel/req').json()
                    except Exception:
                        pass
                    return None
                data = {'notes': f'{EMAIL}----fixture-password----{SECRET}', 'email': EMAIL, 'proxy': 'http://fixture:pass@127.0.0.1:21001', 'authorizationUrl': URL, 'accountId': 'original-workspace'}
                with patch.object(chatgpt_client, 'create_http_session', side_effect=lambda **kw: Session()), patch.object(oauth_client, 'create_http_session', side_effect=lambda **kw: Session()), patch.object(oauth_client, 'build_sentinel_token', side_effect=sentinel), patch.object(socket, 'create_connection', side_effect=AssertionError('Network forbidden')), patch.object(runner, 'emit', side_effect=lambda event, **fields: messages.append({'event': event, **fields})):
                    runner.run(data)
                expected = {'forbidden': ('http_rejected', 403), 'invalid_json': ('response_invalid_json', 200), 'timeout': ('request_timeout', None)}[failure]
                self.assertEqual(messages[-1]['diagnostic'], {'stage': 'security_token', 'reason': expected[0], 'httpStatus': expected[1]})
                self.assertFalse(any(m['event'] == 'complete' for m in messages))
                self.assertNotIn('private-', json.dumps(messages))

    def mfa_failure(self, issue_status, verify_status=200, error_code='unknown-upstream-code', codes=None, workspace_after_restart=False):
        messages = []
        self.mfa_requests = []
        self.mfa_sessions, self.authorization_requests = [], []
        requests = self.mfa_requests
        data = {'notes': f'{EMAIL}----fixture-password----{SECRET}', 'email': EMAIL, 'proxy': 'http://fixture:pass@127.0.0.1:21001', 'authorizationUrl': URL, 'accountId': 'original-workspace'}
        class Session:
            def __init__(self):
                self.cookies = RequestsCookieJar()
                self.headers = {}
                workspace = 'other-workspace' if workspace_after_restart and testcase.authorization_requests else 'original-workspace'
                self.cookies.set('oai-client-auth-session', json.dumps({'workspace_id': workspace}), domain='auth.openai.com')
                self.closed = False
                self.cookies.set('fixture-local-session', str(len(testcase.mfa_sessions)), domain='auth.openai.com')
                testcase.mfa_sessions.append(self)
            def close(self):
                self.closed = True
            def request(self, method, url, **kwargs):
                if method == 'GET' and url == URL:
                    testcase.authorization_requests.append((self, url))
                    return types.SimpleNamespace(status_code=302, url=url, headers={'Location':'https://auth.openai.com/mfa-challenge/fixture-factor'}, text='')
                assert method == 'POST'
                assert url in {'https://auth.openai.com/api/accounts/mfa/issue_challenge', 'https://auth.openai.com/api/accounts/mfa/verify'}
                requests.append(url.rsplit('/', 1)[-1])
                index = requests.count('verify') - 1
                status = issue_status if url.endswith('issue_challenge') else (verify_status[index] if isinstance(verify_status, list) else verify_status)
                code = error_code[index] if isinstance(error_code, list) else error_code
                body = {} if status == 200 else {'error': {'code': code, 'message': 'private-body fixture-password'}}
                if url.endswith('/verify') and status == 200:
                    body = {'continue_url': 'http://127.0.0.1:1455/auth/callback?state=fixture&code=fixture-code'}
                return types.SimpleNamespace(status_code=status, url=url, headers={}, text=json.dumps(body), json=lambda:body)
        generator = {'return_value': '123456'} if codes is None else {'side_effect': codes}
        testcase = self
        with patch.object(TotpMfaClient, 'get_mfa_code', **generator) as get_code, patch.object(chatgpt_client, 'create_http_session', side_effect=lambda **kwargs: Session()), patch.object(oauth_client, 'create_http_session', side_effect=lambda **kwargs: Session()), patch.object(oauth_client.OAuthClient, '_resolve_totp_factor', return_value={'id':'fixture-factor', 'factor_type':'totp'}), patch.object(oauth_client.OAuthClient, '_visit_oauth_page'), patch.object(socket, 'create_connection', side_effect=AssertionError('Network forbidden')), patch.object(runner, 'emit', side_effect=lambda event, **fields:messages.append({'event':event, **fields})):
            runner.run(data)
        self.mfa_generation_count = get_code.call_count
        self.mfa_timeouts = [call.kwargs.get('timeout') for call in get_code.call_args_list]
        self.mfa_exclusions = [set(call.kwargs.get('exclude_codes', ())) for call in get_code.call_args_list]
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
        self.assertEqual(self.mfa_generation_count, 1)
        self.assertEqual(self.mfa_requests, ['issue_challenge', 'verify'])

    def test_invalid_state_restarts_once_without_reusing_old_challenge_or_cookies(self):
        messages = self.mfa_failure(200, 409, error_code='invalid_state', codes=['123456', '234567'])
        diagnostic = messages[-1]['diagnostic']
        self.assertEqual(diagnostic['reason'], 'mfa_challenge_invalid')
        self.assertEqual(diagnostic['sessionRestarts'], 1)
        self.assertEqual(diagnostic['previousLogin'], {'stage': 'mfa_verify', 'reason': 'mfa_challenge_invalid', 'httpStatus': 409, 'upstreamCode': 'invalid_state'})
        self.assertEqual(self.mfa_generation_count, 2)
        self.assertEqual(self.mfa_requests, ['issue_challenge', 'verify', 'issue_challenge', 'verify'])
        self.assertEqual(sum(m.get('step') == 'session_restart' for m in messages), 1)
        self.assertEqual(len(self.authorization_requests), 2)
        first, second = [session for session, _ in self.authorization_requests]
        self.assertIsNot(first, second)
        self.assertNotEqual(first.cookies.get('fixture-local-session'), second.cookies.get('fixture-local-session'))
        self.assertTrue(first.closed and second.closed)
        self.assertEqual(self.mfa_exclusions, [set(), {'123456'}])
        for secret in ['123456', 'fixture-password', 'private-body']:
            self.assertNotIn(secret, json.dumps(messages))

    def test_retry_wait_has_a_full_totp_period_plus_margin(self):
        self.mfa_failure(200, 409, error_code='otp_expired', codes=['123456', None])
        self.assertEqual(self.mfa_timeouts, [30, 35])

    def test_invalid_state_on_final_submission_restarts_and_can_succeed(self):
        messages = self.mfa_failure(200, [409, 409, 409, 200], error_code=['otp_expired', 'otp_expired', 'invalid_state', ''], codes=['123456', '234567', '345678', '456789'])
        self.assertEqual(messages[-1]['event'], 'complete')
        self.assertEqual(self.mfa_generation_count, 4)
        self.assertEqual(self.mfa_requests, ['issue_challenge', 'verify', 'verify', 'verify', 'issue_challenge', 'verify'])
        self.assertEqual(self.mfa_exclusions[-1], {'123456', '234567', '345678'})

    def test_new_session_failure_keeps_actual_new_error_and_first_state_error(self):
        messages = self.mfa_failure(200, [409, 429], error_code=['invalid_state', 'too_many_requests'], codes=['123456', '234567'])
        diagnostic = messages[-1]['diagnostic']
        self.assertEqual(messages[-1]['code'], 'limited')
        self.assertEqual(diagnostic['reason'], 'rate_limited')
        self.assertEqual(diagnostic['previousLogin']['reason'], 'mfa_challenge_invalid')
        self.assertEqual(diagnostic['sessionRestarts'], 1)
        self.assertEqual(self.mfa_generation_count, 2)

    def test_retryable_expired_code_can_succeed_without_reissuing_challenge(self):
        messages = self.mfa_failure(200, [409, 200], error_code='otp_expired', codes=['123456', '234567'])
        self.assertEqual(messages[-1]['event'], 'complete')
        self.assertEqual(self.mfa_generation_count, 2)
        self.assertEqual(self.mfa_requests, ['issue_challenge', 'verify', 'verify'])
        self.assertEqual(self.mfa_timeouts, [30, 35])

    def test_invalid_state_while_issuing_challenge_restarts_only_once_without_codes(self):
        messages = self.mfa_failure(409, error_code='invalid_state', codes=[])
        self.assertEqual(messages[-1]['diagnostic']['reason'], 'mfa_challenge_invalid')
        self.assertEqual(messages[-1]['diagnostic']['stage'], 'mfa_issue')
        self.assertEqual(messages[-1]['diagnostic']['sessionRestarts'], 1)
        self.assertEqual(self.mfa_requests, ['issue_challenge', 'issue_challenge'])
        self.assertEqual(self.mfa_generation_count, 0)

    def test_successful_restart_does_not_retain_previous_failed_authorization(self):
        messages = self.mfa_failure(200, [409, 200], error_code='invalid_state', codes=['123456', '234567'])
        self.assertEqual(messages[-1]['event'], 'complete')
        self.assertFalse(any(m['event'] == 'error' for m in messages))
        self.assertEqual(len(self.authorization_requests), 2)
        self.assertEqual([url for _, url in self.authorization_requests], [URL, URL])

    def test_restart_history_does_not_hide_new_workspace_mismatch(self):
        messages = self.mfa_failure(200, [409, 200], error_code='invalid_state', codes=['123456', '234567'], workspace_after_restart=True)
        failure = messages[-1]
        self.assertEqual(failure['event'], 'error')
        self.assertEqual(failure['code'], 'workspace')
        self.assertEqual(failure['workspaces'], [{'id': 'other-workspace'}])
        self.assertEqual(failure['diagnostic']['reason'], 'workspace_unmatched')
        self.assertEqual(failure['diagnostic']['stage'], 'workspace')
        self.assertEqual(failure['diagnostic']['sessionRestarts'], 1)
        self.assertEqual(failure['diagnostic']['previousLogin']['reason'], 'mfa_challenge_invalid')

    def test_409_then_generation_timeout_keeps_both_stages_without_stale_http(self):
        messages = self.mfa_failure(200, 409, error_code='otp_expired', codes=['123456', None])
        self.assertEqual(messages[-1]['diagnostic'], {
            'stage': 'mfa_generate', 'reason': 'mfa_new_code_timeout', 'httpStatus': None,
            'previousVerification': {'stage': 'mfa_verify', 'reason': 'mfa_code_expired', 'httpStatus': 409, 'upstreamCode': 'otp_expired'},
        })
        self.assertEqual(self.mfa_requests, ['issue_challenge', 'verify'])
        for secret in ['123456', 'fixture-password', 'private-body', 'unknown-upstream-code']:
            self.assertNotIn(secret, json.dumps(messages))

    def test_explicit_mfa_rejections_survive_later_generation_timeout(self):
        for code, reason in [('invalid_otp', 'mfa_code_invalid'), ('otp_expired', 'mfa_code_expired')]:
            with self.subTest(code=code):
                messages = self.mfa_failure(200, 409, error_code=code, codes=['123456', None])
                previous = messages[-1]['diagnostic']['previousVerification']
                self.assertEqual(previous, {'stage': 'mfa_verify', 'reason': reason, 'httpStatus': 409, 'upstreamCode': code})
                self.assertEqual(messages[-1]['diagnostic']['reason'], 'mfa_new_code_timeout')
                self.assertEqual(self.mfa_requests.count('verify'), 1)

    def test_initial_generation_failure_has_no_http_or_verification_result(self):
        messages = self.mfa_failure(200, 409, codes=[None])
        self.assertEqual(messages[-1]['diagnostic'], {'stage': 'mfa_generate', 'reason': 'mfa_code_unavailable', 'httpStatus': None})
        self.assertEqual(self.mfa_requests, ['issue_challenge'])

    def test_invalid_generated_code_is_local_and_never_submitted(self):
        messages = self.mfa_failure(200, 409, codes=['not-a-code'])
        self.assertEqual(messages[-1]['diagnostic'], {'stage': 'mfa_generate', 'reason': 'mfa_code_invalid_format', 'httpStatus': None})
        self.assertEqual(self.mfa_requests, ['issue_challenge'])

    def test_generator_exception_keeps_previous_rejection_not_a_network_error(self):
        messages = self.mfa_failure(200, 409, error_code='otp_expired', codes=['123456', ValueError('private-secret')])
        self.assertEqual(messages[-1]['code'], 'mfa')
        self.assertEqual(messages[-1]['diagnostic']['reason'], 'mfa_generation_failed')
        self.assertEqual(messages[-1]['diagnostic']['previousVerification']['reason'], 'mfa_code_expired')
        self.assertNotIn('private-secret', json.dumps(messages))

    def test_409_after_all_submissions_is_not_claimed_as_generation_failure(self):
        messages = self.mfa_failure(200, 409, error_code='otp_expired', codes=['123456', '234567', '345678'])
        self.assertEqual(messages[-1]['diagnostic'], {'stage': 'mfa_verify', 'reason': 'mfa_code_expired', 'httpStatus': 409, 'upstreamCode': 'otp_expired'})
        self.assertEqual(self.mfa_requests.count('verify'), 3)

    def test_ambiguous_conflict_or_ban_does_not_guess_retry_strategy(self):
        for code, reason in [('unknown-upstream-code', 'mfa_conflict'), ('account_banned', 'account_banned'), ('payment_required', 'payment_required')]:
            with self.subTest(code=code):
                messages = self.mfa_failure(200, 409, error_code=code, codes=['123456'])
                self.assertEqual(messages[-1]['diagnostic']['reason'], reason)
                self.assertEqual(self.mfa_generation_count, 1)
                self.assertEqual(self.mfa_requests, ['issue_challenge', 'verify'])

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
