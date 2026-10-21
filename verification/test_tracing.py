"""Offline request tracing, endpoint classification and no-raw-data regression tests."""
import json
import sys
import types
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol'))
from tracing import ObservedSession
from diagnostics import describe_failure, stage_for_url


class TracingTests(unittest.TestCase):
    @staticmethod
    def challenge(**headers):
        return types.SimpleNamespace(status_code=403, headers={'server': 'cloudflare', **headers}, text='<title>Just a moment</title>')

    @patch('tracing.time.sleep')
    def test_initial_challenge_retries_same_get_once_with_existing_session_and_native_parameters(self, sleep):
        for method in ['get', 'request']:
            with self.subTest(method=method):
                calls, observed, steps = [], [], []
                cookies = {}
                accepted = types.SimpleNamespace(status_code=302, headers={'location': '/log-in'}, text='')
                def invoke(*args, **kwargs):
                    calls.append((args, dict(kwargs)))
                    if len(calls) == 1:
                        cookies['fixture-session'] = 'fixture-private-cookie'
                        return self.challenge()
                    self.assertEqual(cookies['fixture-session'], 'fixture-private-cookie')
                    return accepted
                session = types.SimpleNamespace(cookies=cookies)
                setattr(session, method, invoke)
                wrapped = ObservedSession(session, observed.append, recover_initial_page=True, on_initial_retry=lambda: steps.append('retry'))
                url = 'https://auth.openai.com/oauth/authorize?state=fixture-state&code_challenge=fixture-challenge&client_id=fixture&redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback'
                args = ('GET', url) if method == 'request' else (url,)
                kwargs = {'headers': {'User-Agent': 'fixture'}, 'allow_redirects': False, 'impersonate': 'chrome133a', 'timeout': 30}
                self.assertIs(getattr(wrapped, method)(*args, **kwargs), accepted)
                self.assertEqual(calls, [(args, kwargs), (args, kwargs)])
                self.assertEqual(steps, ['retry'])
                self.assertEqual(observed[-1]['httpStatus'], 302)
                self.assertEqual(observed[-1]['initialPageRetries'], 1)
                self.assertIs(wrapped.cookies, cookies)
        self.assertEqual(sleep.call_count, 2)

    @patch('tracing.time.sleep')
    def test_repeated_initial_challenge_stops_after_two_gets_and_remains_a_403(self, sleep):
        calls, observed = [], []
        response = self.challenge()
        session = types.SimpleNamespace(get=lambda *args, **kwargs: calls.append(args) or response)
        wrapped = ObservedSession(session, observed.append, recover_initial_page=True)
        self.assertIs(wrapped.get('https://auth.openai.com/oauth/authorize'), response)
        self.assertEqual(len(calls), 2)
        self.assertEqual(observed[-1]['httpStatus'], 403)
        wrapped.get('https://auth.openai.com/oauth/authorize')
        self.assertEqual(len(calls), 3)
        sleep.assert_called_once_with(2)

    @patch('tracing.time.sleep')
    def test_recovery_never_replays_posts_later_pages_unknown_denials_or_long_retry_after(self, sleep):
        cases = [
            ('POST', 'https://auth.openai.com/oauth/authorize', self.challenge()),
            ('POST', 'https://auth.openai.com/api/accounts/password/verify', self.challenge()),
            ('POST', 'https://auth.openai.com/api/accounts/mfa/verify', self.challenge()),
            ('POST', 'https://auth.openai.com/oauth/token', self.challenge()),
            ('GET', 'https://auth.openai.com/log-in', self.challenge()),
            ('GET', 'https://other.example/oauth/authorize', self.challenge()),
            ('GET', 'https://auth.openai.com/oauth/authorize', types.SimpleNamespace(status_code=403, headers={}, text='forbidden')),
            ('GET', 'https://auth.openai.com/oauth/authorize', self.challenge(**{'retry-after': '60'})),
            ('GET', 'https://auth.openai.com/oauth/authorize', self.challenge(**{'retry-after': 'Wed, 21 Oct 2026 12:00:00 GMT'})),
            ('GET', 'https://auth.openai.com/oauth/authorize', types.SimpleNamespace(status_code=429, headers={'server': 'cloudflare'}, text='Just a moment')),
        ]
        for method, url, response in cases:
            with self.subTest(method=method, url=url, status=response.status_code):
                calls = []
                session = types.SimpleNamespace(request=lambda *a, **kw: calls.append((a, kw)) or response)
                wrapped = ObservedSession(session, lambda attempt: None, recover_initial_page=True)
                self.assertIs(wrapped.request(method, url, allow_redirects=False), response)
                self.assertEqual(len(calls), 1)
        calls = []
        session = types.SimpleNamespace(request=lambda *a, **kw: calls.append((a, kw)) or self.challenge())
        wrapped = ObservedSession(session, lambda attempt: None, recover_initial_page=True)
        wrapped.request('POST', 'https://auth.openai.com/api/accounts/authorize/continue')
        wrapped.request('GET', 'https://auth.openai.com/oauth/authorize')
        self.assertEqual(len(calls), 2)
        sleep.assert_not_called()

    def test_token_posts_never_follow_redirects_or_forward_code_to_another_origin(self):
        for method in ['post', 'request']:
            calls = []
            response = types.SimpleNamespace(status_code=307, json=lambda: {}, headers={'Location': 'https://other.example/token'})
            session = types.SimpleNamespace()
            setattr(session, method, lambda *args, **kw: calls.append((args, kw)) or response)
            wrapped = ObservedSession(session, lambda attempt: None)
            args = ('POST', 'https://auth.openai.com/oauth/token') if method == 'request' else ('https://auth.openai.com/oauth/token',)
            wrapped_method = getattr(wrapped, method)
            self.assertIs(wrapped_method(*args, data={'code': 'private-code', 'code_verifier': 'private-verifier'}, allow_redirects=True), response)
            self.assertEqual(len(calls), 1)
            self.assertIs(calls[0][1]['allow_redirects'], False)

    def test_session_dump_has_its_own_stage(self):
        self.assertEqual(stage_for_url('https://auth.openai.com/api/accounts/client_auth_session_dump'), 'session_lookup')

    def test_page_and_direct_post_stages_are_distinct(self):
        cases = {
            'https://auth.openai.com/log-in': 'login_page',
            'https://auth.openai.com/log-in/password': 'password_page',
            'https://sentinel.openai.com/backend-api/sentinel/req': 'security_token',
            'https://auth.openai.com/oauth/token': 'token_exchange',
            'https://auth.openai.com/unknown-page?code=private-code': 'authorize_follow',
            'https://auth.openai.com/api/accounts/unknown-operation': 'account_request',
        }
        for url, expected in cases.items():
            self.assertEqual(stage_for_url(url), expected)

    def test_get_post_and_request_preserve_original_arguments_and_session(self):
        for method in ['get', 'post', 'request']:
            with self.subTest(method=method):
                observed, calls = [], []
                response = types.SimpleNamespace(status_code=409, json=lambda: {'error': {'code': 'account_banned', 'message': 'private-response'}})
                session = types.SimpleNamespace(cookies={}, headers={})
                setattr(session, method, lambda *args, **kwargs: calls.append((args, kwargs)) or response)
                wrapped = ObservedSession(session, observed.append)
                self.assertIs(wrapped.cookies, session.cookies)
                self.assertIs(wrapped.headers, session.headers)
                url = 'https://auth.openai.com/api/accounts/password/verify?state=private-state'
                args = ('POST', url) if method == 'request' else (url,)
                self.assertIs(getattr(wrapped, method)(*args, json={'password': 'private-password'}, timeout=30, allow_redirects=False), response)
                self.assertEqual(calls[0], (args, {'json': {'password': 'private-password'}, 'timeout': 30, 'allow_redirects': False}))
                self.assertEqual(observed, [{'stage': 'password', 'httpStatus': 409, 'upstreamError': 'account_banned'}])
                self.assertNotIn('private-', json.dumps(observed))

    def test_json_failure_and_invalid_shape_retain_stage_and_success_http(self):
        for invalid in [True, False]:
            def read_json():
                if invalid:
                    raise ValueError('private-json-error')
                return []
            attempts = []
            response = types.SimpleNamespace(status_code=200, json=read_json)
            wrapped = ObservedSession(types.SimpleNamespace(post=lambda *a, **kw: response), attempts.append)
            wrapped.post('https://auth.openai.com/oauth/token', data={'code': 'private-code'})
            value = describe_failure({'error': 'token_exchange_failed'}, attempt=attempts[-1])
            self.assertEqual(value['diagnostic']['stage'], 'token_exchange')
            self.assertEqual(value['diagnostic']['reason'], 'response_invalid_json' if invalid else 'response_invalid_shape')
            self.assertEqual(value['diagnostic']['httpStatus'], 200)
            self.assertNotIn('private-', json.dumps(value))

    def test_timeout_clears_stale_http_and_keeps_direct_page_stage(self):
        attempts = []
        def fail(*args, **kwargs):
            raise TimeoutError('private-proxy private-code')
        wrapped = ObservedSession(types.SimpleNamespace(get=fail), attempts.append)
        with self.assertRaises(TimeoutError):
            wrapped.get('https://auth.openai.com/log-in/password')
        value = describe_failure(attempt=attempts[-1])
        self.assertEqual(value['diagnostic'], {'stage': 'password_page', 'reason': 'request_timeout', 'httpStatus': None})
        self.assertNotIn('private-', json.dumps(value))

    def test_internal_exception_is_not_a_proxy_failure(self):
        value = describe_failure(attempt={'stage': 'workspace', 'httpStatus': 200}, exception=TypeError('private-data'))
        self.assertEqual(value['code'], 'protocol')
        self.assertEqual(value['diagnostic']['stage'], 'workspace')
        self.assertEqual(value['diagnostic']['reason'], 'protocol_processing_failed')

    def test_generic_result_does_not_hide_rejected_security_token_request(self):
        value = describe_failure({'error': 'login_continue_failed'}, attempt={'stage': 'security_token', 'httpStatus': 403})
        self.assertEqual(value['diagnostic'], {'stage': 'security_token', 'reason': 'http_rejected', 'httpStatus': 403})

    def test_returned_final_page_supplies_stage_when_request_metadata_missing(self):
        value = describe_failure({'error': 'private-error', 'oauth_protocol': {'final_url': 'https://auth.openai.com/log-in/password?state=private-state'}})
        self.assertEqual(value['diagnostic']['stage'], 'password_page')
        self.assertNotIn('private-', json.dumps(value))
