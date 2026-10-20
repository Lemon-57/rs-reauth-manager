"""Network-isolated session-manager contract and failure tests."""
import copy
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol'))
from sessions import BASE, SessionCleanupError, cleanup, device_sessions
from test_fallback import tokens, jwt, AUTH
from test_protocol import EMAIL
from requests.cookies import RequestsCookieJar
from vendor.lib import chatgpt_client
from fallback import claims

DEVICE = '59859b73-b63b-45f4-86f9-e728a9512905'


def row(sid, current=False):
    return {'session_id': sid, 'is_current_device': current, 'platform': 'private-platform', 'ip_address': 'private-ip'}


class SessionGuards(unittest.TestCase):
    def test_only_unique_explicit_current_device_is_kept(self):
        body = {'devices': [row('current', True), row('other'), {'session_id': None, 'is_current_device': False, 'is_trusted_device': True}]}
        self.assertEqual(device_sessions(body), ('current', {'other'}))

    def test_ambiguous_missing_duplicate_or_incomplete_directory_stops(self):
        cases = [None, [], {}, {'devices': []}, {'devices': [row('other')]},
                 {'devices': [row('a', True), row('b', True)]},
                 {'devices': [row('a', True), row('a')]},
                 {'devices': [row('a', True), {'session_id': 'b'}]},
                 {'devices': [row('a', True), row('b', 0)]},
                 {'devices': [row('a', True), row('bad\nid')]},
                 {'devices': [row('a', True), row(None)]},
                 {'devices': [row('a', True)] * 1001}]
        for body in cases:
            with self.subTest(body=str(body)[:80]), self.assertRaises(SessionCleanupError):
                device_sessions(body)
        for key in ['has_more', 'hasMore', 'next_cursor', 'nextCursor', 'next_page', 'nextPage']:
            with self.subTest(key=key), self.assertRaises(SessionCleanupError):
                device_sessions({'devices': [row('a', True)], key: 'more'})


class SessionFlow(unittest.TestCase):
    def setUp(self):
        self.calls, self.events = [], []
        self.rows = [row('current', True), row('old-b'), row('old-a')]
        self.data = {'tokens': tokens(), 'email': EMAIL, 'userId': 'original-user', 'accountId': 'personal-workspace',
                     'planType': 'free', 'deviceId': DEVICE, 'clientId': 'fixture', 'proxy': 'http://fixture:pass@127.0.0.1:21001'}
        self.revocation_status, self.revoke_body, self.sticky = 200, {}, False
        self.fail_post, self.new_session, self.swap_current = False, False, False
        self.refresh = {**tokens(), 'refresh_token': 'rotated-private-rt'}
        self.session = None

    def run_cleanup(self):
        testcase = self
        def response(status, body):
            return types.SimpleNamespace(status_code=status, json=lambda: copy.deepcopy(body))
        class Session:
            def __init__(self):
                self.headers, self.cookies = {}, RequestsCookieJar()
            def close(self):
                testcase.closed = True
            def get(self, url, **kwargs):
                testcase.assertEqual(url, BASE)
                testcase.assertFalse(kwargs['allow_redirects'])
                testcase.assertEqual(kwargs['headers']['oai-device-id'], DEVICE)
                testcase.assertTrue(kwargs['headers']['Authorization'].startswith('Bearer '))
                testcase.calls.append(('GET', 'sessions'))
                if testcase.new_session and len(testcase.rows)==1: testcase.rows.append(row('new-login'))
                return response(200, {'devices': testcase.rows})
            def post(self, url, **kwargs):
                testcase.assertFalse(kwargs['allow_redirects'])
                if url == BASE + '/revoke':
                    sid = kwargs['json']['session_id']
                    testcase.assertNotEqual(sid, 'current')
                    testcase.assertEqual(set(kwargs['json']), {'session_id'})
                    testcase.calls.append(('POST', sid))
                    if testcase.fail_post:
                        raise TimeoutError('private-proxy-auth private-session-data')
                    if not testcase.sticky:
                        testcase.rows = [r for r in testcase.rows if r['session_id'] != sid]
                    if testcase.swap_current:
                        testcase.rows[0]['session_id'] = 'changed-current'
                    return response(testcase.revocation_status, testcase.revoke_body)
                testcase.assertEqual(url, 'https://auth.openai.com/oauth/token')
                testcase.assertEqual(kwargs['data'], {'grant_type': 'refresh_token', 'refresh_token': 'fixture-private-rt', 'client_id': 'fixture'})
                testcase.calls.append(('POST', 'refresh'))
                if testcase.new_session:
                    testcase.rows.append(row('new-login'))
                return response(200, testcase.refresh)
        def factory(**kwargs):
            testcase.assertEqual(kwargs['proxy'], testcase.data['proxy'])
            testcase.session = Session()
            return testcase.session
        with patch.object(chatgpt_client, 'create_http_session', side_effect=factory):
            cleanup(self.data, lambda event, **fields: self.events.append({'event': event, **fields}))

    def test_logout_others_returns_only_device_completion(self):
        self.run_cleanup()
        self.assertEqual([target for method, target in self.calls if method == 'POST'], ['old-a', 'old-b'])
        self.assertEqual(self.rows, [row('current', True)])
        self.assertEqual(self.session.cookies.get('oai-did', domain='chatgpt.com'), DEVICE)
        self.assertTrue(self.closed)
        output = self.events[-1]
        self.assertEqual(output['event'], 'sessions_cleaned')
        self.assertEqual(output['revokedCount'], 2)
        self.assertTrue(output['otherSessionsRevoked'])
        self.assertNotIn('tokens', output)
        public = str(self.events[:-1])
        for secret in ['private-ip', 'private-platform', 'old-a', 'fixture-private-rt', 'rotated-private-rt', DEVICE]:
            self.assertNotIn(secret, public)

    def test_no_others_emits_zero_count_without_touching_token_service(self):
        self.rows = [row('current', True)]
        self.run_cleanup()
        self.assertEqual([c for c in self.calls if c[0] == 'POST'], [])
        self.assertEqual(self.events[-1]['revokedCount'], 0)

    def test_post_native_refresh_verification_is_read_only_and_preserves_same_session(self):
        self.data.update(action='verify_sessions',expectedSessionId='current')
        self.rows=[row('current',True)]
        del self.data['tokens']['refresh_token']
        self.run_cleanup()
        self.assertEqual(self.events[-1],{'event':'sessions_verified','otherSessionsRevoked':True,'currentSessionRetained':True})
        self.assertFalse(any(method=='POST' for method,_ in self.calls))

    def test_post_native_refresh_changed_session_or_new_device_stops_without_revocation(self):
        for rows in [[row('changed',True)],[row('current',True),row('new-device')]]:
            self.setUp();self.data.update(action='verify_sessions',expectedSessionId='current');self.rows=rows
            with self.subTest(rows=rows),self.assertRaises(SessionCleanupError):self.run_cleanup()
            self.assertFalse(any(method=='POST' for method,_ in self.calls))

    def test_missing_current_prevents_all_mutations(self):
        self.rows = [row('old')]
        with self.assertRaisesRegex(SessionCleanupError, 'sessions_current_unconfirmed'):
            self.run_cleanup()
        self.assertFalse(any(c[0] == 'POST' for c in self.calls))

    def test_rejected_sticky_or_error_response_is_not_success(self):
        for status, body, sticky in [(403, {}, False), (200, {'error': 'private-message'}, False), (200, {}, True), (204, {}, True)]:
            self.setUp()
            self.revocation_status, self.revoke_body, self.sticky = status, body, sticky
            with self.subTest(status=status, sticky=sticky), self.assertRaises(SessionCleanupError):
                self.run_cleanup()
            self.assertNotIn(('POST', 'refresh'), self.calls)
            self.assertFalse(any(e['event'] == 'sessions_cleaned' for e in self.events))

    def test_revocation_timeout_never_replays_or_refreshes(self):
        self.fail_post = True
        with self.assertRaisesRegex(SessionCleanupError, '^sessions_transport_unconfirmed$'):
            self.run_cleanup()
        self.assertEqual([c for c in self.calls if c[0] == 'POST'], [('POST', 'old-a')])

    def test_current_marker_change_stops_before_next_device(self):
        self.swap_current = True
        with self.assertRaisesRegex(SessionCleanupError, 'sessions_revoke_unconfirmed'):
            self.run_cleanup()
        self.assertEqual([c for c in self.calls if c[0] == 'POST'], [('POST', 'old-a')])

    def test_new_login_at_final_readback_is_not_reported_as_complete(self):
        self.new_session = True
        with self.assertRaises(SessionCleanupError):
            self.run_cleanup()
        self.assertFalse(any(e['event'] == 'sessions_cleaned' for e in self.events))

    def test_session_worker_never_needs_or_returns_rt(self):
        del self.data['tokens']['refresh_token']
        self.run_cleanup()
        self.assertEqual(self.events[-1]['event'],'sessions_cleaned')
        self.assertNotIn('tokens',self.events[-1])
        self.assertNotIn(('POST','refresh'),self.calls)

    def test_initial_identity_device_and_proxy_are_checked_before_network(self):
        for key, value in [('userId', 'wrong-user'), ('deviceId', ''), ('proxy', ''), ('planType', 'team')]:
            self.setUp()
            self.data[key] = value
            with self.subTest(key=key), self.assertRaises((SessionCleanupError, ValueError)):
                self.run_cleanup()
            self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
