import contextlib
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from fixed_pool_onboarding import Adapter, Rejected, atomic


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'private').mkdir()
        atomic(self.root / 'private/pool.json', [{'family': 4, 'port': 31001}, {'family': 6, 'port': 31002}])
        registry = self.root / 'registry.json'
        atomic(registry, [])
        self.manager = types.SimpleNamespace(root=self.root, reg=registry,
            rows=lambda: json.loads(registry.read_text()), cfg={'exits': {'4': '192.0.2.1', '6': '2001:db8::1'}})
        self.module = types.SimpleNamespace(atomic=atomic, allocation_lock=lambda _: contextlib.nullcontext(),
            choose_family=lambda counts: min((4, 6), key=lambda family: (counts[family], family)))
        self.adapter = Adapter(self.manager, self.module, self.root / 'receipts', 12345, 'https://fixture.invalid')
        self.calls = []
        self.accounts = []
        self.flow = 0
        self.adapter.backend = self.backend
        self.adapter.verify_exit = lambda entry: self.calls.append(('exit', entry['management_id']))

    def backend(self, path, headers, body=None):
        self.calls.append((path, body))
        if path.startswith('/api/admin/accounts?page='):
            return {'items': list(self.accounts), 'page': {'total': len(self.accounts)}}
        if path.endswith('/oauth/start'):
            self.flow += 1
            return {'flowId': str(self.flow), 'authorizationUrl': 'https://fixture.invalid/authorize'}
        if path.endswith('/oauth/complete'):
            entry = self.manager.rows()[-1]
            self.account = {'id': 'fixture-account', 'email': entry['email'], 'enabled': False,
                'provider': 'openai', 'authenticationKind': 'oauth', 'notes': body['settings']['notes'],
                'outboundProxyEndpoint': f"http://{entry['host']}:{entry['port']}",
                'hasRefreshToken': True, 'capacity': {'usedSlots': 0}, 'userId': 'fixture-user', 'accountId': 'fixture-workspace'}
            self.accounts.append(self.account)
            return {'accountId': self.account['id']}
        if path.startswith('/api/admin/accounts/detail?'):
            return {'account': self.account}
        raise AssertionError('unexpected backend path')

    def start(self, email='fixture@example.com'):
        return self.adapter.call('/_management/onboarding/start', {'x-api-key': 'fixture'},
            {'email': email, 'requestId': '12345678-1234-4234-9234-123456789012'})

    def body(self, start):
        return {'provider': 'openai', 'flowId': start['flowId'], 'callbackUrl': 'http://localhost/callback?fixture',
            'settings': {'enabled': False, 'notes': 'fixture@example.com----fixture-password----JBSWY3DPEHPK3PXP'}}

    def test_native_chain_keeps_one_proxy_and_binds_paused_account(self):
        started = self.start()
        entry = self.manager.rows()[0]
        self.assertEqual(entry['family'], 4)
        self.assertEqual(entry['port'], 31001)
        native = next(body for path, body in self.calls if path.endswith('/oauth/start'))
        self.assertEqual(native['outboundProxyUrl'], started['outboundProxyUrl'])
        done = self.adapter.call('/api/admin/accounts/oauth/complete', {}, self.body(started))
        self.assertEqual(done['accountId'], self.manager.rows()[0]['rs_account_id'])
        receipt = json.loads(self.adapter.receipt_path(entry['email']).read_text())
        self.assertEqual(receipt['phase'], 'bound')
        self.assertTrue(receipt['nativeCompleteConfirmed'])
        self.assertFalse(self.account['enabled'])
        self.assertNotIn('notes', receipt)

    def test_directory_duplicate_stops_before_any_reservation(self):
        self.accounts = [{'id': 'existing', 'provider': 'openai', 'email': 'FIXTURE@EXAMPLE.COM'}]
        with self.assertRaises(Rejected):
            self.start()
        self.assertEqual(self.manager.rows(), [])

    def test_authentication_failure_precedes_registry_access(self):
        self.adapter.backend = lambda *args: (_ for _ in ()).throw(Rejected(403))
        with self.assertRaises(Rejected):
            self.start()
        self.assertEqual(self.manager.rows(), [])

    def test_uncertain_start_cannot_reallocate_after_restart(self):
        real = self.backend
        self.adapter.backend = lambda path, *args: (_ for _ in ()).throw(TimeoutError()) if path.endswith('/oauth/start') else real(path, *args)
        with self.assertRaises(TimeoutError):
            self.start()
        self.adapter = Adapter(self.manager, self.module, self.root / 'receipts', 12345, 'https://fixture.invalid')
        self.adapter.backend = self.backend
        with self.assertRaises(Rejected):
            self.start()
        self.assertEqual(len(self.manager.rows()), 1)

    def test_reservations_balance_with_separate_authentication(self):
        self.start()
        self.start('second@example.com')
        entries = self.manager.rows()
        self.assertEqual([entry['family'] for entry in entries], [4, 6])
        self.assertNotEqual(entries[0]['username'], entries[1]['username'])
        self.assertNotEqual(entries[0]['password'], entries[1]['password'])

    def test_ambiguous_pool_template_stops_before_reservation(self):
        atomic(self.root / 'private/pool.json', [{'family': 4, 'port': 31001}, {'family': 4, 'port': 31003}])
        with self.assertRaises(Rejected):
            self.start()
        self.assertEqual(self.manager.rows(), [])
        self.assertFalse(self.adapter.receipt_path('fixture@example.com').exists())

    def test_exit_failure_blocks_native_start_and_keeps_receipt(self):
        self.adapter.verify_exit = lambda _: (_ for _ in ()).throw(Rejected(502))
        with self.assertRaises(Rejected):
            self.start()
        self.assertFalse(any(path.endswith('/oauth/start') for path, _ in self.calls))
        self.assertTrue(self.adapter.receipt_path('fixture@example.com').exists())

    def test_uncertain_complete_is_not_replayed(self):
        started = self.start()
        real = self.backend
        self.adapter.backend = lambda path, *args: (_ for _ in ()).throw(TimeoutError()) if path.endswith('/oauth/complete') else real(path, *args)
        with self.assertRaises(TimeoutError):
            self.adapter.call('/api/admin/accounts/oauth/complete', {}, self.body(started))
        self.adapter.backend = self.backend
        with self.assertRaises(Rejected):
            self.adapter.call('/api/admin/accounts/oauth/complete', {}, self.body(started))
        self.assertFalse(self.accounts)

    def test_enabled_wrong_email_and_unknown_flow_rejected_before_exchange(self):
        started = self.start()
        for change in ['enabled', 'notes', 'flowId']:
            body = self.body(started)
            if change == 'enabled':
                body['settings']['enabled'] = True
            elif change == 'notes':
                body['settings']['notes'] = 'other@example.com----fixture----JBSWY3DPEHPK3PXP'
            else:
                body['flowId'] = 'unknown'
            with self.assertRaises(Rejected):
                self.adapter.call('/api/admin/accounts/oauth/complete', {}, body)
        self.assertFalse(self.accounts)

    def test_directory_total_mismatch_rejected(self):
        self.adapter.backend = lambda *args: {'items': [], 'page': {'total': 1}}
        with self.assertRaises(Rejected):
            self.start()
        self.assertEqual(self.manager.rows(), [])

    def test_transport_requires_business_success_and_preserves_201(self):
        adapter = Adapter(self.manager, self.module, self.root / 'transport', 12345, 'https://fixture.invalid')
        for status, document, accepted in [(201, {'code': 200, 'data': {'flowId': 'fixture'}}, True),
                (200, {'code': 409, 'data': {}}, False), (201, {'code': 200}, False)]:
            response = types.SimpleNamespace(status=status, read=lambda _: json.dumps(document).encode())
            connection = types.SimpleNamespace(request=lambda *args: None, getresponse=lambda: response, close=lambda: None)
            with patch('http.client.HTTPConnection', return_value=connection):
                if accepted:
                    self.assertEqual(adapter.backend('/fixture', {})['flowId'], 'fixture')
                else:
                    with self.assertRaises(Rejected):
                        adapter.backend('/fixture', {})


if __name__ == '__main__':
    unittest.main()
