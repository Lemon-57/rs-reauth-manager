import contextlib
import hashlib
import json
import tempfile
import types
import unittest
import time
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
        if path.endswith('/oauth/complete') or path.endswith('/accounts/import'):
            entry = self.manager.rows()[-1]
            self.account = {'id': 'fixture-account', 'email': entry['email'], 'enabled': False,
                'provider': 'openai', 'authenticationKind': 'oauth', 'notes': body['settings']['notes'],
                'outboundProxyEndpoint': f"http://{entry['host']}:{entry['port']}",
                'hasRefreshToken': True, 'concurrencyLimit': body['settings'].get('concurrencyLimit'),
                'capacity': {'usedSlots': 0}, 'userId': 'fixture-user', 'accountId': 'fixture-workspace'}
            self.accounts.append(self.account)
            return {'accountIds': [self.account['id']]} if path.endswith('/accounts/import') else {'accountId': self.account['id']}
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

    def test_new_native_account_explicitly_sets_and_reads_back_three_concurrency(self):
        started = self.start()
        body = self.body(started)
        body['settings']['concurrencyLimit'] = None
        self.adapter.call('/api/admin/accounts/oauth/complete', {}, body)
        self.assertEqual(self.account['concurrencyLimit'], 3)
        self.assertIsNone(body['settings']['concurrencyLimit'])

    def test_deleted_registrations_do_not_skew_current_account_balance(self):
        atomic(self.manager.reg, [{'family': 4, 'email': 'old@example.com', 'rs_account_id': 'deleted'}] * 10)
        self.start()
        self.assertEqual(self.manager.rows()[-1]['family'], 4)

    def test_pending_reservations_count_toward_balance(self):
        atomic(self.manager.reg, [{'family': 4, 'email': 'pending@example.com', 'rs_account_id': None}])
        self.start()
        self.assertEqual(self.manager.rows()[-1]['family'], 6)

    def import_body(self):
        return {'provider': 'openai', 'data': {'email': 'fixture@example.com', 'refreshToken': 'fixture-rt'},
            'settings': {'enabled': False, 'concurrencyLimit': None,
                         'notes': 'fixture@example.com----fixture-password----JBSWY3DPEHPK3PXP'}}

    def test_provided_rt_uses_reserved_proxy_native_import_and_three_concurrency(self):
        result = self.adapter.call('/api/admin/accounts/import', {}, self.import_body())
        entry = self.manager.rows()[0]
        self.assertEqual(result['accountIds'], [entry['rs_account_id']])
        native = next(body for path, body in self.calls if path.endswith('/accounts/import'))
        self.assertEqual(native['data']['outboundProxyUrl'], self.adapter.url(entry))
        self.assertEqual(native['settings']['concurrencyLimit'], 3)
        self.assertFalse(any(path.endswith('/oauth/start') for path, _ in self.calls))
        receipt = self.adapter.receipt_path(entry['email']).read_text()
        self.assertNotIn('fixture-rt', receipt)
        self.assertNotIn('fixture-password', receipt)

    def test_uncertain_rt_import_cannot_allocate_or_import_again(self):
        real = self.backend
        self.adapter.backend = lambda path, *args: (_ for _ in ()).throw(TimeoutError()) if path.endswith('/accounts/import') else real(path, *args)
        with self.assertRaises(TimeoutError):
            self.adapter.call('/api/admin/accounts/import', {}, self.import_body())
        self.adapter.backend = self.backend
        with self.assertRaises(Rejected):
            self.adapter.call('/api/admin/accounts/import', {}, self.import_body())
        self.assertEqual(len(self.manager.rows()), 1)

    def test_binding_appends_optional_identity_mapping_without_changing_existing_entries(self):
        mapping = self.root / 'mapping.json'
        existing = {'target_rs_id': 'existing', 'management_id': 'existing-management'}
        atomic(mapping, [existing])
        self.adapter.identity_mapping = mapping
        self.adapter.call('/api/admin/accounts/import', {}, self.import_body())
        rows = json.loads(mapping.read_text())
        self.assertEqual(rows[0], existing)
        self.assertEqual(rows[1]['target_rs_id'], self.account['id'])
        self.assertEqual(rows[1]['management_id'], self.manager.rows()[0]['management_id'])

    def test_native_save_and_binding_share_the_background_allocator_lock(self):
        held = []
        @contextlib.contextmanager
        def lock(_):
            self.assertFalse(held)
            held.append(True)
            try:
                yield
            finally:
                held.pop()
        real = self.backend
        def backend(path, *args):
            if path.endswith('/oauth/complete') or path.startswith('/api/admin/accounts/detail?'):
                self.assertTrue(held)
            return real(path, *args)
        self.module.allocation_lock = lock
        self.adapter.backend = backend
        started = self.start()
        self.adapter.call('/api/admin/accounts/oauth/complete', {}, self.body(started))

    def test_busy_allocator_waits_before_reserving_and_starts_native_once(self):
        attempts = []
        @contextlib.contextmanager
        def lock(_):
            attempts.append(True)
            if len(attempts) < 3:
                raise BlockingIOError()
            yield
        self.module.allocation_lock = lock
        with patch('fixed_pool_onboarding.time.sleep'):
            self.start()
        self.assertEqual(len(attempts), 3)
        self.assertEqual(len(self.manager.rows()), 1)
        self.assertEqual(sum(path.endswith('/oauth/start') for path, _ in self.calls), 1)

    def test_busy_complete_does_not_mark_native_pending_before_lock(self):
        started = self.start()
        @contextlib.contextmanager
        def busy(_):
            raise BlockingIOError()
            yield
        self.module.allocation_lock = busy
        with patch('fixed_pool_onboarding.time.monotonic', side_effect=[0, 21]):
            with self.assertRaises(Rejected) as failure:
                self.adapter.call('/api/admin/accounts/oauth/complete', {}, self.body(started))
        self.assertEqual(failure.exception.status, 409)
        receipt = json.loads(self.adapter.receipt_path('fixture@example.com').read_text())
        self.assertEqual(receipt['phase'], 'native_started')
        self.assertFalse(any(path.endswith('/oauth/complete') for path, _ in self.calls))

    def test_exception_inside_held_lock_is_not_retried(self):
        started = self.start()
        real = self.backend
        def backend(path, *args):
            if path.endswith('/oauth/complete'):
                self.calls.append((path, None))
                raise BlockingIOError()
            return real(path, *args)
        self.adapter.backend = backend
        with self.assertRaises(BlockingIOError):
            self.adapter.call('/api/admin/accounts/oauth/complete', {}, self.body(started))
        self.assertEqual(sum(path.endswith('/oauth/complete') for path, _ in self.calls), 1)
        receipt = json.loads(self.adapter.receipt_path('fixture@example.com').read_text())
        self.assertEqual(receipt['phase'], 'native_complete_pending')

    def prepare_recovery(self):
        self.start()
        path = self.adapter.receipt_path('fixture@example.com')
        receipt = json.loads(path.read_text())
        receipt.update(phase='native_complete_pending', created=time.time()-1800)
        atomic(path, receipt)
        permits = self.root/'permits.json'
        atomic(permits, {path.stem: {'receiptSha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'oldFlowAbsent': True, 'expiresAt': time.time()+600}})
        self.adapter.recovery_permits = permits
        return path, permits

    def test_explicit_recovery_keeps_original_fixed_auth_and_history(self):
        path, _ = self.prepare_recovery()
        entry = self.manager.rows()[0]
        old = json.loads(path.read_text())
        started = self.start()
        self.assertEqual(self.manager.rows(), [entry])
        self.assertEqual(started['outboundProxyUrl'], self.adapter.url(entry))
        receipt = json.loads(path.read_text())
        self.assertEqual(receipt['recoveryHistory'], [old])
        self.assertNotEqual(receipt['flowId'], old['flowId'])
        with self.assertRaises(Rejected):
            self.start()

    def test_recovery_requires_fresh_exact_receipt_approval_and_absent_old_flow(self):
        path, permits = self.prepare_recovery()
        valid = json.loads(permits.read_text())
        for field, value in [('receiptSha256', 'changed'), ('oldFlowAbsent', False), ('expiresAt', 0)]:
            invalid = json.loads(json.dumps(valid));invalid[path.stem][field] = value
            atomic(permits, invalid)
            with self.assertRaises(Rejected):
                self.start()
        self.assertEqual(len(self.manager.rows()), 1)

    def test_recovery_rejects_bound_identity_and_live_flow(self):
        path, permits = self.prepare_recovery()
        entries = self.manager.rows();entries[0]['rs_account_id'] = 'already-bound'
        atomic(self.manager.reg, entries)
        with self.assertRaises(Rejected):
            self.start()
        entries[0]['rs_account_id'] = None;atomic(self.manager.reg, entries)
        receipt = json.loads(path.read_text());receipt['created'] = time.time();atomic(path, receipt)
        approval = json.loads(permits.read_text());approval[path.stem]['receiptSha256'] = hashlib.sha256(path.read_bytes()).hexdigest();atomic(permits, approval)
        with self.assertRaises(Rejected):
            self.start()


if __name__ == '__main__':
    unittest.main()
