from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing
import sqlite3
import tempfile
import unittest

from daily_import_weight import DailyImportWeight
from native_task_finalization import install
from test_native_task_finalization import fixture, Backend, Allocator


class Tests(unittest.TestCase):
    def test_daily_plans_cannot_enable_without_daily_ledger(self):
        for plan in ['pro', 'prolite']:
            with self.subTest(plan=plan):
                service = fixture()
                service.NativePolicy = service.NativePolicy.__bases__[0]
                service.Application = service.Application.__bases__[0]
                install(service, None)
                backend, allocator = Backend(plan), Allocator()
                with self.assertRaises(Exception) as caught:
                    service.NativePolicy(backend, allocator).finish([backend.account['id']], [
                        (allocator.entry, ('fixture-user', 'fixture-workspace'), True)])
                self.assertEqual(caught.exception.status, 503)
                self.assertFalse(backend.account['enabled'])

    def test_business_fixed_weight_needs_no_daily_ledger(self):
        service = fixture()
        service.NativePolicy = service.NativePolicy.__bases__[0]
        service.Application = service.Application.__bases__[0]
        install(service, None)
        backend, allocator = Backend('self_serve_business_prolite'), Allocator()
        service.NativePolicy(backend, allocator).finish([backend.account['id']], [
            (allocator.entry, ('fixture-user', 'fixture-workspace'), True)])
        self.assertEqual((backend.account['concurrencyLimit'], backend.account['weight'], backend.account['supplier']), (10,20,'shannian'))
        self.assertTrue(backend.account['enabled'])

    def test_beijing_midnight_and_recovery_keep_original_assignment(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'weights.sqlite3'
            weights = DailyImportWeight.initialize(path)
            weights.clock = lambda: datetime(2026, 11, 6, 15, 59, 59, tzinfo=timezone.utc)
            self.assertEqual(weights.reserve('first', 1)['weight'], 50)
            self.assertEqual(weights.reserve('second', 2)['weight'], 49)
            weights.clock = lambda: datetime(2026, 11, 6, 16, 0, tzinfo=timezone.utc)
            third = weights.reserve('third', 3)
            self.assertEqual((third['weight'], third['day']), (50, '2026-11-07'))
            self.assertEqual(weights.reserve('second', 2)['weight'], 49)
            self.assertEqual(DailyImportWeight(path).reserve('third', 3), third)
            self.assertEqual(weights.reserve('first', 4)['weight'], 49) # explicit new slot

    def test_concurrent_process_connections_and_floor(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'weights.sqlite3'
            DailyImportWeight.initialize(path)
            def reserve(index):
                return DailyImportWeight(path).reserve(str(index), index + 1)
            with ThreadPoolExecutor(max_workers=12) as pool:
                receipts = list(pool.map(reserve, range(105)))
            self.assertEqual(sorted(r['ordinal'] for r in receipts), list(range(1, 106)))
            self.assertEqual(sorted(r['weight'] for r in receipts), [1] * 56 + list(range(2, 51)))
            with ThreadPoolExecutor(max_workers=12) as pool:
                repeated = list(pool.map(lambda _: reserve(200), range(20)))
            self.assertTrue(all(r == repeated[0] for r in repeated))

    def test_legacy_receipts_are_immutable_and_new_sequences_start_independently(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'weights.sqlite3'
            weights=DailyImportWeight.initialize(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("INSERT INTO assignments VALUES ('old',1,'2026-11-06',2,99)")
            self.assertEqual(weights.reserve('old',1,'prolite')['weight'],99)
            self.assertEqual(weights.reserve('old',1,'pro')['sequence'],'legacy')
            self.assertEqual(weights.reserve('a',2,'pro')['weight'],50)
            self.assertEqual(weights.reserve('b',3,'prolite')['weight'],100)
            with self.assertRaisesRegex(ValueError, 'unsupported_import_weight_plan'):
                weights.reserve('c',4,'self_serve_business_prolite')
            self.assertEqual(weights.reserve('c',4,'pro')['weight'],49)
            with self.assertRaisesRegex(ValueError,'sequence_changed'):
                weights.reserve('a',2,'prolite')
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT * FROM assignments').fetchall(),[('old',1,'2026-11-06',2,99)])

    def test_missing_corrupt_or_unknown_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'weights.sqlite3'
            with self.assertRaises(sqlite3.OperationalError):
                DailyImportWeight(path).reserve('first', 1)
            self.assertFalse(path.exists())
            DailyImportWeight.initialize(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('PRAGMA user_version=2')
            with self.assertRaises(ValueError):
                DailyImportWeight(path).reserve('first', 1)

    def test_native_finalization_shares_sequence_only_for_pro_plans(self):
        with tempfile.TemporaryDirectory() as root:
            weights = DailyImportWeight.initialize(Path(root) / 'weights.sqlite3')
            for index, (plan, expected) in enumerate([('pro', 50), ('free', 1), ('prolite', 100), ('self_serve_business_prolite', 20), ('promax', 1), ('pro', 49), ('prolite',99)]):
                service = fixture()
                # Apply to the original base, avoiding nested finalization wrappers.
                service.NativePolicy = service.NativePolicy.__bases__[0]
                service.Application = service.Application.__bases__[0]
                install(service, weights)
                backend, allocator = Backend(plan), Allocator()
                backend.account['id'] = backend.document['id'] = 'account-' + str(index)
                policy = service.NativePolicy(backend, allocator)
                policy.finish([backend.account['id']], [(allocator.entry, ('fixture-user', 'fixture-workspace'), True)])
                self.assertEqual(backend.account['weight'], expected)
                if plan in ['pro','prolite','self_serve_business_prolite']:
                    self.assertEqual(backend.account['concurrencyLimit'], 10 if plan=='self_serve_business_prolite' else 100)
                self.assertTrue(backend.account['enabled'])
            # Retry after a write failed must use the already allocated value.
            self.assertEqual(weights.reserve('account-2', 24001,'prolite')['weight'], 100)

    def test_plugin_exit_proof_and_native_finish_reuse_the_same_assignment(self):
        from prolite_policy_service import Application, IPV6_CHECK
        from test_fleet_import_service import Allocator as FleetAllocator, Backend as FleetBackend
        with tempfile.TemporaryDirectory() as root:
            weights = DailyImportWeight.initialize(Path(root) / 'weights.sqlite3')
            weights.reserve('prior-import', 20000)
            for plan, expected in [('pro',49),('self_serve_business_prolite',20),('prolite',100)]:
                allocator = FleetAllocator(plan)
                backend = FleetBackend(allocator)
                entry = allocator.allocate('fixture-flow')
                account_id = backend.create({'refreshToken': 'fixture'}, {'enabled': False,
                    'concurrencyLimit': 3, 'weight': 1}, allocator.url(entry))
                unique_id = 'proof-' + plan
                backend.accounts[unique_id] = backend.accounts.pop(account_id)
                backend.accounts[unique_id]['id'] = unique_id
                backend.documents[unique_id] = backend.documents.pop(account_id)
                backend.documents[unique_id]['id'] = unique_id
                account_id = unique_id
                allocator.bind(entry, account_id)
                checker = Application(1, 2, 'https://fixture.invalid', allocator, weights)
                checker.send = lambda port, path, headers, body=None: (200, {'code': 200, 'data': backend(path, body)})
                for _ in range(2):
                    status, result = checker.call(IPV6_CHECK, {}, {'accountId': account_id, 'credentialRevision': 1})
                    self.assertEqual(status, 200)
                    if plan == 'self_serve_business_prolite':
                        self.assertNotIn('importWeight',result['data'])
                    else:
                        self.assertEqual(result['data']['importWeight']['weight'], expected)
                self.assertFalse(backend.accounts[account_id]['enabled'])
                self.assertEqual(backend.accounts[account_id]['weight'], 1) # Proof does not mutate the account.


if __name__ == '__main__':
    unittest.main()
