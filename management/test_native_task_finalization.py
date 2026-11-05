"""原生任务索引、Pro/ProLite 配置及结果未知时的不重放保护"""
import base64
import copy
import json
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

from native_task_finalization import digest, install


def token(plan='prolite', user='fixture-user', workspace='fixture-workspace'):
    claims = {'email': 'fixture@example.invalid', 'sub': 'fixture-subject', 'iat': 1000, 'exp': time.time() + 3600,
              'https://api.openai.com/auth': {'chatgpt_user_id': user,
                  'chatgpt_account_id': workspace, 'chatgpt_plan_type': plan}}
    return 'fixture.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.fixture'


class Rejected(Exception):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


class Allocator:
    def __init__(self):
        self.entry = {'port': 24001, 'host': 'fixture', 'username': 'fixture', 'password': 'fixture',
                      'ipv6': '2001:db8::1', 'account_id': None}
        self.history = {'entries': {'2001:db8::1': {'account_id': None, 'retired': False}}}
        self.verified = 0

    def all_rows(self):
        return [self.entry]

    def lookup(self, _):
        return self.entry

    def owner(self, entry):
        return entry['account_id']

    def slots(self):
        return {24001: self.entry}

    def use_history(self):
        return self.history

    def verify(self, _):
        self.verified += 1


class OriginalPolicy:
    def __init__(self, backend, allocator):
        self.backend, self.allocator = backend, allocator
        self.imports = 0

    def detail(self, account_id):
        return self.backend('/api/admin/accounts/detail?accountId=' + account_id)['account']

    def preflight_imports(self, _):
        pass

    def inventory(self):
        return []

    def match(self, row, provider='openai', existing=None):
        return None

    def entry_for(self, account):
        return self.allocator.entry

    def import_item(self, body, prefix):
        self.imports += 1
        prepared = copy.deepcopy(body)
        desired = prepared['settings']['enabled']
        prepared['settings']['enabled'] = False
        return prepared, [(self.allocator.entry, ('fixture-user', 'fixture-workspace'), desired)]

    def finish(self, account_ids, allocations):
        for account_id in account_ids:
            self.allocator.entry['account_id'] = account_id
            self.allocator.history['entries']['2001:db8::1']['account_id'] = account_id
            self.backend('/api/admin/accounts/batch-update', {'accountIds': [account_id], 'enabled': False})


class OriginalApplication:
    def __init__(self, allocator, root):
        self.allocator, self.root = allocator, Path(root)
        self.workers = set()

    def record_path(self, submission):
        return self.root / (submission + '.json')


def fixture():
    service = types.SimpleNamespace(NativePolicy=OriginalPolicy, Application=OriginalApplication,
        PolicyError=Rejected, MUTATION=threading.RLock(), candidates=lambda data: data.get('accounts', [data]),
        oauth_candidate=lambda row: True,
        atomic=lambda path, value: path.write_text(json.dumps(value)))
    install(service)
    return service


class Backend:
    def __init__(self, plan='prolite'):
        self.account = {'id': 'fixture-account', 'email': 'fixture@example.invalid', 'enabled': False,
            'userId': 'fixture-user', 'accountId': 'fixture-workspace', 'planType': plan,
            'concurrencyLimit': 3, 'weight': 1, 'notes': None, 'groups': []}
        self.account.update(capacity={'usedSlots': 0}, modelAccess={'mode': 'all', 'models': []})
        self.document = {'id': 'fixture-account', 'accessToken': token(plan), 'idToken': token(plan),
                         'refreshToken': 'fixture-rt', 'outboundProxyUrl': 'http://fixture:24001'}
        self.writes = []
        self.calls = []
        self.task = {'taskId': 'fixture-task', 'finishedAt': 'fixture-time', 'items': [
            {'index': 1, 'status': 'succeeded', 'accountIds': ['fixture-account']}]}

    def __call__(self, path, body=None):
        self.calls.append((path, copy.deepcopy(body)))
        if path.startswith('/api/admin/accounts/detail?'):
            return {'account': copy.deepcopy(self.account)}
        if path.startswith('/api/admin/accounts/export?'):
            return {'documents': [{'document': {'accounts': [copy.deepcopy(self.document)]}}]}
        if path.startswith('/api/admin/account-groups/options?'):
            return {'items': [{'id': 'fixture-pro-group', 'name': 'GPT Pro', 'enabled': True}]}
        if path == '/api/admin/accounts/batch-update':
            self.writes.append(copy.deepcopy(body))
            self.account.update({k: v for k, v in body.items() if k not in ['accountIds', 'groupIds']})
            if 'groupIds' in body:
                self.account['groups'] = [{'id': ident} for ident in body['groupIds']]
            return {}
        if path.startswith('/api/admin/accounts/import-tasks/detail?'):
            return copy.deepcopy(self.task)
        if path == '/api/admin/accounts/import-tasks':
            return {'taskId': 'fixture-task'}
        raise AssertionError('Unexpected fixture API')


class Tests(unittest.TestCase):
    def test_native_one_based_results_finalize_first_and_later_entries(self):
        for version, native_index in [(None, 1), (None, 3), (2, 1), (2, 3)]:
            with self.subTest(version=version, index=native_index), tempfile.TemporaryDirectory() as root:
                service = fixture()
                allocator, backend = Allocator(), Backend()
                app = service.Application(allocator, root)
                policy = service.NativePolicy(backend, allocator)
                backend.task['items'][0]['index'] = native_index
                index = native_index - 1 if version is None else native_index
                record = {'result': {'taskId': 'fixture-task'}, 'finished': [], 'bindings': [
                    {'index': index, 'port': 24001, 'identity': ['fixture-user', 'fixture-workspace'],
                     'desired': True, 'notesHash': digest(None)}]}
                if version:
                    record['version'] = version
                path = Path(root) / 'receipt.json'
                path.write_text(json.dumps(record))
                app.finish_task(path, record, backend, policy)
                self.assertTrue(backend.account['enabled'])
                self.assertEqual((backend.account['concurrencyLimit'], backend.account['weight']), (100, 100))
                self.assertEqual(backend.account['groups'], [{'id': 'fixture-pro-group'}])
                self.assertEqual(allocator.owner(allocator.entry), 'fixture-account')
                before = len(backend.writes)
                app.finish_task(path, record, backend, policy)
                self.assertEqual(len(backend.writes), before)

    def test_other_plans_retain_explicit_settings_and_enable_choice(self):
        for plan in ['promax', 'plus', 'team', 'business', 'free', 'go']:
            with self.subTest(plan=plan):
                service = fixture()
                allocator, backend = Allocator(), Backend(plan)
                backend.account.update(concurrencyLimit=7, weight=9, groups=[{'id': 'fixture-group'}])
                policy = service.NativePolicy(backend, allocator)
                policy.finish(['fixture-account'], [(allocator.entry, ('fixture-user', 'fixture-workspace'), False)])
                self.assertFalse(backend.account['enabled'])
                self.assertEqual((backend.account['concurrencyLimit'], backend.account['weight']), (7, 9))
                self.assertEqual(backend.account['groups'], [{'id': 'fixture-group'}])

    def test_invalid_tokens_and_unique_exit_failure_cannot_enable(self):
        for error in ['identity', 'plan', 'shared', 'exit']:
            with self.subTest(error=error):
                service = fixture()
                allocator, backend = Allocator(), Backend()
                if error == 'identity':
                    backend.document['idToken'] = token(user='another-user')
                elif error == 'plan':
                    backend.account['planType'] = 'pro'
                elif error == 'shared':
                    allocator.entry['ipv6'] = '192.0.2.1'
                else:
                    allocator.verify = lambda _: (_ for _ in ()).throw(ValueError('fixture-exit'))
                with self.assertRaises(Rejected):
                    service.NativePolicy(backend, allocator).finish(['fixture-account'], [
                        (allocator.entry, ('fixture-user', 'fixture-workspace'), True)])
                self.assertFalse(backend.account['enabled'])
                self.assertFalse(any(write.get('enabled') for write in backend.writes))

    def test_pro_and_prolite_both_use_verified_pro_policy(self):
        for plan in ['pro', 'prolite']:
            with self.subTest(plan=plan):
                service = fixture()
                allocator, backend = Allocator(), Backend(plan)
                service.NativePolicy(backend, allocator).finish(['fixture-account'], [
                    (allocator.entry, ('fixture-user', 'fixture-workspace'), True)])
                self.assertTrue(backend.account['enabled'])
                self.assertEqual((backend.account['concurrencyLimit'], backend.account['weight']), (100, 100))
                self.assertEqual(backend.account['groups'], [{'id': 'fixture-pro-group'}])

    def test_at_only_does_not_require_or_invent_refresh_or_id_tokens(self):
        service = fixture()
        allocator, backend = Allocator(), Backend('free')
        backend.document.pop('refreshToken')
        backend.document.pop('idToken')
        service.NativePolicy(backend, allocator).finish(['fixture-account'], [
            (allocator.entry, ('fixture-user', 'fixture-workspace'), True)])
        self.assertTrue(backend.account['enabled'])
        self.assertEqual(backend.account['concurrencyLimit'], 3)

    def test_all_new_plans_require_independent_ipv6_and_saved_import_controls(self):
        for plan in ['free', 'pro', 'prolite']:
            for failure in ['shared-exit', 'missing-rt', 'notes-mismatch']:
                with self.subTest(plan=plan, failure=failure):
                    service = fixture()
                    allocator, backend = Allocator(), Backend(plan)
                    policy = service.NativePolicy(backend, allocator)
                    policy.import_controls = {('fixture-user', 'fixture-workspace'): {
                        'expectsRT': True, 'notesHash': digest(None)}}
                    if failure == 'shared-exit':
                        allocator.entry['ipv6'] = '192.0.2.1'
                    elif failure == 'missing-rt':
                        backend.document.pop('refreshToken')
                    else:
                        backend.account['notes'] = 'unexpected-notes'
                    with self.assertRaises(Rejected):
                        policy.finish(['fixture-account'], [
                            (allocator.entry, ('fixture-user', 'fixture-workspace'), True)])
                    self.assertFalse(any(write.get('enabled') for write in backend.writes))

    def test_unknown_submission_is_not_replayed_after_restart(self):
        with tempfile.TemporaryDirectory() as root:
            service = fixture()
            allocator, backend = Allocator(), Backend()
            app = service.Application(allocator, root)
            policy = service.NativePolicy(backend, allocator)
            body = {'submissionId': '00000000-0000-0000-0000-000000000001', 'items': [
                {'provider': 'openai', 'data': {'email': 'fixture@example.invalid', 'refreshToken': 'fixture'}}]}
            backend_call = lambda path, data=None: (_ for _ in ()).throw(TimeoutError())
            with self.assertRaises(TimeoutError):
                app.submit_task(body, backend_call, policy)
            self.assertEqual(policy.imports, 1)
            app = service.Application(allocator, root)
            with self.assertRaises(Rejected):
                app.submit_task(body, backend, policy)
            self.assertEqual(policy.imports, 1)

    def test_already_enabled_account_is_not_paused_for_reconciliation(self):
        service = fixture()
        allocator, backend = Allocator(), Backend()
        backend.account['enabled'] = True
        with self.assertRaises(Rejected):
            service.NativePolicy(backend, allocator).finish(['fixture-account'], [
                (allocator.entry, ('fixture-user', 'fixture-workspace'), True)])
        self.assertEqual(backend.writes, [])

    def test_paused_existing_account_keeps_settings_proxy_and_record_identity(self):
        service = fixture()
        allocator, backend = Allocator(), Backend('pro')
        backend.account.update(concurrencyLimit=7, weight=9, groups=[{'id': 'fixture-group'}], notes='fixture-notes')
        policy = service.NativePolicy(backend, allocator)
        policy.match = lambda *args, **kwargs: copy.deepcopy(backend.account)
        body = {'provider': 'openai', 'data': {'email': backend.account['email'], 'refreshToken': 'fixture-new'},
                'settings': {'enabled': True, 'concurrencyLimit': 100, 'weight': 100, 'groupIds': []}}
        prepared, allocations = policy.import_item(body, 'fixture')
        self.assertEqual(prepared['settings']['concurrencyLimit'], 7)
        self.assertEqual(prepared['settings']['weight'], 9)
        self.assertEqual(prepared['settings']['notes'], 'fixture-notes')
        policy.finish(['fixture-account'], allocations)
        self.assertTrue(backend.account['enabled'])
        self.assertEqual((backend.account['concurrencyLimit'], backend.account['weight']), (7, 9))
        self.assertEqual(backend.account['groups'], [{'id': 'fixture-group'}])

    def test_known_older_refresh_version_cannot_overwrite_current_credentials(self):
        service = fixture()
        allocator, backend = Allocator(), Backend('free')
        policy = service.NativePolicy(backend, allocator)
        policy.match = lambda *args, **kwargs: copy.deepcopy(backend.account)
        with self.assertRaises(Rejected):
            policy.import_item({'provider': 'openai', 'data': {
                'accessToken': backend.document['accessToken'], 'refreshToken': 'fixture-obsolete'}}, 'fixture')
        self.assertEqual(policy.imports, 0)

    def test_new_task_records_native_indices_and_safe_notes_digest(self):
        with tempfile.TemporaryDirectory() as root, patch('threading.Thread'):
            service = fixture()
            allocator, backend = Allocator(), Backend()
            app = service.Application(allocator, root)
            policy = service.NativePolicy(backend, allocator)
            body = {'submissionId': '00000000-0000-0000-0000-000000000002', 'items': [
                {'provider': 'openai', 'data': {'email': 'fixture@example.invalid', 'refreshToken': 'fixture'},
                 'settings': {'notes': 'fixture-private-notes'}}]}
            app.submit_task(body, backend, policy)
            saved = app.record_path(body['submissionId']).read_text()
            record = json.loads(saved)
            self.assertEqual(record['bindings'][0]['index'], 1)
            self.assertNotIn('fixture-private-notes', saved)
            self.assertEqual(record['bindings'][0]['notesHash'], digest('fixture-private-notes'))
            prepared = next(data for path, data in backend.calls if path == '/api/admin/accounts/import-tasks')
            self.assertEqual(prepared['items'][0]['settings']['concurrencyLimit'], 3)
            self.assertFalse(prepared['items'][0]['settings']['enabled'])


if __name__ == '__main__':
    unittest.main()
