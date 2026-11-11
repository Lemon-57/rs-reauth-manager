"""Exercise the actual native policy with fresh reservations and persisted readback."""
import base64
import contextlib
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
import urllib.parse

from fleet_import_service import load_service
from fleet_slots import RemoteAllocator, SlotError


def jwt(plan, user='fixture-user'):
    claims = {'email': 'fixture@example.invalid', 'sub': 'fixture-subject',
        'iat': int(time.time()), 'exp': time.time() + 3600,
        'https://api.openai.com/auth': {'chatgpt_user_id': user,
            'chatgpt_account_id': 'fixture-workspace', 'chatgpt_plan_type': plan}}
    return 'fixture.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.signature'


class Allocator:
    url = staticmethod(RemoteAllocator.url)
    endpoint = staticmethod(RemoteAllocator.endpoint)
    owner = staticmethod(RemoteAllocator.owner)

    def __init__(self, plan):
        self.plan, self.entries, self.keys, self.flows = plan, [], {}, {}
        self.configuration = {'host': '127.0.0.1'}
        self.refreshes = self.verifications = 0

    def allocate(self, key):
        if key not in self.keys:
            number = len(self.entries) + 1
            entry = {'host': '127.0.0.1', 'port': 25000 + number, 'username': 'fixture' + str(number),
                'password': 'fixture-password-' + str(number), 'ipv6': '2001:db8::' + str(number),
                'family': 6, 'account_id': None, 'key': key, 'validated_at': time.time()}
            self.entries.append(entry)
            self.keys[key] = entry
        return self.keys[key]

    def verify(self, entry):
        self.verifications += 1
        entry['validated_at'] = time.time()

    def exchange_refresh(self, entry, refresh):
        self.refreshes += 1
        assert entry['account_id'] is None
        return {'access_token': jwt(self.plan), 'id_token': jwt(self.plan), 'refresh_token': 'fixture-issued-rt'}

    def bind(self, entry, account_id):
        entry['account_id'] = account_id

    def lookup(self, url):
        port = urllib.parse.urlsplit(url).port
        return next((entry for entry in self.entries if entry['port'] == port), None)

    def all_rows(self):
        return self.entries

    def slots(self):
        return {entry['port']: entry for entry in self.entries}

    def use_history(self):
        return {'entries': {entry['ipv6']: {'account_id': entry['account_id'], 'retired': False} for entry in self.entries}}

    def flow(self, flow, entry, account_id):
        self.flows[flow] = (entry, account_id)

    def get_flow(self, flow):
        return self.flows[flow]


class Backend:
    def __init__(self, allocator):
        self.allocator, self.accounts, self.documents, self.writes = allocator, {}, {}, []

    def create(self, data, settings, proxy):
        account_id = 'acct_fixture_' + str(len(self.accounts) + 1)
        self.accounts[account_id] = {'id': account_id, 'provider': 'openai', 'authenticationKind': 'oauth',
            'email': 'fixture@example.invalid', 'name': 'fixture@example.invalid', 'userId': 'fixture-user',
            'accountId': 'fixture-workspace', 'planType': self.allocator.plan,
            'enabled': settings['enabled'], 'concurrencyLimit': settings['concurrencyLimit'],
            'weight': settings['weight'], 'notes': settings.get('notes'), 'groups': [],
            'modelAccess': settings.get('modelAccess', {'mode': 'all'}),
            'outboundProxyEndpoint': self.allocator.endpoint(self.allocator.lookup(proxy)),
            'capacity': {'usedSlots': 0}}
        self.documents[account_id] = {'id': account_id, 'accessToken': jwt(self.allocator.plan),
            'idToken': jwt(self.allocator.plan), 'outboundProxyUrl': proxy,
            'refreshToken': data.get('refreshToken')}
        return account_id

    def __call__(self, path, body=None):
        url = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qs(url.query)
        if url.path == '/api/admin/accounts':
            return {'items': list(self.accounts.values())}
        if url.path == '/api/admin/accounts/detail':
            return {'account': copy.deepcopy(self.accounts[query['accountId'][0]])}
        if url.path == '/api/admin/accounts/export':
            return {'documents': [{'provider': 'openai', 'document': {'accounts': [copy.deepcopy(self.documents[query['accountIds'][0]])]}}]}
        if url.path == '/api/admin/accounts/import':
            data = body['data'].get('accounts', [body['data']])[0]
            account_id = self.create(data, body['settings'], data['outboundProxyUrl'])
            return {'accountIds': [account_id], 'importedCount': 1, 'configRevision': 1}
        if url.path in ('/api/admin/accounts/batch-update', '/api/admin/accounts/update'):
            self.writes.append(copy.deepcopy(body))
            account = self.accounts[body['accountIds'][0] if 'accountIds' in body else body['accountId']]
            account.update({key: value for key, value in body.items() if key not in {'accountId', 'accountIds', 'groupIds'}})
            if 'groupIds' in body:
                account['groups'] = [{'id': group, 'name': 'GPT Pro', 'enabled': True} for group in body['groupIds']]
            return {'configRevision': 1}
        if url.path == '/api/admin/account-groups/options':
            return {'items': [{'id': 'gpt-pro', 'name': 'GPT Pro', 'enabled': True}]}
        if url.path == '/api/admin/accounts/oauth/start':
            self.start_proxy = body['outboundProxyUrl']
            self.existing_oauth = body.get('accountId')
            return {'flowId': 'native-fixture-flow', 'authorizationUrl': 'https://fixture.invalid/native'}
        if url.path == '/api/admin/accounts/oauth/complete':
            entry, _ = self.allocator.get_flow(body['flowId'])
            if self.existing_oauth:
                return {'accountId': self.existing_oauth}
            account_id = self.create({'refreshToken': 'native-fixture-rt'}, body['settings'], self.allocator.url(entry))
            return {'accountId': account_id}
        raise AssertionError('Unexpected native API: ' + url.path)


class Tests(unittest.TestCase):
    def test_rt_failure_preserves_safe_status_without_persisting_or_replaying(self):
        from legacy_policy import PolicyError
        for status in (409, 422, 502):
            policy, backend, allocator = self.policy()
            attempts = []
            def fail(entry, refresh):
                attempts.append(entry['port'])
                raise SlotError('Safe RT failure', status)
            allocator.exchange_refresh = fail
            with self.assertRaises(PolicyError) as caught:
                policy.import_sync({'provider': 'openai', 'data': {
                    'email': 'fixture@example.invalid', 'refreshToken': 'fixture-rt'},
                    'settings': {'enabled': False}})
            self.assertEqual(caught.exception.status, status)
            self.assertEqual(len(attempts), 1)
            self.assertEqual(len(allocator.entries), 1)
            self.assertFalse(backend.accounts)

    def test_legacy_management_edits_keep_original_proxy_and_controls(self):
        policy, backend, allocator = self.policy()
        created = policy.import_sync({'provider': 'openai', 'data': {'email': 'fixture@example.invalid',
            'accessToken': jwt('pro')}, 'settings': {'enabled': True}})
        account = backend.accounts[created['accountIds'][0]]
        # The existing local fixed-pool account remains outside the fleet host.
        allocator.configuration = {'host': 'pool.example.invalid'}
        account['outboundProxyEndpoint'] = 'http://127.0.0.1:27060/'
        before = copy.deepcopy(account)
        policy.update('/api/admin/accounts/batch-update', {'accountIds': [account['id']], 'notes': 'edited'})
        self.assertEqual(account, {**before, 'notes': 'edited'})
        self.assertEqual(len(allocator.entries), 1)
        with self.assertRaises(Exception):
            policy.update('/api/admin/accounts/batch-update', {'accountIds': [account['id']],
                'outboundProxyUrl': 'http://another:proxy@another.invalid:20000'})

    def test_ordinary_existing_native_oauth_keeps_original_exit_groups_and_capacity(self):
        policy, backend, allocator = self.policy()
        created = policy.import_sync({'provider': 'openai', 'data': {'email': 'fixture@example.invalid',
            'accessToken': jwt('pro')}, 'settings': {'enabled': True}})
        account = backend.accounts[created['accountIds'][0]]
        account.update(concurrencyLimit=7, weight=9, groups=[{'id': 'custom', 'name': 'Custom'}])
        original = copy.deepcopy(account)
        start = policy.start_oauth({'provider': 'openai', 'accountId': account['id']})
        policy.complete_oauth({'provider': 'openai', 'flowId': start['flowId'], 'callbackUrl': 'fixture'})
        self.assertEqual(account, original)
        self.assertEqual(len(allocator.entries), 1)

    def policy(self, plan='pro', receipt_root=None):
        service = load_service(Path(__file__).with_name('native_core'), receipt_root, __import__('types').SimpleNamespace(reserve=lambda *args: {'weight':100 if args[2]=='prolite' else 50}))
        # Proxy-budget logic is independently inherited; these cases test import
        # identity, pool reservation, native persistence and scheduling completion.
        service.NativePolicy.ensure_new_proxy_budget = lambda *_: None
        allocator = Allocator(plan)
        backend = Backend(allocator)
        return service.NativePolicy(backend, allocator), backend, allocator

    def test_all_native_token_formats_reserve_new_unique_ipv6_before_persistence(self):
        for plan in ['pro', 'prolite', 'self_serve_business_prolite', 'free', 'team', 'business', 'plus', 'promax', 'go']:
            for kind in ['at', 'rt', 'json']:
                with self.subTest(plan=plan, kind=kind):
                    policy, backend, allocator = self.policy(plan)
                    data = {'email': 'fixture@example.invalid'}
                    if kind == 'rt':
                        data['refreshToken'] = 'fixture-provided-rt'
                    else:
                        data.update(accessToken=jwt(plan), idToken=jwt(plan))
                    if kind == 'json':
                        data = {'accounts': [data]}
                    result = policy.import_sync({'provider': 'openai', 'data': data,
                        'settings': {'enabled': True, 'notes': 'fixture----fixture----fixture'}})
                    account = backend.accounts[result['accountIds'][0]]
                    self.assertTrue(account['enabled'])
                    self.assertEqual(allocator.owner(allocator.entries[0]), account['id'])
                    self.assertEqual(len(allocator.entries), 1)
                    self.assertGreaterEqual(allocator.verifications, 2)
                    self.assertEqual(allocator.refreshes, int(kind == 'rt'))
                    self.assertEqual(account['concurrencyLimit'], 10 if plan=='self_serve_business_prolite' else 100 if plan in ['pro', 'prolite'] else 3)
                    if plan in ['pro', 'prolite', 'self_serve_business_prolite']:
                        self.assertEqual(account['weight'], 20 if plan=='self_serve_business_prolite' else 100 if plan=='prolite' else 50)
                        if plan=='self_serve_business_prolite':self.assertEqual(account['supplier'],'shannian')
                        self.assertEqual(account['groups'], [{'id': 'gpt-pro', 'name': 'GPT Pro', 'enabled': True}])

    def test_plugin_rt_import_remains_paused_until_plugin_completion(self):
        policy, backend, allocator = self.policy()
        result = policy.import_sync({'provider': 'openai', 'data': {'email': 'fixture@example.invalid',
            'refreshToken': 'fixture-rt'}, 'settings': {'enabled': False}})
        self.assertFalse(backend.accounts[result['accountIds'][0]]['enabled'])
        self.assertEqual(backend.accounts[result['accountIds'][0]]['groups'][0]['name'], 'GPT Pro')

    def test_native_oauth_new_account_gets_pro_group_and_100_settings(self):
        policy, backend, allocator = self.policy()
        start = policy.start_oauth({'provider': 'openai', 'name': 'fixture@example.invalid'})
        self.assertEqual(backend.start_proxy, allocator.url(allocator.entries[0]))
        result = policy.complete_oauth({'provider': 'openai', 'flowId': start['flowId'], 'callbackUrl': 'fixture-callback'})
        account = backend.accounts[result['accountId']]
        self.assertTrue(account['enabled'])
        self.assertEqual(account['groups'][0]['name'], 'GPT Pro')
        self.assertEqual((account['concurrencyLimit'], account['weight']), (100, 50))

    def test_distinct_submissions_never_reuse_a_failed_reservation(self):
        policy, backend, allocator = self.policy()
        body = {'provider': 'openai', 'data': {'email': 'fixture@example.invalid', 'accessToken': jwt('pro')}}
        one, allocations = policy.import_item(body, 'submission-one')
        two, later = policy.import_item(body, 'submission-two')
        self.assertNotEqual(allocations[0][0]['ipv6'], later[0][0]['ipv6'])
        self.assertNotEqual(one['data']['outboundProxyUrl'], two['data']['outboundProxyUrl'])
        again, recovered = policy.import_item(body, 'submission-two')
        self.assertEqual(recovered[0][0], later[0][0])


if __name__ == '__main__':
    unittest.main()
