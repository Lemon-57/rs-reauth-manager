import copy
import sys
import types
import unittest
from unittest.mock import patch

import fleet_sync
from fleet_slots import RemoteAllocator


class Allocator:
    url = staticmethod(RemoteAllocator.url)
    def __init__(self, config):
        pass

    def rows(self):
        return [{'account_id': 'acct_fixture', 'host': '192.0.2.10', 'port': 25001,
                 'username': 'fixture', 'password': 'fixture-password', 'ipv6': '2001:db8::1'}]

    def use_history(self):
        return {'entries': {'2001:db8::1': {'account_id': 'acct_fixture', 'retired': False}}}


class Tests(unittest.TestCase):
    def test_reimport_keeps_the_original_destination_identity(self):
        old = {'original_rs_id': 'source-original', 'target_rs_id': 'source-current',
               'management_id': 'chat-original', 'email': 'fixture@example.invalid',
               'user_id': 'fixture-user', 'workspace_id': 'fixture-workspace'}
        new = {**old, 'original_rs_id': 'source-current', 'management_id': 'chat-fresh'}
        mappings, registry = fleet_sync.retain_destination_ids({'source-current': old},
            {'source-current': new}, {'chat-fresh': {'management_id': 'chat-fresh', 'port': 25001}})
        self.assertEqual(mappings['source-current'], old)
        self.assertEqual(registry['chat-original']['port'], 25001)
        self.assertNotIn('chat-fresh', registry)

    def test_old_source_scope_does_not_depend_on_remote_pool(self):
        with patch.object(fleet_sync, 'RemoteAllocator', side_effect=AssertionError('Unexpected pool read')):
            self.assertEqual(fleet_sync.collect([{'outboundProxyEndpoint': 'http://127.0.0.1:27060'}], None, {'slots': {'host': '192.0.2.10'}}), ({}, {}))

    def test_projection_requires_current_instance_account_authentication_and_owner(self):
        row = {'id': 'acct_fixture', 'email': 'fixture@example.invalid', 'userId': 'fixture-user',
               'accountId': 'fixture-workspace', 'outboundProxyEndpoint': 'http://192.0.2.10:25001'}
        saved = {'id': row['id'], 'outboundProxyUrl': 'http://fixture:fixture-password@192.0.2.10:25001/'}
        def backend(_):
            return {'documents': [{'provider': 'openai', 'document': {'accounts': [saved]}}]}
        with patch.object(fleet_sync, 'RemoteAllocator', Allocator):
            mappings, registry = fleet_sync.collect([row], backend, {'slots': {'host': '192.0.2.10'}})
            self.assertEqual(mappings[row['id']]['user_id'], row['userId'])
            entry = next(iter(registry.values()))
            self.assertEqual(entry['rs_account_id'], row['id'])
            self.assertTrue(entry['_fleet_unique'])
            saved['outboundProxyUrl'] = 'http://another:account@192.0.2.10:25001'
            with self.assertRaises(ValueError):
                fleet_sync.collect([row], backend, {'slots': {'host': '192.0.2.10'}})

    def test_mixed_routes_preserve_existing_validation_and_exact_new_exit(self):
        legacy = types.SimpleNamespace()
        checked = []
        legacy.validate_binding = lambda row, reg: checked.append(row['management_id'])
        calls = []
        direct = types.SimpleNamespace(build_targets=lambda desired, known: calls.append(copy.deepcopy(desired)) or known)
        entry = {'host': '192.0.2.10', 'port': 25001, 'username': 'fixture',
                 'password': 'fixture-password', '_fleet_unique': True}
        registry = {'new': entry, 'old': {}}
        wanted = {'new': {'management_id': 'new', 'proxy': RemoteAllocator.url(entry)},
                  'old': {'management_id': 'old', 'proxy': 'http://old:fixture@127.0.0.1:27060'}}
        with patch.dict(sys.modules, {'native_proxy_policy': legacy, 'sync_direct': direct}):
            fleet_sync.install_routes(lambda: registry)
            self.assertEqual(direct.build_targets(wanted, {'existing': 'mapping'}), {'existing': 'mapping'})
            self.assertEqual(set(calls[0]), {'old'})
            legacy.validate_binding(wanted['old'], registry)
            self.assertEqual(checked, ['old'])
            wrong = {**wanted['new'], 'proxy': 'http://other:password@192.0.2.10:25001'}
            with self.assertRaises(ValueError):
                direct.build_targets({'new': wrong}, {})


if __name__ == '__main__':
    unittest.main()
