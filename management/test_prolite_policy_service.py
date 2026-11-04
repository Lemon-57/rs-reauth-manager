import copy
import unittest
from prolite_policy_service import Application, CHECK, unique_entry


class Allocator:
    def __init__(self):
        self.entry = {'host': 'fixture', 'port': 24001, 'username': 'fixture', 'password': 'fixture',
                      'ipv6': '2001:db8::1', 'account_id': 'fixture-account'}
        self.history = {'entries': {'2001:db8::1': {'account_id': 'fixture-account', 'retired': False}}}
        self.rows = [self.entry]

    def lookup(self, _):
        return self.entry

    def owner(self, entry):
        return entry['account_id']

    def slots(self):
        return {24001: copy.deepcopy(self.entry)}

    def use_history(self):
        return self.history

    def all_rows(self):
        return self.rows


class Tests(unittest.TestCase):
    def test_fixed_slot_requires_unique_ipv6_and_permanent_account_owner(self):
        allocator = Allocator()
        self.assertEqual(unique_entry(allocator, 'fixture', 'fixture-account'), allocator.entry)
        for change in ['owner', 'retired', 'shared', 'ipv4']:
            allocator = Allocator()
            if change == 'owner':
                allocator.history['entries']['2001:db8::1']['account_id'] = 'another-account'
            elif change == 'retired':
                allocator.history['entries']['2001:db8::1']['retired'] = True
            elif change == 'shared':
                allocator.rows.append({**allocator.entry, 'port': 24002})
            else:
                allocator.entry['ipv6'] = '192.0.2.1'
            with self.subTest(change=change), self.assertRaises(ValueError):
                unique_entry(allocator, 'fixture', 'fixture-account')

    def test_authentication_precedes_every_check_and_forward(self):
        app = Application(19701, 18118, 'https://fixture.invalid')
        app.send = lambda *args: (403, {'code': 403})
        self.assertEqual(app.call(CHECK, {}, {'accountId': 'fixture', 'credentialRevision': 1})[0], 403)

    def test_shared_pool_fails_without_allocating_or_forwarding(self):
        app = Application(19701, 18118, 'https://fixture.invalid')
        calls = []
        app.send = lambda *args: (calls.append(args) or (200, {'code': 200, 'data': {}}))
        self.assertEqual(app.call(CHECK, {}, {'accountId': 'fixture', 'credentialRevision': 1})[0], 409)
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
