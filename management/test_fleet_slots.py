import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.parse

from fleet_slots import Broker, RemoteAllocator, SlotError, atomic


class Authority:
    url = staticmethod(RemoteAllocator.url)
    owner = staticmethod(RemoteAllocator.owner)

    def __init__(self, root):
        self.path = Path(root) / 'registry.json'
        self.reservations = Path(root) / 'reservations.json'
        atomic(self.path, [])
        atomic(self.reservations, {})
        self.history = {'entries': {}}
        self.mutex = threading.RLock()

    def lock(self):
        return self.mutex

    def rows(self):
        return json.loads(self.path.read_text())

    def reserved(self):
        return json.loads(self.reservations.read_text())

    def all_rows(self):
        return self.rows() + list(self.reserved().values())

    def allocate(self, key):
        reserved = self.reserved()
        if key not in reserved:
            number = len(self.history['entries']) + 1
            entry = {'host': 'fixture', 'port': 25000 + number, 'ipv6': '2001:db8::' + str(number),
                'username': 'fixture' + str(number), 'password': 'fixture-password' + str(number),
                'account_id': None, 'key': key}
            self.history['entries'][entry['ipv6']] = {'account_id': None, 'retired': False,
                'reservation_hash': hashlib.sha256(key.encode()).hexdigest()}
            reserved[key] = entry
            atomic(self.reservations, reserved)
        return reserved[key]

    def use_history(self):
        return self.history

    def lookup(self, url):
        return next((entry for entry in self.all_rows() if self.url(entry) == url), None)

    def verify(self, entry):
        pass

    def bind(self, entry, account_id):
        rows = self.rows()
        existing = next((row for row in rows if row['port'] == entry['port']), None)
        if existing:
            assert existing['account_id'] == account_id
            return
        assert not any(row['account_id'] == account_id for row in rows)
        entry['account_id'] = account_id
        rows.append(entry)
        atomic(self.path, rows)
        atomic(self.reservations, {key: row for key, row in self.reserved().items() if row['port'] != entry['port']})
        self.history['entries'][entry['ipv6']]['account_id'] = account_id

    def slots(self):
        return {row['port']: row for row in self.all_rows()}


class Tests(unittest.TestCase):
    def test_refresh_failures_never_echo_upstream_body_or_retry(self):
        import urllib.error
        client = RemoteAllocator({})
        entry = {'host': 'proxy.example.invalid', 'port': 25001,
                 'username': 'fixture', 'password': 'fixture-password'}
        for error, status in [
            (urllib.error.HTTPError('https://auth.openai.com/oauth/token', 401,
                'fixture-secret', {}, io.BytesIO(b'fixture-secret')), 422),
            (urllib.error.URLError('fixture-secret'), 502),
            (TimeoutError('fixture-secret'), 502),
            (ValueError('fixture-secret'), 502),
        ]:
            with patch('urllib.request.build_opener') as build:
                build.return_value.open.side_effect = error
                with self.assertRaises(SlotError) as caught:
                    client.exchange_refresh(entry, 'fixture-secret')
                self.assertEqual(caught.exception.status, status)
                self.assertNotIn('fixture-secret', str(caught.exception))
                self.assertEqual(build.return_value.open.call_count, 1)

    def test_supplied_refresh_validation_runs_locally_through_its_fixed_proxy(self):
        client = RemoteAllocator({'host': 'pool.example.invalid', 'port': 19720})
        entry = {'host': 'proxy.example.invalid', 'port': 25001,
                 'username': 'fixture', 'password': 'fixture-password'}
        calls = []
        class Opener:
            def open(self, request, timeout):
                calls.append((request, timeout))
                return io.BytesIO(b'{"access_token":"fixture-at","refresh_token":"fixture-rt"}')
        with patch('urllib.request.build_opener', return_value=Opener()) as build:
            client.rpc = lambda *_: (_ for _ in ()).throw(AssertionError('Pool control must never receive an account RT'))
            result = client.exchange_refresh(entry, 'fixture-provided-rt')
            self.assertEqual(result['refresh_token'], 'fixture-rt')
            self.assertEqual(build.call_args.args[0].proxies, {'https': client.url(entry)})
            request, timeout = calls[0]
            self.assertEqual(request.full_url, 'https://auth.openai.com/oauth/token')
            self.assertEqual(urllib.parse.parse_qs(request.data.decode())['refresh_token'], ['fixture-provided-rt'])

    def test_fleet_uses_distinct_never_used_ipv6_and_exact_recovery(self):
        with tempfile.TemporaryDirectory() as root:
            authority = Authority(root)
            broker = Broker(authority, Path(root) / 'ledger.json')
            first = broker.call('lac01', 'allocate', ['same-request'])
            second = broker.call('lac02', 'allocate', ['same-request'])
            self.assertNotEqual(first['ipv6'], second['ipv6'])
            self.assertEqual(first, broker.call('lac01', 'allocate', ['same-request']))
            fresh = broker.call('lac01', 'allocate', ['new-request'])
            self.assertNotEqual(first['ipv6'], fresh['ipv6'])
            with self.assertRaises(SlotError):
                broker.call('lac02', 'verify', [first])
            self.assertIsNone(broker.call('lac02', 'lookup', [authority.url(first)]))

    def test_explicit_reimport_retains_old_consumers_and_permanent_ownership(self):
        with tempfile.TemporaryDirectory() as root:
            authority = Authority(root)
            broker = Broker(authority, Path(root) / 'ledger.json')
            first = broker.call('lac01', 'allocate', ['original'])
            broker.call('lac01', 'bind', [first, 'acct_fixture'])
            second = broker.call('lac01', 'allocate', ['reimport'])
            broker.call('lac01', 'bind', [second, 'acct_fixture'])
            self.assertEqual(authority.rows()[0]['port'], second['port'])
            self.assertEqual(authority.lookup(authority.url(first))['account_id'], 'acct_fixture')
            self.assertEqual(authority.history['entries'][first['ipv6']]['account_id'], 'acct_fixture')
            self.assertFalse(authority.history['entries'][first['ipv6']]['retired'])
            self.assertEqual(len(authority.reserved()), 1)
            with self.assertRaises(Exception):
                broker.call('lac01', 'bind', [first, 'acct_different'])


if __name__ == '__main__':
    unittest.main()
