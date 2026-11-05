import datetime
import json
import tempfile
import types
import unittest
from pathlib import Path
from exact_start_recovery import recovery_adapter


class Rejected(Exception):
    pass


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'receipt.json'
        self.entries = [{'management_id': 'entry', 'email': 'fixture@example.com',
                         'rs_account_id': None}]
        owner = self
        class Base:
            def __init__(self):
                self.manager = types.SimpleNamespace(rows=lambda: owner.entries)
            def receipt_path(self, email): return owner.path
            def directory(self, headers):
                if headers != {'auth': 'fixture'}: raise Rejected(403)
                return owner.accounts
            def url(self, entry): return 'http://fixture:fixture@127.0.0.1:24001'
            def verify_exit(self, entry): owner.probes += 1
            def start(self, headers, body):
                self.directory(headers)
                if owner.path.exists(): raise Rejected(409)
                owner.starts += 1
                result = {'flowId': 'flow', 'authorizationUrl': 'https://example.invalid',
                          'expiresAt': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat(),
                          'outboundProxyUrl': self.url(owner.entries[0])}
                owner.path.write_text(json.dumps({'requestId': body['requestId'], 'email': body['email'],
                    'phase': 'native_started', 'flowId': 'flow', 'entryId': 'entry'}))
                return result
        self.starts = self.probes = 0
        self.accounts = []
        self.adapter = recovery_adapter(types.SimpleNamespace(Adapter=Base, Rejected=Rejected,
            atomic=lambda path, value: path.write_text(json.dumps(value))))()
        self.body = {'email': 'fixture@example.com', 'requestId': 'fixture-request'}

    def test_same_start_recovers_without_new_allocation_or_time_wait(self):
        first = self.adapter.start({'auth': 'fixture'}, self.body)
        self.assertEqual(self.adapter.start({'auth': 'fixture'}, self.body), first)
        self.assertEqual(self.starts, 1)
        self.assertEqual(self.probes, 1)

    def test_auth_identity_completion_expiry_and_nonce_fail_closed(self):
        self.adapter.start({'auth': 'fixture'}, self.body)
        saved = self.path.read_text()
        for phase in ['native_complete_pending', 'native_saved', 'bound']:
            receipt = json.loads(saved); receipt['phase'] = phase
            self.path.write_text(json.dumps(receipt))
            with self.assertRaises(Rejected): self.adapter.start({'auth': 'fixture'}, self.body)
        self.path.write_text(saved)
        with self.assertRaises(Rejected): self.adapter.start({}, self.body)
        with self.assertRaises(Rejected): self.adapter.start({'auth': 'fixture'}, {**self.body, 'requestId': 'other'})
        self.entries[0]['rs_account_id'] = 'bound'
        with self.assertRaises(Rejected): self.adapter.start({'auth': 'fixture'}, self.body)
        self.entries[0]['rs_account_id'] = None
        self.accounts = [{'provider': 'openai', 'email': 'FIXTURE@example.com'}]
        with self.assertRaises(Rejected): self.adapter.start({'auth': 'fixture'}, self.body)
        self.accounts = []
        for expiry in ['2000-01-01T00:00:00Z', 'invalid', None]:
            receipt = json.loads(saved); receipt['nativeStartResult']['expiresAt'] = expiry
            self.path.write_text(json.dumps(receipt))
            with self.assertRaises(Rejected): self.adapter.start({'auth': 'fixture'}, self.body)
        self.assertEqual(self.starts, 1)


if __name__ == '__main__': unittest.main()
