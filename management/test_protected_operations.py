import json
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from protected_operations import Operations


class OperationsTests(unittest.TestCase):
    def test_polling_executes_once_and_persists_only_sanitized_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            started, release = threading.Event(), threading.Event()
            calls = []

            def send(path, headers, body, timeout):
                calls.append((path, timeout))
                started.set()
                release.wait(3)
                return 201, {'code': 200, 'data': {'accountIds': ['fixture'], 'refreshToken': 'must-not-persist'}}

            ops = Operations(directory, send)
            body = {'requestId': str(uuid.uuid4()), 'request': {'provider': 'openai', 'data': {'refreshToken': 'fixture-secret'}}}
            self.assertEqual(ops.call({}, body)[0], 202)
            self.assertTrue(started.wait(1))
            for _ in range(3):
                self.assertEqual(ops.call({}, body)[0], 202)
            conflict = {**body, 'request': {'provider': 'openai', 'data': {'refreshToken': 'other'}}}
            self.assertEqual(ops.call({}, conflict)[0], 409)
            pending = next(Path(directory).glob('*.json')).read_text()
            self.assertNotIn('fixture-secret', pending)
            release.set()
            for _ in range(100):
                result = ops.call({}, body)
                if result[0] != 202:
                    break
                time.sleep(.01)
            self.assertEqual(result, (201, {'code': 200, 'data': {'accountIds': ['fixture']}}))
            self.assertEqual(calls, [('/api/admin/accounts/import', 600)])
            restored = Operations(directory, send)
            self.assertEqual(restored.call({}, body), result)
            self.assertNotIn('must-not-persist', next(Path(directory).glob('*.json')).read_text())

    def test_uncertain_intent_never_replays_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            started, release = threading.Event(), threading.Event()

            def send(*_):
                started.set()
                release.wait(3)
                raise TimeoutError()

            body = {'requestId': str(uuid.uuid4()), 'request': {'provider': 'openai'}}
            ops = Operations(directory, send)
            self.assertEqual(ops.call({}, body)[0], 202)
            self.assertTrue(started.wait(1))
            restored = Operations(directory, lambda *_: self.fail('must not replay'))
            self.assertEqual(restored.call({}, body)[1]['diagnostic']['code'], 'rt_result_unconfirmed')
            release.set()
            for _ in range(100):
                if not ops.running:
                    break
                time.sleep(.01)

    def test_rejected_rt_diagnostic_still_allows_the_existing_bounded_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = {'code': 'rt_rejected', 'upstreamStatus': 400, 'reason': 'refresh_token_expired'}
            ops = Operations(directory, lambda *_: (422, {'code': 42201, 'diagnostic': diagnostic, 'message': 'private body'}))
            body = {'requestId': str(uuid.uuid4()), 'request': {'provider': 'openai'}}
            self.assertEqual(ops.call({}, body)[0], 202)
            for _ in range(100):
                result = ops.call({}, body)
                if result[0] != 202:
                    break
                time.sleep(.01)
            self.assertEqual(result, (422, {'code': 422, 'diagnostic': diagnostic}))
            self.assertNotIn('private body', next(Path(directory).glob('*.json')).read_text())


if __name__ == '__main__':
    unittest.main()
