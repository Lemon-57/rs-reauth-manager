import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from import_diagnostics import rejected, sanitize
from fleet_slots import RemoteAllocator, SlotError
from fleet_import_service import load_service
from pathlib import Path
from test_fleet_import_service import Allocator, Backend


class Tests(unittest.TestCase):
    def test_rejection_body_only_emits_allowlisted_codes(self):
        for body, reason in [
            ({'error': {'code': 'refresh_token_reused', 'message': 'secret-token'}}, 'refresh_token_reused'),
            ({'error': 'invalid_grant', 'error_description': 'secret-password'}, 'invalid_grant'),
            ({'error': {'message': 'token expired secret-token'}}, None),
            ({'error': {'code': 'secret-token'}}, None),
            ([], None),
        ]:
            error = urllib.error.HTTPError('https://fixture.invalid', 401, 'secret', {},
                io.BytesIO(json.dumps(body).encode()))
            diagnostic = rejected(error)
            self.assertEqual(diagnostic.get('reason'), reason)
            self.assertEqual(diagnostic['upstreamStatus'], 401)
            self.assertNotIn('secret', json.dumps(diagnostic))

    def test_untrusted_fields_and_oversized_bodies_are_not_returned(self):
        for value in [None, [], {'code': []}, {'code': 'secret'}]:
            self.assertIsNone(sanitize(value))
        self.assertEqual(sanitize({'code': 'rt_rejected', 'reason': [], 'upstreamStatus': True,
            'message': 'secret'}), {'code': 'rt_rejected'})
        error = urllib.error.HTTPError('https://fixture.invalid', 403, 'secret', {}, io.BytesIO(b'x' * 40000))
        self.assertEqual(rejected(error), {'code': 'rt_rejected', 'upstreamStatus': 403})

    def test_exchange_and_native_policy_preserve_diagnostic_without_save_or_retry(self):
        service = load_service(Path(__file__).with_name('native_core'))
        allocator = Allocator('pro')
        remote = RemoteAllocator({})
        allocator.exchange_refresh = remote.exchange_refresh
        backend = Backend(allocator)
        policy = service.NativePolicy(backend, allocator)
        error = urllib.error.HTTPError('https://fixture.invalid', 400, 'secret', {},
            io.BytesIO(b'{"error":{"code":"refresh_token_reused","message":"secret"}}'))
        with patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(service.PolicyError) as caught:
                policy.import_sync({'provider': 'openai', 'data': {'email': 'fixture@example.invalid',
                    'refreshToken': 'fixture-rt'}, 'settings': {'enabled': False}})
            self.assertEqual(caught.exception.diagnostic, {'code': 'rt_rejected',
                'upstreamStatus': 400, 'reason': 'refresh_token_reused'})
            self.assertEqual(caught.exception.status, 422)
            self.assertEqual(opener.return_value.open.call_count, 1)
            self.assertFalse(backend.accounts)


if __name__ == '__main__':
    unittest.main()
