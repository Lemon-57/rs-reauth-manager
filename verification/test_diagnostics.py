"""Offline error projection and privacy tests; no real account or network."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol'))
from diagnostics import describe_failure, stage_for_url, transport_reason


class DiagnosticTests(unittest.TestCase):
    def test_mfa_reasons_do_not_all_mean_wrong_secret(self):
        cases = {'mfa_totp_factor_not_available': 'mfa_factor_missing', 'mfa_totp_secret_required': 'mfa_secret_missing', 'mfa_totp_provider_invalid': 'mfa_provider_invalid', 'mfa_totp_code_unavailable': 'mfa_code_unavailable', 'mfa_totp_rejected_400': 'mfa_code_rejected', 'mfa_issue_challenge_http_403': 'mfa_issue_failed', 'mfa_primary_factor_required': 'primary_factor_required'}
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(describe_failure({'error': source})['diagnostic']['reason'], expected)

    def test_mfa_rate_limit_precedes_generic_mfa(self):
        for source in ['mfa_totp_rejected_429', 'email_otp_rejected_429']:
            self.assertEqual(describe_failure({'error': source})['code'], 'limited')
        value = describe_failure({'error': 'private-upstream-code'}, attempt={'stage': 'mfa_verify', 'httpStatus': 429})
        self.assertEqual(value, {'code': 'limited', 'diagnostic': {'stage': 'mfa_verify', 'reason': 'rate_limited', 'httpStatus': 429}})

    def test_stage_records_only_known_path_not_query_or_credentials(self):
        self.assertEqual(stage_for_url('https://auth.openai.com/api/accounts/mfa/verify?code=private-code'), 'mfa_verify')
        for url in ['https://evil.example/api/accounts/mfa/verify', 'https://private-user:private-password@auth.openai.com/api/accounts/mfa/verify', None]:
            self.assertEqual(stage_for_url(url), 'unknown')

    def test_unknown_error_is_not_reinterpreted_as_credential_error(self):
        v = describe_failure({'error': 'private-password mfa: private-rt https://private-host/?code=secret'})
        self.assertEqual(v['code'], 'protocol')
        self.assertEqual(v['diagnostic']['reason'], 'upstream_unknown')
        self.assertNotIn('private-', json.dumps(v))
        self.assertNotIn('secret', json.dumps(v))

    def test_http_and_transport_categories_preserve_no_exception_message(self):
        class CurlError(Exception):
            code = 28
        exc = CurlError('https://private-user:private-pass@private-proxy private-code')
        self.assertEqual(transport_reason(exc), 'request_timeout')
        v = describe_failure(attempt={'stage': 'password'}, exception=exc)
        self.assertEqual(v['diagnostic']['reason'], 'request_timeout')
        self.assertNotIn('private-', json.dumps(v))
        self.assertEqual(describe_failure(attempt={'stage': 'authorize', 'httpStatus': 503})['diagnostic']['reason'], 'upstream_unavailable')

    def test_human_challenges_are_distinct(self):
        for source, expected in [('email_otp_provider_required', 'email_code_required'), ('phone_required', 'phone_required'), ('oauth_cloudflare_challenge', 'security_challenge')]:
            v = describe_failure({'error': source})
            self.assertEqual(v['code'], 'human')
            self.assertEqual(v['diagnostic']['reason'], expected)

    def test_identity_and_callback_not_reported_as_network_faults(self):
        self.assertEqual(describe_failure({'error': 'fallback_identity'})['diagnostic']['stage'], 'identity')
        self.assertEqual(describe_failure({'error': 'state'})['diagnostic']['reason'], 'state_mismatch')

    def test_rejects_boolean_or_unbounded_http_status(self):
        for status in [True, -1, 600, '403', None]:
            self.assertIsNone(describe_failure(attempt={'httpStatus': status})['diagnostic']['httpStatus'])

    def test_malformed_or_untrusted_metadata_cannot_leak_or_crash(self):
        for attempt in [{'stage': []}, {'stage': {}}, {'transport': 'private-password'}, {'transport': ['private-password']}]:
            self.assertNotIn('private-password', json.dumps(describe_failure(attempt=attempt)))
        self.assertEqual(describe_failure({'oauth_protocol': {'last_page_type': []}})['diagnostic']['stage'], 'unknown')
