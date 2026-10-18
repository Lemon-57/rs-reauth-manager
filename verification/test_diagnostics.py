"""Offline error projection and privacy tests; no real account or network."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol'))
from diagnostics import describe_failure, retry_action, stage_for_url, transport_reason


class DiagnosticTests(unittest.TestCase):
    def test_retry_policy_requires_explicit_step_and_error_not_http_alone(self):
        for stage in ['login', 'password', 'mfa_issue', 'mfa_verify']:
            failure = describe_failure({'error': 'invalid_state'}, attempt={'stage': stage, 'httpStatus': 409})
            self.assertEqual(failure['diagnostic']['stage'], stage)
            self.assertEqual(retry_action(failure), 'restart_login')
        for code in ['invalid_otp', 'otp_expired']:
            failure = describe_failure({'error': code}, attempt={'stage': 'mfa_verify', 'httpStatus': 409})
            self.assertEqual(retry_action(failure), 'new_code')
        for stage, code, status in [
            ('mfa_verify', 'invalid_state', 429), ('mfa_verify', 'invalid_state', 503),
            ('mfa_verify', 'unknown', 409), ('mfa_verify', 'account_banned', 409),
            ('mfa_verify', 'payment_required', 402), ('password', 'invalid_username_or_password', 401),
            ('token_exchange', 'invalid_state', 409), ('callback', 'invalid_state', 409),
            ('mfa_verify', 'phone_required', 403), ('mfa_verify', 'oauth_cloudflare_challenge', 200),
        ]:
            with self.subTest(stage=stage, code=code, status=status):
                self.assertEqual(retry_action(describe_failure({'error': code}, attempt={'stage': stage, 'httpStatus': status})), 'stop')

    def test_free_selection_errors_are_workspace_errors_not_mfa_or_transport(self):
        for reason in ['free_workspace_missing', 'free_workspace_ambiguous']:
            value = describe_failure({'error': reason}, attempt={'stage': 'consent', 'httpStatus': 200})
            self.assertEqual(value, {'code': 'protocol', 'diagnostic': {'stage': 'workspace', 'reason': reason, 'httpStatus': None}})

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
        for source, expected in [('email_otp_provider_required', 'email_code_required'), ('phone_required', 'phone_required'), ('add_phone_failed', 'phone_verification_failed'), ('oauth_cloudflare_challenge', 'security_challenge')]:
            v = describe_failure({'error': source})
            self.assertEqual(v['code'], 'human')
            self.assertEqual(v['diagnostic']['reason'], expected)

    def test_email_send_and_rate_limit_are_not_merged(self):
        failed = describe_failure({'error': 'passwordless_send_otp_http_403'})
        self.assertEqual(failed['diagnostic']['reason'], 'email_send_failed')
        self.assertEqual(failed['diagnostic']['httpStatus'], 403)
        limited = describe_failure({'error': 'passwordless_send_otp_http_429'})
        self.assertEqual(limited['code'], 'limited')
        self.assertEqual(limited['diagnostic']['reason'], 'rate_limited')

    def test_explicit_ban_codes_are_distinct_but_forbidden_is_not_guessed(self):
        for source in ['account_banned', 'account_blocked', 'account_deactivated', 'account_disabled', 'account_suspended', 'access_terminated', 'user_deactivated', 'user_suspended']:
            with self.subTest(source=source):
                value = describe_failure({'error': source})
                self.assertEqual(value['code'], 'account')
                self.assertEqual(value['diagnostic']['reason'], 'account_banned')
        forbidden = describe_failure({'error': 'private-upstream-code'}, attempt={'stage': 'password', 'httpStatus': 403})
        self.assertEqual(forbidden['diagnostic']['reason'], 'http_rejected')

    def test_account_banned_and_payment_required_are_separate(self):
        banned = describe_failure({'error': 'account_banned'}, attempt={'stage': 'password', 'httpStatus': 402})
        self.assertEqual(banned['code'], 'account')
        self.assertEqual(banned['diagnostic']['reason'], 'account_banned')
        for source in ['payment_required', 'payment required']:
            value = describe_failure({'error': source})
            self.assertEqual(value['code'], 'billing')
            self.assertEqual(value['diagnostic']['reason'], 'payment_required')
        payment = describe_failure({'error': 'oauth_http_402'}, attempt={'stage': 'password', 'httpStatus': 402})
        self.assertEqual(payment['code'], 'billing')
        self.assertEqual(payment['diagnostic']['reason'], 'payment_required')

    def test_identity_and_callback_not_reported_as_network_faults(self):
        self.assertEqual(describe_failure({'error': 'fallback_identity'})['diagnostic']['stage'], 'identity')
        self.assertEqual(describe_failure({'error': 'state'})['diagnostic']['reason'], 'state_mismatch')

    def test_local_generation_never_inherits_previous_http_status(self):
        value = describe_failure({'error': 'mfa_totp_code_unavailable'}, attempt={'stage': 'mfa_verify', 'httpStatus': 409})
        self.assertEqual(value['diagnostic'], {'stage': 'mfa_generate', 'reason': 'mfa_code_unavailable', 'httpStatus': None})

    def test_conflict_expiry_and_invalid_code_have_distinct_meanings(self):
        for code, reason in [('invalid_otp', 'mfa_code_invalid'), ('invalid_totp', 'mfa_code_invalid'), ('otp_expired', 'mfa_code_expired'), ('invalid_state', 'mfa_challenge_invalid')]:
            value = describe_failure({'error': code}, attempt={'stage': 'mfa_verify', 'httpStatus': 409})
            self.assertEqual(value['diagnostic']['reason'], reason)
            self.assertEqual(value['diagnostic']['upstreamCode'], code)
        value = describe_failure({'error': 'mfa_totp_rejected_409'})
        self.assertEqual(value['diagnostic']['reason'], 'mfa_conflict')
        self.assertEqual(value['diagnostic']['httpStatus'], 409)

    def test_response_machine_code_wins_over_vendor_generic_failure(self):
        value = describe_failure({'error': 'mfa_totp_verification_failed'}, attempt={'stage': 'mfa_verify', 'httpStatus': 409, 'mfaError': 'otp_expired'})
        self.assertEqual(value['diagnostic']['reason'], 'mfa_code_expired')
        self.assertEqual(value['diagnostic']['upstreamCode'], 'otp_expired')

    def test_rejects_boolean_or_unbounded_http_status(self):
        for status in [True, -1, 600, '403', None]:
            self.assertIsNone(describe_failure(attempt={'httpStatus': status})['diagnostic']['httpStatus'])

    def test_malformed_or_untrusted_metadata_cannot_leak_or_crash(self):
        for attempt in [{'stage': []}, {'stage': {}}, {'transport': 'private-password'}, {'transport': ['private-password']}]:
            self.assertNotIn('private-password', json.dumps(describe_failure(attempt=attempt)))
        self.assertEqual(describe_failure({'oauth_protocol': {'last_page_type': []}})['diagnostic']['stage'], 'unknown')
