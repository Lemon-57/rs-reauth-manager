"""Deterministic local TOTP timing tests; no real waiting or credentials."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol'))
import totp

SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'


class Clock:
    def __init__(self, phase=0.1, *, frozen_wall=False, oversleep=0):
        self.phase = phase
        self.elapsed = 0.0
        self.frozen_wall = frozen_wall
        self.oversleep = oversleep

    def monotonic(self):
        return self.elapsed

    def wall(self):
        return 1800000000.0 + self.phase + (0 if self.frozen_wall else self.elapsed)

    def sleep(self, seconds):
        self.elapsed += seconds + self.oversleep


class TotpTimingTests(unittest.TestCase):
    def get_code(self, clock, *, timeout=30, exclude_codes=None):
        with patch.object(totp.time, 'monotonic', clock.monotonic), patch.object(totp.time, 'time', clock.wall), patch.object(totp.time, 'sleep', clock.sleep):
            return totp.TotpMfaClient(SECRET).get_mfa_code(timeout=timeout, exclude_codes=exclude_codes)

    def test_rfc6238_sha1_vector(self):
        code, remaining = totp.totp_code(SECRET, at_time=59, digits=8)
        self.assertEqual(code, '94287082')
        self.assertEqual(remaining, 1)

    def test_unused_code_returns_immediately(self):
        clock = Clock(phase=5)
        code = self.get_code(clock)
        self.assertEqual(code, totp.totp_code(SECRET, at_time=clock.wall())[0])
        self.assertEqual(clock.elapsed, 0)

    def test_waits_for_new_code_instead_of_reusing_rejected_code(self):
        clock = Clock(phase=5)
        previous = totp.totp_code(SECRET, at_time=clock.wall())[0]
        code = self.get_code(clock, exclude_codes={previous})
        self.assertIsNotNone(code)
        self.assertNotEqual(code, previous)
        self.assertEqual(clock.elapsed, 25)

    def test_checks_for_new_code_at_deadline_instead_of_false_timeout(self):
        clock = Clock()
        previous = totp.totp_code(SECRET, at_time=clock.wall())[0]
        code = self.get_code(clock, exclude_codes={previous})
        self.assertIsNotNone(code)
        self.assertNotEqual(code, previous)
        self.assertEqual(clock.elapsed, 30)

    def test_last_four_seconds_are_not_submitted(self):
        clock = Clock(phase=26)
        expiring = totp.totp_code(SECRET, at_time=clock.wall())[0]
        code = self.get_code(clock)
        self.assertIsNotNone(code)
        self.assertNotEqual(code, expiring)
        self.assertEqual(clock.elapsed, 4)

    def test_true_timeout_uses_monotonic_budget_and_never_oversleeps_it(self):
        clock = Clock(frozen_wall=True)
        previous = totp.totp_code(SECRET, at_time=clock.wall())[0]
        self.assertIsNone(self.get_code(clock, timeout=5.02, exclude_codes={previous}))
        self.assertAlmostEqual(clock.elapsed, 5.02)

    def test_no_code_is_returned_after_deadline_when_execution_is_delayed(self):
        clock = Clock(phase=26, oversleep=6)
        self.assertIsNone(self.get_code(clock, timeout=5))

    def test_retry_margin_tolerates_polling_delay(self):
        clock = Clock(oversleep=0.2)
        previous = totp.totp_code(SECRET, at_time=clock.wall())[0]
        code = self.get_code(clock, timeout=35, exclude_codes={previous})
        self.assertIsNotNone(code)
        self.assertNotEqual(code, previous)
        self.assertLess(clock.elapsed, 35)


if __name__ == '__main__':
    unittest.main()
