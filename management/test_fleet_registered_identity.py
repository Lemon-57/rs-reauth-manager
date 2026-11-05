import copy
import unittest

from fleet_registered_identity import reservation_confirmed


class Tests(unittest.TestCase):
    def fixture(self, phase):
        row = {'management_id': 'onboarding_fixture', 'email': 'fixture@example.invalid'}
        entry = {'reservation_id': 'original-reservation'}
        old = {'requestId': 'original-reservation', 'entryId': row['management_id'],
               'email': row['email'], 'phase': phase}
        if phase != 'reserved':
            old['exitVerified'] = True
            old['flowId'] = 'original-native-flow'
        receipt = {'requestId': 'approved-recovery', 'phase': 'bound', 'nativeCompleteConfirmed': True,
                   'recoveryApproved': True, 'exitVerified': True, 'recoveryHistory': [old]}
        return receipt, entry, row

    def test_completed_approved_recovery_accepts_its_exact_original_reservation(self):
        for phase in ['reserved', 'native_started', 'native_complete_pending']:
            with self.subTest(phase=phase):
                receipt, entry, row = self.fixture(phase)
                self.assertTrue(reservation_confirmed(receipt, entry, row))

    def test_unconfirmed_or_different_reservations_never_gain_identity(self):
        for field in ['nativeCompleteConfirmed', 'recoveryApproved', 'exitVerified']:
            receipt, entry, row = self.fixture('reserved')
            receipt[field] = False
            self.assertFalse(reservation_confirmed(receipt, entry, row))
        for field, value in [('requestId', 'another-reservation'), ('entryId', 'another-entry'),
                             ('email', 'another@example.invalid'), ('flowId', 'unconfirmed-flow'),
                             ('phase', 'unknown')]:
            receipt, entry, row = self.fixture('reserved')
            receipt['recoveryHistory'][0][field] = value
            self.assertFalse(reservation_confirmed(receipt, entry, row))


if __name__ == '__main__':
    unittest.main()
