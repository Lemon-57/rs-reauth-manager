import unittest
from unittest.mock import Mock
from native_ipv6_verification import ExitVerificationError, verify_native_exit


class VerificationTests(unittest.TestCase):
    def entry(self):
        return {'host': '127.0.0.1', 'port': 24001, 'username': 'fixture-user',
                'password': 'fixture-password', 'ipv6': '2001:db8::1'}

    def connection(self, body=b'2001:db8::1', status=200):
        value = Mock()
        value.getresponse.return_value.status = status
        value.getresponse.return_value.read.return_value = body
        return value

    def test_first_detector_unavailable_uses_same_auth_and_exit(self):
        first = self.connection()
        first.request.side_effect = TimeoutError()
        second = self.connection(b'ip=2001:db8::1\n')
        factory = Mock(side_effect=[first, second])
        verify_native_exit(self.entry(), factory, sleep=lambda _: None)
        self.assertEqual(factory.call_count, 2)
        self.assertEqual(first.set_tunnel.call_args.args, ('api6.ipify.org', 443))
        self.assertEqual(second.set_tunnel.call_args.args, ('www.cloudflare.com', 443))
        self.assertEqual(first.set_tunnel.call_args.kwargs, second.set_tunnel.call_args.kwargs)
        self.assertTrue(all(call.args == ('127.0.0.1', 24001) for call in factory.call_args_list))
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_mismatch_or_invalid_address_never_tries_another_detector(self):
        for body in [b'2001:db8::2', b'192.0.2.1', b'invalid']:
            connection = self.connection(body)
            factory = Mock(return_value=connection)
            with self.assertRaises(ExitVerificationError):
                verify_native_exit(self.entry(), factory)
            self.assertEqual(factory.call_count, 1)
            connection.close.assert_called_once()

    def test_network_failure_is_bounded_and_never_changes_entry(self):
        connections = [self.connection() for _ in range(4)]
        for connection in connections:
            connection.request.side_effect = ConnectionError()
        factory = Mock(side_effect=connections)
        entry = self.entry()
        original = entry.copy()
        with self.assertRaisesRegex(ExitVerificationError, 'exit_unavailable'):
            verify_native_exit(entry, factory, sleep=lambda _: None)
        self.assertEqual(factory.call_count, 4)
        self.assertEqual(entry, original)

    def test_deadline_prevents_new_connections(self):
        factory = Mock()
        with self.assertRaisesRegex(ExitVerificationError, 'exit_unavailable'):
            verify_native_exit(self.entry(), factory, clock=Mock(side_effect=[0, 19]))
        factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
