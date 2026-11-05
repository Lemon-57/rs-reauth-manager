import unittest
from fleet_routes import tables


class Tests(unittest.TestCase):
    def test_only_designated_import_and_frontend_ports_are_redirected(self):
        config = {'managementPort': 19721, 'legacyPorts': [19701, 19709, 19713],
            'frontend': {'interface': 'eth0', 'httpPort': 18082, 'httpsPort': 18445,
                         'ipv4': ['127.0.0.1', '192.0.2.1'], 'ipv6': ['::1', '2001:db8::1']}}
        rendered = tables(config)
        self.assertEqual({name for _, name, _ in rendered},
            {'rs_fleet_import', 'rs_fleet_frontend', 'rs_fleet_ingress_access'})
        management = rendered[0][2]
        self.assertIn('19701, 19709, 19713', management)
        self.assertNotIn('18532', management)
        self.assertNotIn('18579', management)
        self.assertNotIn('flush', ''.join(body for _, _, body in rendered))
        self.assertIn('priority -150', management)
        self.assertIn('ip6 daddr', rendered[1][2])

    def test_management_target_never_loops_into_its_own_alias(self):
        with self.assertRaises(ValueError):
            tables({'managementPort': 19721, 'legacyPorts': [19701, 19721]})


if __name__ == '__main__':
    unittest.main()
