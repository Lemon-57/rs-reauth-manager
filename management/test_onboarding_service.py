import unittest
from unittest.mock import patch
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import onboarding_service as service


class Allocator:
    def get_flow(self, flow):
        assert flow == 'native-flow'
        return {'port': 24001}, None

    def owner(self, entry):
        return None

    def url(self, entry):
        return 'http://fixture:fixture@127.0.0.1:24001'


class Tests(unittest.TestCase):
    def setUp(self):
        self.adapter = service.Adapter(Allocator(), 18135, 18118)
        self.calls = []
        self.rows = []
        self.allowed = True
        self.native_status = 200
        self.native_code = 200

    def send(self, port, path, headers, body=None, host='127.0.0.1'):
        self.calls.append((port, path, body))
        if not self.allowed:
            return 403, {'code': 403}
        if path.startswith('/api/admin/accounts?'):
            page = int(path.split('page=')[1].split('&')[0])
            size = int(path.split('pageSize=')[1])
            return 200, {'code': 200, 'data': {'items': self.rows[(page-1)*size:page*size]}}
        if path == '/api/admin/accounts/oauth/start':
            return self.native_status, {'code': self.native_code, 'data': {'flowId': 'native-flow', 'authorizationUrl': 'fixture-native-url'}}
        return self.native_status, {'code': self.native_code, 'data': {}}

    def start(self):
        with patch.object(service, 'send', self.send):
            return self.adapter.call('/_management/onboarding/start', {'X-Api-Key': 'fixture-key'}, {'email': 'fixture@example.com', 'requestId': '12345678-1234-4234-9234-123456789012'})

    def test_native_manager_allocates_and_flow_reads_same_registered_proxy(self):
        status, result = self.start()
        self.assertEqual(status, 200)
        self.assertEqual(result['data']['flowId'], 'native-flow')
        self.assertTrue(result['data']['outboundProxyUrl'].endswith(':24001'))
        self.assertEqual(sum(c[1] == '/api/admin/accounts/oauth/start' for c in self.calls), 1)
        self.assertEqual(self.start()[0], 409)
        self.assertEqual(sum(c[1] == '/api/admin/accounts/oauth/start' for c in self.calls), 1)

    def test_created_native_start_keeps_original_flow_and_proxy(self):
        self.native_status = 201
        status,result = self.start()
        self.assertEqual(status,200)
        self.assertEqual(result['data']['flowId'],'native-flow')
        self.assertEqual(result['data']['authorizationUrl'],'fixture-native-url')
        self.assertIn('outboundProxyUrl',result['data'])
        self.assertEqual(self.start()[0],409)
        self.assertEqual(sum(c[1].endswith('oauth/start') for c in self.calls),1)

    def test_created_completion_is_normalized_without_replacing_native_data(self):
        self.native_status = 201
        with patch.object(service,'send',self.send):
            for path in ['/api/admin/accounts/oauth/complete','/api/admin/accounts/import']:
                status,result=self.adapter.call(path,{'X-Api-Key':'fixture-key'},{'fixture':True})
                self.assertEqual(status,200)
                self.assertEqual(result,{'code':200,'data':{}})

    def test_transport_success_does_not_hide_business_failure_or_bad_envelope(self):
        for status,body in [(201,{'code':403,'data':{}}),(200,{'code':200}),(202,{'code':200,'data':{}}),(503,{'code':200,'data':{}})]:
            actual,result=service.normalize_success(status,body)
            self.assertNotEqual(actual,200)
        self.native_status=201;self.native_code=403
        self.assertEqual(self.start()[0],502)

    def test_complete_directory_case_insensitive_dedup_precedes_allocation(self):
        self.rows = [{'id': str(i), 'provider': 'openai', 'email': f'other{i}@example.com'} for i in range(100)]
        self.rows.append({'id': 'target', 'provider': 'openai', 'email': 'FIXTURE@EXAMPLE.COM'})
        self.assertEqual(self.start()[0], 409)
        self.assertFalse(any(c[1].endswith('oauth/start') for c in self.calls))

    def test_authentication_precedes_input_or_allocator_access(self):
        self.allowed = False
        self.assertEqual(self.start()[0], 403)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.adapter.pending, {})

    def test_rt_and_native_completion_only_use_existing_protected_manager(self):
        with patch.object(service, 'send', self.send):
            for path in ['/api/admin/accounts/import', '/api/admin/accounts/oauth/complete']:
                self.assertEqual(self.adapter.call(path, {'X-Api-Key': 'fixture-key'}, {'fixture': True})[0], 200)
                self.assertEqual(self.calls[-1], (18135, path, {'fixture': True}))


if __name__ == '__main__':
    unittest.main()
