import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server import INSTANCE, Server, import_payload, public_jobs, Rejected
from auth import password_hash

TEST_SALT = '01' * 32
TEST_CREDENTIALS = {'username': 'test-admin', 'salt': TEST_SALT,
                    'passwordHash': password_hash('test-password', TEST_SALT),
                    'upstreamKey': 'test-upstream-key'}


class Upstream(BaseHTTPRequestHandler):
    calls = []
    imports = 0
    broken_import = False
    revision = 7
    reject_import = False

    def log_message(self, *args):
        pass

    def answer(self, status, value, cookies=()):
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(raw)))
        for cookie in cookies:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        type(self).calls.append(('GET', self.path))
        admin = self.headers.get('X-API-Key') == 'test-upstream-key' and not self.headers.get('Cookie')
        if self.path == '/api/auth/status':
            return self.answer(200, {'code': 200, 'data': {'authenticated': admin, 'session': {'role': 'admin'} if admin else None}})
        if not admin:
            return self.answer(401, {})
        if self.path == '/api/admin/plugins/extensions':
            return self.answer(200, {'code': 200, 'data': [{'target': {'instanceId': INSTANCE, 'artifactSha256': 'a' * 64, 'revision': type(self).revision}}]})
        if self.path.endswith('/api/api/jobs'):
            return self.answer(200, {'jobs': [{'requestId': 'hidden', 'accountId': '', 'status': 'success'}]})
        self.answer(404, {})

    def do_POST(self):
        type(self).calls.append(('POST', self.path))
        value = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if self.path == '/api/auth/login':
            if value == {'mode': 'admin', 'username': 'test-admin', 'password': 'test-password'}:
                return self.answer(200, {'code': 200, 'data': {'role': 'admin'}}, ['cpr_session=test-admin; Path=/; Secure; HttpOnly; SameSite=Lax', 'cpr_refresh=test-renewal; Path=/api/auth; Secure; HttpOnly; SameSite=Lax'])
            return self.answer(401, {})
        if self.headers.get('X-API-Key') != 'test-upstream-key' or self.headers.get('Cookie'):
            return self.answer(401, {})
        if self.path.endswith('/api/api/import-line'):
            if self.headers.get('Origin') or self.headers.get('Cookie'):
                return self.answer(403, {'message': 'Protected native origin rejected'})
            if value.get('groupIds') != []:
                return self.answer(400, {'message': '导入参数无效'})
            type(self).imports += 1
            if type(self).reject_import:
                return self.answer(403, {'code': 403, 'message': '第 1 行账号已存在，本批未提交'})
            if type(self).broken_import:
                self.connection.shutdown(2)
                return
            return self.answer(200, {'jobs': [{'requestId': value['requestId'] + ':import', 'accountId': '', 'status': 'queued', 'step': 'queued', 'message': '等待处理', 'startedAt': None, 'finishedAt': None, 'importInfo': {'line': 1, 'email': 'sample@example.com', 'nativeStartId': 'private-receipt'}}]})
        self.answer(404, {})


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.portal = Server(('127.0.0.1', 0), f'http://127.0.0.1:{cls.upstream.server_port}', 'https://import.example.com', TEST_CREDENTIALS)
        threading.Thread(target=cls.portal.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.portal.shutdown(); cls.portal.server_close()
        cls.upstream.shutdown(); cls.upstream.server_close()

    def setUp(self):
        Upstream.calls = []; Upstream.imports = 0; Upstream.broken_import = False; Upstream.revision = 7; Upstream.reject_import = False
        self.portal.auth.sessions.clear(); self.portal.auth.attempts.clear(); self.portal.auth.global_attempts.clear()
        token, status = self.portal.auth.login('test-admin', 'test-password', 'test')
        self.assertEqual(status, 200)
        self.cookie = 'import_session=' + token

    def call(self, method, path, value=None, admin=False, origin='https://import.example.com', host='import.example.com'):
        headers = {'Host': host, 'Origin': origin, 'Content-Type': 'application/json'}
        if admin:
            headers['Cookie'] = self.cookie + '; unrelated=not-forwarded'
        connection = http.client.HTTPConnection('127.0.0.1', self.portal.server_port, timeout=5)
        connection.request(method, path, None if value is None else json.dumps(value), headers)
        reply = connection.getresponse()
        result = reply.status, reply.getheaders(), reply.read()
        connection.close()
        return result

    def payload(self):
        return {'requestId': str(uuid.uuid4()), 'line': 'sample@example.com----test-only----JBSWY3DPEHPK3PXP'}

    def test_anonymous_cannot_read_or_import(self):
        self.assertEqual(self.call('GET', '/api/jobs')[0], 401)
        self.assertEqual(self.call('POST', '/api/import', self.payload())[0], 401)
        self.assertEqual(Upstream.imports, 0)

    def test_cross_origin_and_host_are_rejected_before_upstream(self):
        for params in ({'origin': 'https://elsewhere.example'}, {'origin': 'null'}, {'host': 'elsewhere.example'}):
            self.assertIn(self.call('POST', '/api/import', self.payload(), admin=True, **params)[0], [400, 403])
        self.assertEqual(Upstream.calls, [])

    def test_only_import_route_is_exposed(self):
        for path in ['/api/admin/accounts', '/api/cancel', '/api/import?retry=1', '/../server.py']:
            self.assertEqual(self.call('GET', path, admin=True)[0], 404)
        self.assertEqual(Upstream.calls, [])

    def test_independent_login_and_cookie_security(self):
        status, headers, raw = self.call('POST', '/api/login', {'username': 'test-admin', 'password': 'test-password'})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(raw)['authenticated'])
        cookies = [v for k, v in headers if k.lower() == 'set-cookie']
        self.assertTrue(any('import_session=' in v and 'Path=/;' in v and 'SameSite=Strict' in v for v in cookies))
        self.assertTrue(all('HttpOnly' in v and 'Secure' in v for v in cookies))
        self.assertEqual(Upstream.calls, [])

    def test_wrong_password_logout_and_bypass_protection(self):
        self.assertEqual(self.call('POST', '/api/login', {'username': 'test-admin', 'password': 'wrong-test-password'})[0], 401)
        self.assertEqual(self.call('GET', '/api/jobs', admin=True)[0], 200)
        self.assertEqual(self.call('POST', '/api/logout', {}, admin=True)[0], 200)
        self.assertEqual(self.call('GET', '/api/jobs', admin=True)[0], 401)

    def test_login_attempts_are_bounded(self):
        for _ in range(11):
            token, status = self.portal.auth.login('test-admin', 'wrong-test-password', 'limited-source')
        self.assertEqual(status, 429)
        self.assertIsNone(token)

    def test_key_login_cannot_be_requested_by_browser(self):
        self.assertEqual(self.call('POST', '/api/login', {'apiKey': 'test-only'})[0], 400)
        self.assertEqual(Upstream.calls, [])

    def test_discover_current_plugin_and_submit_once(self):
        status, headers, raw = self.call('POST', '/api/import', self.payload(), admin=True)
        self.assertEqual(status, 200)
        self.assertEqual(Upstream.imports, 1)
        self.assertTrue(Upstream.calls[-1][1].endswith('/7/api/api/import-line'))
        self.assertNotIn(b'private-receipt', raw)
        Upstream.revision = 9
        self.assertEqual(self.call('GET', '/api/jobs', admin=True)[0], 200)
        self.assertTrue(Upstream.calls[-1][1].endswith('/9/api/api/jobs'))
        self.assertEqual(Upstream.imports, 1)

    def test_uncertain_import_is_never_replayed(self):
        Upstream.broken_import = True
        status, _, raw = self.call('POST', '/api/import', self.payload(), admin=True)
        self.assertEqual(status, 502)
        self.assertEqual(Upstream.imports, 1)
        self.assertIn('勿重复提交', raw.decode())

    def test_plugin_validation_does_not_invalidate_portal_session(self):
        Upstream.reject_import = True
        status, _, raw = self.call('POST', '/api/import', self.payload(), admin=True)
        self.assertEqual(status, 400)
        self.assertIn('已存在', raw.decode())
        self.assertEqual(self.call('GET', '/api/jobs', admin=True)[0], 200)

    def test_duplicate_emails_and_invalid_input_do_not_reach_plugin(self):
        value = self.payload(); value['line'] += '\nSAMPLE@example.com----test-only----JBSWY3DPEHPK3PXP'
        self.assertEqual(self.call('POST', '/api/import', value, admin=True)[0], 400)
        value = self.payload(); value['proxy'] = 'not-allowed'
        self.assertEqual(self.call('POST', '/api/import', value, admin=True)[0], 400)
        self.assertEqual(Upstream.calls, [])

    def test_only_import_jobs_and_safe_fields_are_returned(self):
        value = public_jobs({'jobs': [{'requestId': 'reauth', 'secret': 'never-return'}, {'requestId': 'import', 'importInfo': {'line': 1, 'email': 'sample@example.com', 'nativeStartId': 'private'}, 'secret': 'never-return'}]})
        self.assertEqual(len(value['jobs']), 1)
        self.assertNotIn('nativeStartId', value['jobs'][0]['importInfo'])
        self.assertNotIn('secret', value['jobs'][0])

    def test_input_contract_preserves_notes_and_optional_rt(self):
        value = self.payload(); value['line'] += '----test-refresh-token'
        self.assertEqual(import_payload(value), value)
        self.assertEqual(set(import_payload(value)), {'line', 'requestId'})

    def test_security_headers_and_no_directory_listing(self):
        status, headers, raw = self.call('GET', '/')
        self.assertEqual(status, 200)
        headers = dict((k.lower(), v) for k, v in headers)
        self.assertEqual(headers['cache-control'], 'no-store')
        self.assertIn("frame-ancestors 'none'", headers['content-security-policy'])
        self.assertEqual(self.call('GET', '/web/')[0], 404)

    def test_existing_sessions_survive_handover_and_logout_revokes_both(self):
        candidate = Server(('127.0.0.1', 0), f'http://127.0.0.1:{self.upstream.server_port}',
                           'https://import.example.com', TEST_CREDENTIALS, self.portal.server_port)
        threading.Thread(target=candidate.serve_forever, daemon=True).start()
        try:
            self.assertFalse(candidate.auth.authenticated(self.cookie))
            self.assertTrue(candidate.authenticated(self.cookie))
            self.assertTrue(candidate.previous_auth(self.cookie, logout=True))
            self.assertFalse(candidate.authenticated(self.cookie))
            self.assertFalse(self.portal.auth.authenticated(self.cookie))
        finally:
            candidate.shutdown(); candidate.server_close()


if __name__ == '__main__':
    unittest.main()
