"""Authenticated import front end; validate existing unique IPv6 without allocating or rebinding."""
import argparse
import hashlib
import http.client
import importlib
import ipaddress
import json
import signal
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CHECK = '/_management/onboarding/prolite-check'
IPV6_CHECK = '/_management/onboarding/ipv6-check'
FORWARD = {'/_management/onboarding/start', '/api/admin/accounts/import',
           '/api/admin/accounts/oauth/complete', '/api/admin/accounts/batch-update', '/api/admin/accounts/update'}
AUTH = {'cookie', 'authorization', 'x-api-key', 'origin', 'x-csrf-token'}


def unique_entry(allocator, proxy_url, account_id):
    entry = allocator.lookup(proxy_url)
    if not entry or allocator.owner(entry) != account_id or ipaddress.ip_address(entry['ipv6']).version != 6:
        raise ValueError('fixed_ipv6_owner')
    slot = allocator.slots()[entry['port']]
    if any(entry[key] != slot[key] for key in ['host', 'port', 'username', 'password', 'ipv6']):
        raise ValueError('fixed_slot_authentication')
    history = allocator.use_history()['entries'][entry['ipv6']]
    if history.get('account_id') != account_id or history.get('retired') is not False:
        raise ValueError('permanent_owner')
    if any(row.get('ipv6') == entry['ipv6'] and row.get('port') != entry['port']
           for row in allocator.all_rows()):
        raise ValueError('shared_ipv6')
    return entry


class Application:
    def __init__(self, forward_port, gateway_port, origin, allocator=None, daily_weights=None):
        self.forward_port, self.gateway_port, self.origin = forward_port, gateway_port, origin
        self.allocator = allocator
        self.daily_weights = daily_weights

    def send(self, port, path, headers, body=None):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=150)
        try:
            forwarded = {key: value for key, value in headers.items() if key.lower() in AUTH}
            forwarded.update({'Content-Type': 'application/json', 'Host': urllib.parse.urlsplit(self.origin).netloc,
                              'X-Forwarded-Proto': 'https'})
            connection.request('GET' if body is None else 'POST', path,
                               None if body is None else json.dumps(body).encode(), forwarded)
            response = connection.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('response_limit')
            return response.status, json.loads(raw)
        finally:
            connection.close()

    def read(self, path, headers):
        status, result = self.send(self.gateway_port, path, headers)
        if status != 200 or result.get('code') != 200:
            raise ValueError('authenticated_read_failed')
        return result['data']

    def call(self, path, headers, body):
        status, result = self.send(self.gateway_port, '/api/admin/accounts?page=1&pageSize=1', headers)
        if status != 200 or result.get('code') != 200:
            return 403, {'code': 403}
        if path in FORWARD:
            return self.send(self.forward_port, path, headers, body)
        if path not in {CHECK, IPV6_CHECK} or set(body) != {'accountId', 'credentialRevision'}:
            return 422, {'code': 422}
        account_id, revision = body['accountId'], body['credentialRevision']
        if not isinstance(account_id, str) or not account_id or len(account_id) > 128 or type(revision) is not int or revision < 1:
            return 422, {'code': 422}
        # Shared IPv4/IPv6 pools do not satisfy the ProLite-specific unique IPv6 requirement.
        if self.allocator is None:
            return 409, {'code': 409, 'message': 'Independent IPv6 pool unavailable; account remains paused'}
        query = urllib.parse.urlencode({'accountId': account_id})
        before = self.read('/api/admin/accounts/detail?' + query, headers)['account']
        if (before.get('id') != account_id or before.get('provider') != 'openai'
                or before.get('authenticationKind') != 'oauth' or before.get('enabled') is not False
                or (path == CHECK and str(before.get('planType', '')).strip().lower() != 'prolite')
                or before.get('capacity', {}).get('usedSlots') != 0):
            return 409, {'code': 409}
        export = self.read('/api/admin/accounts/export?' + urllib.parse.urlencode(
            {'accountIds': account_id, 'confirm': 'export_sensitive_accounts'}), headers)
        documents = export['documents']
        if len(documents) != 1 or documents[0]['provider'] != 'openai':
            raise ValueError('account_export')
        accounts = documents[0]['document']['accounts']
        if len(accounts) != 1 or accounts[0]['id'] != account_id:
            raise ValueError('account_export_identity')
        entry = unique_entry(self.allocator, accounts[0]['outboundProxyUrl'], account_id)
        self.allocator.verify(entry)
        after = self.read('/api/admin/accounts/detail?' + query, headers)['account']
        for key in ['id', 'userId', 'accountId', 'planType', 'enabled', 'outboundProxyId',
                    'outboundProxyEndpoint', 'notes', 'groups', 'weight', 'concurrencyLimit', 'modelAccess']:
            if before.get(key) != after.get(key):
                raise ValueError('account_changed')
        if after.get('capacity', {}).get('usedSlots') != 0:
            raise ValueError('account_busy')
        proof = {'accountId': account_id, 'credentialRevision': revision, 'independentIPv6': True}
        if str(before.get('planType', '')).strip().lower() in ('pro', 'prolite', 'self_serve_business_prolite'):
            if self.daily_weights is None:
                raise ValueError('shared_daily_weight_unavailable')
            proof['importWeight'] = self.daily_weights.reserve(account_id, entry['port'], before['planType'])
        return 200, {'code': 200, 'data': proof}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.reply(200 if self.path == '/health' else 404,
                   {'code': 200, 'data': {'sourceSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                         'independentIPv6Pool': self.server.app.allocator is not None}})

    def reply(self, status, result):
        raw = json.dumps(result).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def do_POST(self):
        status, result = 503, {'code': 503}
        try:
            if self.client_address[0] != '127.0.0.1' or self.path not in FORWARD | {CHECK, IPV6_CHECK}:
                status, result = 404, {'code': 404}
            elif self.headers.get('Transfer-Encoding'):
                status, result = 400, {'code': 400}
            elif not any(self.headers.get(key) for key in ['Cookie', 'Authorization', 'X-Api-Key']):
                status, result = 403, {'code': 403}
            elif self.headers.get('Origin') not in (None, self.server.app.origin) or (self.headers.get('Cookie') and not self.headers.get('Origin')):
                status, result = 403, {'code': 403}
            else:
                self.connection.settimeout(15)
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 49152:
                    raise ValueError('body_limit')
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError('body_type')
                status, result = self.server.app.call(self.path, dict(self.headers), body)
        except Exception:
            # Never include upstream bodies, proxy authentication or account materials in logs.
            status, result = 503, {'code': 503}
        self.reply(status, result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--forward-port', type=int, required=True)
    parser.add_argument('--gateway-port', type=int, required=True)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--manager-unit')
    parser.add_argument('--allocator-sha256')
    args = parser.parse_args()
    origin = urllib.parse.urlsplit(args.origin)
    if origin.scheme != 'https' or not origin.netloc or origin.path or origin.username or origin.password or origin.query or origin.fragment:
        parser.error('Invalid HTTPS origin')
    allocator = None
    if args.manager_unit:
        assert subprocess.check_output(['systemctl', 'is-active', args.manager_unit], text=True).strip() == 'active'
        root = Path(subprocess.check_output(['systemctl', 'show', args.manager_unit, '-p', 'WorkingDirectory', '--value'], text=True).strip()).resolve(strict=True)
        path = root / 'native_allocator.py'
        assert hashlib.sha256(path.read_bytes()).hexdigest() == args.allocator_sha256
        sys.path.insert(0, str(root))
        module = importlib.import_module('native_allocator')
        assert Path(module.__file__).resolve(strict=True) == path
        allocator = module.NativeAllocator()
        allocator.use_history()
        allocator.slots()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.app = Application(args.forward_port, args.gateway_port, args.origin, allocator)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
