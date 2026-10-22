"""Authenticated loopback adapter to the effective protected manager, never a second allocator."""
import argparse
import http.client
import importlib
import json
import os
import signal
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ALLOWED = {'/api/admin/accounts/import', '/api/admin/accounts/oauth/complete', '/api/admin/accounts/batch-update'}
AUTH_HEADERS = {'cookie', 'x-api-key', 'authorization', 'origin', 'x-csrf-token'}
LOCK = threading.RLock()
PUBLIC_ORIGIN = 'https://rs.example.invalid'
MANAGER_UNIT = 'rs-protected-manager.service'


def send(port, path, headers, body=None, host='127.0.0.1'):
    conn = http.client.HTTPConnection(host, port, timeout=120)
    try:
        request_headers = {k: v for k, v in headers.items() if k.lower() in AUTH_HEADERS}
        request_headers.update({'Content-Type': 'application/json', 'Host': urllib.parse.urlsplit(PUBLIC_ORIGIN).netloc, 'X-Forwarded-Proto': 'https'})
        conn.request('GET' if body is None else 'POST', path, None if body is None else json.dumps(body).encode(), request_headers)
        response = conn.getresponse()
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('response_limit')
        return response.status, json.loads(raw)
    finally:
        conn.close()


def normalize_success(status, result):
    # Preserve the business envelope and native data; normalize only successful creation responses.
    if status in (200, 201) and isinstance(result, dict) and result.get('code') == 200 and isinstance(result.get('data'), dict):
        return 200, result
    return status if status not in (200, 201) else 502, result if status not in (200, 201) else {'code': 502}


class Adapter:
    def __init__(self, allocator, manager_port, gateway_port, manager_host='127.0.0.1'):
        self.allocator = allocator
        self.manager_port = manager_port
        self.manager_host = manager_host
        self.gateway_port = gateway_port
        self.pending = {}

    def call(self, path, headers, body):
        # Validate the original administrator authentication before reading input or reserving a slot.
        status, verified = send(self.gateway_port, '/api/admin/accounts?page=1&pageSize=1', headers)
        if status != 200 or verified.get('code') != 200:
            return 403, {'code': 403}
        if path in ALLOWED:
            return normalize_success(*send(self.manager_port, path, headers, body, host=self.manager_host))
        if path != '/_management/onboarding/start' or set(body) != {'email', 'requestId'}:
            return 422, {'code': 422}
        email, request_id = body['email'], body['requestId']
        import uuid
        uuid.UUID(request_id)
        if not isinstance(email, str) or len(email) > 254 or '@' not in email or any(c.isspace() for c in email):
            return 422, {'code': 422}
        with LOCK:
            key = email.casefold()
            # Full directory check before the effective manager allocates a never-used fixed slot.
            seen = set()
            for page in range(1, 1001):
                status, result = send(self.gateway_port, f'/api/admin/accounts?page={page}&pageSize=100', headers)
                if status != 200 or result.get('code') != 200:
                    return 503, {'code': 503}
                rows = result['data']['items']
                for account in rows:
                    if account['id'] in seen:
                        return 503, {'code': 503}
                    seen.add(account['id'])
                    if account.get('provider') == 'openai' and str(account.get('email') or '').casefold() == key:
                        return 409, {'code': 409}
                if len(rows) < 100:
                    break
            else:
                return 503, {'code': 503}
            if key in self.pending or len(self.pending) >= 1000:
                # No second allocation or OAuth flow on response uncertainty.
                return 409, {'code': 409}
            self.pending[key] = request_id
            status, result = send(self.manager_port, '/api/admin/accounts/oauth/start', headers, {'provider': 'openai', 'name': 'team+' + email}, host=self.manager_host)
            if status not in (200, 201) or result.get('code') != 200:
                return status if status not in (200, 201) else 502, {'code': status if status not in (200, 201) else 502}
            data = result['data']
            entry, account_id = self.allocator.get_flow(data['flowId'])
            if account_id or self.allocator.owner(entry):
                return 409, {'code': 409}
            # The manager already verified the slot, actual exit, credentials and registered its native flow.
            return 200, {'code': 200, 'data': {**data, 'outboundProxyUrl': self.allocator.url(entry)}}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_POST(self):
        status, result = 503, {'code': 503}
        try:
            if self.client_address[0] != '127.0.0.1' or self.path not in ALLOWED | {'/_management/onboarding/start'}:
                status, result = 404, {'code': 404}
            elif self.headers.get('Transfer-Encoding'):
                status, result = 400, {'code': 400}
            elif not any(self.headers.get(k) for k in ['Cookie', 'Authorization', 'X-Api-Key']):
                status, result = 403, {'code': 403}
            elif self.headers.get('Origin') not in (None, PUBLIC_ORIGIN) or (self.headers.get('Cookie') and not self.headers.get('Origin')):
                status, result = 403, {'code': 403}
            else:
                self.connection.settimeout(15)
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 49152:
                    raise ValueError('body_limit')
                status, result = self.server.adapter.call(self.path, dict(self.headers), json.loads(self.rfile.read(size)))
        except Exception:
            # Do not send exceptions, headers, input or backend bodies to diagnostics.
            status, result = 503, {'code': 503}
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


def main():
    global PUBLIC_ORIGIN, MANAGER_UNIT
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--manager-host', default='127.0.0.1')
    parser.add_argument('--manager-port', type=int, required=True)
    parser.add_argument('--gateway-port', type=int, required=True)
    parser.add_argument('--public-origin', required=True)
    parser.add_argument('--manager-unit', required=True)
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.public_origin)
    if parsed.scheme != 'https' or not parsed.netloc or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username or parsed.password:
        parser.error('public origin must be an HTTPS origin')
    PUBLIC_ORIGIN = args.public_origin.rstrip('/')
    MANAGER_UNIT = args.manager_unit
    # Discover the effective service; never import an allocator from an archive or this adapter directory.
    unit = MANAGER_UNIT
    if subprocess.check_output(['systemctl', 'is-active', unit], text=True).strip() != 'active':
        raise RuntimeError('protected_manager_unavailable')
    root = Path(subprocess.check_output(['systemctl', 'show', unit, '--property=WorkingDirectory', '--value'], text=True).strip()).resolve(strict=True)
    sys.path.insert(0, str(root))
    module = importlib.import_module('native_allocator')
    if Path(module.__file__).resolve(strict=True) != root / 'native_allocator.py':
        raise RuntimeError('allocator_path_mismatch')
    allocator = module.NativeAllocator()
    allocator.use_history()
    allocator.slots()
    os.umask(0o077)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.adapter = Adapter(allocator, args.manager_port, args.gateway_port, args.manager_host)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
