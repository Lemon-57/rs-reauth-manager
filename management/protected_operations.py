"""Keep one protected RT import alive while the plugin polls short authenticated requests."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUTH = {'cookie', 'authorization', 'x-api-key', 'origin', 'x-csrf-token'}
FORWARD = {'/_management/onboarding/start', '/_management/onboarding/ipv6-check',
           '/_management/onboarding/prolite-check', '/api/admin/accounts/import',
           '/api/admin/accounts/oauth/complete', '/api/admin/accounts/update',
           '/api/admin/accounts/batch-update'}
OPERATION = '/_management/import-operation'


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class Operations:
    def __init__(self, root, send):
        self.root, self.send = Path(root), send
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.running = set()

    def call(self, headers, body):
        if set(body) != {'requestId', 'request'}:
            return 422, {'code': 422}
        try:
            uuid.UUID(body['requestId'])
        except (ValueError, TypeError, AttributeError):
            return 422, {'code': 422}
        request = body['request']
        if not isinstance(request, dict) or request.get('provider') != 'openai':
            return 422, {'code': 422}
        content_hash = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        path = self.root / (body['requestId'] + '.json')
        with self.lock:
            if path.exists():
                record = json.loads(path.read_text())
                if record['requestHash'] != content_hash:
                    return 409, {'code': 409}
                if record['phase'] == 'complete':
                    return record['status'], record['response']
                if body['requestId'] not in self.running:
                    return 503, {'code': 503, 'diagnostic': {'code': 'rt_result_unconfirmed'}}
                return 202, {'code': 200, 'data': {'pending': True}}
            if self.running:
                return 409, {'code': 409}
            record = {'requestHash': content_hash, 'phase': 'intent'}
            atomic(path, record)
            self.running.add(body['requestId'])
            threading.Thread(target=self.execute, args=(body['requestId'], path, record, dict(headers), request), daemon=True).start()
            return 202, {'code': 200, 'data': {'pending': True}}

    def execute(self, operation_id, path, record, headers, request):
        try:
            status, result = self.send('/api/admin/accounts/import', headers, request, 600)
            if 200 <= status < 300 and result.get('code') == 200:
                data = result.get('data')
                if not isinstance(data, dict) or not isinstance(data.get('accountIds'), list):
                    raise ValueError('invalid_receipt')
                response = {'code': 200, 'data': {key: data[key] for key in ('accountIds', 'importedCount', 'configRevision') if key in data}}
            else:
                from import_diagnostics import sanitize
                response = {'code': status, 'diagnostic': sanitize(result.get('diagnostic'))}
            record.update(phase='complete', status=status, response=response)
        except Exception:
            record.update(phase='complete', status=503, response={'code': 503, 'diagnostic': {'code': 'rt_result_unconfirmed'}})
        finally:
            with self.lock:
                atomic(path, record)
                self.running.discard(operation_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--forward-port', required=True, type=int)
    parser.add_argument('--legacy-port', required=True, type=int)
    parser.add_argument('--auth-port', required=True, type=int)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--root', required=True, type=Path)
    args = parser.parse_args()

    def send(path, headers, body=None, timeout=110):
        port = args.auth_port if path.startswith('/api/admin/accounts?') else args.forward_port if path == '/api/admin/accounts/import' else args.legacy_port
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
        try:
            forwarded = {key: value for key, value in headers.items() if key.lower() in AUTH}
            forwarded['Content-Type'] = 'application/json'
            connection.request('GET' if body is None else 'POST', path, None if body is None else json.dumps(body).encode(), forwarded)
            response = connection.getresponse()
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError('response_limit')
            return response.status, json.loads(raw)
        finally:
            connection.close()

    operations = Operations(args.root, send)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.reply(200 if self.path == '/health' else 404, {'ready': self.path == '/health'})

        def do_POST(self):
            status, result = 503, {'code': 503}
            try:
                headers = dict(self.headers)
                if (self.client_address[0] != '127.0.0.1' or self.headers.get('Transfer-Encoding')
                        or not any(self.headers.get(key) for key in ('Cookie', 'Authorization', 'X-Api-Key'))
                        or self.headers.get('Origin') not in (None, args.origin)
                        or (self.headers.get('Cookie') and not self.headers.get('Origin'))):
                    self.reply(403, {'code': 403})
                    return
                self.connection.settimeout(10)
                size = int(self.headers.get('Content-Length', '0'))
                if self.path not in FORWARD | {OPERATION} or not 0 < size <= 65536:
                    self.reply(422, {'code': 422})
                    return
                body = json.loads(self.rfile.read(size))
                if self.path == OPERATION:
                    auth_status, auth = send('/api/admin/accounts?page=1&pageSize=1', headers, timeout=15)
                    if auth_status != 200 or auth.get('code') != 200:
                        status, result = 403, {'code': 403}
                    else:
                        status, result = operations.call(headers, body)
                else:
                    status, result = send(self.path, headers, body)
            except Exception:
                pass
            self.reply(status, result)

        def reply(self, status, value):
            raw = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(raw)

    ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
