"""Protected native onboarding for an existing, explicitly configured fixed exit pool.

Uses the running pool manager's registry and lock. No token exchange, proxy
process creation, live reload, account import fallback, or existing-account edits.
"""
import argparse
import contextlib
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import secrets
import signal
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Rejected(Exception):
    def __init__(self, status=409):
        self.status = status


def atomic(path, value):
    path = Path(path)
    temporary = path.with_suffix('.next')
    with temporary.open('w', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if os.name != 'nt':
        descriptor = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class Adapter:
    def __init__(self, manager, pool_module, private, gateway_port, origin, identity_mapping=None, recovery_permits=None):
        self.manager = manager
        self.module = pool_module
        self.private = Path(private)
        self.private.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.gateway_port = gateway_port
        self.origin = origin
        self.identity_mapping = Path(identity_mapping) if identity_mapping else None
        self.recovery_permits = Path(recovery_permits) if recovery_permits else None
        self.lock = threading.RLock()

    @contextlib.contextmanager
    def allocation_lock(self):
        # The live allocator deliberately uses LOCK_NB. Contention is normal;
        # wait before any reservation or native request, never replay a request.
        deadline = time.monotonic() + 20
        while True:
            lock = self.module.allocation_lock(self.manager.root / 'private/allocation.lock')
            try:
                lock.__enter__()
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Rejected(409) from None
                time.sleep(0.1)
                continue
            break
        try:
            yield
        except BaseException as error:
            if not lock.__exit__(type(error), error, error.__traceback__):
                raise
        else:
            lock.__exit__(None, None, None)

    def backend(self, path, headers, body=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.gateway_port, timeout=120)
        allowed = {'cookie', 'authorization', 'x-api-key', 'origin', 'x-csrf-token'}
        forwarded = {key: value for key, value in headers.items() if key.lower() in allowed}
        forwarded.update({'Content-Type': 'application/json', 'Host': urllib.parse.urlsplit(self.origin).netloc,
                          'X-Forwarded-Proto': 'https'})
        try:
            connection.request('GET' if body is None else 'POST', path,
                               None if body is None else json.dumps(body).encode(), forwarded)
            response = connection.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise Rejected(502)
            document = json.loads(raw)
            if response.status not in (200, 201) or document.get('code') != 200 or not isinstance(document.get('data'), dict):
                raise Rejected(403 if response.status in (401, 403) else 502)
            return document['data']
        finally:
            connection.close()

    def directory(self, headers):
        rows = []
        expected = None
        for page in range(1, 1001):
            document = self.backend(f'/api/admin/accounts?page={page}&pageSize=100', headers)
            total = document['page']['total']
            if expected is None:
                expected = total
            if total != expected:
                raise Rejected()
            rows.extend(document['items'])
            if len(document['items']) < 100:
                if len(rows) != expected or len({row['id'] for row in rows}) != expected:
                    raise Rejected(503)
                return rows
        raise Rejected(503)

    @staticmethod
    def url(entry):
        return f"http://{entry['username']}:{entry['password']}@{entry['host']}:{entry['port']}"

    def verify_exit(self, entry):
        proxy = self.url(entry)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
        # One bounded, authenticated request, with no direct or alternate-exit fallback.
        with opener.open('https://api64.ipify.org', timeout=20) as response:
            actual = response.read(128).decode().strip()
        if ipaddress.ip_address(actual) != ipaddress.ip_address(entry['exit_ip']):
            raise Rejected(502)

    def receipt_path(self, email):
        return self.private / (hashlib.sha256(email.casefold().encode()).hexdigest() + '.json')

    def reserve(self, email, request_id, account_ids):
        path = self.receipt_path(email)
        if path.exists():
            return self.recover_reservation(path, email, request_id)
        with self.allocation_lock():
            if (self.manager.root / 'private/pending.json').exists():
                raise Rejected()
            rows = self.manager.rows()
            if any(str(row.get('email') or '').casefold() == email.casefold() for row in rows):
                raise Rejected()
            # Historical registrations remain valid identities, but do not count
            # deleted accounts as current pool consumers. Pending reservations count.
            current = [row for row in rows if not row.get('rs_account_id') or row['rs_account_id'] in account_ids]
            counts = {family: sum(row['family'] == family for row in current) for family in (4, 6)}
            family = self.module.choose_family(counts)
            templates = json.loads((self.manager.root / 'private/pool.json').read_text())
            ports = {row['port'] for row in templates if row['family'] == family}
            if len(ports) != 1 or not all(isinstance(port, int) and 1 <= port <= 65535 for port in ports):
                raise Rejected(503)
            entry = {'management_id': 'onboarding_' + uuid.uuid4().hex,
                     'reservation_id': request_id, 'email': email, 'rs_account_id': None,
                     'username': 'fixed' + secrets.token_hex(12), 'password': secrets.token_hex(24),
                     'family': family, 'host': '127.0.0.1', 'port': ports.pop(),
                     'exit_ip': self.manager.cfg['exits'][str(family)]}
            receipt = {'email': email, 'requestId': request_id, 'phase': 'reserved',
                       'entryId': entry['management_id'], 'created': time.time()}
            atomic(path, receipt)
            # The already-running authentication service notices the registry mtime.
            self.module.atomic(self.manager.reg, rows + [entry])
        return path, receipt, entry

    def recover_reservation(self, path, email, request_id):
        # Operator-only, short-lived approval after directory/flow reconciliation.
        # Ordinary retries still stop. A changed receipt invalidates the approval.
        if not self.recovery_permits:
            raise Rejected()
        with self.allocation_lock():
            raw = path.read_bytes()
            receipt = json.loads(raw)
            permits = json.loads(self.recovery_permits.read_text())
            permit = permits.get(path.stem, {})
            now = time.time()
            if (permit.get('receiptSha256') != hashlib.sha256(raw).hexdigest()
                    or permit.get('oldFlowAbsent') is not True
                    or not now < permit.get('expiresAt', 0) <= now + 900
                    or receipt.get('phase') != 'native_complete_pending'
                    or not receipt.get('flowId') or now - receipt.get('created', now) < 900
                    or receipt.get('email', '').casefold() != email.casefold()):
                raise Rejected()
            entries = [entry for entry in self.manager.rows()
                       if entry.get('management_id') == receipt.get('entryId')]
            if (len(entries) != 1 or entries[0].get('rs_account_id')
                    or entries[0].get('email', '').casefold() != email.casefold()
                    or (self.manager.root / 'private/pending.json').exists()):
                raise Rejected()
            if self.identity_mapping and any(row.get('management_id') == receipt['entryId']
                    for row in json.loads(self.identity_mapping.read_text())):
                raise Rejected()
            # Keep the previous flow and first ownership; never alter credentials.
            updated = {'email': email, 'requestId': request_id, 'phase': 'reserved',
                       'entryId': receipt['entryId'], 'created': now,
                       'recoveryHistory': [receipt], 'recoveryApproved': True}
            atomic(path, updated)
            return path, updated, entries[0]

    def start(self, headers, body):
        if set(body) != {'email', 'requestId'}:
            raise Rejected(422)
        email, request_id = body['email'], body['requestId']
        if not isinstance(email, str) or len(email) > 254 or email.count('@') != 1 or any(c.isspace() for c in email):
            raise Rejected(422)
        try:
            uuid.UUID(request_id)
        except (ValueError, TypeError, AttributeError):
            raise Rejected(422) from None
        rows = self.directory(headers)
        if any(row.get('provider') == 'openai' and str(row.get('email') or '').casefold() == email.casefold() for row in rows):
            raise Rejected()
        path, receipt, entry = self.reserve(email, request_id, {row['id'] for row in rows})
        self.verify_exit(entry)
        receipt['phase'] = 'native_start_pending'
        atomic(path, receipt)
        data = self.backend('/api/admin/accounts/oauth/start', headers,
                            {'provider': 'openai', 'name': 'team+' + email, 'outboundProxyUrl': self.url(entry)})
        if not isinstance(data.get('flowId'), str) or not isinstance(data.get('authorizationUrl'), str):
            raise Rejected(502)
        receipt.update({'phase': 'native_started', 'flowId': data['flowId'], 'exitVerified': True})
        atomic(path, receipt)
        return {**data, 'outboundProxyUrl': self.url(entry)}

    def complete(self, headers, body):
        if set(body) != {'provider', 'flowId', 'callbackUrl', 'settings'} or body['provider'] != 'openai':
            raise Rejected(422)
        matches = [(path, json.loads(path.read_text())) for path in self.private.glob('*.json')]
        matches = [(path, receipt) for path, receipt in matches if receipt.get('flowId') == body['flowId']]
        if len(matches) != 1:
            raise Rejected()
        path, receipt = matches[0]
        if receipt['phase'] != 'native_started':
            raise Rejected()
        settings = body['settings']
        notes = settings.get('notes') if isinstance(settings, dict) else None
        if not isinstance(settings, dict) or settings.get('enabled') is not False or not isinstance(notes, str):
            raise Rejected(422)
        fields = notes.split('----')
        if len(fields) != 3 or not all(fields) or fields[0].casefold() != receipt['email'].casefold():
            raise Rejected(422)
        body = {**body, 'settings': {**settings, 'concurrencyLimit': 3}}
        rows = self.directory(headers)
        if any(row.get('provider') == 'openai' and str(row.get('email') or '').casefold() == receipt['email'].casefold() for row in rows):
            raise Rejected()
        entries = [entry for entry in self.manager.rows() if entry.get('management_id') == receipt['entryId']]
        if len(entries) != 1 or entries[0].get('rs_account_id'):
            raise Rejected()
        entry = entries[0]
        self.verify_exit(entry)
        # Keep the existing background allocator from racing native persistence
        # and assigning the new account a second identity before binding finishes.
        with self.allocation_lock():
            receipt['phase'] = 'native_complete_pending'
            atomic(path, receipt)
            result = self.backend('/api/admin/accounts/oauth/complete', headers, body)
            receipt.update({'phase': 'native_saved', 'accountId': result['accountId']})
            atomic(path, receipt)
            self.bind(headers, path, receipt, entry, result['accountId'], notes, rows)
        return result

    def bind(self, headers, path, receipt, entry, account_id, notes, rows):
        account = self.backend('/api/admin/accounts/detail?accountId=' + urllib.parse.quote(account_id), headers)['account']
        expected_endpoint = f"http://{entry['host']}:{entry['port']}"
        if (account['enabled'] is not False or account['email'].casefold() != receipt['email'].casefold()
                or account['notes'] != notes or account.get('provider') != 'openai'
                or account.get('authenticationKind') != 'oauth' or account.get('concurrencyLimit') != 3
                or account.get('outboundProxyEndpoint', '').rstrip('/') != expected_endpoint
                or not account.get('hasRefreshToken') or account.get('capacity', {}).get('usedSlots') != 0
                or not account.get('userId') or not account.get('accountId')
                or any(row['id'] == account['id'] or (row.get('provider') == 'openai' and
                       (row.get('userId'), row.get('accountId')) == (account['userId'], account['accountId'])) for row in rows)):
            raise Rejected(502)
        registered = self.manager.rows()
        selected = next(row for row in registered if row['management_id'] == receipt['entryId'])
        if selected.get('rs_account_id'):
            raise Rejected()
        if self.identity_mapping:
            mapping = json.loads(self.identity_mapping.read_text())
            if not isinstance(mapping, list) or any(row.get('target_rs_id') == account['id'] or
                    row.get('management_id') == entry['management_id'] for row in mapping):
                raise Rejected()
            atomic(self.identity_mapping, mapping + [{'original_rs_id': account['id'],
                'target_rs_id': account['id'], 'management_id': entry['management_id'],
                'email': account['email'], 'user_id': account['userId'], 'workspace_id': account['accountId']}])
        selected.update({'rs_account_id': account['id'], 'user_id': account['userId']})
        self.module.atomic(self.manager.reg, registered)
        receipt.update({'phase': 'bound', 'nativeCompleteConfirmed': True})
        atomic(path, receipt)

    def import_token(self, headers, body):
        if set(body) != {'provider', 'data', 'settings'} or body['provider'] != 'openai':
            raise Rejected(422)
        data, settings = body['data'], body['settings']
        if not isinstance(data, dict) or set(data) != {'email', 'refreshToken'} or not isinstance(settings, dict):
            raise Rejected(422)
        email, token, notes = data['email'], data['refreshToken'], settings.get('notes')
        if (not isinstance(email, str) or email.count('@') != 1 or len(email) > 254 or any(c.isspace() for c in email)
                or not isinstance(token, str) or not 1 <= len(token) <= 32768 or any(c.isspace() for c in token)
                or settings.get('enabled') is not False or not isinstance(notes, str)):
            raise Rejected(422)
        fields = notes.split('----')
        if len(fields) != 3 or not all(fields) or fields[0].casefold() != email.casefold():
            raise Rejected(422)
        rows = self.directory(headers)
        if any(row.get('provider') == 'openai' and str(row.get('email') or '').casefold() == email.casefold() for row in rows):
            raise Rejected()
        path, receipt, entry = self.reserve(email, str(uuid.uuid4()), {row['id'] for row in rows})
        self.verify_exit(entry)
        with self.allocation_lock():
            receipt['phase'] = 'native_import_pending'
            atomic(path, receipt)
            result = self.backend('/api/admin/accounts/import', headers, {**body,
                'data': {**data, 'outboundProxyUrl': self.url(entry)}, 'settings': {**settings, 'concurrencyLimit': 3}})
            ids = result.get('accountIds')
            if not isinstance(ids, list) or len(ids) != 1 or not isinstance(ids[0], str):
                raise Rejected(502)
            receipt.update({'phase': 'native_saved', 'accountId': ids[0]})
            atomic(path, receipt)
            self.bind(headers, path, receipt, entry, ids[0], notes, rows)
        return result

    def call(self, path, headers, body):
        # Authentication is checked with caller credentials before registry access.
        self.backend('/api/admin/accounts?page=1&pageSize=1', headers)
        with self.lock:
            if path == '/_management/onboarding/start':
                return self.start(headers, body)
            if path == '/api/admin/accounts/oauth/complete':
                return self.complete(headers, body)
            if path == '/api/admin/accounts/import':
                return self.import_token(headers, body)
            raise Rejected(404)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        status = 200 if self.path == '/health' else 404
        raw = json.dumps({'code': status}).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        status, document = 503, {'code': 503}
        try:
            if self.client_address[0] != '127.0.0.1' or self.headers.get('Transfer-Encoding'):
                raise Rejected(403)
            if not any(self.headers.get(key) for key in ['Cookie', 'X-Api-Key', 'Authorization']):
                raise Rejected(403)
            if self.headers.get('Origin') not in (None, self.server.adapter.origin) or (self.headers.get('Cookie') and not self.headers.get('Origin')):
                raise Rejected(403)
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 49152:
                raise Rejected(422)
            self.connection.settimeout(15)
            data = self.server.adapter.call(self.path, dict(self.headers), json.loads(self.rfile.read(size)))
            status, document = 200, {'code': 200, 'data': data}
        except Rejected as error:
            status, document = error.status, {'code': error.status}
        except Exception:
            pass
        raw = json.dumps(document).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(raw)


def main():
    parser = argparse.ArgumentParser()
    for name in ['manager-unit', 'manager-source', 'manager-sha256', 'pool-root', 'private', 'public-origin']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--gateway-port', type=int, required=True)
    parser.add_argument('--identity-mapping')
    parser.add_argument('--recovery-permits')
    args = parser.parse_args()
    if subprocess.check_output(['systemctl', 'is-active', args.manager_unit], text=True).strip() != 'active':
        raise RuntimeError('effective_pool_manager_unavailable')
    source = Path(args.manager_source).resolve(strict=True)
    if hashlib.sha256(source.read_bytes()).hexdigest() != args.manager_sha256:
        raise RuntimeError('effective_pool_manager_changed')
    invocation = subprocess.check_output(['systemctl', 'show', args.manager_unit, '-p', 'ExecStart', '--value'], text=True)
    if str(source) not in invocation or args.pool_root not in invocation:
        raise RuntimeError('effective_pool_manager_path_mismatch')
    spec = importlib.util.spec_from_file_location('effective_fixed_pool', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    os.umask(0o077)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    if args.identity_mapping:
        mapping = Path(args.identity_mapping).resolve(strict=True)
        if not isinstance(json.loads(mapping.read_text()), list):
            raise RuntimeError('identity_mapping_invalid')
    server.adapter = Adapter(module.Manager(args.pool_root), module, args.private, args.gateway_port, args.public_origin, args.identity_mapping, args.recovery_permits)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    server.serve_forever()


if __name__ == '__main__':
    main()
