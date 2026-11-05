"""Small authenticated facade over the discovered live immutable IPv6 allocator.

No proxy process or address pool is created here. Site adapters receive only
their own reservations; allocation and permanent history remain authoritative
on the host that actually owns the prebuilt proxy pool.
"""
import argparse
import contextlib
import hashlib
import hmac
import http.client
import importlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def atomic(path, value):
    path = Path(path)
    temporary = path.with_suffix('.next')
    with temporary.open('w', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if os.name != 'nt':
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class SlotError(Exception):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


class Broker:
    def __init__(self, allocator, ledger, legacy_site='pool'):
        self.allocator, self.ledger = allocator, Path(ledger)
        self.legacy_site = legacy_site
        self.mutex = threading.RLock()

    def records(self):
        value = json.loads(self.ledger.read_text()) if self.ledger.exists() else {}
        if not isinstance(value, dict):
            raise SlotError('Pool registration unavailable', 503)
        return value

    def visible(self, site, entry):
        record = self.records().get(str(entry['port']))
        return record['site'] == site if record else site == self.legacy_site

    def entry(self, site, supplied):
        # Resolve every operation from the authoritative registry, never trust
        # caller-provided IPs, credentials, port mappings or ownership fields.
        entry = self.allocator.lookup(self.allocator.url(supplied))
        if not entry or not self.visible(site, entry):
            raise SlotError('Reservation does not belong to this instance')
        return entry

    def call(self, site, method, args):
        with self.mutex:
            allocator = self.allocator
            records = self.records()
            def visible(entry):
                record = records.get(str(entry['port']))
                return record['site'] == site if record else site == self.legacy_site
            if method == 'allocate':
                key, = args
                if not isinstance(key, str) or not 1 <= len(key) <= 256:
                    raise SlotError('Invalid reservation identifier', 422)
                key = 'fleet:' + site + ':' + key
                entry = allocator.allocate(key)
                if allocator.owner(entry):
                    raise SlotError('Import reservation already belongs to an account')
                history = allocator.use_history()['entries'][entry['ipv6']]
                if (history.get('account_id') or history.get('retired') is not False
                        or history.get('reservation_hash') != hashlib.sha256(key.encode()).hexdigest()
                        or ipaddress.ip_address(entry['ipv6']).version != 6):
                    raise SlotError('Import reservation history mismatch')
                records = self.records()
                prior = records.get(str(entry['port']))
                wanted = {'site': site, 'keyHash': hashlib.sha256(key.encode()).hexdigest()}
                if prior and prior != wanted:
                    raise SlotError('Reservation ownership changed')
                records[str(entry['port'])] = wanted
                atomic(self.ledger, records)
                allocator.verify(entry)
                return entry
            if method in {'rows', 'all_rows'}:
                return [entry for entry in getattr(allocator, method)() if visible(entry)]
            if method == 'slots':
                ports = {row['port'] for row in allocator.all_rows() if visible(row)}
                return {port: entry for port, entry in allocator.slots().items()
                        if port in ports}
            if method == 'use_history':
                ips = {row['ipv6'] for row in allocator.all_rows() if visible(row)}
                return {'entries': {ip: entry for ip, entry in allocator.use_history()['entries'].items() if ip in ips}}
            if method == 'lookup':
                entry = allocator.lookup(args[0])
                return entry if entry and self.visible(site, entry) else None
            if method == 'get_flow':
                try:
                    entry, account_id = allocator.get_flow(site + ':' + args[0])
                except Exception as error:
                    if site != self.legacy_site or getattr(error, 'status', None) != 409:
                        raise
                    # Preserve already-started native LA-03 flows across the
                    # management cutover. Their original reservation is reused
                    # only for the same still-live native flow.
                    entry, account_id = allocator.get_flow(args[0])
                return [self.entry(site, entry), account_id]
            if method not in {'verify', 'flow', 'bind'}:
                raise SlotError('Unsupported slot operation', 404)
            entry = self.entry(site, args[0])
            if method == 'verify':
                allocator.verify(entry)
                return entry
            if method == 'flow':
                flow, account_id = args[1:]
                allocator.flow(site + ':' + flow, entry, account_id)
                return None
            account_id = args[1]
            if not isinstance(account_id, str) or not account_id.startswith('acct_') or len(account_id) > 128:
                raise SlotError('Invalid account binding', 422)
            if allocator.owner(entry) not in (None, account_id):
                raise SlotError('Historical IPv6 ownership cannot be transferred')
            # An explicit, paused import may replace its original fixed exit.
            # Retain the old authentication and first ownership for all existing
            # consumers; no data-plane stop, reload, revocation or IP reuse.
            with allocator.lock():
                rows = allocator.rows()
                old = next((row for row in rows if row['account_id'] == account_id), None)
                if old and old['port'] != entry['port']:
                    if not self.visible(site, old):
                        raise SlotError('Account belongs to another instance')
                    reserved = allocator.reserved()
                    retained_key = 'retained:import:' + account_id + ':' + str(old['port'])
                    reserved[retained_key] = old
                    # Preserve recovery material before changing the live registry.
                    atomic(allocator.reservations, reserved)
                    atomic(allocator.path, [row for row in rows if row['port'] != old['port']])
                allocator.bind(entry, account_id)
            return allocator.lookup(allocator.url(entry))


class RemoteAllocator:
    """Per-instance client; no credentials or pool state are logged."""
    def __init__(self, configuration):
        self.configuration = configuration

    def rpc(self, method, *args):
        config = self.configuration
        connection = http.client.HTTPConnection(config['host'], config['port'], timeout=90)
        try:
            connection.request('POST', '/slots', json.dumps({'method': method, 'args': args}),
                {'Content-Type': 'application/json', 'X-Slot-Site': config['site'],
                 'Authorization': 'Bearer ' + Path(config['keyFile']).read_text().strip()})
            response = connection.getresponse()
            value = json.load(response)
            if response.status != 200:
                raise SlotError(value.get('message', 'Protected slot operation failed'), response.status)
            return value['data']
        finally:
            connection.close()

    @staticmethod
    def url(entry):
        return 'http://' + urllib.parse.quote(entry['username'], safe='') + ':' + urllib.parse.quote(entry['password'], safe='') + '@' + entry['host'] + ':' + str(entry['port'])

    @staticmethod
    def endpoint(entry):
        return 'http://' + entry['host'] + ':' + str(entry['port'])

    @staticmethod
    def owner(entry):
        return entry.get('account_id')

    def allocate(self, key):
        return self.rpc('allocate', key)

    def bind(self, entry, account_id):
        saved = self.rpc('bind', entry, account_id)
        entry.update(saved)

    def verify(self, entry):
        entry.update(self.rpc('verify', entry))

    def lookup(self, url):
        return self.rpc('lookup', url)

    def rows(self):
        return self.rpc('rows')

    def all_rows(self):
        return self.rpc('all_rows')

    def slots(self):
        return {int(port): value for port, value in self.rpc('slots').items()}

    def use_history(self):
        return self.rpc('use_history')

    def used_ipv6(self):
        return set(self.use_history()['entries'])

    def flow(self, flow, entry, account_id):
        return self.rpc('flow', entry, flow, account_id)

    def get_flow(self, flow):
        return self.rpc('get_flow', flow)

    def exchange_refresh(self, entry, token):
        # Explicitly supplied RT validation runs on its own RS host. The pool
        # control service never receives account tokens; only the assigned,
        # authenticated proxy carries the encrypted upstream HTTPS connection.
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': self.url(entry)}))
        body = urllib.parse.urlencode({'grant_type': 'refresh_token', 'refresh_token': token,
            'client_id': self.configuration.get('oauthClientId', 'app_EMoamEEZ73f0CkXaXp7hrann')}).encode()
        try:
            request = urllib.request.Request('https://auth.openai.com/oauth/token', data=body,
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
            with opener.open(request, timeout=45) as response:
                result = json.load(response)
            if not result.get('access_token') or not result.get('refresh_token'):
                raise ValueError('Incomplete native refresh result')
            return result
        except Exception:
            raise SlotError('RT exchange failed; private diagnostics withheld', 422) from None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        status, result = 503, {'message': 'Protected slot operation failed'}
        try:
            site = self.headers.get('X-Slot-Site')
            expected = self.server.principals.get(site)
            if (self.path != '/slots' or not expected
                    or not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + expected['key'])
                    or self.client_address[0] not in expected['sources']):
                raise SlotError('Unauthorized', 403)
            size = int(self.headers.get('Content-Length', '0'))
            if self.headers.get('Transfer-Encoding') or not 0 < size <= 65536:
                raise SlotError('Invalid request', 400)
            self.connection.settimeout(15)
            body = json.loads(self.rfile.read(size))
            result = {'data': self.server.broker.call(site, body['method'], body['args'])}
            status = 200
        except SlotError as error:
            status, result = error.status, {'message': str(error)}
        except Exception:
            pass
        raw = json.dumps(result).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manager-unit', required=True)
    parser.add_argument('--allocator-sha256', required=True)
    parser.add_argument('--private', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--listen', required=True)
    parser.add_argument('--legacy-site', required=True)
    args = parser.parse_args()
    assert subprocess.check_output(['systemctl', 'is-active', args.manager_unit], text=True).strip() == 'active'
    root = Path(subprocess.check_output(['systemctl', 'show', args.manager_unit, '-p', 'WorkingDirectory', '--value'], text=True).strip()).resolve(strict=True)
    assert hashlib.sha256((root / 'native_allocator.py').read_bytes()).hexdigest() == args.allocator_sha256
    sys.path.insert(0, str(root))
    module = importlib.import_module('native_allocator')
    assert Path(module.__file__).resolve() == root / 'native_allocator.py'
    allocator = module.NativeAllocator()
    allocator.slots()
    allocator.use_history()
    server = ThreadingHTTPServer((args.listen, args.port), Handler)
    server.principals = json.loads((args.private / 'principals.json').read_text())
    server.broker = Broker(allocator, args.private / 'slot-ledger.json', args.legacy_site)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
