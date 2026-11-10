"""Native per-instance imports backed by the existing independent IPv6 pool."""
import argparse
import copy
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import signal
import sys
import threading
import time
import urllib.parse

from fleet_slots import RemoteAllocator, SlotError, atomic
from import_diagnostics import from_error
from native_task_finalization import install as install_finalization
from onboarding_service import Adapter as OAuthAdapter
from prolite_policy_service import Application as ExitCheck
from daily_import_weight import DailyImportWeight

LOADED_SOURCE_HASHES = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
    for name in ['import_diagnostics.py', 'fleet_import_service.py', 'fleet_slots.py', 'native_task_finalization.py',
                 'onboarding_service.py', 'prolite_policy_service.py', 'daily_import_weight.py']}


class ScopedAllocator:
    """Each submission gets a fresh reservation namespace; exact recovery is idempotent."""
    def __init__(self, allocator, prefix):
        self.allocator, self.prefix = allocator, prefix

    def allocate(self, key):
        return self.allocator.allocate(self.prefix + ':' + hashlib.sha256(key.encode()).hexdigest())

    def __getattr__(self, name):
        return getattr(self.allocator, name)


def fresh_policy(service, receipt_root=None):
    Parent = service.NativePolicy

    class Policy(Parent):
        importing = False
        preflighting = False

        def update(self, path, body):
            ids = body.get('accountIds') if path.endswith('/batch-update') else [body.get('accountId')]
            if not isinstance(ids, list) or not ids or len(set(ids)) != len(ids):
                raise service.PolicyError('Invalid account selection', 400)
            rows = [self.detail(account_id) for account_id in ids]
            pool_host = getattr(self.allocator, 'configuration', {}).get('host')
            def legacy(account):
                return (account.get('authenticationKind') == 'oauth'
                    and urllib.parse.urlsplit(account.get('outboundProxyEndpoint') or '').hostname != pool_host)
            if not any(legacy(account) for account in rows):
                return super().update(path, body)
            for account in rows:
                if account.get('authenticationKind') != 'oauth':
                    continue
                if legacy(account):
                    if not account.get('outboundProxyEndpoint'):
                        raise service.PolicyError('Existing fixed proxy is missing', 409)
                else:
                    self.entry_for(account)
                sensitive = body.get('enabled') is False or any(key in body for key in
                    ['connection', 'credentials', 'data', 'accessToken', 'refreshToken'])
                if sensitive and account.get('capacity', {}).get('usedSlots') != 0:
                    raise service.PolicyError('Wait for existing requests to finish', 409)
                if 'outboundProxyUrl' in body or 'outboundProxyId' in body:
                    if len(rows) != 1:
                        raise service.PolicyError('Fixed proxy fields require one account', 422)
                    document = self.backend('/api/admin/accounts/export?' + urllib.parse.urlencode(
                        {'accountIds': account['id'], 'confirm': 'export_sensitive_accounts'}))
                    saved = document['documents'][0]['document']['accounts'][0]
                    if (saved['id'] != account['id']
                            or ('outboundProxyUrl' in body and (body['outboundProxyUrl'] or '').rstrip('/') != saved['outboundProxyUrl'].rstrip('/'))
                            or ('outboundProxyId' in body and body['outboundProxyId'] != account.get('outboundProxyId'))):
                        raise service.PolicyError('Use an explicit import to reserve a new fixed IPv6', 409)
            result = self.backend(path, body)
            for before in rows:
                after = self.detail(before['id'])
                if (before.get('outboundProxyEndpoint') or '').rstrip('/') != (after.get('outboundProxyEndpoint') or '').rstrip('/'):
                    raise service.PolicyError('Existing fixed proxy readback changed', 502)
                if any(before.get(key) != after.get(key) for key in
                       ['enabled', 'concurrencyLimit', 'weight', 'modelAccess', 'notes'] if key not in body):
                    raise service.PolicyError('Unrequested account setting changed', 502)
            return result

        def preflight_imports(self, items):
            previous, self.preflighting = self.preflighting, True
            try:
                return super().preflight_imports(items)
            finally:
                self.preflighting = previous

        def entry_for(self, account, verify=False):
            if self.preflighting:
                # Parent preflight already requires an exact, paused, idle
                # existing account. No allocation or token exchange occurs here.
                return {'account_id': account['id']}
            if self.importing:
                return self.allocator.allocate('replacement:' + account['id'])
            return super().entry_for(account, verify)

        def import_item(self, body, reservation_prefix):
            allocator = self.allocator
            self.allocator = ScopedAllocator(allocator, reservation_prefix)
            self.importing = True
            try:
                return super().import_item(body, reservation_prefix)
            except SlotError as error:
                mapped = service.PolicyError(str(error), error.status)
                mapped.diagnostic = from_error(error)
                raise mapped from None
            finally:
                self.importing = False
                self.allocator = allocator

        def complete_oauth(self, body):
            entry, account_id = self.allocator.get_flow(body['flowId'])
            if account_id:
                return super().complete_oauth(body)
            plugin_flow = False
            if receipt_root is not None:
                for path in Path(receipt_root).glob('*.json'):
                    record = json.loads(path.read_text())
                    if record.get('result', {}).get('data', {}).get('flowId') == body['flowId']:
                        plugin_flow = True
                        break
            prepared = copy.deepcopy(body)
            settings = prepared.setdefault('settings', {})
            desired = settings.get('enabled', True)
            settings.update(enabled=False)
            if settings.get('concurrencyLimit') is None:
                settings['concurrencyLimit'] = 3
            settings.setdefault('weight', 1)
            settings.setdefault('groupIds', [])
            settings.setdefault('notes', None)
            result = super().complete_oauth(prepared)
            if not plugin_flow:
                account = self.detail(result['accountId'])
                identity = (account['userId'], account['accountId'])
                self.new_identities = {identity: True}
                self.finish([account['id']], [(entry, identity, desired)])
            return result

        def start_oauth(self, body):
            try:
                return super().start_oauth(body)
            except SlotError as error:
                mapped = service.PolicyError(str(error), error.status)
                mapped.diagnostic = from_error(error)
                raise mapped from None

    service.NativePolicy = Policy


def load_service(core, receipt_root=None, daily_weights=None):
    core = Path(core).resolve(strict=True)
    sys.path.insert(0, str(core))
    spec = importlib.util.spec_from_file_location('fleet_native_core', core / 'management_service.py')
    service = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(service)
    install_finalization(service, daily_weights)
    fresh_policy(service, receipt_root)
    return service


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.configuration.read_text())
    import onboarding_service
    onboarding_service.PUBLIC_ORIGIN = config['origin']
    root = Path(config['stateRoot'])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    daily_weights = DailyImportWeight(config['dailyImportWeightLedger']) if config.get('dailyImportWeightLedger') else None
    service = load_service(Path(__file__).with_name('native_core'), root / 'oauth-starts', daily_weights)
    for path in Path(__file__).with_name('native_core').glob('*.py'):
        LOADED_SOURCE_HASHES['native_core/' + path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    service.PUBLIC_ORIGIN = config['origin']
    service.REGISTRY_SOURCES = set(config.get('registrySources', ['127.0.0.1']))
    service.UPSTREAM_PORT = config['gatewayPort']
    allocator = RemoteAllocator(config['slots'])

    def backend(path, headers, body=None):
        connection = http.client.HTTPConnection('127.0.0.1', config['gatewayPort'], timeout=180)
        try:
            forwarded = {key: value for key, value in headers.items() if key.lower() in
                {'cookie', 'x-api-key', 'authorization', 'origin', 'referer', 'x-csrf-token'}}
            forwarded.update({'Content-Type': 'application/json',
                'Host': urllib.parse.urlsplit(config['origin']).netloc, 'X-Forwarded-Proto': 'https'})
            connection.request('GET' if body is None else 'POST', path,
                body=None if body is None else json.dumps(body), headers=forwarded)
            response = connection.getresponse()
            raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise service.PolicyError('Native response limit', 503)
            if response.status >= 400:
                raise service.UpstreamError(response.status, raw)
            document = json.loads(raw)
            if document.get('code') != 200:
                raise service.UpstreamError(502, b'{"code":502}')
            return document['data']
        finally:
            connection.close()

    port = config['port']
    adapter = OAuthAdapter(allocator, port, config['gatewayPort'], state_dir=root / 'oauth-starts')
    checker = ExitCheck(port, config['gatewayPort'], config['origin'], allocator, daily_weights)
    application = service.Application(allocator, root / 'tasks', backend=backend)
    Original = service.Handler
    source_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    class Handler(Original):
        def end_headers(self):
            self.send_header('X-RS-Import-Policy', 'daily-pro-weight-0.1.69' if daily_weights else 'fresh-ipv6-gpt-pro-0.1.68')
            return super().end_headers()

        def dispatch(self):
            path = urllib.parse.urlsplit(self.path).path
            if path in {'/healthz', '/health'} and self.command == 'GET':
                health = {'status': 'ok', 'sourceSha256': source_sha,
                    'freshIndependentIPv6': True, 'proImportGroup': 'GPT Pro',
                    'independentIPv6Pool': True, 'loadedSourceSha256': LOADED_SOURCE_HASHES,
                    'dailyImportWeight': {'enabled': daily_weights is not None, 'timezone': 'Asia/Shanghai',
                                         'step': 1, 'minimum': 1, 'plans': ['pro', 'prolite', 'self_serve_business_prolite'], 'sequences': [{'id': 'pro', 'start': 50, 'plans': ['pro', 'self_serve_business_prolite']}, {'id': 'prolite', 'start': 100, 'plans': ['prolite']}]}}
                self.reply(200, {'code': 200, 'data': health} if path == '/health' else health)
                return
            if path not in {'/_management/onboarding/start', '/_management/onboarding/ipv6-check',
                             '/_management/onboarding/prolite-check'}:
                return super().dispatch()
            try:
                headers = dict(self.headers)
                backend('/api/admin/accounts?page=1&pageSize=1', headers)
                origin = self.headers.get('Origin')
                if origin not in (None, config['origin']) or (self.headers.get('Cookie') and not origin):
                    raise service.PolicyError('Cross-origin request rejected', 403)
                size = int(self.headers.get('Content-Length', '0'))
                if self.command != 'POST' or self.headers.get('Transfer-Encoding') or not 0 < size <= 49152:
                    raise service.PolicyError('Invalid management request', 400)
                self.connection.settimeout(15)
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict):
                    raise service.PolicyError('Invalid management body', 400)
                if path == '/_management/onboarding/start':
                    status, result = adapter.call(path, headers, body)
                else:
                    status, result = checker.call(path, headers, body)
                self.reply(status, result)
            except service.UpstreamError as error:
                self.reply(error.status, error.raw, raw=True)
            except (service.PolicyError, SlotError) as error:
                self.reply(error.status, {'code': error.status, 'message': str(error), 'diagnostic': from_error(error)})
            except Exception:
                self.reply(503, {'code': 503, 'message': 'Protected import verification failed'})

        do_GET = dispatch
        do_POST = dispatch
        do_PUT = dispatch
        do_DELETE = dispatch

    servers = []
    for address in config.get('listen', ['127.0.0.1']):
        server = service.ThreadingHTTPServer((address, port), Handler)
        server.app = application
        servers.append(server)
    signal.signal(signal.SIGTERM, lambda *_: [threading.Thread(target=s.shutdown, daemon=True).start() for s in servers])
    threads = [threading.Thread(target=s.serve_forever) for s in servers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for server in servers:
        server.server_close()


if __name__ == '__main__':
    main()
