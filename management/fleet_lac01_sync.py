"""LAC-01 host/authentication adapter; runs the LAC-02 exact incremental engine."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--configuration', required=True, type=Path)
    for name in ['runtime-root', 'manager-source', 'manager-sha256', 'pool-root', 'migration', 'handover', 'receipts', 'chat-key']:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    global ROOT
    ROOT = Path(args.runtime_root)
    sys.path.insert(0, str(ROOT))
    runtime_config = json.loads((ROOT / 'sync-config.json').read_text())
    os.umask(0o077)
    manifest = json.loads((ROOT / 'artifact.json').read_text())
    for name, digest in manifest['installed'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Synchronization artifact changed')
    spec = importlib.util.spec_from_file_location('local_pool', args.manager_source)
    if hashlib.sha256(Path(spec.origin).read_bytes()).hexdigest() != args.manager_sha256:
        raise ValueError('Effective fixed allocator changed')
    manager_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager_module)
    manager = manager_module.Manager(args.pool_root)
    import sync_rs, migration_identity, native_proxy_policy, local_identity
    original = sync_rs.request_json
    def request(base, path, key, method='GET', body=None, rs=False):
        if rs:
            if base != runtime_config['rs_url'] or method != 'GET' or body is not None:
                raise ValueError('Unexpected RS mutation')
            return manager.api(path)
        if base != runtime_config['app_url']:
            raise ValueError('Unexpected Chat2API endpoint')
        return original(base, path, key, method, body, rs)
    sync_rs.request_json = request
    # Only identity projection differs: use LAC-01's existing native/migration
    # receipts. Never change the authoritative proxy registry or its IDs.
    source = manager.directory()
    migration = json.loads(Path(args.migration).read_text())
    handover = json.loads(Path(args.handover).read_text())
    def receipt(email):
        name = hashlib.sha256(email.casefold().encode()).hexdigest() + '.json'
        return json.loads((Path(args.receipts) / name).read_text())
    allowed = {int(k): v for k, v in manager.cfg['exits'].items()}
    from fleet_sync import collect, install_routes
    fleet_mappings, fleet_registry = collect(source, manager.api, json.loads(args.configuration.read_text()))
    mappings, registry = local_identity.project([row for row in source if row['id'] not in fleet_mappings], manager.rows(), receipt, migration, handover, allowed)
    mappings.update(fleet_mappings)
    registry.update(fleet_registry)
    install_routes(lambda: registry)
    # Instance-owned metadata only; never copy the reference host's accounts,
    # credentials, identity files, quota or execution state.
    import sync_incremental
    ledger_path = ROOT / 'private/source-plan-ledger.json'
    ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else {}
    imported = []
    migrated_ids = {r['target'] for r in migration.get('completed', [])}
    for row in source:
        if row.get('planType'):
            ledger[row['id']] = row['planType']
        if row['id'] in fleet_mappings or row['id'] in migrated_ids or receipt(row['email']).get('nativeImportConfirmed') is True:
            imported.append({'target_id': row['id']})
    sync_incremental.atomic(ledger_path, ledger)
    sync_incremental.atomic(ROOT / 'imported-fixed-proxies.json', imported)
    migration_identity.mappings = lambda: mappings
    native_proxy_policy.load_registry = lambda: registry
    spec = importlib.util.spec_from_file_location('exact_engine', ROOT / 'sync_exact_20261022.py')
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    sys.argv = [str(ROOT / 'sync_exact_20261022.py')] + (['--apply'] if args.apply else [])
    engine.main()

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        import traceback
        # Line positions and exception type suffice for reconciliation; no token,
        # receipt contents, proxy authentication or raw upstream errors are logged.
        print(json.dumps({'state': 'failed', 'kind': type(error).__name__,
                          'frames': [[Path(f.filename).name, f.lineno] for f in traceback.extract_tb(error.__traceback__)],
                          'credentials_omitted': True}))
        raise SystemExit(1)
