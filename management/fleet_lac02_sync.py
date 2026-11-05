"""Use verified onboarding ownership with an existing RS synchronization engine."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from fleet_registered_identity import registered_mappings


def install_identity_reader(identity_module, registry_loader, legacy_validator, mapping, receipts,
                            chat_identities=None):
    def read_receipt(email):
        name = hashlib.sha256(email.casefold().encode()).hexdigest() + '.json'
        return json.loads((receipts / name).read_text(encoding='utf-8'))

    def mappings():
        rows = json.loads(mapping.read_text(encoding='utf-8'))
        return registered_mappings(rows, registry_loader(), read_receipt, legacy_validator,
                                   chat_identities)

    identity_module.mappings = mappings

    def chat_registry():
        registry = registry_loader()
        rows = json.loads(mapping.read_text(encoding='utf-8'))
        verified = registered_mappings(rows, registry, read_receipt, legacy_validator,
                                       chat_identities)
        renamed = {row['management_id']: verified[row['target_rs_id']]['management_id']
                   for row in rows if row['management_id'].startswith('onboarding_')}
        result = {}
        for mid, entry in registry.items():
            destination = renamed.get(mid, mid)
            if destination in result:
                raise ValueError('Duplicate proxy identity alias')
            result[destination] = dict(entry, management_id=destination)
        return result

    return chat_registry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime-root', type=Path, required=True)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--engine-sha256', required=True)
    parser.add_argument('--identity-map', type=Path, required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--chat-identities', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--configuration', required=True, type=Path)
    args = parser.parse_args()
    root = args.runtime_root.resolve(strict=True)
    engine = (root / args.engine).resolve(strict=True)
    if engine.parent != root or hashlib.sha256(engine.read_bytes()).hexdigest() != args.engine_sha256:
        raise ValueError('Synchronization engine changed; deployment review required')
    sys.path.insert(0, str(root))
    import migration_identity
    import migration_policy
    import native_proxy_policy

    # 只替换身份读取边界，复用现行同步器的锁、写入回执及在途请求保护。
    aliases = (json.loads(args.chat_identities.read_text(encoding='utf-8'))
               if args.chat_identities else {})
    native_proxy_policy.load_registry = install_identity_reader(
        migration_identity, native_proxy_policy.load_registry,
        migration_policy.validate_mappings, args.identity_map, args.receipts, aliases,
    )
    from fleet_sync import collect, install_routes, retain_destination_ids
    import sync_rs
    config = json.loads((root / 'sync-config.json').read_text())
    key = (root / 'rs-api.key').read_text().strip()
    def backend(path):
        return sync_rs.request_json(config['rs_url'], path, key, rs=True)
    source = []
    for page in range(1, 1001):
        batch = backend('/api/admin/accounts?page=' + str(page) + '&pageSize=100')['items']
        source.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ValueError('Incomplete source directory')
    fleet_mappings, fleet_registry = collect(source, backend, json.loads(args.configuration.read_text()))
    prior_mappings, prior_registry = migration_identity.mappings, native_proxy_policy.load_registry
    fleet_mappings, fleet_registry = retain_destination_ids(prior_mappings(), fleet_mappings, fleet_registry)
    migration_identity.mappings = lambda: {**prior_mappings(), **fleet_mappings}
    native_proxy_policy.load_registry = lambda: {**prior_registry(), **fleet_registry}
    install_routes(native_proxy_policy.load_registry)
    spec = importlib.util.spec_from_file_location('registered_sync_engine', engine)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.argv = [str(engine)] + (['--apply'] if args.apply else [])
    module.main()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # 固定错误类型投影，禁止将身份、代理认证或令牌写入日志。
        print(json.dumps({'state': 'failed', 'kind': type(error).__name__, 'credentials_omitted': True}))
        raise SystemExit(1)
