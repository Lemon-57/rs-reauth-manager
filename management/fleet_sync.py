"""Add verified fleet-pool imports to the unchanged incremental sync engines."""
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import urllib.parse

from fleet_slots import RemoteAllocator


def collect(rows, backend, configuration):
    pool_host = configuration['slots'].get('proxyHost', configuration['slots']['host'])
    candidates = [row for row in rows if urllib.parse.urlsplit(
        row.get('outboundProxyEndpoint') or '').hostname == pool_host]
    if not candidates:
        return {}, {}
    allocator = RemoteAllocator(configuration['slots'])
    registered = {entry['account_id']: entry for entry in allocator.rows()}
    history = allocator.use_history()['entries']
    mappings, registry = {}, {}
    for row in candidates:
        entry = registered.get(row['id'])
        if (not entry or ipaddress.ip_address(entry['ipv6']).version != 6
                or history[entry['ipv6']].get('account_id') != row['id']
                or history[entry['ipv6']].get('retired') is not False):
            raise ValueError('Independent IPv6 import ownership mismatch')
        document = backend('/api/admin/accounts/export?' + urllib.parse.urlencode(
            {'accountIds': row['id'], 'confirm': 'export_sensitive_accounts'}))
        documents = document['documents']
        if (len(documents) != 1 or documents[0]['provider'] != 'openai'
                or len(documents[0]['document']['accounts']) != 1):
            raise ValueError('Import projection export incomplete')
        saved = documents[0]['document']['accounts'][0]
        if saved['id'] != row['id'] or not hmac.compare_digest(
                saved['outboundProxyUrl'].rstrip('/'), allocator.url(entry)):
            raise ValueError('Import projection fixed authentication mismatch')
        mid = 'acct_' + hashlib.sha256(('rs:' + row['id']).encode()).hexdigest()[:24]
        mappings[row['id']] = {'original_rs_id': row['id'], 'target_rs_id': row['id'],
            'management_id': mid, 'email': row['email'], 'user_id': row['userId'],
            'workspace_id': row['accountId']}
        registry[mid] = {**entry, 'management_id': mid, 'rs_account_id': row['id'],
            'email': row['email'], 'user_id': row['userId'], 'exit_ip': entry['ipv6'],
            '_fleet_unique': True}
    return mappings, registry


def install_routes(registry_provider):
    import native_proxy_policy
    import sync_direct
    previous_validation = native_proxy_policy.validate_binding
    previous_targets = sync_direct.build_targets

    def validate(wanted, registry):
        entry = registry.get(wanted['management_id'])
        if entry and entry.get('_fleet_unique'):
            if not hmac.compare_digest(wanted['proxy'].rstrip('/'), RemoteAllocator.url(entry)):
                raise ValueError('Independent import proxy authentication mismatch')
            return entry
        return previous_validation(wanted, registry)

    def targets(desired, known):
        remaining = {}
        registry = registry_provider()
        for mid, row in desired.items():
            if registry.get(mid, {}).get('_fleet_unique'):
                validate(row, registry)
            else:
                remaining[mid] = row
        return previous_targets(remaining, known)

    native_proxy_policy.validate_binding = validate
    sync_direct.build_targets = targets


def retain_destination_ids(previous, mappings, registry):
    """Reimports retain an already-bound Chat2API identity and its counters."""
    for source_id, mapping in mappings.items():
        old = previous.get(source_id)
        if old is None:
            continue
        if (old['email'].casefold(), old['user_id'], old['workspace_id']) != (
                mapping['email'].casefold(), mapping['user_id'], mapping['workspace_id']):
            raise ValueError('Existing synchronization identity changed')
        fresh_mid = mapping['management_id']
        entry = registry.pop(fresh_mid)
        mappings[source_id] = dict(old)
        registry[old['management_id']] = dict(entry, management_id=old['management_id'])
    return mappings, registry
