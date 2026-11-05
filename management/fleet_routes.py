"""Persist only this deployment's new-connection routes; never flush conntrack."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.request


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError('Route operation failed; original diagnostic content withheld')
    return result.stdout


def exists(family, name):
    return subprocess.run(['nft', 'list', 'table', family, name], capture_output=True).returncode == 0


def tables(config):
    port = int(config['managementPort'])
    ports = config['legacyPorts']
    if port in ports or not all(type(value) is int and 1 <= value <= 65535 for value in [port, *ports]):
        raise ValueError('Management route would loop')
    selected = ', '.join(map(str, ports))
    rules = 'table ip rs_fleet_import { chain output { type nat hook output priority -150; policy accept; '
    rules += 'ip daddr 127.0.0.1 tcp dport { ' + selected + ' } redirect to :' + str(port) + '; '
    private = config.get('privateManagement')
    if private:
        host = str(ipaddress.IPv4Address(private['host']))
        source = ', '.join(str(ipaddress.IPv4Address(ip)) for ip in private['sources'])
        native = ', '.join(str(int(p)) for p in private['ports'])
        rules += 'ip daddr ' + host + ' tcp dport { ' + native + ' } dnat to ' + host + ':' + str(port) + '; '
    rules += '} '
    if private:
        rules += 'chain prerouting { type nat hook prerouting priority -150; policy accept; iifname "' + private['interface'] + '" ip saddr { ' + source + ' } ip daddr ' + host + ' tcp dport { ' + native + ' } dnat to ' + host + ':' + str(port) + '; } '
    rules += '}\n'
    rules = rules.replace('; } ', '; }\n')
    result = [('ip', 'rs_fleet_import', rules)]
    frontend = config.get('frontend')
    if frontend:
        iface = frontend['interface']
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', iface):
            raise ValueError('Invalid interface')
        http_port, https_port = int(frontend['httpPort']), int(frontend['httpsPort'])
        body = 'table inet rs_fleet_frontend { chain prerouting { type nat hook prerouting priority -150; policy accept; '
        body += 'iifname "' + iface + '" tcp dport 80 redirect to :' + str(http_port) + '; '
        body += 'iifname "' + iface + '" tcp dport 443 redirect to :' + str(https_port) + '; } '
        body += 'chain output { type nat hook output priority -150; policy accept; '
        for family, values in [('ip', frontend['ipv4']), ('ip6', frontend['ipv6'])]:
            addresses = ', '.join(str(ipaddress.ip_address(value)) for value in values)
            if addresses:
                body += family + ' daddr { ' + addresses + ' } tcp dport 80 redirect to :' + str(http_port) + '; '
                body += family + ' daddr { ' + addresses + ' } tcp dport 443 redirect to :' + str(https_port) + '; '
        body += '} }\n'
        body = body.replace('; } ', '; }\n')
        result.append(('inet', 'rs_fleet_frontend', body))
        guard = 'table inet rs_fleet_ingress_access { chain input { type filter hook input priority -310; policy accept; iifname "lo" return; tcp dport { ' + str(http_port) + ', ' + str(https_port) + ' } ct original proto-dst { 80, 443 } return; tcp dport { ' + str(http_port) + ', ' + str(https_port) + ' } drop; } }\n'
        guard = guard.replace('; } ', '; }\n')
        result.append(('inet', 'rs_fleet_ingress_access', guard))
    return result


def private_access(config, rollback=False):
    private = config.get('privateManagement')
    if not private:
        return ''
    table, chain = private['guardTable'], private['guardChain']
    if not all(re.fullmatch(r'[a-zA-Z0-9_]+', item) for item in [table, chain]):
        raise ValueError('Invalid guard chain')
    document = json.loads(run(['nft', '-j', 'list', 'chain', 'inet', table, chain]))
    comments = {'fleet-native-slot-control', 'fleet-native-import-entry'}
    result = ''.join('delete rule inet ' + table + ' ' + chain + ' handle ' + str(item['rule']['handle']) + '\n'
        for item in document['nftables'] if item.get('rule', {}).get('comment') in comments)
    if rollback:
        return result
    for port, peers, comment in [(config['poolPort'], private['poolSources'], 'fleet-native-slot-control'),
                                (config['managementPort'], private['sources'], 'fleet-native-import-entry')]:
        result += 'insert rule inet ' + table + ' ' + chain + ' iifname "' + private['interface'] + '" ip saddr { ' + ', '.join(str(ipaddress.IPv4Address(ip)) for ip in peers) + ' } ip daddr ' + str(ipaddress.IPv4Address(private['host'])) + ' tcp dport ' + str(int(port)) + ' accept comment "' + comment + '"\n'
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', required=True, type=Path)
    parser.add_argument('--mode', choices=['check', 'apply', 'rollback'], required=True)
    args = parser.parse_args()
    config = json.loads(args.configuration.read_text())
    if args.mode == 'apply':
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(60):
            try:
                with opener.open('http://127.0.0.1:' + str(config['managementPort']) + '/healthz', timeout=2) as response:
                    assert json.load(response)['freshIndependentIPv6']
                break
            except (OSError, ValueError, AssertionError):
                if attempt == 59:
                    raise RuntimeError('Candidate management is not ready') from None
                time.sleep(.5)
    transaction = ''
    definitions = tables(config)
    for family, name, body in definitions:
        if exists(family, name):
            transaction += 'delete table ' + family + ' ' + name + '\n'
        if args.mode != 'rollback':
            transaction += body
    transaction += private_access(config, args.mode == 'rollback')
    path = args.configuration.with_name('route-transaction.nft')
    path.write_text(transaction)
    run(['nft', '-c', '-f', str(path)])
    if args.mode != 'check':
        run(['nft', '-f', str(path)])
    print(json.dumps({'mode': args.mode, 'syntaxVerified': True,
                     'onlyNewConnections': True, 'conntrackFlushed': False,
                     'managedTables': [name for _, name, _ in definitions]}))


if __name__ == '__main__':
    main()
