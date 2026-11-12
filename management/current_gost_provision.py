"""Validate a reserved immutable slot against the effective managed GOST data plane."""
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import time
import urllib.parse
import urllib.request

FIELDS = ('host', 'port', 'username', 'password', 'ipv6', 'family')


def provisioner(allocator, configuration, run):
    config = json.loads(Path(configuration).read_text())
    api = urllib.parse.urlsplit(config['api_url'])
    if api.scheme != 'http' or api.hostname != '127.0.0.1' or not api.port or api.username:
        raise ValueError('managed_gost_api')
    private = Path(config['root']) / 'private'
    credentials = json.loads((private / 'api-auth.json').read_text())
    authorization = 'Basic ' + base64.b64encode((credentials['username'] + ':' + credentials['password']).encode()).decode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def provision(entry):
        expected = allocator.slots().get(entry['port'])
        if expected is None or any(expected[key] != entry[key] for key in FIELDS):
            raise ValueError('immutable_slot_mismatch')
        history = allocator.use_history()['entries'][entry['ipv6']]
        if history['retired'] or history.get('reservation_hash') != hashlib.sha256(entry['key'].encode()).hexdigest():
            raise ValueError('permanent_reservation_mismatch')
        target = (private / 'container.id').read_text().strip() if (private / 'container.id').exists() else config['container']
        container = json.loads(run(config['docker'] + ['inspect', target]))[0]
        if not container['State']['Running'] or container['State']['OOMKilled']:
            raise ValueError('managed_gost_unavailable')
        identity = hashlib.sha256(json.dumps({key: entry[key] for key in FIELDS}, sort_keys=True).encode()).hexdigest()
        name = 'exit-' + str(entry['port']) + '-' + identity[:12]
        request = urllib.request.Request(config['api_url'] + '/config', headers={'Authorization': authorization})
        with opener.open(request, timeout=5) as response:
            services = json.load(response)['services']
        service = next((service for service in services if service['name'] == name), None)
        if (service is None or service.get('status', {}).get('state') != 'ready'
                or service.get('addr') != '10.77.18.1:' + str(entry['port'] + config['offset'])
                or service.get('interface') != entry['ipv6']
                or service.get('handler', {}).get('type') != 'http'
                or service.get('handler', {}).get('auther') != name
                or service.get('listener', {}).get('type') != 'tcp' or service.get('climiter') != name):
            raise ValueError('managed_gost_slot_not_ready')
        addresses = json.loads(run(['ip', '-j', '-6', 'addr', 'show', 'dev', 'eth0']))[0]['addr_info']
        address = next((item for item in addresses if item['local'] == str(ipaddress.IPv6Address(entry['ipv6']))), None)
        if address is None:
            before = json.loads(run(['ip', '-j', '-6', 'route', 'get', '2606:4700:4700::1111']))[0]['prefsrc']
            prior = next((item for item in addresses if item['local'] == before), None)
            if not prior or prior.get('deprecated') or 'deprecated' in prior.get('flags', []):
                raise ValueError('default_ipv6_source_not_preferred')
            # Explicitly bound GOST traffic can use this address. Keeping it
            # deprecated prevents changing the host's automatic source choice.
            run(['ip', '-6', 'addr', 'add', entry['ipv6'] + '/64', 'dev', 'eth0',
                 'preferred_lft', '0', 'valid_lft', 'forever'])
            deadline = time.monotonic() + 6
            while True:
                rows = json.loads(run(['ip', '-j', '-6', 'addr', 'show', 'dev', 'eth0']))[0]['addr_info']
                address = next((item for item in rows if item['local'] == entry['ipv6']), None)
                if address and not address.get('tentative') and 'tentative' not in address.get('flags', []):
                    break
                if time.monotonic() > deadline:
                    raise ValueError('managed_ipv6_dad_timeout')
                time.sleep(.2)
            after = json.loads(run(['ip', '-j', '-6', 'route', 'get', '2606:4700:4700::1111']))[0]['prefsrc']
            if after != before:
                raise ValueError('default_ipv6_source_changed')
        if not address or address.get('dadfailed') or address.get('tentative') or 'tentative' in address.get('flags', []):
            raise ValueError('managed_ipv6_not_ready')
    return provision
