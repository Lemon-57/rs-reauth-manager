import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from current_gost_provision import FIELDS, provisioner


class CurrentProvisionTests(unittest.TestCase):
    def test_current_listener_is_accepted_while_wrong_identity_and_retirement_are_rejected(self):
        entry = {'host': '10.77.18.1', 'port': 25001, 'username': 'fixture-user', 'password': 'fixture-password', 'ipv6': '2001:db8::1', 'family': 6, 'key': 'fixture-reservation'}
        history = {'retired': False, 'reservation_hash': hashlib.sha256(entry['key'].encode()).hexdigest()}

        class Allocator:
            def slots(self):
                return {entry['port']: entry}

            def use_history(self):
                return {'entries': {entry['ipv6']: history}}

        name = 'exit-25001-' + hashlib.sha256(json.dumps({key: entry[key] for key in FIELDS}, sort_keys=True).encode()).hexdigest()[:12]
        service = {'name': name, 'addr': '10.77.18.1:11001', 'interface': entry['ipv6'], 'handler': {'type': 'http', 'auther': name}, 'listener': {'type': 'tcp'}, 'climiter': name, 'status': {'state': 'ready'}}

        class Opener:
            def open(self, request, timeout):
                return io.StringIO(json.dumps({'services': [service]}))

        addresses = [{'local': entry['ipv6'], 'flags': []}]
        added = []

        def run(args):
            if args[0] == 'docker':
                return json.dumps([{'State': {'Running': True, 'OOMKilled': False}}])
            if 'route' in args:
                return json.dumps([{'prefsrc': '2001:db8::10'}])
            if 'add' in args:
                self.assertEqual(args[args.index('preferred_lft') + 1], '0')
                addresses.append({'local': entry['ipv6'], 'flags': ['deprecated']})
                added.append(entry['ipv6'])
                return ''
            return json.dumps([{'addr_info': addresses}])

        with tempfile.TemporaryDirectory() as directory, patch('urllib.request.build_opener', return_value=Opener()):
            root = Path(directory)
            (root / 'private').mkdir()
            (root / 'private/api-auth.json').write_text(json.dumps({'username': 'fixture', 'password': 'fixture'}))
            configuration = root / 'manager.json'
            configuration.write_text(json.dumps({'root': directory, 'api_url': 'http://127.0.0.1:19592', 'container': 'current-gost', 'docker': ['docker'], 'offset': -14000}))
            verify = provisioner(Allocator(), configuration, run)
            verify(entry)
            addresses[:] = [{'local': '2001:db8::10', 'flags': []}]
            verify(entry)
            self.assertEqual(added, [entry['ipv6']])
            service['interface'] = '2001:db8::2'
            with self.assertRaisesRegex(ValueError, 'slot_not_ready'):
                verify(entry)
            service['interface'] = entry['ipv6']
            history['retired'] = True
            with self.assertRaisesRegex(ValueError, 'reservation_mismatch'):
                verify(entry)


if __name__ == '__main__':
    unittest.main()
