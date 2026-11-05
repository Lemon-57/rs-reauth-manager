"""Cold-start the delivered entry point and inspect its live loaded-code evidence."""
import hashlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest


class Tests(unittest.TestCase):
    def test_actual_entry_point_starts_and_reports_loaded_module_hashes(self):
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0))
                port = reserve.getsockname()[1]
            configuration = {'origin': 'https://fixture.example.invalid', 'port': port,
                'gatewayPort': 1, 'stateRoot': str(path / 'state'),
                'slots': {'host': '127.0.0.1', 'port': 1, 'site': 'fixture', 'keyFile': str(path / 'fixture.key')}}
            (path / 'site.json').write_text(json.dumps(configuration))
            process = subprocess.Popen([sys.executable, '-B', str(root / 'fleet_import_service.py'),
                '--configuration', str(path / 'site.json')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    self.assertIsNone(process.poll(), 'Delivered service exited before becoming ready')
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=.5)
                    try:
                        connection.request('GET', '/healthz')
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.getheader('X-RS-Import-Policy'), 'fresh-ipv6-gpt-pro-0.1.68')
                        value = json.load(response)
                        self.assertTrue(value['freshIndependentIPv6'])
                        for name, digest in value['loadedSourceSha256'].items():
                            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)
                        break
                    except (ConnectionError, OSError):
                        time.sleep(.05)
                    finally:
                        connection.close()
                else:
                    self.fail('Delivered service did not become ready')
            finally:
                if process.poll() is None:
                    process.terminate()
                process.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
