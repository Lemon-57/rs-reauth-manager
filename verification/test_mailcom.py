import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol'))
from mailcom import MailcomClient, MailcomError, extract_code, mailbox_password  # noqa: E402


class MailcomHandler(BaseHTTPRequestHandler):
    messages = []
    requests = []
    status = 200
    response_code = 0
    response_message = 'ok'

    def log_message(self, *args):
        return

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = json.loads(self.rfile.read(length) or b'{}')
        type(self).requests.append({
            'path': self.path,
            'key': self.headers.get('X-Key'),
            'body': body,
        })
        payload = {
            'code': type(self).response_code,
            'msg': type(self).response_message,
            'data': {
                'username': body.get('email'),
                'cached': False,
                'correctPassword': body.get('password'),
                'type': body.get('type', 'inbox'),
                'count': len(type(self).messages),
                'emails': type(self).messages,
            },
        }
        raw = json.dumps(payload).encode()
        self.send_response(type(self).status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class MailcomTests(unittest.TestCase):
    def setUp(self):
        MailcomHandler.messages = []
        MailcomHandler.requests = []
        MailcomHandler.status = 200
        MailcomHandler.response_code = 0
        MailcomHandler.response_message = 'ok'
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), MailcomHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_four_field_mailbox_password_only(self):
        self.assertEqual(mailbox_password('a@gmx.com----gpt----mailbox----GEZDGNBVGY3TQOJQ', 'a@gmx.com'), 'mailbox')
        self.assertIsNone(mailbox_password('a@gmx.com----gpt----GEZDGNBVGY3TQOJQ', 'a@gmx.com'))
        self.assertIsNone(mailbox_password('b@gmx.com----gpt----mailbox----GEZDGNBVGY3TQOJQ', 'a@gmx.com'))

    def test_api_uses_header_key_and_extracts_verification_code(self):
        MailcomHandler.messages = [{
            'mailId': 'mail-1',
            'subject': 'Your OpenAI verification code',
            'sender': 'OpenAI <noreply@tm.openai.com>',
            'time': 'now',
            'folderId': 'inbox',
            'timestamp': 1,
            'isUnread': True,
            'content': '<html><body>Your verification code is <b>123456</b>.</body></html>',
        }]
        client = MailcomClient('a@gmx.com', 'mailbox-password', 'test-key', base_url=self.base)
        messages = client.messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(extract_code(messages[0]), '123456')
        self.assertEqual(MailcomHandler.requests[0]['path'], '/get')
        self.assertEqual(MailcomHandler.requests[0]['key'], 'test-key')
        self.assertEqual(MailcomHandler.requests[0]['body']['password'], 'mailbox-password')
        self.assertNotIn('correctPassword', json.dumps(messages))

    def test_wait_for_new_message_ignores_baseline(self):
        old = {
            'mailId': 'old',
            'subject': 'Your OpenAI verification code',
            'sender': 'OpenAI <noreply@tm.openai.com>',
            'timestamp': 1,
            'folderId': 'inbox',
            'content': 'Your verification code is 111111.',
        }
        new = {
            'mailId': 'new',
            'subject': 'Your OpenAI verification code',
            'sender': 'OpenAI <noreply@tm.openai.com>',
            'timestamp': 2,
            'folderId': 'inbox',
            'content': 'Your verification code is <span>222222</span>.',
        }
        MailcomHandler.messages = [old]
        client = MailcomClient('a@gmx.com', 'mailbox-password', 'test-key', base_url=self.base)
        baseline = client.snapshot_openai_message_ids()
        MailcomHandler.messages = [old, new]
        self.assertEqual(
            client.wait_for_new_verification_code(
                'a@gmx.com',
                timeout=2,
                exclude_codes={'111111'},
                exclude_message_ids=baseline,
            ),
            '222222',
        )

    def test_api_error_does_not_expose_password_or_key(self):
        MailcomHandler.status = 403
        MailcomHandler.response_code = 40001
        MailcomHandler.response_message = 'mailbox-password test-key'
        client = MailcomClient('a@gmx.com', 'mailbox-password', 'test-key', base_url=self.base)
        with self.assertRaises(MailcomError) as raised:
            client.messages()
        text = str(raised.exception) + json.dumps(raised.exception.diagnostic())
        self.assertNotIn('mailbox-password', text)
        self.assertNotIn('test-key', text)
        self.assertEqual(raised.exception.api_code, 40001)


if __name__ == '__main__':
    unittest.main()
