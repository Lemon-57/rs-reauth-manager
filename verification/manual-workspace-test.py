"""Exercise existing-account workspace selection on an offline OAuth flow."""

import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from requests.cookies import RequestsCookieJar

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol'))
import runner
from vendor.lib import chatgpt_client, oauth_client


class ManualWorkspaceTests(unittest.TestCase):
    def test_selection_and_callback(self):
        callback = 'http://127.0.0.1:1455/auth/callback'
        consent = 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent'
        authorization = 'https://auth.openai.com/oauth/authorize?' + urlencode({
            'state': 'fixture', 'client_id': 'fixture', 'redirect_uri': callback,
            'response_type': 'code', 'code_challenge': 'a' * 43, 'code_challenge_method': 'S256',
        })
        for case, available, active, automatic, expected in [
            ('same workspace', ['previous', 'new'], 'new', False, 'previous'),
            ('unique replacement', ['new'], None, False, 'new'),
            ('explicit active workspace', ['new', 'other'], 'new', False, 'new'),
            ('ambiguous', ['new', 'other'], None, False, None),
            ('not selectable', ['new', 'other'], 'outside', False, None),
            ('automatic ambiguity unchanged', ['new', 'other'], 'new', True, None),
            ('two teams with explicit selection', ['new', 'other'], 'new', False, 'new'),
            ('two teams with no selection', ['new', 'other'], None, False, None),
        ]:
            with self.subTest(case=case):
                selections, messages = [], []
                choices = [{'id': workspace} for workspace in available]
                if case.startswith('two teams'):
                    for choice in choices:
                        choice['kind'] = 'organization'
                cookie = {'workspaces': choices, 'workspace_id': active}

                class Session:
                    def __init__(self):
                        self.headers = {}
                        self.cookies = RequestsCookieJar()
                        self.cookies.set('oai-client-auth-session', json.dumps(cookie), domain='auth.openai.com')

                    def close(self):
                        pass

                    def request(self, method, url, **kwargs):
                        if method == 'GET' and url == authorization:
                            return SimpleNamespace(status_code=302, url=url, headers={'Location': consent}, text='')
                        if method == 'GET' and url == consent:
                            return SimpleNamespace(status_code=200, url=url, headers={}, text=json.dumps({'workspaces': choices}))
                        if method == 'POST' and url.endswith('/workspace/select'):
                            selections.append(kwargs['json']['workspace_id'])
                            return SimpleNamespace(status_code=302, url=url, headers={'Location': callback+'?state=fixture&code=fixture-code'}, text='')
                        raise AssertionError('Unexpected offline OAuth request')

                data = {
                    'email': 'fixture@example.com', 'notes': 'fixture@example.com----fixture-password----GEZDGNBVGY3TQOJQ',
                    'proxy': 'http://127.0.0.1:21001', 'authorizationUrl': authorization,
                    'accountId': 'previous', 'userId': 'fixture-user', 'planType': 'free',
                    'acceptCurrentProfile': True, 'automatic': automatic,
                }
                with (
                    patch.object(chatgpt_client, 'create_http_session', side_effect=lambda **kwargs: Session()),
                    patch.object(oauth_client, 'create_http_session', side_effect=lambda **kwargs: Session()),
                    patch.object(socket, 'create_connection', side_effect=AssertionError('Network forbidden')),
                    patch.object(runner, 'emit', side_effect=lambda event, **fields: messages.append({'event': event, **fields})),
                ):
                    runner.run(data)
                if expected is None:
                    self.assertEqual(selections, [])
                    self.assertEqual(messages[-1]['code'], 'workspace')
                else:
                    self.assertEqual(selections, [expected])
                    self.assertEqual(messages[-1]['event'], 'complete')
                    self.assertEqual(messages[-1]['callbackUrl'], callback+'?state=fixture&code=fixture-code')
                    self.assertNotIn('tokens', messages[-1])
                    if expected != 'previous':
                        self.assertEqual(messages[-1]['workspaceId'], expected)


if __name__ == '__main__':
    unittest.main()
