import sys
import unittest
import importlib.util
import tempfile
import uuid
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'protocol'))
from fallback import free_workspace_candidate,new_account_workspace_candidate,team_candidate


class PaidOnboardingTests(unittest.TestCase):
    def test_business_prolite_is_a_team_candidate_and_never_personal(self):
        for kind in [{}, {'kind': 'organization'}]:
            evidence = {'workspaces': [{'id': 'business-team', 'plan_type': 'self_serve_business_prolite', **kind}]}
            self.assertEqual(team_candidate(evidence, ''), 'business-team')
            with self.assertRaisesRegex(ValueError, 'free_workspace_missing'):
                new_account_workspace_candidate(evidence, '')
        with self.assertRaisesRegex(ValueError, '^workspace$'):
            team_candidate({'workspaces': [{'id': 'one', 'plan_type': 'self_serve_business_prolite'},
                                          {'id': 'two', 'plan_type': 'team'}]}, '')

    def test_native_start_uses_exact_email_for_each_protected_adapter(self):
        root = Path(__file__).resolve().parents[1]
        for filename in ['fixed_pool_onboarding.py', 'onboarding_service.py']:
            spec = importlib.util.spec_from_file_location('test_adapter', root/'management'/filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for email in ['person@example.invalid', 'team+person@example.invalid']:
                with self.subTest(adapter=filename, email=email), tempfile.TemporaryDirectory() as temporary:
                    calls = []
                    entry = {'username':'fixture', 'password':'fixture', 'host':'127.0.0.1', 'port':21001}
                    flow = {'flowId':'fixture-flow', 'authorizationUrl':'https://example.invalid/authorize'}
                    if filename == 'fixed_pool_onboarding.py':
                        adapter = object.__new__(module.Adapter)
                        adapter.directory = lambda *_: []
                        adapter.reserve = lambda *_: (Path(temporary)/'receipt.json', {}, entry)
                        adapter.verify_exit = lambda *_: None
                        def backend(path, headers, body):
                            calls.append(body)
                            return flow
                        adapter.backend = backend
                        adapter.start({}, {'email':email, 'requestId':str(uuid.uuid4())})
                    else:
                        allocator = SimpleNamespace(get_flow=lambda _: (entry, None), owner=lambda _: None,
                                                    url=lambda _: 'http://fixture:fixture@127.0.0.1:21001')
                        adapter = module.Adapter(allocator, 18135, 18118, state_dir=temporary)
                        def send(port, path, headers, body=None, **kwargs):
                            if path.startswith('/api/admin/accounts?'):
                                return 200, {'code':200, 'data':{'items':[]}}
                            self.assertEqual(path, '/api/admin/accounts/oauth/start')
                            calls.append(body)
                            return 201, {'code':200, 'data':flow}
                        with patch.object(module, 'send', send):
                            status, _ = adapter.call('/_management/onboarding/start', {},
                                                     {'email':email, 'requestId':str(uuid.uuid4())})
                            self.assertEqual(status, 200)
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0]['name'], email)
                    self.assertEqual(calls[0]['provider'], 'openai')

    def test_unique_prolite_workspace_is_available_to_new_account_flow(self):
        evidence={'workspaces':[{'id':'personal-pro','is_personal':True,'plan_type':'prolite'}]}
        self.assertEqual(new_account_workspace_candidate(evidence,''),'personal-pro')
        with self.assertRaisesRegex(ValueError,'free_workspace_missing'):
            free_workspace_candidate(evidence,'')

    def test_paid_selection_rejects_multiple_personal_workspaces(self):
        evidence={'workspaces':[{'id':'one','plan_type':'pro'},{'id':'two','plan_type':'prolite'}]}
        with self.assertRaisesRegex(ValueError,'free_workspace_ambiguous'):
            new_account_workspace_candidate(evidence,'')

    def test_organization_cannot_be_misclassified_as_paid_personal(self):
        for evidence in [
            {'workspaces':[{'id':'team','kind':'organization','plan_type':'prolite'}]},
            {'workspaces':[{'id':'team','is_personal':False,'plan_type':'pro'}]},
        ]:
            with self.assertRaisesRegex(ValueError,'free_workspace_missing'):
                new_account_workspace_candidate(evidence,'')


if __name__=='__main__':
    unittest.main()
