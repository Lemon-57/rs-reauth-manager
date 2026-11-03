import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'protocol'))
from fallback import free_workspace_candidate,new_account_workspace_candidate


class PaidOnboardingTests(unittest.TestCase):
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
