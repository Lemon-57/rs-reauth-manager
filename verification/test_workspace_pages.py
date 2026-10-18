"""Exact, bounded workspace evidence extraction with no JavaScript execution."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol'))
from workspace_pages import workspace_page

WID = '11111111-2222-3333-4444-555555555555'


class WorkspacePageTests(unittest.TestCase):
    def test_json_script_and_nested_workspace_keys(self):
        for data in [{'workspace_id': WID}, {'page': {'workspaceId': WID}}]:
            self.assertEqual(workspace_page('<script type="application/json">'+json.dumps(data)+'</script>'), {'workspaces': [{'id': WID}]})

    def test_double_encoded_router_stream(self):
        payload = json.dumps({'workspaces': [{'id': WID, 'is_personal': True, 'plan_type': 'free', 'name': 'private-name'}]})
        page = '<script>window.stream.enqueue('+json.dumps(payload)+');</script>'
        self.assertEqual(workspace_page(page), {'workspaces': [{'id': WID, 'is_personal': True, 'plan_type': 'free'}]})

    def test_flattened_router_id_pairs(self):
        page = '<script>window.stream.enqueue('+json.dumps(json.dumps(['workspaces', 'id', WID]))+');</script>'
        self.assertEqual(workspace_page(page), {'workspaces': [{'id': WID}]})

    def test_referenced_router_objects_retain_all_workspaces_and_metadata(self):
        table = [{'_1': 2}, 'workspaces', [3, 8], {'_4': 5, '_6': 7}, 'id', WID, 'type', 'team', {'_4': 9, '_6': 10}, 'second-personal', 'personal']
        page = '<script>window.stream.enqueue('+json.dumps(json.dumps(table))+');</script>'
        self.assertEqual(workspace_page(page), {'workspaces': [{'id': WID, 'type': 'team'}, {'id': 'second-personal', 'type': 'personal'}]})

    def test_invalid_or_cyclic_router_references_are_rejected(self):
        for table in [[{'_1': 2}, 'workspaces', [2]], [{'_1': 99}, 'workspaces']]:
            with self.subTest(table=table), self.assertRaisesRegex(ValueError, '^workspace_evidence_invalid$'):
                workspace_page(json.dumps(table))

    def test_literal_html_entities_in_script_json_are_not_unescaped(self):
        data = {'workspaces': [{'id': WID, 'name': 'literal &quot;private-name&quot;', 'type': 'personal'}]}
        self.assertEqual(workspace_page('<script>'+json.dumps(data)+'</script>'), {'workspaces': [{'id': WID, 'type': 'personal'}]})

    def test_json_parse_and_hydration_assignment(self):
        data = {'workspace_id': WID}
        for script in ['window.data = '+json.dumps(data)+';', 'window.data = JSON.parse('+json.dumps(json.dumps(data))+');']:
            self.assertEqual(workspace_page('<script>'+script+'</script>'), {'workspaces': [{'id': WID}]})

    def test_repeated_hydration_sources_are_deduplicated(self):
        data = json.dumps({'workspace_id': WID})
        self.assertEqual(workspace_page('<script>'+data+'</script><script>'+data+'</script>'), {'workspaces': [{'id': WID}]})

    def test_optional_null_fields_do_not_hide_a_valid_candidate(self):
        value = {'workspace_id': None, 'workspaces': [{'id': WID, 'kind': None, 'type': '', 'is_personal': True}]}
        self.assertEqual(workspace_page(json.dumps(value)), {'workspaces': [{'id': WID, 'is_personal': True}]})

    def test_different_ids_are_preserved_not_collapsed_to_first(self):
        value = workspace_page(json.dumps({'workspace_id': WID, 'nested': {'workspaceId': 'second-workspace'}}))
        self.assertEqual([w['id'] for w in value['workspaces']], [WID, 'second-workspace'])

    def test_bare_substring_or_unrelated_id_is_not_workspace_evidence(self):
        for page in [WID, '<div>'+WID+'</div>', json.dumps({'id': WID}), '<script>alert("'+WID+'")</script>']:
            self.assertEqual(workspace_page(page), {'workspaces': []})

    def test_serialized_json_in_unrelated_text_is_not_workspace_evidence(self):
        page = json.dumps({'message': json.dumps({'workspace_id': WID})})
        self.assertEqual(workspace_page(page), {'workspaces': []})

    def test_large_markup_does_not_exhaust_hydration_assignment_scan(self):
        page = '<div class="x">text</div>' * 100 + '<script>'+json.dumps({'workspace_id': WID})+'</script>'
        self.assertEqual(workspace_page(page), {'workspaces': [{'id': WID}]})

    def test_duplicate_conflicting_malformed_and_oversized_evidence_is_rejected(self):
        for data in [
            {'workspaces': [{'id': WID}, {'id': WID}]},
            {'workspaces': [{'id': WID, 'plan_type': 'free'}], 'other': {'workspaces': [{'id': WID, 'plan_type': 'team'}]}},
            {'workspaces': 17}, {'workspace_id': 'bad\nvalue'},
            {'workspaces': [{'id': str(i)} for i in range(31)]},
        ]:
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, '^workspace_evidence_invalid$'):
                workspace_page(json.dumps(data))

    def test_page_and_recursion_limits(self):
        with self.assertRaisesRegex(ValueError, '^workspace_evidence_invalid$'):
            workspace_page('x' * (2 * 1024 * 1024 + 1))
        value = {'workspace_id': WID}
        for _ in range(22):
            value = {'nested': value}
        with self.assertRaisesRegex(ValueError, '^workspace_evidence_invalid$'):
            workspace_page(json.dumps(value))


if __name__ == '__main__':
    unittest.main()
