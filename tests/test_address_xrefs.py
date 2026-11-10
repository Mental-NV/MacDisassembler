from unittest.mock import patch

from macscope import address_xrefs, cli, engine, storage
from test_core import TemporaryCase, synthetic_snapshot


class AddressReferenceTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.workspace = self.project()
        self.snapshot, self.record = synthetic_snapshot(self.workspace)

    def args(self, *words):
        return cli.parser().parse_args(['xrefs', '--project', str(self.workspace.path), *words])

    def query(self, *words):
        with patch.object(storage.Project, 'snapshot', return_value=(self.snapshot, self.record)), \
                patch.object(engine, 'dependencies') as dependencies:
            result = cli.execute(self.args(*words))
            dependencies.assert_not_called()
        return result

    def index(self, refs=(), computed=()):
        raw = self.snapshot['engine']
        for key, rows in ((address_xrefs.REFERENCES, refs), (address_xrefs.COMPUTED, computed)):
            raw[key] = list(rows)
            raw['coverage'][key] = {'status': 'complete', 'emitted': len(rows)}

    def test_global_data_reference_and_empty_result_are_complete(self):
        ref = {'from': '0x200', 'to': '0x100', 'type': 'DATA', 'source': 'ANALYSIS'}
        self.index([ref])
        for direction, va in (('to', '0x100'), ('from', '0x200')):
            result = self.query('--' + direction, va)
            self.assertEqual(result['status'], 'complete')
            self.assertEqual(result['data']['references'], [dict(ref, evidence='ghidra_reference',
                                                                  target_status='recorded')])
        self.assertEqual(self.query('--to', '0x300')['coverage']['known_total'], 0)

    def test_computed_flow_distinguishes_hints_and_missing_targets_from_data(self):
        call = {'from': '0x20', 'to': '0x100', 'type': 'UNCONDITIONAL_CALL'}
        read = {'from': '0x30', 'to': '0x200', 'type': 'READ'}
        self.index([call, read], [{'addr': '0x20', 'flow': 'COMPUTED_CALL'},
                                  {'addr': '0x30', 'flow': 'COMPUTED_JUMP'}])
        hint, = self.query('--to', '0x100')['data']['references']
        self.assertEqual(hint['target_status'], 'indirect_or_inferred')
        result = self.query('--from', '0x30')
        first, last = result['data']['references']
        self.assertEqual(first['target_status'], 'recorded')
        self.assertEqual(last['target_status'], 'unresolved')
        self.assertEqual(last['evidence'], 'ghidra_instruction')
        self.assertIsNone(last['to'])
        self.assertEqual(result['data']['gaps'], ['unresolved_computed_target'])

    def test_legacy_and_budget_limited_index_reuse_available_function_evidence(self):
        ref = {'from': '0x100000000', 'to': '0x100000010', 'type': 'UNCONDITIONAL_CALL'}
        caller, callee, _ = self.snapshot['functions']
        caller['xrefs_from_sample'].append(ref)
        callee['xrefs_to_entry'].append(ref)
        legacy = self.query('--to', ref['to'])
        self.assertIn('image_reference_index_unavailable', legacy['data']['gaps'])
        self.assertEqual(legacy['coverage']['returned_count'], 1)
        self.index([ref])
        self.assertTrue(address_xrefs.omit_for_snapshot_budget(self.snapshot))
        limited = self.query('--to', ref['to'])
        self.assertEqual(limited['data']['references'], legacy['data']['references'])
        self.assertIn('image_reference_index_incomplete', limited['data']['gaps'])
        self.assertEqual(self.snapshot['status'], 'partial')

    def test_address_pages_bind_to_direction_and_selector_and_keep_function_default(self):
        self.index([{'from': va, 'to': '0x80', 'type': 'DATA'} for va in ('0x22', '0x100', '0x4')])
        first = self.query('--to', '0x80', '--limit', '1')
        cursor = first['coverage']['next_cursor']
        second = self.query('--to', '0x080', '--cursor', cursor)
        rows = first['data']['references'] + second['data']['references']
        self.assertEqual([row['from'] for row in rows], ['0x4', '0x22', '0x100'])
        self.error('stale_cursor', self.query, '--from', '0x80', '--cursor', cursor)
        self.error('xref_scope', self.query, '--from', '0x80', '--direction', 'to')
        self.assertEqual(self.query('--name', 'unique', '--limit', '1')['coverage']['known_total'], 0)
        self.error('address', self.query, '--to', '80')
        self.error('usage', self.args, '--to', '0x1', '--from', '0x2')
        self.assertEqual(set(self.query('--name', 'unique')['data']), {'function_id', 'to_entry', 'from_body'})

    def test_truncated_function_samples_recover_exact_disjoint_body_and_entry_pages(self):
        function = self.snapshot['functions'][0]
        start = function['entry_va']
        selected = ['0x100000003', '0x100000006', '0x100000009']
        outgoing = [{'from': va, 'to': '0x10', 'type': 'DATA'} for va in selected]
        incoming = [{'from': '0x80', 'to': start, 'type': 'DATA'}]
        outside = {'from': '0x100000004', 'to': '0x10', 'type': 'DATA'}
        self.index([outside, *reversed(outgoing), *incoming])
        function.update(body_ranges=[[start, selected[0]], [selected[1], selected[2]]],
                        coverage={'body_ranges': {'status': 'complete', 'emitted': 2}},
                        xrefs_from_truncated=True, xrefs_from_sample=outgoing[:1], xrefs_to_entry_truncated=True)
        selector = ('--function-id', function['function_id'])
        result = self.query(*selector)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['data']['from_body'], outgoing)
        self.assertEqual(result['data']['to_entry'], incoming)
        self.assertEqual(result['data']['reference_sources'],
                         {'from_body': 'image_reference_index', 'to_entry': 'image_reference_index'})
        page = self.query(*selector, '--limit', '2')
        self.assertEqual(page['data']['from_body'], outgoing[:1])
        self.assertEqual(page['data']['to_entry'], incoming)
        self.assertEqual(page['coverage']['known_total'], 4)
        cursor = page['coverage']['next_cursor']
        next_page = self.query(*selector, '--limit', '2', '--cursor', cursor)
        self.assertEqual(next_page['data']['from_body'], outgoing[1:])
        self.assertEqual(next_page['data']['to_entry'], [])
        self.error('stale_cursor', self.query, *selector, '--direction', 'from', '--cursor', cursor)

        function['coverage']['body_ranges']['status'] = 'partial'
        self.assertEqual(self.query(*selector)['data']['from_body'], outgoing[:1])
        function['coverage']['body_ranges']['status'] = 'complete'
        function['xrefs_from_sample'] = [outside]
        mismatch = self.query(*selector)
        self.assertEqual(mismatch['data']['from_body'], [outside])
        self.assertEqual(mismatch['coverage']['truncation_reason'], 'xrefs_from_incomplete')
        function['xrefs_from_sample'] = outgoing[:1]
        self.index([*incoming, outgoing[0]])
        self.assertEqual(self.query(*selector)['coverage']['truncation_reason'], 'xrefs_from_incomplete')
        self.index([*incoming, *outgoing])
        self.snapshot['engine']['coverage'][address_xrefs.REFERENCES]['truncated'] = True
        self.assertEqual(self.query(*selector)['data']['from_body'], outgoing[:1])
