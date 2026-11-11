"""Exact owned source extent does not upgrade independent chain semantics."""
import copy
import unittest
from unittest.mock import patch
from macscope import callback_twohop, focused, terminal
import test_terminal_linker_boundary as native_shape


class SourceBoundaryTests(unittest.TestCase):
    def report(self, raw=None):
        raw=raw or native_shape.fixture()
        outer={'source_envelope_sha256':'a'*64,
               'selection':{'start_va':'0x1210','end_va':'0x1214'},
               'sites':[{'kind':'direct_branch','instruction_va':'0x1210',
                         'instruction_bytes':raw[0x210:0x214].hex(),'target_va':'0x1200'}],
               'stop_reason':'direct_transfer_boundary','gaps':[{'reason':'direct_transfer_boundary'}]}
        link={'status':'verified_direct_entry_link','destination_selection':{'start_va':'0x1200'}}
        return raw,outer,link

    def result(self, raw=None, mutate=lambda o,l:None):
        raw,outer,link=self.report(raw);mutate(outer,link)
        before=copy.deepcopy(outer)
        result=callback_twohop.source_boundary(raw,{'arch':'arm64','offset':'0x0'},outer,link)
        self.assertEqual(before,outer)
        return result

    def test_terminal_exact_proof_and_receipt_binding(self):
        r=self.result();self.assertEqual(r['status'],'verified_complete_selected_thunk')
        self.assertEqual(r['basis'],'terminal_linker_branch')
        self.assertEqual(r['source_envelope_sha256'],'a'*64)
        self.assertEqual(r['extent']['boundary']['source_bytes'],'fcffff17')
        self.assertEqual(r['extent']['boundary']['target_va'],r['target_va'])
        self.assertEqual(r['extent']['end_va_exclusive'],r['selection']['end_va'])

    def test_ordinary_exact_next_linker_extent(self):
        raw=native_shape.fixture(section_size=0x18,stream=bytes.fromhex('8004100400'))
        r=self.result(raw);self.assertEqual(r['status'],'verified_complete_selected_thunk')
        self.assertEqual(r['basis'],'next_linker_start');self.assertNotIn('boundary',r['extent'])

    def test_padded_last_and_longer_ordinary_extent_not_promoted(self):
        self.assertEqual(self.result(native_shape.fixture(section_size=0x18))['status'],'gap')
        r=self.result(native_shape.fixture(section_size=0x1c,stream=bytes.fromhex('8004100800')))
        self.assertEqual(r['reason'],'selection_is_not_complete_source_extent')

    def test_partial_wrong_target_wrong_bytes_nonbranch_rejected(self):
        mutations=[lambda o,l:o['gaps'].append({'reason':'disassembly_incomplete'}),
                   lambda o,l:l.update(status='gap'),
                   lambda o,l:l['destination_selection'].update(start_va='0x1204'),
                   lambda o,l:o['sites'][0].update(instruction_bytes='fdffff17'),
                   lambda o,l:o['sites'][0].update(instruction_va='0x120c'),
                   lambda o,l:o['sites'][0].update(kind='direct_call'),
                   lambda o,l:(o['sites'][0].update(target_va='0x1204'),l['destination_selection'].update(start_va='0x1204'))]
        for mutate in mutations:
            with self.subTest(mutate=mutate):self.assertEqual(self.result(mutate=mutate)['status'],'gap')

    def test_malformed_mapping_failure_is_scoped(self):
        from macscope.errors import Error
        with patch.object(focused,'extent',side_effect=Error('focused_terminal_mapping','bad',3)):
            r=self.result();self.assertEqual(r['reason'],'source_boundary_unavailable')
            self.assertEqual(r['extent_error'],'focused_terminal_mapping')
