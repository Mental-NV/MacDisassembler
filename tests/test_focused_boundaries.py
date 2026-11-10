"""Owned instruction/CFG evidence for optimization-independent body checks."""
import copy
import unittest
from unittest.mock import patch

from macscope import flow_evidence, focused_boundaries as scope, focused_tailcalls


class FocusedBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.proof = {'entry_va':'0x1000','end_va_exclusive':'0x1010'}
        self.function = {
            'body_ranges':[['0x1000','0x100f']], 'decompile_status':'complete','pseudocode':'return 42;',
            'instructions':[
                {'addr':'0x1000','bytes':'210080d2','flow':'FALL_THROUGH','fallthrough':'0x1004'},
                {'addr':'0x1004','bytes':'410000b4','flow':'CONDITIONAL_JUMP','fallthrough':'0x1008'},
                {'addr':'0x1008','bytes':'03000014','flow':'UNCONDITIONAL_JUMP','fallthrough':None},
                {'addr':'0x100c','bytes':'c0035fd6','flow':'TERMINATOR','fallthrough':None}],
            'blocks':[
                {'min':'0x1000','max':'0x1007','flow':'CONDITIONAL_JUMP','edges_truncated':False,
                 'dsts':[{'from':'0x1004','to':'0x100c','flow':'CONDITIONAL_JUMP'},
                         {'from':'0x1004','to':'0x1008','flow':'FALL_THROUGH'}]},
                {'min':'0x1008','max':'0x100b','flow':'UNCONDITIONAL_JUMP','edges_truncated':False,
                 'dsts':[{'from':'0x1008','to':'0x1014','flow':'UNCONDITIONAL_JUMP'}]},
                {'min':'0x100c','max':'0x100f','flow':'TERMINATOR','edges_truncated':False,'dsts':[]}],
            'coverage':{key:{'status':'complete','emitted':count,'truncated':False,'error':None}
                        for key,count in (('instructions',4),('cfg',3),('body_ranges',1),('pseudocode',1))},
            'native_scope':{'policy':'macscope-focused-native-scope/1','status':'complete','operations_scanned':2,
                'operations_truncated':False,'outside_body_operations':0,'outside_body_addresses':[],'error':None}}

    def reasons(self):
        return [row['reason'] for row in scope.gaps(self.function,self.proof)]

    def internal(self):
        self.function['blocks'][1]['dsts'][0]['to']='0x100c'
        self.function['instructions'][2]['bytes']='01000014'

    def test_optimized_away_escape_is_partial_even_without_outside_pcode(self):
        original=copy.deepcopy(self.function)
        reviewed=flow_evidence.review(self.function,arch='arm64',focused_extent=self.proof)
        self.assertEqual(reviewed['decompile_status'],'partial')
        self.assertEqual(reviewed['engine_decompile_status'],'complete')
        self.assertEqual(reviewed['native_scope']['outside_body_operations'],0)
        self.assertEqual(reviewed['pseudocode'],'return 42;')
        row,=reviewed['control_flow_gaps']
        self.assertEqual((row['reason'],row['from'],row['to']),('focused_flow_outside_body','0x1008','0x1014'))
        self.assertEqual(self.function,original)

    def test_no_focused_review_does_not_change_other_query_modes(self):
        self.assertEqual(flow_evidence.review(self.function,arch='arm64'),self.function)

    def test_internal_jump_and_ordinary_outside_calls_remain_complete(self):
        self.internal()
        self.assertEqual(self.reasons(),[])
        self.function['instructions'][2]['flow']='UNCONDITIONAL_CALL'
        self.function['instructions'][2]['fallthrough']='0x100c'
        self.function['blocks'][1]['dsts'][0].update(to='EXTERNAL:00000001',flow='UNCONDITIONAL_CALL')
        self.assertEqual(self.reasons(),[])

    def test_conditional_and_fallthrough_escapes_are_not_hidden(self):
        self.internal()
        self.function['blocks'][0]['dsts'][0]['to']='0x1014'
        self.assertIn('focused_flow_outside_body',self.reasons())
        self.function['blocks'][0]['dsts'][0]['to']='0x100c'
        self.function['instructions'][3]['flow']='FALL_THROUGH'
        self.function['instructions'][3]['fallthrough']='0x1010'
        self.assertIn('focused_flow_outside_body',self.reasons())

    def test_missing_jump_with_only_fallthrough_still_fails_closed(self):
        self.internal()
        self.function['blocks'][0]['dsts'].pop(0)
        self.assertIn('focused_flow_destination_unavailable',self.reasons())

    def test_conditional_missing_and_mid_instruction_fallthrough_fail_closed(self):
        self.internal()
        self.function['instructions'][1]['fallthrough']=None
        self.function['blocks'][0]['dsts'].pop(1)
        self.assertIn('focused_flow_destination_unavailable',self.reasons())
        self.function['instructions'][1]['fallthrough']='0x1002'
        self.assertIn('focused_flow_destination_unavailable',self.reasons())

    def test_missing_unresolved_and_mid_instruction_jump_targets_fail_closed(self):
        self.internal()
        for target in (None,'EXTERNAL:00000001','0x100d'):
            with self.subTest(target=target):
                self.function['blocks'][1]['dsts'][0]['to']=target
                self.assertIn('focused_flow_destination_unavailable',self.reasons())
        self.function['blocks'][1]['dsts']=[]
        self.assertIn('focused_flow_destination_unavailable',self.reasons())

    def test_tail_exit_requires_exact_applied_proof_not_only_a_call_label(self):
        instruction=self.function['instructions'][2]
        instruction.update(flow='CALL_TERMINATOR',original_flow='UNCONDITIONAL_JUMP',flow_override='CALL_RETURN')
        edge=self.function['blocks'][1]['dsts'][0]
        edge['flow']='CALL_TERMINATOR'
        self.assertIn('focused_tail_call_unverified',self.reasons())
        plan={'policy':focused_tailcalls.POLICY,'arch':'arm64','reason':None,'candidates':[
            {'source_va':'0x1008','source_bytes':instruction['bytes'],'target_va':'0x1014',
             'target_kind':'linker_function_start','target_bytes':'c0035fd6'}]}
        self.proof['tail_calls']=plan
        self.function['tail_call_recovery']={'policy':focused_tailcalls.POLICY,
            'request_sha256':focused_tailcalls.request_digest(plan),'decisions':[{'source_va':'0x1008','outcome':'applied'}]}
        self.assertEqual(self.reasons(),[])
        edge['to']='0x1018'
        self.assertIn('focused_tail_call_unverified',self.reasons())

    def test_brk_stays_classified_and_real_indirect_jump_stays_partial(self):
        self.internal()
        for encoded,expected in (('200020d4','complete'),('00001fd6','partial')):
            with self.subTest(encoded=encoded):
                self.function['instructions'][2].update(bytes=encoded,flow='COMPUTED_JUMP')
                self.function['blocks'][1].update(flow='COMPUTED_JUMP',dsts=[])
                self.assertEqual(self.reasons(),[])
                reviewed=flow_evidence.review(self.function,arch='arm64',focused_extent=self.proof)
                self.assertEqual(reviewed['decompile_status'],expected)

    def test_incomplete_or_malformed_capture_is_not_proof_of_confinement(self):
        self.internal()
        original=copy.deepcopy(self.function)
        for mutation in ('cfg_missing','facet','emitted','error','block_truncated','instruction_missing',
                         'block_outside','source_missing','body_missing','null_edge','null_facet'):
            self.function=copy.deepcopy(original)
            if mutation=='cfg_missing': self.function['blocks']=[]
            elif mutation=='facet': self.function['coverage'].pop('cfg')
            elif mutation=='emitted': self.function['coverage']['cfg']['emitted']=2
            elif mutation=='error': self.function['cfg_error']='bounded failure'
            elif mutation=='block_truncated': self.function['blocks'][0]['edges_truncated']=True
            elif mutation=='instruction_missing': self.function['instructions'][0].pop('fallthrough')
            elif mutation=='block_outside': self.function['blocks'][2]['max']='0x1013'
            elif mutation=='source_missing': self.function['blocks'][1]['dsts'][0]['from']='0x1018'
            elif mutation=='body_missing': self.function['body_ranges']=[]
            elif mutation=='null_edge': self.function['blocks'][1]['dsts']=[None]
            elif mutation=='null_facet': self.function['coverage']['cfg']=None
            with self.subTest(mutation=mutation):
                self.assertIn('focused_control_flow_incomplete',self.reasons())

    def test_scan_and_output_caps_are_fail_closed(self):
        self.internal()
        for key,value in (('MAX_BLOCKS',2),('MAX_INSTRUCTIONS',3),('MAX_EDGES',2)):
            with patch.object(scope,key,value):
                self.assertIn('focused_control_flow_incomplete',self.reasons())
        self.function['blocks'][1]['dsts'][0]['to']='0x1014'
        with patch.object(scope,'MAX_GAPS',0):
            self.assertEqual(self.reasons(),['focused_control_flow_incomplete'])
