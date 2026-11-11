"""Bounded presentation tests; no native app or engine required."""
import copy
import unittest
from macscope import terminal


def render(evidence):
    report = terminal.Report()
    terminal.callback_summary(report, evidence)
    return report.output.getvalue()


class CallbackTextTests(unittest.TestCase):
    def evidence(self):
        assignment = {'selection': {'start_va':'0xb00','end_va':'0xb0c'},
            'source_envelope_sha256':'a'*64, 'stop_reason':'selected_prefix_end',
            'sites':[{'kind':'memory_store','instruction_va':'0xb08','lane':0,
                      'value':{'kind':'address','value':'0xb34'}}]}
        return {'status':'inconclusive','selection':{'start_va':'0xb34','end_va':'0xb38'},
            'source_envelope_sha256':'b'*64,'stop_reason':'direct_branch',
            'composition':{'status':'inconclusive','candidate_status':'conditional_candidate',
                'independent_evidence':{'assignment':assignment},'unknowns':['persistence'],
                'gaps':[],'assumptions':[], 'path_obligations':[], 'call_obligations':[]}}

    def test_conditional_and_negative_text_differ(self):
        e=self.evidence();before=copy.deepcopy(e);positive=render(e)
        self.assertEqual(e,before)
        self.assertIn('Analysis status: inconclusive',positive)
        self.assertIn('conditional_candidate (not runtime proof)',positive)
        self.assertIn('persistence: unknown',positive)
        e['composition']['candidate_status']='gap'
        e['composition']['gaps']=[{'reason':'unique_paired_assignment_not_proven'}]
        v=e['composition']['independent_evidence']['assignment']['sites'][0]
        v['value']['value']='0xd78';wrong=render(e)
        v['value']={'kind':'range_input_register','register':'x21'};unknown=render(e)
        self.assertEqual(len({positive,wrong,unknown}),3)
        self.assertIn('value=address:0xd78',wrong)
        self.assertIn('value=range_input_register:x21',unknown)
        self.assertIn('Expected selected thunk entry: 0xb34',unknown)
        self.assertIn('unique_paired_assignment_not_proven',unknown)

    def test_no_callback_leaves_old_disassembly_unchanged(self):
        data={'instructions':[{'addr':'0xb34','bytes':'6fffff17','text':'b 0x8f0'}]}
        r=terminal.Report();terminal.disasm(r,data)
        self.assertEqual(r.output.getvalue(),'Address             Bytes                            Instruction\n0xb34               6fffff17                        b 0x8f0\n')
        data['callback_evidence']={'status':'inconclusive'}
        r=terminal.Report();terminal.disasm(r,data)
        self.assertIn('Callback evidence',r.output.getvalue())

    def test_solo_and_destination_effects(self):
        e={'status':'inconclusive','missing_evidence':['runtime_invocation_target'],
           'destination_link':{'status':'linked','reason':'owned_reason','destination_evidence':{'stop_reason':'owned_stop'},'destination_effects':{'counts':{
               'stack_or_frame':4,'mapped_image_nonstack':0,'unresolved_destination':1}}}}
        text=render(e)
        self.assertIn('runtime_invocation_target',text)
        self.assertIn('Destination link: linked; reason=owned_reason',text)
        self.assertIn('Destination prefix stop: owned_stop',text)
        self.assertIn('stack/frame=4; mapped nonstack=0; unresolved=1',text)

    def test_scoped_gaps_and_path_predicates(self):
        e=self.evidence();c=e['composition']
        c['gaps']=[{'role':'writer','evidence':{'reason':'unsupported','instruction_va':'0x10'}}]
        c['assumptions']=[{'role':'writer','condition':'AAPCS64'}]
        c['path_obligations']=[{'role':'invocation','evidence':{'kind':'branch','instruction_va':'0xc84','fallthrough_predicate':'nonzero'}}]
        c['call_obligations']=[{'role':'writer','evidence':{'kind':'direct_call','instruction_va':'0x914'}}]
        text=render(e)
        for item in ('role=writer; unsupported; site=0x10','role=writer; AAPCS64',
                     'fallthrough=nonzero','side effects unknown','site=0x914'):
            self.assertIn(item,text)

    def test_hostile_oversize_fields_and_lists_bounded(self):
        e=self.evidence();c=e['composition'];bad='\x1b\n\r\u202e😀'*10000
        e['source_envelope_sha256']=bad
        e['destination_link']={'status':bad,'reason':bad,'destination_evidence':{'stop_reason':bad}}
        c['destination_effects']={'counts':{k:bad for k in ('stack_or_frame','mapped_image_nonstack','unresolved_destination')}}
        c['status']=bad;c['candidate_status']=bad
        c['assignment_diagnostic']={'reason':bad}
        for key in ('gaps','assumptions','path_obligations','call_obligations','unknowns'):
            c[key]=[{'role':bad,'reason':bad,'condition':bad,'instruction_va':bad}]*1000
        c['independent_evidence']['assignment']['sites']=[{'kind':'memory_store','instruction_va':bad,'lane':bad,'value':{'kind':bad,'register':bad}}]*1000
        text=render(e)
        self.assertLessEqual(len(text.splitlines()),64)
        self.assertLessEqual(len(text.encode()),16*1024)
        self.assertNotIn('\x1b',text);self.assertNotIn('\r',text);self.assertNotIn('\u202e',text)
        self.assertIn('[truncated]',text);self.assertEqual(text.count('Omitted 996 entries'),6)
        self.assertIn('--format json',text)
        self.assertEqual(text,render(e))

    def test_container_not_stringified_recursively(self):
        x={};x['cycle']=x
        self.assertIn('[structured; see JSON]',render({'status':x}))

    def test_composition_reason_precedes_role_local_boundaries(self):
        e=self.evidence();c=e['composition'];c['candidate_status']='gap'
        c['gaps']=[{'role':'invocation','evidence':{'reason':'local_boundary'}}]*4 + [
            {'reason':'unique_paired_assignment_not_proven'}]
        before=copy.deepcopy(e);text=render(e)
        self.assertIn('unique_paired_assignment_not_proven',text)
        self.assertIn('Omitted 1 entries',text)
        self.assertEqual(e,before)

    def test_assignment_diagnostic_detail_is_visible(self):
        e=self.evidence()
        e['composition']['assignment_diagnostic']={'reason':'no_address_valued_store'}
        self.assertIn('Assignment diagnostic: no_address_valued_store',render(e))

    def test_twohop_writer_proof_gap_is_separate(self):
        e={'status':'inconclusive','two_hop_chain':{'status':'inconclusive',
            'link_status':'verified_two_hop_entry_links','writer_call_evidence':{
                'status':'gap','gaps':[{'reason':'writer_unsupported_boundary'}]}}}
        text=render(e)
        self.assertIn('Two-hop links: verified_two_hop_entry_links',text)
        self.assertIn('Conditional writer proof: gap',text)
        self.assertIn('writer_unsupported_boundary',text)
