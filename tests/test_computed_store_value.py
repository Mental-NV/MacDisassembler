"""No symbolic arithmetic upgrade without exact local def-use and guard evidence."""
import copy
import unittest
from macscope import callback_evidence,computed_store_value,writer_call_obligations
from test_callback_evidence import receipt


def fixture():
    r=callback_evidence.project(receipt([0xb1000413,0x54000086,0x940003fe,0xf9000a93,0xd65f03c0]),
        abi='aapcs64',checked_add=True)['data']['callback_evidence']
    store=next(s for s in r['sites'] if s['kind']=='memory_store')
    return r,store


class ComputedStoreTests(unittest.TestCase):
    def test_supported_symbolic_computation_keeps_runtime_unknown(self):
        r,s=fixture();before=copy.deepcopy(r);p=computed_store_value.project(r,s)
        self.assertEqual(p['basis'],'scoped_checked_add_computation')
        self.assertEqual(p['runtime_value'],'unknown')
        self.assertEqual(p['symbolic_input']['register'],'x0')
        self.assertEqual(p['guard']['fallthrough_predicate'],'no_signed_overflow')
        self.assertEqual(r,before)
        p['definition']['left']['register']='modified';self.assertEqual(r,before)

    def test_foreign_result_scope_and_definition_mismatches(self):
        changes=[lambda r,s:s['value'].update(source_envelope_sha256='b'*64),
            lambda r,s:s['value'].update(selection_start_va='0x999'),
            lambda r,s:s['value'].update(origin_va='0x1010'),
            lambda r,s:r['sites'][0].update(result={}),
            lambda r,s:r['sites'][0].update(instruction_bytes='00000000'),
            lambda r,s:r['sites'][0].update(immediate=2),
            lambda r,s:r['sites'][0].update(destination_register='x20'),
            lambda r,s:r['sites'].append(copy.deepcopy(r['sites'][0])),
            lambda r,s:s.update(instruction_va='0x1000')]
        for change in changes:
            r,s=fixture();change(r,s);self.assertIsNone(computed_store_value.project(r,s))

    def test_missing_guard_or_condition_fails(self):
        changes=[lambda r,s:r.update(path_obligations=[]),
            lambda r,s:s.update(conditional_on_calls=[]),
            lambda r,s:s.update(conditional_on_branches=[]),
            lambda r,s:r['path_obligations'][0].update(tested_value={}),
            lambda r,s:r['sites'][0].update(conditional_on_calls=['0xff0']),
            lambda r,s:r['path_obligations'][0].update(instruction_va='0x1008')]
        for change in changes:
            r,s=fixture();change(r,s);self.assertIsNone(computed_store_value.project(r,s))

    def test_root_load_clobber_nested_and_foreign_input_fail(self):
        for value in ({'kind':'memory_read','origin_va':'0xff0'},
                      {'kind':'call_clobbered','register':'x0','call_va':'0xff0'},
                      {'kind':'checked_add_result','origin_va':'0xff0'},
                      {'kind':'range_input_register','register':'x0','selection_start_va':'0x999','source_envelope_sha256':'b'*64}):
            r,s=fixture();r['sites'][0]['left']=value
            self.assertIsNone(computed_store_value.project(r,s))

    def test_computed_value_not_a_computed_base_proof(self):
        r,s=fixture();link={'status':'verified_direct_entry_link','destination_evidence':r,'store_relations':[
            {'instruction_va':s['instruction_va'],'base_correspondence':{'status':'matched_input_register'},
             'value_correspondence':{'status':'not_correlated'}}]}
        p=writer_call_obligations.project(link,{'writer':r})
        self.assertEqual(p['post_call_stores'][0]['value_basis'],'scoped_checked_add_computation')
        self.assertEqual(p['status'],'conditional_obligations')
        s['location']['base']=copy.deepcopy(s['value'])
        p=writer_call_obligations.project(link,{'writer':r})
        self.assertEqual(p['status'],'gap')
        self.assertIn('writer_post_call_base_unresolved',[g['reason'] for g in p['gaps']])

    def test_matching_guard_copies_cannot_override_byte_predicate(self):
        for key,value in (('target_va','0x1000'),('fallthrough_va','0x9999'),
                          ('predicate_status','statically_satisfied'),('branch','b.vc'),('width',32)):
            r,s=fixture()
            guard=r['path_obligations'][0]
            site=next(x for x in r['sites'] if x['instruction_va']==guard['instruction_va'])
            guard[key]=value;site[key]=value
            self.assertIsNone(computed_store_value.project(r,s))
        r,s=fixture();r['sites'][0]['overflow_flag']['value']=True
        r['path_obligations'][0]['tested_value']['value']=True
        r['sites'][1]['tested_value']['value']=True
        self.assertIsNone(computed_store_value.project(r,s))
