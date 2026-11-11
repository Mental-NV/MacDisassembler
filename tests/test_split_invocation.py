"""Explicit path obligations do not establish actual callback execution."""
import copy
import unittest
from macscope import callback_evidence, cli
from test_callback_evidence import receipt
from test_callback_provenance import encoded
import test_callback_composition


def project(words, *, abi=None, fallthrough=True, start=0x1000):
    r=receipt(words)
    r['data']['selection'].update(start_va=hex(start),end_va=hex(start+4*len(words)))
    for i,row in enumerate(r['data']['instructions']):row['addr']=hex(start+4*i)
    return callback_evidence.project(r,provenance=True,abi=abi,fallthrough=fallthrough)['data']['callback_evidence']


def cb(reg=1, delta=8, nonzero=False, width=64):
    return 0x34000000|((width==64)<<31)|(nonzero<<24)|(((delta//4)&0x7ffff)<<5)|reg


class PathObligationTests(unittest.TestCase):
    def test_native_contiguous_invocation_path(self):
        words=encoded('950e40f9550100b4941240f9e00315aae10314aa49ffff97e00313aaa0023fd6')
        r=project(words,abi='aapcs64',start=0xc80)
        self.assertEqual(r['stop_reason'],'invocation_boundary')
        branch,=r['path_obligations']
        self.assertEqual(branch['target_va'],'0xcac')
        self.assertEqual(branch['fallthrough_predicate'],'nonzero')
        self.assertEqual(branch['predicate_status'],'unverified')
        call=r['sites'][-1]
        self.assertEqual(call['instruction_va'],'0xc9c')
        self.assertEqual(call['operand'],{'kind':'memory_read','origin_va':'0xc80'})
        self.assertEqual(call['register_inputs']['x20'],{'kind':'memory_read','origin_va':'0xc88'})
        self.assertEqual(call['conditional_on_calls'],['0xc94'])
        self.assertEqual(call['conditional_on_branches'],['0xc84'])
        loads=[s for s in r['sites'] if s['kind']=='memory_load']
        self.assertEqual(loads[0]['location']['base'],loads[1]['location']['base'])
        self.assertEqual(r['status'],'inconclusive')
        self.assertIn('alternate_branch_paths_not_analyzed',r['missing_evidence'])
        self.assertEqual(project(words,start=0xc80)['stop_reason'],'direct_transfer_boundary')
        self.assertEqual(project(words,abi='aapcs64',fallthrough=False)['stop_reason'],'unsupported_instruction_boundary')

    def test_cbz_cbnz_width_and_conditions(self):
        for width in (32,64):
            for nonzero in (False,True):
                r=project([cb(nonzero=nonzero,width=width),0xf9000000])
                b,=r['path_obligations']
                self.assertEqual(b['width'],width)
                self.assertEqual(b['fallthrough_predicate'],'zero' if nonzero else 'nonzero')
                self.assertEqual(r['sites'][-1]['conditional_on_branches'],['0x1000'])

    def test_constant_impossible_and_satisfied(self):
        self.assertEqual(project([cb(reg=31),0xf9000000])['stop_reason'],'impossible_fallthrough_predicate')
        r=project([cb(reg=31,nonzero=True),0xf9000000])
        self.assertEqual(r['path_obligations'][0]['predicate_status'],'statically_satisfied')
        # MOVZ x1,#1,LSL32: zero when tested as W, nonzero as X.
        for width,reason in ((32,'impossible_fallthrough_predicate'),(64,'selected_prefix_end')):
            self.assertEqual(project([0xd2c00021,cb(width=width)],abi='aapcs64')['stop_reason'],reason)

    def test_cycles_unsupported_and_budget(self):
        for delta in (0,-4):
            self.assertEqual(project([cb(delta=delta)])['stop_reason'],'conditional_backedge_or_cycle')
        for word in (0x54000000,0x36000001):
            self.assertEqual(project([word,0xf9000000])['stop_reason'],'unsupported_instruction_boundary')
        r=project([cb(delta=4)]*17+[0xf9000000])
        self.assertEqual(r['stop_reason'],'branch_condition_budget')
        self.assertEqual(len(r['path_obligations']),16)
        self.assertFalse(any(s['kind']=='memory_store' for s in r['sites']))

    def test_contradictions_respect_value_versions_and_widths(self):
        for first_width,second_width,impossible in ((64,64,True),(32,32,True),(64,32,True),(32,64,False)):
            # CBNZ fallthrough requires zero; CBZ fallthrough requires nonzero.
            r=project([cb(nonzero=True,width=first_width,delta=16),cb(width=second_width,delta=12),0xd63f0020])
            self.assertEqual(r['stop_reason'],'contradictory_fallthrough_predicates' if impossible else 'invocation_boundary')
        # A fresh load is not aliased to the earlier value, even at same offset.
        r=project([0xf9400001,cb(nonzero=True,delta=20),0xf9400001,cb(delta=12),0xd63f0020])
        self.assertEqual(r['stop_reason'],'invocation_boundary')
        # MOV preserves identity, so copying cannot evade the contradiction.
        r=project([cb(nonzero=True,delta=20),0xaa0103e2,cb(reg=2,delta=12),0xd63f0040])
        self.assertEqual(r['stop_reason'],'contradictory_fallthrough_predicates')
        # Symbolic W ADD zero-extension makes W==0 && X!=0 contradictory too.
        r=project([0x0b020021,cb(nonzero=True,width=32,delta=16),cb(width=64,delta=12),0xd63f0020])
        self.assertEqual(r['stop_reason'],'contradictory_fallthrough_predicates')

    def test_unknown_writes_are_distinct_versions_not_register_aliases(self):
        # Initial x1=-1 makes ADD;zero;ADD;nonzero feasible.
        r=project([0x91000421,cb(nonzero=True,delta=20),0x91000421,cb(delta=12),0xd63f0020])
        self.assertEqual(r['stop_reason'],'invocation_boundary')
        first,second=r['path_obligations']
        self.assertNotEqual(first['tested_value']['value_identity'],second['tested_value']['value_identity'])
        # Without a new write, the same unknown version is contradictory.
        r=project([0x91000421,cb(nonzero=True,delta=16),cb(delta=12),0xd63f0020])
        self.assertEqual(r['stop_reason'],'contradictory_fallthrough_predicates')

    def test_immutable_deterministic(self):
        source=receipt([cb(),0xf9000000]);before=copy.deepcopy(source)
        first=callback_evidence.project(source,provenance=True,fallthrough=True)
        self.assertEqual(first,callback_evidence.project(source,provenance=True,fallthrough=True))
        self.assertEqual(source,before)
        with self.assertRaises(ValueError):callback_evidence.project(source,fallthrough=True)


class SplitCompositionTests(unittest.TestCase):
    def setUp(self):
        self.f=test_callback_composition.CompositionTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def test_split_loads_require_explicit_pin(self):
        self.f.change(0x240,'080840f9140c40f900013fd6',invocation_end=0x124c)
        self.assertEqual(self.f.composed()['candidate_status'],'gap')
        r=self.f.composed(context_register='x20')
        self.assertEqual(r['candidate_status'],'conditional_candidate',r['gaps'])
        self.assertEqual(r['invocation_context_mode'],'explicit_register')
        self.assertEqual(r['status'],'inconclusive')

    def test_branch_call_chain_is_conditional_only(self):
        self.f.change(0x240,'150840f9550100b4140c40f90d000094e00313aaa0023fd6',invocation_end=0x1258)
        r=self.f.composed(context_register='x20',fallthrough=True,abi='aapcs64')
        self.assertEqual(r['candidate_status'],'conditional_candidate',r['gaps'])
        self.assertEqual(r['call_obligations'][0]['memory_effects'],'unknown')
        self.assertEqual(r['path_obligations'][0]['evidence']['fallthrough_predicate'],'nonzero')
        self.assertIn('context_lifetime_after_calls',r['unknowns'])
        self.assertIn('intervening_memory_unchanged',r['unknowns'])
        self.assertEqual(r['conditional_register_bindings'][0]['requires_call_conditions'],['0x124c'])
        self.assertEqual(r['conditional_register_bindings'][0]['requires_branch_conditions'],['0x1244'])
        self.assertEqual(self.f.composed(context_register='x20',fallthrough=True)['candidate_status'],'gap')
        self.assertEqual(self.f.composed(context_register='x20',abi='aapcs64')['candidate_status'],'gap')

    def test_same_offsets_different_bases_do_not_compose(self):
        self.f.change(0x240,'080840f9340c40f900013fd6',invocation_end=0x124c)
        r=self.f.composed(context_register='x20')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'split_load_base_identity_not_proven'},r['gaps'])

    def test_clobbered_target_or_context(self):
        for code in ('150840f9140c40f9f50309aaa0023fd6',
                     '150840f9140c40f9f40309aaa0023fd6'):
            self.f.change(0x240,code,invocation_end=0x1250)
            self.assertEqual(self.f.composed(context_register='x20')['candidate_status'],'gap')

    def test_caller_saved_context_does_not_survive(self):
        self.f.change(0x240,'150840f9010c40f90e000094a0023fd6',invocation_end=0x1250)
        r=self.f.composed(context_register='x1',fallthrough=True,abi='aapcs64')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'unique_split_invocation_load_not_proven'},r['gaps'])

    def test_store_between_earlier_context_and_target_is_gap(self):
        self.f.change(0x240,'140c40f9000000f9150840f9a0023fd6',invocation_end=0x1250)
        r=self.f.composed(context_register='x20')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'intervening_invocation_store'},r['gaps'])

    def test_target_context_same_load_cannot_compose(self):
        self.f.change(0x240,'140840f980023fd6',invocation_end=0x1248) # LDRx20;BLRx20
        r=self.f.composed(context_register='x20')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'target_and_context_load_not_distinct'},r['gaps'])

    def test_parser_scope(self):
        args=cli.parser().parse_args(['disasm','--project','owned','--from-import','--range','0x1200:0x1204','--callback-invocation-fallthrough'])
        self.f.error('callback_scope',cli.execute,args)

    def test_context_register_copy_preserves_load_identity(self):
        self.f.change(0x240,'080840f9020c40f9f40302aa00013fd6',invocation_end=0x1250)
        r=self.f.composed(context_register='x20')
        self.assertEqual(r['candidate_status'],'conditional_candidate',r['gaps'])
        self.assertEqual(r['facts']['invocation_context_load']['register'],'x2')

    def test_other_role_calls_remain_composition_gaps(self):
        self.f.change(0x210,'00000094800a00f9')
        r=self.f.composed(fallthrough=True,abi='aapcs64')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'writer_intervening_call'},r['gaps'])

    def test_contradictory_invocation_path_cannot_compose(self):
        self.f.change(0x240,'150840f9140c40f9950000b4750000b5a0023fd6',invocation_end=0x1254)
        r=self.f.composed(context_register='x20',fallthrough=True)
        self.assertEqual(r['candidate_status'],'gap')
        self.assertEqual(r['independent_evidence']['invocation']['stop_reason'],'contradictory_fallthrough_predicates')

    def test_direct_call_reentry_is_not_assumed_to_return(self):
        self.f.change(0x240,'150840f9140c40f900000094a0023fd6',invocation_end=0x1250)
        r=self.f.composed(context_register='x20',fallthrough=True,abi='aapcs64')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'invocation_direct_call_cycle_or_reentry'},r['gaps'])
