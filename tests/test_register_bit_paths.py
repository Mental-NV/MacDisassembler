import unittest
from macscope import callback_evidence, register_relations as relations
from test_register_relations import fixture


def bit_branch(bit=0, reg=0, nonzero=False, displacement=64):
    assert displacement%4==0 and -32768<=displacement<=32764
    return (0x36000000 | ((bit>>5)<<31) | ((bit&31)<<19) | (int(nonzero)<<24)
            | (((displacement//4)&0x3fff)<<5) | reg)


def view(words, enabled=True):
    row=fixture(words)
    return relations.derive(row,(0x100,0x100+4*len(words)),abi='aapcs64',bit_test_fallthrough=enabled)


class BitPathTests(unittest.TestCase):
    def test_width_bits_and_predicates(self):
        for bit in (0,31,32,63):
            for nonzero in (False,True):
                with self.subTest(bit=bit,nonzero=nonzero):
                    out=view([bit_branch(bit,3,nonzero),0xd63f0100]);branch=out['path_obligations'][0]
                    self.assertEqual(branch['bit_index'],bit);self.assertEqual(branch['width'],32 if bit<32 else 64)
                    self.assertEqual(branch['branch'],'tbnz' if nonzero else 'tbz')
                    self.assertEqual(branch['fallthrough_predicate'],'bit_clear' if nonzero else 'bit_set')
                    self.assertEqual(branch['predicate_status'],'unverified');self.assertEqual(branch['target_va'],'0x140')
                    self.assertEqual(out['sites'][-1]['conditional_on_branches'],['0x100'])
                    self.assertEqual(out['policy'],relations.BIT_TEST_POLICY);self.assertEqual(out['decoder_policy'],callback_evidence.BIT_TEST_POLICY)

    def test_zero_register_constants_and_zero_extended_values(self):
        for bit in (0,31,32,63):
            impossible=view([bit_branch(bit,31),0xd63f0100]);self.assertEqual(impossible['stop_reason'],'impossible_fallthrough_predicate');self.assertEqual(len(impossible['sites']),1)
            satisfied=view([bit_branch(bit,31,True),0xd63f0100]);self.assertEqual(satisfied['path_obligations'][0]['predicate_status'],'statically_satisfied')
        # MOVZ x0,#1 produces a non-relocated constant.
        self.assertEqual(view([0xd2800020,bit_branch(0),0xd63f0100])['path_obligations'][0]['predicate_status'],'statically_satisfied')
        self.assertEqual(view([0xd2800020,bit_branch(1),0xd63f0100])['stop_reason'],'impossible_fallthrough_predicate')
        # ADD w2,w0,w1: the shared decoder explicitly records zero extension.
        out=view([0x0b010002,bit_branch(32,2),0xd63f0100]);self.assertEqual(out['stop_reason'],'impossible_fallthrough_predicate')
        out=view([0x8b010002,bit_branch(32,2),0xd63f0100]);self.assertEqual(out['path_obligations'][0]['predicate_status'],'unverified')

    def test_contradictions_moves_and_independent_bits(self):
        out=view([bit_branch(0),0xaa0003e2,bit_branch(0,2,True),0xd63f0100])
        self.assertEqual(out['stop_reason'],'contradictory_fallthrough_predicates')
        self.assertFalse(any(s['kind']=='indirect_invocation' for s in out['sites']))
        out=view([bit_branch(0),bit_branch(1,0,True),0xd63f0100]);self.assertEqual(len(out['path_obligations']),2)
        out=view([bit_branch(0),0x94000040,bit_branch(0,0,True),0xd63f0100]);self.assertEqual(len(out['path_obligations']),2)
        # Two loads from the same symbolic address are not the same observed value.
        out=view([0xf9400020,bit_branch(0),0xf9400020,bit_branch(0,0,True),0xd63f0100]);self.assertEqual(len(out['path_obligations']),2)

    def test_backward_self_and_branch_budget(self):
        for delta in (-4,0,-32768):
            out=view([bit_branch(displacement=delta),0xd63f0100]);self.assertEqual(out['stop_reason'],'conditional_backedge_or_cycle')
            self.assertEqual(out['sites'][0]['target_va'],hex((0x100+delta)&((1<<64)-1)))
        out=view([bit_branch(bit=i,displacement=1024) for i in range(17)]+[0xd63f0100])
        self.assertEqual(out['stop_reason'],'branch_condition_budget');self.assertEqual(len(out['path_obligations']),16)
        self.assertFalse(any(s['kind']=='indirect_invocation' for s in out['sites']))

    def test_calls_and_guard_survive_to_context(self):
        out=view([0x94000040,bit_branch(),0x94000040,0xaa0003e2,0xaa0203f4,0xd63f0100])
        last=out['sites'][-1]
        self.assertEqual(last['conditional_on_calls'],['0x100','0x108'])
        self.assertEqual(last['conditional_on_branches'],['0x104'])
        self.assertEqual(last['register_inputs']['x20'],{'kind':'call_clobbered','register':'x0','call_va':'0x108'})
        self.assertEqual(out['path_obligations'][0]['tested_value'],{'kind':'call_clobbered','register':'x0','call_va':'0x100'})

    def test_default_barrier_unsupported_opcode_and_mixed_modes(self):
        off=view([bit_branch(),0xd63f0100],False)
        self.assertEqual(off['policy'],relations.POLICY);self.assertEqual(off['decoder_policy'],callback_evidence.POLICY)
        self.assertEqual(off['stop_reason'],'unsupported_instruction_boundary');self.assertNotIn('path_obligations',off)
        for word in (0x34000040,0x54000040,bit_branch()^(1<<25)):
            self.assertEqual(view([word,0xd63f0100])['stop_reason'],'unsupported_instruction_boundary')
        response={'data':{'selection':{'start_va':'0x100','end_va':'0x104','arch':'arm64'},'instructions':[{'addr':'0x100','bytes':'40000036'}]}}
        for kw in ({'fallthrough':True},{'checked_add':True}):
            with self.assertRaises(ValueError):callback_evidence.project(response,abi='aapcs64',bit_test_fallthrough=True,**kw)
        with self.assertRaises(ValueError):callback_evidence.project(response,bit_test_fallthrough=True)

    def test_independent_apple_assembler_bytes(self):
        # Apple clang21 oracle, source SHA80ffcd5f02b112a5fc9ab7bcafca791852318675b65d8e91a6039d8617446eb9.
        rows=[('c0000036',0,0,32,0x18,'tbz'),('a100f837',4,31,32,0x18,'tbnz'),
              ('820000b6',8,32,64,0x18,'tbz'),('6300f8b7',12,63,64,0x18,'tbnz'),
              ('5f003836',16,7,32,0x18,'tbz'),('7fffbfb7',20,55,64,0,'tbnz')]
        for raw,site,bit,width,target,kind in rows:
            with self.subTest(raw=raw):
                # Relocate entire object-section oracle by0x100 for this owned envelope.
                word=int.from_bytes(bytes.fromhex(raw),'little')
                out=view([0xd503201f]*(site//4)+[word])
                branch=out['sites'][-1]
                self.assertEqual(branch['instruction_bytes'],raw)
                self.assertEqual((branch['bit_index'],branch['width'],branch['target_va'],branch['branch']),
                                 (bit,width,hex(0x100+target),kind))

    def test_relocated_addresses_are_not_known_runtime_bits(self):
        # ADR is unslid; neither MOV nor arithmetic may turn its bits into constants.
        for prefix,reg in [([0x10000000],0),([0x10000000,0xaa0003e2],2),
                           ([0x10000000,0x8b0003e2],2),([0x10000000,0x0b1f0002],2),
                           ([0x10000000,0x8b000000],0),
                           ([0x10000000,0x91000402],2)]:
            out=view(prefix+[bit_branch(12,reg),0xd63f0100])
            self.assertEqual(out['path_obligations'][0]['predicate_status'],'unverified')
        # A W ADD still independently zero-extends even when source is relocated.
        out=view([0x10000000,0x0b0003e2,bit_branch(32,2),0xd63f0100])
        self.assertEqual(out['stop_reason'],'impossible_fallthrough_predicate')

    def test_copied_relocated_value_contradiction_not_numeric_alias(self):
        out=view([0x10000000,bit_branch(12),0xaa0003e2,bit_branch(12,2,True),0xd63f0100])
        self.assertEqual(out['stop_reason'],'contradictory_fallthrough_predicates')
        self.assertFalse(any(row['kind']=='indirect_invocation' for row in out['sites']))
        # ADR x2,-8 at0x108 names the same unslid numeric address but a distinct origin.
        out=view([0x10000000,bit_branch(12),0x10ffffc2,bit_branch(12,2,True),0xd63f0100])
        self.assertEqual(len(out['path_obligations']),2)
