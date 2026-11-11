"""Owned instruction bytes and metadata, with no third-party app inputs."""
import copy
import struct
import unittest
from unittest.mock import patch

from macscope import flow_gap_classification as proof, flow_gap_evidence
from test_focused_tailcalls import section, branch


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.start = 0x1100
        self.binary = bytearray(0x400)
        self.parsed = {'arch':'arm64', 'flags':'0x80',
            'sections':[section('__text',0x1100,0x100,0x100), section('__got',0x1200,0x100,0x200,flags=0,protection=1)],
            'segments':[{'name':'__TEXT','va':'0x1000','file_offset':'0x0','file_size':'0x400'}],
            'loader':{'data_in_code':None,'encryption':None,'dylibs':[{'kind':'load','path':'/usr/lib/libOwned.dylib'}]}}
        self.binding = {'kind':'bind','library':'/usr/lib/libOwned.dylib','library_ordinal':1,'symbol':'_owned',
            'resolution':'declared_symbol','slice_file_offset':'0x200','weak_import':False,'import_addend':0}

    def prepare(self, raw, widths, flows):
        self.binary[0x100:0x100+len(raw)] = raw
        self.extent = {'entry_va':hex(self.start),'end_va_exclusive':hex(self.start+len(raw))}
        self.payload = raw
        cursor, instructions = self.start, []
        for width, flow in zip(widths,flows):
            instructions.append({'addr':hex(cursor),'bytes':raw[cursor-self.start:cursor-self.start+width].hex(),'flow':flow,'fallthrough':hex(cursor+width) if flow == 'FALL_THROUGH' else None})
            cursor += width
        self.function = {'arch':self.parsed['arch'],'instructions':instructions,
            'body_ranges':[[hex(self.start),hex(cursor-1)]],
            'blocks':[{'min':hex(self.start),'max':hex(cursor-1),'flow':flows[-1],'dsts':[],'edges_truncated':False}]}
        self.function['coverage'] = {facet:{'status':'complete','emitted':len(self.function[key]),'truncated':False,'error':None}
            for facet,key in (('instructions','instructions'),('cfg','blocks'),('body_ranges','body_ranges'))}
        self.gap = {'reason':'computed_jump_destination_unavailable','block_min':hex(self.start),'block_max':hex(cursor-1)}
        self.location = flow_gap_evidence.exact(instructions[-1],self.function)

    def arm_wrapper(self):
        self.prepare(struct.pack('<III',0x90000010,0xf9410210,0xd61f0200),[4,4,4],['FALL_THROUGH','FALL_THROUGH','COMPUTED_JUMP'])

    def plan(self, rows=None, gaps=None):
        with patch('macscope.flow_gap_classification.dyld.fixups',return_value=({},[self.binding] if rows is None else rows, gaps or [])):
            return proof.plan(bytes(self.binary),{},self.parsed,self.extent,self.payload)

    def classify(self, plan=None):
        return proof.classification(self.function,self.gap,self.location,plan or self.plan())

    def test_inline_arm_wrapper_and_runtime_target(self):
        self.arm_wrapper()
        result = self.classify()
        self.assertEqual(result['kind'],'verified_linkage_boundary')
        self.assertEqual(result['runtime_target'],'unresolved')
        self.assertEqual(result['proof']['bind_va'],'0x1200')
        self.assertEqual(self.function['instructions'][-1]['flow'],'COMPUTED_JUMP')

    def test_x86_inline_pointer_jump(self):
        self.parsed['arch'] = 'x86_64'
        self.prepare(b'\xff\x25'+struct.pack('<i',0x1200-0x1106),[6],['COMPUTED_JUMP'])
        self.assertEqual(self.classify()['kind'],'verified_linkage_boundary')

    def test_computed_outside_edge_preserves_unresolved_runtime_target(self):
        for arch in ('arm64', 'x86_64'):
            self.parsed['arch'] = arch
            if arch == 'arm64':
                self.arm_wrapper()
            else:
                self.prepare(b'\xff\x25'+struct.pack('<i',0x1200-0x1106),[6],['COMPUTED_JUMP'])
            source = self.function['instructions'][-1]['addr']
            edge = {'from':source,'to':'0x3000','flow':'COMPUTED_JUMP'}
            self.function['blocks'][0]['dsts'] = [edge]
            self.gap = dict(edge, reason='focused_flow_outside_body', source='ghidra_cfg')
            result = self.classify()
            self.assertEqual(result['kind'], 'verified_linkage_boundary')
            self.assertEqual(result['runtime_target'], 'unresolved')
            self.assertEqual(result['proof']['bind_va'], '0x1200')
            self.assertNotIn('target_va', result['proof'])
            original = copy.deepcopy(self.gap)
            for changes in ({'from':'0x1104' if arch == 'x86_64' else '0x1100'},
                            {'flow':'UNCONDITIONAL_JUMP'}, {'to':'0x4000'},
                            {'reason':'decompiler_unresolved_jump'}):
                self.gap = dict(original, **changes)
                self.assertEqual(self.classify()['kind'], 'unclassified', (arch, changes))
            self.gap = original
            self.function['blocks'][0]['dsts'] = []
            self.assertEqual(self.classify()['kind'], 'unclassified')
            self.function['blocks'][0]['dsts'] = [edge, copy.deepcopy(edge)]
            self.assertEqual(self.classify()['kind'], 'unclassified')

    def test_binding_rejections(self):
        self.arm_wrapper()
        original = copy.deepcopy(self.binding)
        for changes in ({'weak_import':True},{'authenticated':True},{'library_ordinal':-1},{'stream':'weak_bind'},
                        {'import_addend':1},{'library':'/wrong'},{'resolution':'name_only'}):
            self.binding = dict(original,**changes)
            self.assertEqual(self.classify()['kind'],'unclassified',changes)
        self.binding = original
        for rows,gaps in (([original,original],[]),([],[]),([original],['partial'])):
            self.assertEqual(self.classify(self.plan(rows,gaps))['kind'],'unclassified')

    def test_captured_sequence_boundaries_and_flow_required(self):
        self.arm_wrapper()
        plan = self.plan()
        for index in range(3):
            function = copy.deepcopy(self.function)
            function['instructions'][index]['bytes'] = '00000000'
            self.assertEqual(proof.classification(function,self.gap,flow_gap_evidence.exact(function['instructions'][-1],function),plan)['kind'],'unclassified')
        self.function['instructions'][0]['flow'] = 'CONDITIONAL_JUMP'
        self.assertEqual(self.classify(plan)['reason'],'wrapper_fallthrough_unverified')

    def test_interior_edge_split_block_and_truncation_rejected(self):
        for mode in ('edge','split','truncated'):
            self.arm_wrapper()
            if mode == 'edge':
                self.function['blocks'][0]['dsts'] = [{'from':'0x1108','to':'0x1104','flow':'UNCONDITIONAL_JUMP'}]
            elif mode == 'split':
                self.function['blocks'][0]['min'] = '0x1104'
            else:
                self.function['blocks'][0]['edges_truncated'] = True
            self.assertEqual(self.classify()['kind'],'unclassified')

    def test_non_ram_and_malformed_edge_destinations_are_unclassified(self):
        for destination in ('EXTERNAL:00000001', 'ram:00001104', 'not-an-address',
                            '0x10000000000000000', '', '-1'):
            self.arm_wrapper()
            self.function['blocks'][0]['dsts'] = [
                {'from':'0x1108','to':destination,'flow':'UNCONDITIONAL_JUMP'}]
            self.assertEqual(self.classify(), {'kind':'unclassified',
                'reason':'wrapper_edge_destination_unverified'}, destination)

    def test_other_unknown_transfers_cannot_prove_arm_wrapper_interior_safe(self):
        for destinations in ([], [{'from':'0x1140','to':None,'flow':'COMPUTED_JUMP'}]):
            self.arm_wrapper()
            self.function['blocks'].append({'min':'0x1140','max':'0x1143',
                'flow':'COMPUTED_JUMP','edges_truncated':False,'dsts':destinations})
            self.function['coverage']['cfg']['emitted'] = 2
            self.function['instructions'].append({'addr':'0x1140','bytes':'00001fd6',
                'flow':'COMPUTED_JUMP','fallthrough':None})
            self.function['body_ranges'].append(['0x1140','0x1143'])
            self.function['coverage']['instructions']['emitted'] = 4
            self.function['coverage']['body_ranges']['emitted'] = 2
            self.assertEqual(self.classify()['reason'], 'wrapper_edge_destination_unverified')

    def test_flat_namespace_binding_is_unclassified(self):
        self.arm_wrapper()
        for flags in ('0x0', '0x180'):
            self.parsed['flags'] = flags
            self.assertEqual(self.classify()['reason'], 'binding_unverified')

    def test_names_selectors_and_unknown_registers_never_prove(self):
        self.prepare(struct.pack('<I',0xd61f0000),[4],['COMPUTED_JUMP'])
        self.function.update(name='wrapper_objc_msgSend',selector='owned:')
        self.assertEqual(self.classify()['reason'],'source_proof_unavailable')

    def test_direct_branches_match_actual_gap_edge(self):
        for arch,raw,flow in (('arm64',branch(0x1100,0x1180),'UNCONDITIONAL_JUMP'),
                              ('arm64',struct.pack('<I',0x54000400),'CONDITIONAL_JUMP'),
                              ('arm64',struct.pack('<I',0xb4000400),'CONDITIONAL_JUMP'),
                              ('arm64',struct.pack('<I',0x36000400),'CONDITIONAL_JUMP'),
                              ('x86_64',b'\xe9'+struct.pack('<i',0x1180-0x1105),'UNCONDITIONAL_JUMP'),
                              ('x86_64',b'\x75\x7e','CONDITIONAL_JUMP')):
            self.parsed['arch'] = arch
            self.prepare(raw,[len(raw)],[flow])
            self.gap = {'reason':'focused_branch_outside_body','from':'0x1100','to':'0x1180','flow':flow}
            self.assertEqual(self.classify()['kind'],'unresolved_internal_transfer',(arch,raw.hex()))
            self.gap.update(to=hex(0x1100+len(raw)),flow='FALL_THROUGH')
            self.assertEqual(self.classify()['kind'],'unclassified')

    def test_target_data_encryption_and_mapping_rejected(self):
        self.prepare(branch(0x1100,0x1180),[4],['UNCONDITIONAL_JUMP'])
        self.gap = {'from':'0x1100','to':'0x1180','flow':'UNCONDITIONAL_JUMP'}
        for mode in ('embedded','encrypted','ambiguous'):
            parsed = copy.deepcopy(self.parsed)
            if mode == 'embedded':
                self.parsed['loader']['data_in_code'] = {'status':'complete','records':[{'slice_file_offset':'0x180','length':4}]}
            elif mode == 'encrypted':
                self.parsed['loader']['encryption'] = {'cryptid':1,'slice_file_offset':'0x180','size':'0x4'}
            else:
                self.parsed['sections'].append(copy.deepcopy(self.parsed['sections'][0]))
            self.assertEqual(self.classify()['kind'],'unclassified')
            self.parsed = parsed

    def test_limits_fail_closed(self):
        self.prepare(branch(0x1100,0x1180)*65,[4]*65,['UNCONDITIONAL_JUMP']*65)
        self.assertEqual(self.plan()['reason'],'candidate_limit')
        self.arm_wrapper()
        with patch.object(proof,'MAX_BIND_SLOTS',0):
            self.assertEqual(self.plan()['reason'],'binding_slot_limit')
        with patch.object(proof,'MAX_REQUEST_BYTES',10):
            self.assertEqual(self.plan()['reason'],'request_byte_limit')
        with patch.object(proof,'MAX_SCAN_BYTES',8):
            self.assertEqual(self.plan()['reason'],'scan_byte_limit')

    def test_malformed_plans_raise(self):
        self.arm_wrapper()
        original = self.plan()
        for mutate in (lambda p:p.update(extra=True),lambda p:p.update(candidates=[None]),
                       lambda p:p['candidates'][0].update(source_bytes='bad'),
                       lambda p:p['candidates'][0].update(bind_va='0x1208'),
                       lambda p:p.update(reason='candidate_limit'),
                       lambda p:p['candidates'][0]['instructions'][1].update(va='0x1108')):
            value = copy.deepcopy(original)
            mutate(value)
            with self.assertRaises(ValueError):
                proof.validate_plan(value)

    def test_decode_overflow_calls_and_unsupported_encodings(self):
        self.assertIsNone(proof.direct('x86_64',0,b'\xeb\x80'))
        self.assertIsNone(proof.direct('x86_64',(1<<64)-2,b'\xeb\x7f'))
        self.assertIsNone(proof.direct('x86_64',0x1100,b'\xe8\0\0\0\0'))
        self.assertIsNone(proof.direct('arm64',0x1100,struct.pack('<I',0x94000000)))
        self.assertIsNone(proof.direct('arm64',0x1100,struct.pack('<I',0xd61f0200)))


if __name__ == '__main__':
    unittest.main()
