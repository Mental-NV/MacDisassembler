"""Owned synthetic branch bytes and Mach-O tables; no application material."""
import struct
from pathlib import Path
import unittest
from unittest.mock import patch

from macscope import focused, focused_tailcalls as tail, flow_evidence, import_links, macho_load
from macscope.errors import Error


def branch(source, target, opcode=0x14000000):
    return struct.pack('<I', opcode | (((target - source) // 4) & 0x3ffffff))


def uleb(number):
    out = bytearray()
    while number >= 128:
        out.append((number & 127) | 128)
        number >>= 7
    out.append(number)
    return bytes(out)


def section(name, start, size, offset, flags=0x80000400, protection=5, width=0):
    return {'segment':'__TEXT', 'name':name, 'va':hex(start), 'size':hex(size),
            'file_offset':hex(offset), 'flags':hex(flags), 'protections':protection, 'reserved2':width}


class TailCallTests(unittest.TestCase):
    def setUp(self):
        self.start, self.target = 0x1100, 0x1120
        self.payload = branch(self.start, self.target)
        self.data = bytearray(512)
        self.data[0x100:0x104] = self.payload
        self.data[0x120:0x124] = bytes.fromhex('c0035fd6')
        stream = uleb(0x100) + uleb(4) + uleb(0x1c) + b'\0'
        self.data[0x1e0:0x1e0+len(stream)] = stream
        self.parsed = {'arch':'arm64', 'flags':'0x80',
            'sections':[section('__text',0x1100,0x80,0x100)],
            'segments':[{'name':'__TEXT','va':'0x1000','file_offset':'0x0','file_size':'0x200'}],
            'loader':{'linkedit':[{'kind':'function_starts','slice_file_offset':'0x1e0','size':hex(len(stream))}],
                      'data_in_code':None, 'encryption':None, 'dylibs':[{'kind':'load','path':'/usr/lib/libSystem.B.dylib'}]}}
        self.image = {'offset':'0x0', 'arch':'arm64'}
        self.proof = {'entry_va':hex(self.start), 'end_va_exclusive':hex(self.start+4)}

    def plan(self):
        return tail.plan(bytes(self.data), self.image, self.parsed, self.proof, self.payload)

    def prepared(self):
        plan = self.plan()
        report = {'policy':tail.POLICY, 'request_sha256':tail.request_digest(plan),
                  'decisions':[{'source_va':hex(self.start),'outcome':'applied'}]}
        function = {'instructions':[{'addr':hex(self.start),'bytes':self.payload.hex(),'flow':'CALL_TERMINATOR'}],
                    'origin':{'extent':{'tail_calls':plan}}}
        return plan, report, function

    def test_bridge_uses_the_existing_macho_language_pin(self):
        bridge = Path(__file__).resolve().parents[1] / 'src' / 'macscope' / 'bridge'
        focus = (bridge / 'MacscopeFocus.java').read_text()
        export = (bridge / 'MacscopeBridge.java').read_text()
        self.assertIn('AARCH64:LE:64:AppleSilicon', focus)
        self.assertIn('AARCH64:LE:64:AppleSilicon', export)
        self.assertNotIn('AARCH64:LE:64:v8A', focus)

    def test_positive_linker_start_and_signed_branch_decode(self):
        row, = self.plan()['candidates']
        self.assertEqual(row['target_kind'], 'linker_function_start')
        self.assertEqual(row['target_va'], hex(self.target))
        self.assertEqual(tail.branch_target(0x2000, branch(0x2000, 0x1000)), 0x1000)
        for raw, address in ((branch(0x1000,0x1100,0x94000000),0x1000),
                             (bytes.fromhex('00000054'),0x1000),(b'\0'*3,0x1000),
                             (branch(0x1000,0x1100),0x1001),(branch(4,0),0)):
            self.assertIsNone(tail.branch_target(address,raw))

    def test_interior_same_extent_noncode_and_wrong_arch_are_never_recovered(self):
        for target in (self.start, self.start+4, self.target+4, 0x11fc):
            self.payload = branch(self.start,target)
            if target == self.start+4:
                self.proof['end_va_exclusive'] = hex(self.start+8)
            self.assertEqual(self.plan()['candidates'], [], target)
        self.payload = branch(self.start,self.target)
        self.parsed['arch'] = 'x86_64'
        self.assertEqual(self.plan()['reason'],'architecture_unsupported')
        self.parsed['arch'] = 'arm64'
        self.parsed['sections'][0]['protections'] = 1
        self.assertEqual(self.plan()['candidates'], [])

    def test_complete_stream_required_even_after_target_was_found(self):
        end = 0x1e0+int(self.parsed['loader']['linkedit'][0]['size'],16)-1
        self.data[end] = 0x80
        self.assertEqual(self.plan()['reason'],'linker_starts_incomplete')

    def test_membership_beyond_inventory_cap_checks_entire_stream(self):
        count = macho_load.MAX_TABLE_ROWS+3
        stream = b'\x04'*count+b'\0'
        result = macho_load.function_starts(stream,[(0,len(stream))],{'va':'0x1000','file_size':hex(4*count+4)},
                                            members={0x1000+count*4})
        self.assertEqual(result,{'status':'complete','addresses':[hex(0x1000+count*4)]})
        self.assertEqual(macho_load.function_starts(stream[:-1]+b'\x80',[(0,len(stream))],
            {'va':'0x1000','file_size':hex(4*count+4)},members={0x1000+count*4})['status'],'malformed')

    def test_encrypted_embedded_data_and_incomplete_data_tables_fail_closed(self):
        loader = self.parsed['loader']
        for table in ({'status':'partial','records':[]},
                      {'status':'complete','records':[{'slice_file_offset':'0x120','length':1}]}):
            loader['data_in_code'] = table
            self.assertEqual(self.plan()['candidates'], [])
        loader['data_in_code'] = None
        loader['encryption'] = {'cryptid':1,'slice_file_offset':'0x120','size':'0x4'}
        self.assertEqual(self.plan()['candidates'], [])

    def test_ambiguous_mapping_and_candidate_cap_fail_closed(self):
        self.parsed['sections'].append(dict(self.parsed['sections'][0]))
        self.assertEqual(self.plan()['candidates'], [])
        self.parsed['sections'].pop()
        self.payload = b''.join(branch(self.start+i*4,0x1000) for i in range(tail.MAX_CANDIDATES+1))
        self.proof['end_va_exclusive'] = hex(self.start+len(self.payload))
        self.assertEqual(self.plan()['reason'],'candidate_limit')
        self.assertEqual(self.plan()['candidates'], [])

    def setup_stub(self):
        self.payload = branch(self.start,0x1180)
        self.parsed['sections'].extend([section('__stubs',0x1180,12,0x180,flags=0x80000408,width=12),
                                       section('__got',0x1190,8,0x190,flags=0,protection=1)])
        self.data[0x180:0x18c] = struct.pack('<III',0x90000010,0xf940ca10,0xd61f0200)
        return {'kind':'bind','library':'/usr/lib/libSystem.B.dylib','library_ordinal':1,'symbol':'_puts',
                'resolution':'declared_symbol','slice_file_offset':'0x190','weak_import':False,'import_addend':0}

    def test_ordinary_stub_requires_complete_unique_strong_binding(self):
        binding = self.setup_stub()
        with patch.object(tail.dyld,'fixups',return_value=(None,[binding],[])):
            row, = self.plan()['candidates']
            self.assertEqual(row['target_kind'],'declared_import_stub')
            self.assertEqual(row['bind_va'],'0x1190')
        for rows,gaps in (([],[]),([binding,binding],[]),([binding],['limit']),
                          ([dict(binding,weak_import=True)],[]),([dict(binding,authenticated=True)],[]),
                          ([dict(binding,import_addend=1)],[]),([dict(binding,library_ordinal=0)],[])):
            with patch.object(tail.dyld,'fixups',return_value=(None,rows,gaps)):
                self.assertEqual(self.plan()['candidates'], [])

    def test_stub_and_request_limits_decline_all_recovery(self):
        binding = self.setup_stub()
        with patch.object(tail, 'MAX_STUBS', 0), patch.object(tail.dyld, 'fixups') as fixups:
            self.assertEqual(self.plan()['reason'], 'stub_limit')
            self.assertEqual(self.plan()['candidates'], [])
            fixups.assert_not_called()
        with patch.object(tail, 'MAX_REQUEST_BYTES', 16), patch.object(tail.dyld, 'fixups', return_value=(None,[binding],[])):
            self.assertEqual(self.plan()['reason'], 'request_byte_limit')
            self.assertEqual(self.plan()['candidates'], [])

    def test_stub_alignment_width_bytes_and_data_evidence_are_required(self):
        binding = self.setup_stub()
        with patch.object(tail.dyld,'fixups',return_value=(None,[binding],[])):
            for target in (0x1184,0x1188):
                self.payload = branch(self.start,target)
                self.assertEqual(self.plan()['candidates'], [])
            self.payload = branch(self.start,0x1180)
            self.parsed['sections'][1]['reserved2'] = 16
            self.assertEqual(self.plan()['candidates'], [])
            self.parsed['sections'][1]['reserved2'] = 12
            self.data[0x189] = 0
            self.assertEqual(self.plan()['candidates'], [])

    def test_applied_recovery_preserves_original_flow_and_call_consumers(self):
        plan,report,function = self.prepared()
        tail.verify(plan,report,function,annotate=True)
        tail.verify(plan,report,function)
        instruction, target = next(focused.direct_calls('arm64',function))
        self.assertEqual(target,hex(self.target))
        self.assertEqual(instruction['original_flow'],'UNCONDITIONAL_JUMP')
        self.assertEqual(instruction['flow_override'],'CALL_RETURN')
        self.assertEqual(instruction['flow'],'CALL_TERMINATOR')
        self.assertEqual(list(focused.direct_calls('x86_64',function)),[])
        function.pop('tail_call_recovery')
        self.assertIsNone(next(focused.direct_calls('arm64',function))[1])

    def test_report_digest_flow_bytes_unrequested_and_skipped_decisions_rejected(self):
        for mutation in ('digest','flow','bytes','source','skip','extra','original'):
            plan,report,function = self.prepared()
            tail.verify(plan,report,function,annotate=True)
            if mutation == 'digest': report['request_sha256']='0'*64
            elif mutation == 'flow': function['instructions'][0]['flow']='UNCONDITIONAL_JUMP'
            elif mutation == 'bytes': function['instructions'][0]['bytes']='00000014'
            elif mutation == 'source': report['decisions'][0]['source_va']='0x1000'
            elif mutation == 'skip': report['decisions'][0]['outcome']='instruction_unavailable'
            elif mutation == 'extra': function['instructions'].append(dict(function['instructions'][0],addr='0x1104'))
            elif mutation == 'original': function['instructions'][0]['original_flow']='COMPUTED_JUMP'
            with self.subTest(mutation=mutation), self.assertRaises(Error): tail.verify(plan,report,function)
        plan,report,function = self.prepared()
        report['decisions'][0]['outcome']='instruction_unavailable'
        function['instructions']=[]
        tail.verify(plan,report,function,annotate=True)

    def test_import_byte_validation_recognizes_proved_tail_not_bl(self):
        self.setup_stub()
        self.data[0x100:0x104]=self.payload
        instruction={'bytes':self.payload.hex(),'flow':'CALL_TERMINATOR'}
        self.assertIsNone(import_links.call_bytes(self.data,self.parsed,instruction,self.start,0x1180))
        self.assertEqual(import_links.call_bytes(self.data,self.parsed,instruction,self.start,0x1180,tail_target=0x1180),
                         self.payload.hex())

    def test_native_scope_gap_is_independent_of_warning_text(self):
        scope = {'policy':'macscope-focused-native-scope/1','status':'partial','operations_scanned':4,
                 'operations_truncated':False,'outside_body_operations':1,
                 'outside_body_addresses':['0x1120'],'error':None}
        function={'body_ranges':[['0x1100','0x1103']], 'native_scope':scope,
                  'decompile_status':'complete','pseudocode':'return 42;', 'blocks':[]}
        focused.verify_native_scope(function)
        result=flow_evidence.review(function,arch='arm64')
        self.assertEqual(result['decompile_status'],'partial')
        self.assertEqual(result['engine_decompile_status'],'complete')
        self.assertEqual(result['control_flow_gaps'][0]['reason'],'native_operations_outside_body')
        for changes in ({'status':'complete'},{'outside_body_addresses':['0x1100']},
                        {'operations_scanned':100001},{'outside_body_addresses':[]}):
            with self.subTest(changes=changes),self.assertRaises(Error):
                focused.verify_native_scope(dict(function,native_scope=dict(scope,**changes)))
