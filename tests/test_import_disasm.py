"""Owned selected-byte contracts; native instruction oracle is a separate gate."""
import copy
import hashlib
import struct
from unittest.mock import patch
from macscope import cli, import_disasm as subject, storage
from test_core import TemporaryCase
from test_macho import command, image as macho_image


class ImportDisasmTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.project_ = self.project()
        self.raw = b'\0'*256 + bytes.fromhex('400580d2c0035fd6') + b'\0'*248
        self.image = {'image_id':'owned','arch':'arm64','sha256':hashlib.sha256(self.raw).hexdigest(),
                      'offset':'0x0','engine_baseline_sha256':'a'*64}
        self.parsed = {'segments':[{'va':'0x1000','size':'0x200','file_offset':'0x0','file_size':'0x200','protections':5}],
                       'sections':[{'va':'0x1100','size':'0x100','file_offset':'0x100','flags':'0x80000400'}],
                       'loader':{'data_in_code':None,'encryption':None}}
        self.rows = [{'addr':'0x1100','bytes':'400580d2','mnemonic':'mov','text':'mov x0, #42'},
                     {'addr':'0x1104','bytes':'c0035fd6','mnemonic':'ret','text':'ret'}]

    def selection(self,start=0x1100,end=0x1108):
        with patch.object(subject,'thin',return_value=self.parsed):
            return subject.selection(self.raw,self.image,start,end)

    def test_exact_bytes_bounds_identity_and_zero_analysis(self):
        proof,payload = self.selection()
        self.assertEqual(payload,bytes.fromhex('400580d2c0035fd6'))
        self.assertEqual(proof['range_sha256'],hashlib.sha256(payload).hexdigest())
        self.assertEqual(subject.validate_rows({'instructions':self.rows,'gaps':[]},proof,payload),8)

    def test_real_parser_instruction_flags_for_both_architectures(self):
        for arch,cpu,payload in (('arm64',0x0100000C,bytes.fromhex('400580d2c0035fd6')),
                                 ('x86_64',0x01000007,bytes.fromhex('b82a000000c3'))):
            for flags in (0x80000400,0):
                section = struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1100,len(payload),
                                      0x100,2,0,0,flags,0,0,0)
                segment = struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x200,0,0x200,7,5,1,0)
                raw = bytearray(macho_image(cpu=cpu,commands=[command(0x19,segment+section)]))
                raw.extend(bytes(0x200-len(raw)))
                raw[0x100:0x100+len(payload)] = payload
                selected = dict(self.image,arch=arch,sha256=hashlib.sha256(raw).hexdigest())
                if flags:
                    proof,actual = subject.selection(bytes(raw),selected,0x1100,0x1100+len(payload))
                    self.assertEqual(actual,payload)
                    self.assertEqual(proof['arch'],arch)
                else:
                    self.error('disasm_mapping',subject.selection,bytes(raw),selected,0x1100,0x1100+len(payload))

    def test_real_parser_rejects_partial_section_overlap(self):
        for flags in (0,1):  # File-backed data and zero-fill both make section identity ambiguous.
            sections = struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1200,8,0x200,2,0,0,0x80000400,0,0,0)
            sections += struct.pack('<16s16s2Q8I',b'__data',b'__TEXT',0x1204,4,0x204,2,0,0,flags,0,0,0)
            segment = struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x300,0,0x300,7,5,2,0)
            raw = bytearray(macho_image(commands=[command(0x19,segment+sections)]))
            raw.extend(bytes(0x300-len(raw)))
            raw[0x200:0x208] = bytes.fromhex('400580d2c0035fd6')
            selected = dict(self.image,sha256=hashlib.sha256(raw).hexdigest())
            self.error('disasm_mapping',subject.selection,bytes(raw),selected,0x1200,0x1208)

    def test_architecture_alignment_limits_and_mapping(self):
        self.error('disasm_alignment',self.selection,0x1101,0x1108)
        self.error('disasm_scope',self.selection,0x1100,0x2104)
        self.error('disasm_mapping',self.selection,0x11fc,0x1204)
        self.parsed['segments'].append({'va':'0x1100','size':'0x100','file_offset':None,'file_size':'0x0','protections':0})
        self.error('disasm_mapping',self.selection)

    def test_x86_variable_lengths_crossing_and_unknown(self):
        self.image['arch']='x86_64'
        self.raw=b'\0'*256+bytes.fromhex('b82a000000c3')+b'\0'*250
        proof,payload=self.selection(0x1100,0x1106)
        rows=[{'addr':'0x1100','bytes':'b82a000000','mnemonic':'mov','text':'mov eax, 42'},
              {'addr':'0x1105','bytes':'c3','mnemonic':'ret','text':'ret'}]
        self.assertEqual(subject.validate_rows({'instructions':rows,'gaps':[]},proof,payload),6)
        for reason in ('undecodable_or_unavailable','instruction_crosses_range_boundary'):
            self.assertEqual(subject.validate_rows({'instructions':[], 'gaps':[{'start_va':'0x1100','end_va':'0x1106','reason':reason}]},proof,payload),0)
        rows[1]['addr']='0x1104'
        self.error('disasm_result',subject.validate_rows,{'instructions':rows,'gaps':[]},proof,payload)

    def test_corrupt_worker_bytes_and_gaps_rejected(self):
        proof,payload=self.selection()
        for mutate in (lambda x:x['instructions'][0].update(bytes='00000000'),
                       lambda x:x['instructions'].pop(),
                       lambda x:x['instructions'].reverse(),
                       lambda x:x.update(gaps=[{'start_va':'0x1108','end_va':'0x1108','reason':'undecodable_or_unavailable'}])):
            result={'instructions':copy.deepcopy(self.rows),'gaps':[]}
            mutate(result)
            self.error('disasm_result',subject.validate_rows,result,proof,payload)

    def test_data_and_encryption_are_not_guessed_as_code(self):
        self.parsed['loader']['data_in_code']={'status':'partial','records':[]}
        self.error('disasm_data_in_code',self.selection)
        self.parsed['loader']['data_in_code']=None
        self.parsed['loader']['encryption']={'cryptid':1,'slice_file_offset':'0x100','size':'0x8'}
        self.error('disasm_encryption',self.selection)

    def test_receipt_replay_identity_digest_and_no_native_dependencies(self):
        proof,payload=self.selection()
        job='b'*32
        (self.project_.path/'jobs'/job).mkdir()
        manifest={'job_id':job,'status':'complete','mode':'query','disasm_request':subject.binding(self.project_,self.image,proof)}
        response=cli.envelope('disasm',{'selection':manifest['disasm_request'],'instructions':self.rows,'gaps':[],
                                      'covered_bytes':8,'origin':{'job_id':job}})
        subject.publish(self.project_,manifest,response)
        with patch.object(subject.engine,'dependencies',side_effect=AssertionError('native replay')):
            self.assertEqual(subject.replay(self.project_,self.image,proof,payload,job),response)
        self.error('disasm_receipt_identity',subject.replay,self.project_,dict(self.image,engine_baseline_sha256='c'*64),proof,payload,job)
        path=self.project_.path/'jobs'/job/'disasm-result.json'
        path.write_text('{}')
        self.error('disasm_receipt_identity',subject.replay,self.project_,self.image,proof,payload,job)

    def test_callback_projection_preserves_fresh_receipt_and_offline_replay(self):
        from types import SimpleNamespace
        proof,payload=self.selection()
        job='d'*32
        (self.project_.path/'jobs'/job).mkdir()
        manifest={'job_id':job,'status':'complete','mode':'query','disasm_request':subject.binding(self.project_,self.image,proof)}
        args=SimpleNamespace(receipt=None,callback_evidence=True,ghidra=None,java_home=None)
        deps={'ghidra_version':'owned','ghidra_tree_sha256':'e'*64,'bridge_sha256':'f'*64}
        with patch.object(cli.metadata,'verified_slice',return_value=self.raw), \
             patch.object(subject,'selection',return_value=(proof,payload)), \
             patch.object(subject.engine,'dependencies',return_value=deps), \
             patch.object(subject,'run',return_value=({'instructions':self.rows,'gaps':[]},manifest)):
            fresh=cli.imported_disassembly(args,self.project_,self.image,0x1100,0x1108)
        path=self.project_.path/'jobs'/job/'disasm-result.json'
        before=path.read_bytes()
        self.assertNotIn(b'callback_evidence',before)
        self.assertIn('callback_evidence',fresh['data'])
        args.receipt=job
        with patch.object(cli.metadata,'verified_slice',return_value=self.raw), \
             patch.object(subject,'selection',return_value=(proof,payload)), \
             patch.object(subject.engine,'dependencies',side_effect=AssertionError('offline')), \
             patch.object(subject,'run',side_effect=AssertionError('offline')):
            replay=cli.imported_disassembly(args,self.project_,self.image,0x1100,0x1108)
        self.assertEqual(fresh,replay)
        self.assertEqual(before,path.read_bytes())

    def test_parser_requires_explicit_range_for_import_mode(self):
        for words in (['--address','0x1100','--from-import'],['--range','0x1100:0x1108','--receipt','b'*32]):
            args=cli.parser().parse_args(['disasm','--project',str(self.project_.path),*words])
            self.error('disasm_scope',cli.execute,args)

    def test_java_decoder_uses_only_selected_byte_buffer(self):
        from pathlib import Path
        source=(Path(subject.__file__).parent/'bridge'/'MacscopeDisasm.java').read_text()
        self.assertIn('decoder.disassemble(cursor,remaining)',source)
        self.assertNotIn('decoder.disassemble(cursor)',source)
        self.assertIn('java.util.Arrays.copyOfRange(bytes,(int)cursor.subtract(start),bytes.length)',source)

    def test_worker_preserves_timeout_and_cancellation(self):
        from contextlib import ExitStack
        from macscope.errors import Error
        from macscope import jobs
        args=cli.parser().parse_args(['disasm','--project',str(self.project_.path),
            '--from-import','--range','0x1100:0x1108','--experimental-trusted-input'])
        source=self.root/'baseline';source.mkdir();(source/'owned').write_bytes(b'owned database')
        image=dict(self.image,imported=True,engine_baseline_sha256=subject.tree_digest(source),
                   import_dependencies={'ghidra_tree_sha256':'d'*64})
        deps={'ghidra_tree_sha256':'d'*64,'ghidra_path':str(self.root/'ghidra'),'java_home':str(self.root/'jdk')}
        proof,payload=self.selection()
        for status,code in (('timeout',7),('cancelled',130)):
            def timeout(*a,**kw):
                kw['manifest']['status']=status
                raise Error('owned_test_stop','owned test stop',code)
            with ExitStack() as stack:
                for name,value in [('require_worker_host',None),('matches_auxiliary_jdk',True),
                                   ('import_program_path',source),('profile','owned sandbox'),('verify_auxiliary_jdk',None)]:
                    stack.enter_context(patch.object(subject.engine,name,return_value=value))
                stack.enter_context(patch.object(subject.engine,'run_process',side_effect=timeout))
                caught=self.error('owned_test_stop',subject.run,self.project_,image,args,deps,proof,payload)
            _,record=jobs.get(self.project_,caught.partial['job_id'])
            self.assertEqual(record['status'],status)

    def test_publication_failure_retains_job_reference(self):
        proof,_=self.selection();job='d'*32
        (self.project_.path/'jobs'/job).mkdir()
        with patch.object(subject,'write_json',side_effect=OSError('owned publication failure')):
            error=self.error('disasm_publication',subject.publish,self.project_,{'job_id':job},{})
        self.assertEqual(error.partial,{'job_id':job})

    def test_null_receipt_data_is_explicit_error_not_python_crash(self):
        proof,payload=self.selection();job='e'*32
        (self.project_.path/'jobs'/job).mkdir()
        manifest={'job_id':job,'status':'complete','mode':'query','disasm_request':subject.binding(self.project_,self.image,proof)}
        subject.publish(self.project_,manifest,cli.envelope('disasm',None))
        self.error('disasm_receipt_identity',subject.replay,self.project_,self.image,proof,payload,job)
