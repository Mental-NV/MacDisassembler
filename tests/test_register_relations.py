import copy
import unittest
from unittest.mock import patch
from macscope import register_relations as relations, cli, engine
from macscope.errors import Error


def fixture(words, status='complete'):
    start=0x100;end=start+4*len(words)
    return {'status':status,'data':{'arch':'arm64','image_id':'a'*64,'slice_sha256':'b'*64,
        'function_id':'c'*64,'entry_va':hex(start),'origin':{'job_id':'d'*32,
        'extent':{'entry_va':hex(start),'end_va_exclusive':hex(end),'program_sha256':'e'*64}},
        'instructions':[{'addr':hex(start+4*i),'bytes':word.to_bytes(4,'little').hex()} for i,word in enumerate(words)],
        'coverage':{'instructions':{'status':'complete'}},'control_flow_gaps':[]}}


class RegisterRelationTests(unittest.TestCase):
    def view(self,row,start=None,end=None):
        extent=row['data']['origin']['extent']
        return relations.derive(row,(start or int(extent['entry_va'],16),end or int(extent['end_va_exclusive'],16)),abi='aapcs64')

    def test_opaque_post_call_value_forwarding(self):
        row=fixture([0x94000040,0xaa0003e2,0xaa0203f4,0xd63f0100]);before=copy.deepcopy(row)
        out=self.view(row);calls=[s for s in out['sites'] if 'register_inputs' in s]
        self.assertEqual(calls[-1]['register_inputs']['x20'],{'kind':'call_clobbered','register':'x0','call_va':'0x100'})
        self.assertEqual(out['status'],'partial');self.assertEqual(out['source_query_status'],'complete')
        self.assertEqual(out['register_origin_scope'],'function_entry')
        self.assertNotEqual(out['derived_input_sha256'],out['source_envelope_sha256'])
        self.assertNotIn('missing_evidence',out);self.assertEqual(row,before);self.assertEqual(out,self.view(row))

    def test_intervening_call_and_overwrite_do_not_keep_original(self):
        row=fixture([0x94000040,0xaa0003e2,0x94000040,0xaa0203f4,0xd63f0100])
        value=self.view(row)['sites'][-1]['register_inputs']['x20']
        self.assertEqual(value,{'kind':'call_clobbered','register':'x2','call_va':'0x108'})
        row=fixture([0x94000040,0xaa0303e2,0xaa0203f4,0xd63f0100])
        self.assertEqual(self.view(row)['sites'][-1]['register_inputs']['x20']['register'],'x3')

    def test_prologue_tbz_barrier_and_separate_local_range(self):
        row=fixture([0xa9bf4ff4,0xaa0003f4,0x94000040,0x36000040,0x94000040,0xaa0003e2,0xaa0203f4,0xd63f0100])
        whole=self.view(row);self.assertEqual(whole['stop_reason'],'unsupported_instruction_boundary')
        self.assertEqual(whole['interpreted_end_va'],'0x10c')
        calls=[s for s in whole['sites'] if 'register_inputs' in s]
        self.assertEqual(len(calls),1)
        for reg in ('x0','x1','x2'):self.assertEqual(calls[0]['register_inputs'][reg]['register'],reg)
        local=self.view(row,0x110,0x120);self.assertEqual(local['register_origin_scope'],'selected_range_only')
        self.assertEqual(local['entry_to_range_reachability'],'not_established')
        self.assertEqual(local['sites'][-1]['register_inputs']['x20']['call_va'],'0x110')
        self.assertNotIn('conditional_on_branches',local['sites'][-1])

    def test_invalid_range_rows_arch_and_budget(self):
        for bad in ('','0X100:0x104','0x100:0x100','0x100:0x102','0x100:0x304','-1:0x104'):
            with self.subTest(bad=bad),self.assertRaises(Error):relations.parse_range(bad)
        self.assertEqual(relations.parse_range('0x100:0x300'),(256,768))
        row=fixture([0xd503201f,0xd65f03c0])
        for field,value in [('addr','0x100'),('bytes','00')]:
            bad=copy.deepcopy(row);bad['data']['instructions'][1][field]=value
            with self.assertRaises(Error):self.view(bad)
        with self.assertRaises(Error):self.view(row,0xfc,0x108)
        row['data']['arch']='x86_64'
        with self.assertRaises(Error):self.view(row)
        row['data']['arch']='arm64'
        with patch.object(relations,'MAX_BYTES',1),self.assertRaises(Error):self.view(row)
        with self.assertRaises(Error):relations.derive(row,(0x100,0x108),abi=None)

    def test_partial_source_and_unknown_instruction_preserved(self):
        row=fixture([0xffffffff,0xd63f0100],status='partial');row['data']['control_flow_gaps']=[{'reason':'owned_gap'}]
        out=self.view(row);self.assertEqual(out['source_query_status'],'partial')
        self.assertEqual(out['source_control_flow_gaps'],[{'reason':'owned_gap'}])
        self.assertEqual(out['sites'],[]);self.assertEqual(out['interpreted_end_va'],'0x100')


class RegisterReceiptTests(unittest.TestCase):
    def setUp(self):
        import test_query_resume
        self.f=test_query_resume.FocusedResumeTests();self.f.setUp();self.addCleanup(self.f.doCleanups)

    def test_published_retry_and_no_engine(self):
        with patch.object(engine,'dependencies',return_value=self.f.deps),patch.object(engine,'run',side_effect=self.f.worker):self.f.resume()
        entry=int(self.f.entry,16);r=f'{hex(entry)}:{hex(entry+4)}'
        with patch.object(engine,'dependencies',side_effect=AssertionError('engine')),patch.object(engine,'run',side_effect=AssertionError('engine')):
            for requested in [self.f.original,self.f.attempt]:
                out=relations.query(self.f.workspace,requested,r,'aapcs64')
                self.assertEqual(out['requested_job_id'],requested);self.assertEqual(out['publication_job_id'],self.f.attempt)
                args=cli.parser().parse_args(['register-relations','--project',str(self.f.workspace.path),'--query-job',requested,'--range',r,'--abi','aapcs64'])
                self.assertEqual(cli.execute(args)['status'],'partial')

    def test_unpublished_missing_and_changed_identity(self):
        r=f'{self.f.entry}:{hex(int(self.f.entry,16)+4)}'
        for job in [self.f.original,'f'*32,'bad']:
            with self.assertRaises(Error):relations.query(self.f.workspace,job,r,'aapcs64')
        with patch.object(engine,'dependencies',return_value=self.f.deps),patch.object(engine,'run',side_effect=self.f.worker):self.f.resume()
        changed=dict(self.f.workspace.images()[0],engine_baseline_sha256='f'*64)
        with patch.object(self.f.workspace,'images',return_value=[changed]),self.assertRaises(Error):relations.query(self.f.workspace,self.f.original,r,'aapcs64')

    def test_cli_exit6_and_changed_slice_fail_closed(self):
        import io
        from types import SimpleNamespace
        with patch.object(engine,'dependencies',return_value=self.f.deps),patch.object(engine,'run',side_effect=self.f.worker):self.f.resume()
        args=['register-relations','--project',str(self.f.workspace.path),'--query-job',self.f.original,
              '--range',f'{self.f.entry}:{hex(int(self.f.entry,16)+4)}','--abi','aapcs64','--json']
        with patch('sys.stdout',SimpleNamespace(buffer=io.BytesIO())),patch.object(engine,'dependencies',side_effect=AssertionError('engine')):
            self.assertEqual(cli.main(args),6)
        path=self.f.workspace.path/'inputs'/(self.f.image_id+'.macho')
        data=path.read_bytes();path.chmod(0o600);path.write_bytes(data[:-1]+bytes([data[-1]^1]))
        with patch('sys.stdout',SimpleNamespace(buffer=io.BytesIO())),patch('sys.stderr',io.StringIO()),patch.object(engine,'dependencies',side_effect=AssertionError('engine')):
            self.assertNotIn(cli.main(args),(0,6))
