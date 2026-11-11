"""Owned receipt-scoped joins, no address-only graph inference."""
import copy
import shlex
import unittest
from macscope import selected_reference_links as links


def row(job,entry,image='a'*64,refs=()):
    return dict(lead_id=job,image_id=image,requested_job_id=job*32,publication_job_id=job*32,
                entry_va=entry,status='verified',source_envelope_sha256=job*64,query_status='complete',
                outgoing_facets={},gaps=[],incoming_scope='partial_not_global',omitted_references=0,command=None,
                references=[dict(recorded=dict(**{'from':entry,'to':target,'type':'UNCONDITIONAL_CALL'}),direct_bytes_verified=direct,
                                 direct_instruction_bytes='04000094' if direct else None) for target,direct in refs])


class SelectedLinkTests(unittest.TestCase):
    def test_unique_same_image_and_cycle_are_independent_edges(self):
        rows=[row('1','0x100',refs=[('0x200',True)]),row('2','0x200',refs=[('0x100',True)])]
        links.classify(rows)
        self.assertTrue(all(r['references'][0]['status']=='verified_selected_direct_link' for r in rows))
        self.assertEqual(rows[0]['references'][0]['destination_receipts'][0]['job_id'],'2'*32)
        self.assertEqual(len(rows),2)

    def test_cross_image_ambiguity_and_unproven_targets(self):
        rows=[row('1','0x100',refs=[('0x200',True),(None,False),('0x300',False)]),row('2','0x200',image='b'*64),row('3','0x300')]
        links.classify(rows);self.assertEqual([r['status'] for r in rows[0]['references']],['target_not_selected','unresolved_target','recorded_target_match_not_direct_proof'])
        rows.append(row('4','0x300'));links.classify(rows)
        self.assertEqual(rows[0]['references'][2]['status'],'ambiguous_selected_entry')
        self.assertFalse(rows[0]['references'][2]['destination_receipts'])

    def test_command_path_is_quoted_never_binary_text(self):
        path="/tmp/owned project ' quote"
        hint=links.command_hint(path,'a'*64,'b'*32,'0x100')
        self.assertEqual(shlex.split(hint),['macscope','xrefs','--project',path,'--image','a'*64,'--query-job','b'*32,'--address','0x100','--direction','from','--format','text'])
        for path in ('/tmp/line\nbreak','x'*1025,'/tmp/\x1b'):
            self.assertIsNone(links.command_hint(path,'a'*64,'b'*32,'0x100'))

    def test_render_caps_controls_and_counts_are_deterministic(self):
        rows=[row(str(i%9+1),'0x100',refs=[('0x200',False)]*100) for i in range(20)]
        for r in rows:r['gaps']=['\x1b'*1000];r['command']='macscope '+('x'*4000)
        links.classify(rows)
        result={'data':{'selected_reference_links':dict(receipts=rows,omitted_receipts=3,omitted_references=5)}}
        before=copy.deepcopy(result);out=links.render(result)
        self.assertEqual(out,links.render(result));self.assertEqual(result,before)
        self.assertLessEqual(len(out),32768);self.assertLessEqual(out.count(b'\n'),200)
        self.assertNotIn(b'\x1b',out);self.assertIn(b'References displayed:',out);self.assertIn(b'omitted:',out)


class SelectedLinkBuildTests(unittest.TestCase):
    def setUp(self):
        import test_query_resume
        self.f=test_query_resume.FocusedResumeTests();self.f.setUp();self.addCleanup(self.f.doCleanups)

    def report(self):
        f=self.f
        return {'images':[dict(image_id=f.image_id,arch='arm64',artifact_sha256=f.image['artifact_sha256'],
                               slice_sha256=f.image['sha256'],import_program_sha256=f.image['engine_baseline_sha256'])],
                'leads':[dict(lead=dict(id='owned',image_id=f.image_id,query_job=f.original),function=dict(entry_va=f.entry))]}

    def capture(self):
        from unittest.mock import patch
        from macscope import engine
        def worker(*args,**kwargs):
            raw,job=self.f.worker(*args,**kwargs)
            raw['functions'][0]['xrefs_from_sample']=[{'from':self.f.entry,'to':hex(0x2000+i),'type':'DATA','operand_index':0} for i in range(3)]
            return raw,job
        with patch.object(engine,'dependencies',return_value=self.f.deps),patch.object(engine,'run',side_effect=worker):self.f.resume()

    def build(self,report=None):
        from unittest.mock import patch
        from macscope import engine
        with patch.object(engine,'dependencies',side_effect=AssertionError('engine')),patch.object(engine,'run',side_effect=AssertionError('worker')):
            return links.build(self.f.workspace,report or self.report())

    def test_verified_identity_hint_and_unavailable_receipts(self):
        before=self.build();self.assertIsNone(before['receipts'][0]['command'])
        self.assertEqual(before['receipts'][0]['reason'],'evidence_query_unpublished')
        self.capture();r=self.build()['receipts'][0]
        self.assertEqual(r['publication_job_id'],self.f.attempt);self.assertEqual(r['incoming_scope'],'partial_not_global')
        self.assertIn('--query-job '+self.f.original,r['command']);self.assertEqual(len(r['references']),3)
        report=self.report();report['leads'][0]['function']['entry_va']=hex(int(self.f.entry,16)+4)
        self.assertEqual(self.build(report)['receipts'][0]['status'],'unavailable')
        path=self.f.workspace.path/'jobs'/self.f.original/'query-result.json'
        from macscope import storage
        storage.write_json(path,{},force=True)
        self.assertIsNone(self.build()['receipts'][0]['command'])

    def test_caps_dedup_and_missing_leads_are_explicit(self):
        from unittest.mock import patch
        self.capture();report=self.report();report['leads']*=2
        self.assertEqual(len(self.build(report)['receipts']),1)
        report['leads']=[copy.deepcopy(report['leads'][0]) for _ in range(2)]
        report['leads'][1]['lead']['query_job']=self.f.attempt
        with patch.object(links,'MAX_RECEIPTS',1),patch.object(links,'MAX_REFERENCES',1):
            r=self.build(report);self.assertEqual(r['omitted_receipts'],1);self.assertEqual(r['omitted_references'],2)
        for lead in report['leads']:lead['function']=None;lead['lead'].pop('query_job')
        self.assertEqual(len(self.build(report)['receipts']),2)

    def test_data_reference_is_not_promoted_by_matching_call_bytes(self):
        from unittest.mock import patch
        self.capture()
        ins={'addr':self.f.entry,'bytes':'00000094','flow':'UNCONDITIONAL_CALL'}
        with patch.object(links.focused,'direct_calls',return_value=[(ins,'0x2000')]):
            refs=self.build()['receipts'][0]['references']
        self.assertFalse(refs[0]['direct_bytes_verified'])
        self.assertIsNone(refs[0]['direct_instruction_bytes'])

    def test_opt_in_envelope_stays_partial_even_with_resolved_leads(self):
        from unittest.mock import patch
        from macscope import cli
        report={'leads':[{'status':'resolved'}]}
        with patch.object(cli.evidence,'load',return_value={}),patch.object(cli.evidence,'export',return_value=report), \
             patch.object(cli.objc_type_evidence,'redact_report',side_effect=lambda r,_:r), \
             patch.object(links,'build',return_value={'policy':links.POLICY,'status':'partial'}):
            args=cli.parser().parse_args(['evidence','--project',str(self.f.workspace.path),'--leads','unused','--format','links'])
            self.assertEqual(cli.execute(args)['status'],'partial')
