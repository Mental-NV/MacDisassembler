import unittest
from unittest.mock import patch
from macscope import evidence, engine
from macscope.errors import Error


class ExplicitReceiptEvidenceTests(unittest.TestCase):
    def setUp(self):
        import test_query_resume
        self.f=test_query_resume.FocusedResumeTests();self.f.setUp();self.addCleanup(self.f.doCleanups)

    def capture(self):
        with patch.object(engine,'dependencies',return_value=self.f.deps),patch.object(engine,'run',side_effect=self.f.worker):
            self.f.resume()

    def select(self, ids=None):
        with patch.object(engine,'dependencies',side_effect=AssertionError('engine')),patch.object(engine,'run',side_effect=AssertionError('worker')):
            return evidence.from_query_jobs(self.f.workspace,ids or [self.f.original])

    def test_published_original_and_retry_exact_pins(self):
        self.capture()
        for requested in (self.f.original,self.f.attempt):
            m=self.select([requested]);lead=m['leads'][0]
            self.assertEqual(lead['id'],'job-'+requested);self.assertEqual(lead['query_job'],requested)
            self.assertEqual(lead['value'],self.f.entry)
            self.assertEqual(m['images'][0]['import_program_sha256'],self.f.image['engine_baseline_sha256'])
            expected={'schema':evidence.LEADS_SCHEMA,'images':[dict(image_id=self.f.image_id,arch='arm64',
                artifact_sha256=self.f.image['artifact_sha256'],slice_sha256=self.f.image['sha256'],
                import_program_sha256=self.f.image['engine_baseline_sha256'])],
                'leads':[dict(id='job-'+requested,image_id=self.f.image_id,kind='address',value=self.f.entry,query_job=requested)]}
            self.assertEqual(m,expected)
            self.assertEqual(evidence.export(self.f.workspace,m),evidence.export(self.f.workspace,expected))

    def test_unpublished_missing_and_invalid_selection(self):
        with self.assertRaises(Error) as c:self.select()
        self.assertEqual(c.exception.code,'evidence_query_unpublished')
        with self.assertRaises(Error):self.select(['f'*32])
        for selection in ([],[self.f.original]*2,['../job'],['a'*31],[f'{n:032x}' for n in range(17)]):
            with self.subTest(selection=selection),self.assertRaises(Error) as c:
                evidence.from_query_jobs(self.f.workspace,selection)
            self.assertEqual(c.exception.code,'evidence_query_selection')

    def test_current_image_pin_and_published_receipt_corruption(self):
        self.capture()
        image=dict(self.f.workspace.images()[0],engine_baseline_sha256='f'*64)
        with patch.object(self.f.workspace,'images',return_value=[image]),self.assertRaises(Error):self.select()
        from macscope.storage import canonical
        p=self.f.workspace.path/'jobs'/self.f.original/'query-result.json'
        import json
        saved=json.loads(p.read_text());p.chmod(0o600);saved['result']['data']['entry_va']='0x9999';p.write_bytes(canonical(saved))
        with self.assertRaises(Error) as c:self.select()
        self.assertEqual(c.exception.code,'query_receipt')

    def test_parser_mutual_exclusion(self):
        from macscope.cli import parser
        p=parser()
        a=p.parse_args(['evidence','--project','p','--query-job','a'*32,'--query-job','b'*32])
        self.assertEqual(a.evidence_query_jobs,['a'*32,'b'*32]);self.assertIsNone(a.leads)
        with self.assertRaises(Error):p.parse_args(['evidence','--project','p','--query-job','a'*32,'--leads','x'])

    def test_unrelated_retry_and_unsupported_job_are_rejected(self):
        self.capture()
        unrelated='d'*32
        self.f.write_job(unrelated,dict(self.f.record,job_id=unrelated,resumed_from=self.f.original,status='failed'))
        with self.assertRaises(Error) as c:self.select([unrelated])
        self.assertEqual(c.exception.code,'evidence_query_mismatch')
        with patch.object(evidence.jobs,'get',return_value=(None,dict(mode='analyze'))),self.assertRaises(Error):
            self.select()

    def test_four_image_budget_and_missing_image(self):
        records=[];images=[]
        for n in range(5):
            image_id=f'{n+1:064x}'
            request=dict(self.f.request,image_id=image_id)
            records.append((None,dict(mode='query',focused_request=request)))
            images.append(dict(image_id=image_id))
        with patch.object(self.f.workspace,'images',return_value=images),patch.object(evidence.jobs,'get',side_effect=records), \
             patch.object(evidence,'open_image') as opened,patch.object(evidence.metadata,'verified_slice'), \
             patch.object(evidence,'focused_query'),self.assertRaises(Error) as c:
            self.select([f'{n+1:032x}' for n in range(5)])
        self.assertEqual(c.exception.code,'evidence_manifest_limit');self.assertEqual(opened.call_count,4)
        with patch.object(self.f.workspace,'images',return_value=[]),self.assertRaises(Error) as c:self.select()
        self.assertEqual(c.exception.code,'evidence_image_missing')
