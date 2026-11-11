"""Saved focused references preserve selection and discovery limits."""
import copy
import json
import unittest
from unittest.mock import patch
from macscope import cli,engine,focused_references,jobs,storage
import test_query_resume as fixture


class FocusedReferenceTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.FocusedResumeTests();self.f.setUp();self.addCleanup(self.f.doCleanups)

    def capture(self):
        def worker(*args,**kwargs):
            raw,job=self.f.worker(*args,**kwargs)
            raw['functions'][0]['xrefs_from_sample']=[{'from':self.f.entry,'to':hex(0x2000+i),'type':'DATA','operand_index':0} for i in range(3)]
            return raw,job
        with patch.object(engine,'dependencies',return_value=self.f.deps),patch.object(engine,'run',side_effect=worker):self.f.resume()

    def query(self,*options,job=None,entry=None,direction='from'):
        with patch.object(engine,'dependencies',side_effect=AssertionError('engine probe')),patch.object(engine,'run',side_effect=AssertionError('worker')):
            return self.f.run_cli('xrefs','--query-job',job or self.f.original,'--address',entry or self.f.entry,'--direction',direction,*options)

    def test_retry_identity_and_immutable_reference_replay(self):
        self.capture();before={str(p):p.read_bytes() for p in self.f.workspace.path.rglob('*') if p.is_file()}
        first=self.query();self.assertEqual(first,self.query());self.assertEqual(first['status'],'complete')
        self.assertEqual(first['data']['publication_job_id'],self.f.attempt)
        self.assertEqual(first['data']['requested_job_id'],self.f.original)
        self.assertEqual(len(first['data']['from_body']),3)
        self.assertEqual(self.query(job=self.f.attempt)['data']['source_envelope_sha256'],first['data']['source_envelope_sha256'])
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.f.workspace.path.rglob('*') if p.is_file()})
        incoming=self.query(direction='to');self.assertEqual(incoming['status'],'partial')
        self.assertIn('incoming_scope_not_global',incoming['data']['gaps']);self.assertEqual(incoming['data']['to_entry'],[])
        self.assertIsNone(incoming['coverage']['known_total'])

    def test_pagination_is_bound_to_receipt_direction_and_entry(self):
        self.capture();first=self.query('--limit','1');cursor=first['coverage']['next_cursor']
        self.assertEqual(first['status'],'partial');self.assertEqual(first['coverage']['known_total'],3)
        second=self.query('--limit','1','--cursor',cursor)
        self.assertNotEqual(first['data']['from_body'],second['data']['from_body'])
        self.f.error('stale_cursor',self.query,'--cursor',cursor,direction='both')
        self.f.error('stale_cursor',self.query,'--cursor',cursor,job=self.f.attempt)
        self.f.error('focused_terminal_transfer',self.query,entry=hex(int(self.f.entry,16)+4))

    def test_missing_stale_and_wrong_retry_fail_without_engine(self):
        self.f.error('evidence_query_unpublished',self.query)
        self.capture()
        failed='9'*32;self.f.write_job(failed,dict(self.f.record,job_id=failed,resumed_from=self.f.original,status='failed'))
        self.f.error('evidence_query_mismatch',self.query,job=failed)
        path=self.f.workspace.path/'jobs'/self.f.original/'query-result.json'
        receipt=json.loads(path.read_bytes());receipt['result']['data']['pseudocode']='changed';storage.write_json(path,receipt,force=True)
        self.f.error('query_receipt',self.query)

    def test_projection_limits_partial_and_unknown_targets(self):
        self.capture();data=self.query()['data']
        saved=jobs.query_receipt(self.f.workspace,self.f.original,self.f.request)
        saved=copy.deepcopy(saved);saved['status']='partial';f=saved['data']
        f['coverage']['xrefs_from']['status']='partial';f['xrefs_from_sample'][0]['to']=None
        f['xrefs_from_sample']*=2000
        result,rows=focused_references.project(saved,'from')
        self.assertEqual(len(rows),4096);self.assertEqual(result['omitted_records'],1904)
        for reason in ('record_budget','query_result_partial','xrefs_from_incomplete','unresolved_recorded_target'):self.assertIn(reason,result['gaps'])

    def test_selector_combinations_are_rejected_early(self):
        for flags in (['--from',self.f.entry],['--name','owned'],['--address',self.f.entry,'--query-job','bad']):
            args=['xrefs','--project',str(self.f.workspace.path),'--query-job',self.f.original,*flags]
            self.f.error('xref_query_scope',cli.execute,cli.parser().parse_args(args))
