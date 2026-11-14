"""Coordinator durability/resource tests with a mocked native worker."""
import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock
from macscope import batch_export as batch
from macscope.errors import Error

class BatchExportTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.source = self.path/'saved'
        self.source.mkdir()
        (self.source/'db').write_text('saved')
        self.snapshot = {'analysis_id':'a', 'functions':[{'entry_va':hex(i)} for i in range(1,4)]}
        self.project = SimpleNamespace(path=self.path, snapshot=lambda image:(self.snapshot, {'analysis_program_sha256':'digest'}))
        self.image = {'image_id':'image'}
        self.args = SimpleNamespace(batch_size=2, reserve_mib=128, entry=None, resume=False)
        for name, value in [('analyzed_program', self.source), ('worker_limits', {})]:
            patch = mock.patch.object(batch.engine, name, return_value=value)
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(batch.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**10))
        self.disk = patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(batch.engine, 'run', side_effect=self.worker)
        self.run = patch.start(); self.addCleanup(patch.stop)
        self.serial = 0

    def worker(self, project, image, mode, args, deps, *, bulk_entries):
        self.serial += 1
        job = {'job_id':f'{self.serial:032x}'}
        copy = self.path/'jobs'/job['job_id']/'program'
        copy.mkdir(parents=True)
        (copy/'db').write_text('copy')
        return {'functions':[{'entry_va':e, 'decompile_status':'complete', 'pseudocode':'return;'} for e in bulk_entries]}, job

    def export(self):
        return batch.export(self.project,self.image,self.args,{})

    def test_chunks_export_cleanup_and_resume_without_native_work(self):
        result = self.export()
        self.assertEqual(result['record_count'], 3)
        self.assertEqual([c.kwargs['bulk_entries'] for c in self.run.call_args_list], [['0x1','0x2'],['0x3']])
        self.assertFalse(list((self.path/'jobs').glob('*/program')))
        self.assertTrue((self.source/'db').exists())
        self.args.resume = True
        self.run.reset_mock()
        self.assertEqual(self.export()['record_count'],3)
        self.run.assert_not_called()

    def test_failed_chunk_preserves_committed_prefix_and_diagnostics(self):
        def fail_second(*args, **kwargs):
            if kwargs['bulk_entries']==['0x3']:
                raise Error('native_failure','failed', partial={'job_id':'failed-job'})
            return self.worker(*args,**kwargs)
        self.run.side_effect = fail_second
        with self.assertRaises(Error) as caught:
            self.export()
        self.assertEqual(caught.exception.partial['completed'],2)
        self.assertEqual(caught.exception.partial['job_id'],'failed-job')
        self.args.resume=True
        self.run.side_effect=self.worker
        self.run.reset_mock()
        self.assertEqual(self.export()['record_count'],3)
        self.assertEqual(self.run.call_args.kwargs['bulk_entries'],['0x3'])

    def test_record_tampering_prevents_resume(self):
        result=self.export()
        (Path(result['path'])/'functions/0x1.json').write_text('{}')
        self.args.resume=True
        with self.assertRaises(Error) as caught:
            self.export()
        self.assertEqual(caught.exception.code,'batch_integrity')

    def test_partial_chunk_index_is_rejected(self):
        result=self.export()
        path=Path(result['path'])/'index.json'
        value=json.loads(path.read_text());del value['records']['0x2'];path.write_text(json.dumps(value))
        self.args.resume=True
        with self.assertRaises(Error) as caught:self.export()
        self.assertEqual(caught.exception.code,'batch_index')

    def test_low_disk_does_not_start_worker(self):
        self.disk.return_value=SimpleNamespace(free=1)
        with self.assertRaises(Error) as caught:self.export()
        self.assertEqual(caught.exception.code,'batch_disk_reserve')
        self.run.assert_not_called()

    def test_wrong_worker_selection_is_not_persisted(self):
        self.run.return_value=({'functions':[]},{'job_id':'1'*32});self.run.side_effect=None
        with self.assertRaises(Error) as caught:self.export()
        self.assertEqual(caught.exception.code,'batch_result')
        self.assertFalse(list(self.path.glob('batch-exports/*/index.json')))

    def test_interrupted_index_write_replays_whole_chunk(self):
        real_write = batch.write_json
        def fail_index(path, *args, **kwargs):
            if path.name == 'index.json':
                raise OSError('simulated interruption before atomic index publication')
            return real_write(path, *args, **kwargs)
        with mock.patch.object(batch, 'write_json', side_effect=fail_index):
            with self.assertRaises(OSError):self.export()
        self.args.resume=True
        self.run.reset_mock()
        self.assertEqual(self.export()['record_count'],3)
        self.assertEqual(self.run.call_args_list[0].kwargs['bulk_entries'],['0x1','0x2'])
        # Neither an orphan prefix nor a new attempt is silently treated as cached success.
        record = next(self.path.glob('batch-exports/*/functions/0x1.json'))
        self.assertEqual(json.loads(record.read_text())['job_id'],f'{2:032x}')

    def test_worker_failure_status_cannot_be_cached_as_completed(self):
        self.run.return_value=({'functions':[
            {'entry_va':e,'decompile_status':'failed'} for e in ['0x1','0x2']]}, {'job_id':'1'*32})
        self.run.side_effect=None
        with self.assertRaises(Error) as caught:self.export()
        self.assertEqual(caught.exception.code,'batch_result')

    def rewrite_record(self, destination, entry, mutate):
        """Model a corrupt assembled export whose index hash is self-consistent."""
        path = destination/'functions'/(entry+'.json')
        record = json.loads(path.read_text())
        changed = mutate(record)
        path.write_text(json.dumps(record if changed is None else changed))
        index_path = destination/'index.json'
        index = json.loads(index_path.read_text())
        index['records'][entry]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        index_path.write_text(json.dumps(index))

    def test_rehashed_inconsistent_receipt_is_rejected_without_mutation(self):
        mutations = {
            'export': lambda r:r.update(export_id='different'),
            'semantics': lambda r:r.update(semantics='isolated'),
            'chunk_subset': lambda r:r.update(chunk_entries=['0x3','0x1']),
            'chunk_type': lambda r:r.update(chunk_entries='0x3'),
            'job_missing': lambda r:r.pop('job_id') and None,
            'job_malformed': lambda r:r.update(job_id='../outside'),
            'job_type': lambda r:r.update(job_id=[]),
            'function_type': lambda r:r.update(function=[]),
            'function_address': lambda r:r['function'].update(entry_va='0x1'),
            'status': lambda r:r['function'].update(decompile_status='not_requested'),
            'nonobject': lambda r:[],
        }
        result = self.export()
        destination = Path(result['path'])
        originals = {p:p.read_bytes() for p in destination.rglob('*.json')}
        self.args.resume = True
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                for path, content in originals.items():path.write_bytes(content)
                self.rewrite_record(destination, '0x3', mutation)
                before = {p:p.read_bytes() for p in destination.rglob('*.json')}
                self.run.reset_mock()
                with self.assertRaises(Error) as caught:self.export()
                self.assertEqual(caught.exception.code,'batch_record')
                self.run.assert_not_called()
                self.assertEqual(before,{p:p.read_bytes() for p in destination.rglob('*.json')})

    def test_reordered_original_chunk_is_rejected(self):
        destination = Path(self.export()['path'])
        self.rewrite_record(destination,'0x1',lambda r:r.update(chunk_entries=['0x2','0x1']))
        self.args.resume=True
        self.run.reset_mock()
        with self.assertRaises(Error) as caught:self.export()
        self.assertEqual(caught.exception.code,'batch_record')
        self.run.assert_not_called()

    def test_same_chunk_cannot_combine_different_job_receipts(self):
        destination = Path(self.export()['path'])
        self.rewrite_record(destination,'0x2',lambda r:r.update(job_id='f'*32))
        self.args.resume=True
        self.run.reset_mock()
        with self.assertRaises(Error) as caught:self.export()
        self.assertEqual(caught.exception.code,'batch_record')
        self.run.assert_not_called()

    def test_not_requested_status_remains_resumable(self):
        worker = self.worker
        def no_pseudocode(*args,**kwargs):
            result,job = worker(*args,**kwargs)
            for function in result['functions']:
                function.update(decompile_status='not_requested',pseudocode=None)
            return result,job
        self.run.side_effect=no_pseudocode
        result=self.export()
        self.assertEqual(result['outcomes'],{'not_requested':3})
        self.args.resume=True
        self.run.reset_mock()
        self.assertEqual(self.export()['outcomes'],{'not_requested':3})
        self.run.assert_not_called()

    def test_invalid_index_status_type_has_structured_error(self):
        destination = Path(self.export()['path'])
        path = destination/'index.json'
        index = json.loads(path.read_text())
        index['records']['0x1']['status'] = []
        path.write_text(json.dumps(index))
        self.args.resume=True
        self.run.reset_mock()
        with self.assertRaises(Error) as caught:self.export()
        self.assertEqual(caught.exception.code,'batch_index')
        self.run.assert_not_called()
