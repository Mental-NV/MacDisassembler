"""Coordinator durability/resource tests with a mocked native worker."""
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
