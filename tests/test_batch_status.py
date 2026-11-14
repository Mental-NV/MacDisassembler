"""Saved progress is a metadata snapshot, never a native or integrity claim."""
import json
from pathlib import Path
from unittest import TestCase, mock
import test_batch_export as fixtures
from macscope import batch_export as batch, cli
from macscope.errors import Error
from macscope.storage import identity


class BatchStatusTests(TestCase):
    worker = fixtures.BatchExportTests.worker
    export = fixtures.BatchExportTests.export
    def setUp(self):
        fixtures.BatchExportTests.setUp(self)
        self.image['image_id'] = 'a'*64
        self.snapshot['analysis_id'] = 'b'*64

    def saved(self):
        result = self.export()
        self.folder = Path(result['path'])
        return result['export_id']

    def rebind(self, change):
        data = json.loads((self.folder/'manifest.json').read_text())
        change(data)
        new_id = identity(data)
        target = self.folder.parent/new_id
        self.folder.rename(target)
        self.folder = target
        (target/'manifest.json').write_text(json.dumps(data))
        return new_id

    def test_counts_do_not_claim_record_integrity_or_worker_state(self):
        eid = self.saved()
        (self.folder/'functions/0x1.json').write_text('corrupt')
        with mock.patch.object(batch.engine, 'run', side_effect=AssertionError('native')):
            result = batch.status(self.project, eid)
        self.assertEqual((result['indexed_count'], result['unindexed_count']), (3, 0))
        self.assertEqual(result['indexed_chunk_count'], 2)
        self.assertEqual(result['record_integrity'], 'not_checked')
        self.assertEqual(result['worker_state'], 'not_checked')
        self.assertEqual(result['indexed_outcomes'], {'complete':3})

    def test_missing_index_is_unindexed_not_failed_or_finished(self):
        eid = self.saved()
        (self.folder/'index.json').unlink()
        result = batch.status(self.project, eid)
        self.assertEqual(result['unindexed_count'], 3)
        self.assertFalse(result['index_present'])
        self.assertIsNone(result['index_sha256'])

    def test_partial_progress_index(self):
        eid = self.saved()
        path = self.folder/'index.json'
        index = json.loads(path.read_text())
        del index['records']['0x3']
        path.write_text(json.dumps(index))
        result = batch.status(self.project, eid)
        self.assertEqual((result['indexed_count'], result['unindexed_count']), (2,1))
        self.assertEqual(result['indexed_chunk_count'], 1)

    def test_cli_never_resolves_runtime_or_locks_writer(self):
        eid = self.saved()
        with mock.patch.object(cli, 'Project', return_value=self.project), \
                mock.patch.object(cli.engine, 'dependencies', side_effect=AssertionError('runtime')), \
                mock.patch.object(cli, 'check_engine_access', side_effect=AssertionError('trust')):
            result = cli.execute(cli.parser().parse_args(['batch-status', '--project', str(self.path), '--export-id', eid, '--json']))
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['data']['indexed_count'], 3)
        self.assertEqual(result['command'], 'batch-status')

    def test_paths_and_identity_rejected(self):
        eid = self.saved()
        for invalid in ('../escape', 'A'*64, '', 'a'*63):
            with self.subTest(invalid=invalid), self.assertRaises(Error):
                batch.status(self.project, invalid)
        (self.folder/'manifest.json').write_text('{}')
        with self.assertRaises(Error) as caught:
            batch.status(self.project, eid)
        self.assertEqual(caught.exception.code, 'batch_identity')

    def test_manifest_shape_rejected(self):
        changes = [lambda d:d.update(batch_size=True), lambda d:d.update(batch_size=0),
                   lambda d:d.update(entries=['0x2','0x1']), lambda d:d.update(entries=['0x01']),
                   lambda d:d.update(entries=['0x1','0x1']), lambda d:d.update(entries=['0xz']),
                   lambda d:d.update(entries=[]), lambda d:d.update(entries=[None]),
                   lambda d:d.update(schema='future'), lambda d:d.update(image_id='bad'),
                   lambda d:d.update(semantics='focused'), lambda d:d.update(coordinator_policy='future')]
        eid = self.saved()
        original = json.loads((self.folder/'manifest.json').read_text())
        for change in changes:
            with self.subTest(change=change):
                (self.folder/'manifest.json').write_text(json.dumps(original))
                eid = self.rebind(change)
                with self.assertRaises(Error) as caught:
                    batch.status(self.project, eid)
                self.assertEqual(caught.exception.code, 'batch_manifest')

    def test_index_shape_and_partial_chunk_rejected(self):
        eid = self.saved()
        path = self.folder/'index.json'
        original = json.loads(path.read_text())
        cases = [dict(original, export_id='bad'), dict(original, records=[]),
                 dict(original, records={'0x4':{'sha256':'a'*64,'status':'complete'}}),
                 dict(original, records={'0x1':{'sha256':'bad','status':'complete'}}),
                 dict(original, records={'0x1':{'sha256':'a'*64,'status':[]}}),
                 dict(original, records={'0x1':original['records']['0x1']})]
        for data in cases:
            with self.subTest(data=data):
                path.write_text(json.dumps(data))
                with self.assertRaises(Error):batch.status(self.project,eid)

    def test_dangling_symlink_index_is_not_missing_progress(self):
        eid = self.saved()
        path = self.folder/'index.json'
        path.unlink(); path.symlink_to(self.path/'absent')
        with self.assertRaises(Error):batch.status(self.project,eid)

    def test_common_output_cannot_overwrite_batch_evidence(self):
        args = cli.parser().parse_args(['batch-status','--project',str(self.path),'--export-id','a'*64])
        with self.assertRaises(Error) as caught:
            cli.protect_output(args,self.path/'batch-exports'/'anything.json')
        self.assertEqual(caught.exception.code,'output_workspace_conflict')

    def test_real_cli_reads_while_writer_locked_without_workspace_changes(self):
        import hashlib
        import os
        import subprocess
        import sys
        from macscope.storage import Project
        eid = self.saved()
        project = Project.create(self.path/'workspace')
        target = project.path/'batch-exports'/eid
        target.mkdir(parents=True)
        for name in ('manifest.json','index.json'):
            (target/name).write_bytes((self.folder/name).read_bytes())
        def inventory():
            return {str(p.relative_to(project.path)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in project.path.rglob('*') if p.is_file()}
        with project.writer():
            before = inventory()
            result = subprocess.run([sys.executable,'-m','macscope','batch-status',
                                     '--project',str(project.path),'--export-id',eid,'--json'],
                                    env=dict(os.environ, PYTHONPATH=str(Path(batch.__file__).parents[1]),
                                             PYTHONDONTWRITEBYTECODE='1'),
                                    capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertEqual(json.loads(result.stdout)['data']['indexed_count'],3)
            self.assertEqual(inventory(),before)
