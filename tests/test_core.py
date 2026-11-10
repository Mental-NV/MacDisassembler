"""Stdlib regression tests for the CLI, cache, storage and owned worker runner.

No Ghidra/JVM is launched. Engine checks use tiny temporary dependency trees;
worker lifecycle checks launch only this interpreter and self-owned children.
Run: PYTHONPATH=src python3 -m unittest discover -s tests -v
"""
import argparse
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile

# Direct invocation and unittest discovery both work without installing a wheel.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from macscope import SCHEMA_VERSION
from macscope import body_ownership, cli, doctor_probe, engine, engine_checks, evidence, jobs, macho, schema, search, storage
from macscope.errors import Error


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        # macOS /tmp and /var are symlinks, intentionally rejected by checked_path.
        root = '/private/tmp' if Path('/private/tmp').is_dir() else str(Path(tempfile.gettempdir()).resolve())
        self.temp = tempfile.TemporaryDirectory(prefix='macscope-test-', dir=root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(Error) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def project(self, name='workspace'):
        return storage.Project.create(self.root / name)


SYNTHETIC_IMAGE_ID = 'c' * 64
SYNTHETIC_ANALYSIS_ID = 'd' * 64


def synthetic_program(path, payload=b'owned fixture Program'):
    repository = path / 'image.rep'
    data = repository / 'idata'
    database = data / '00' / '~00000000.db' / 'db.1.gbf'
    database.parent.mkdir(parents=True)
    database.write_bytes(payload)
    (path / 'image.gpr').write_bytes(payload)
    (repository / 'project.prp').write_bytes(b'project metadata')
    (data / '~index.dat').write_bytes(b'local repository index')
    return database


def synthetic_snapshot(project, aid=SYNTHETIC_ANALYSIS_ID, *, slice_bytes=None):
    """Commit a deterministic, engine-independent snapshot through the public DB."""
    image = {'image_id': SYNTHETIC_IMAGE_ID, 'arch': 'arm64', 'sha256': '0' * 64,
             'artifact_sha256': '1' * 64, 'input_name': 'synthetic.macho'}
    if slice_bytes is not None:
        image['sha256'] = hashlib.sha256(slice_bytes).hexdigest()
        storage.atomic(project.path / 'inputs' / (SYNTHETIC_IMAGE_ID + '.macho'), slice_bytes, mode=0o400)
    functions = []
    for index, name in enumerate(('duplicate', 'duplicate', 'unique')):
        address = hex(0x100000000 + index * 0x10)
        functions.append({
            'function_id': f'function-{index}', 'image_id': image['image_id'],
            'analysis_id': aid, 'arch': 'arm64', 'entry_va': address,
            'address_space': 'ram', 'engine_entry': address,
            'name': name, 'names': [{'name': name, 'origin': 'ghidra'}],
            'body_ranges': [[address, hex(int(address, 16) + 3)]],
            'signature': f'void {name}(void)', 'is_thunk': False, 'is_external': False,
            'decompile_status': 'complete', 'pseudocode': f'void {name}(void) {{ return; }}',
            'instructions': [{'addr': address, 'mnemonic': 'ret', 'bytes': 'c0035fd6'}],
            'blocks': [{'min': address, 'max': address, 'dsts': []}],
            'xrefs_to_entry': [], 'xrefs_from_sample': [], 'address_spans': [],
            'facets': {},
        })
    snapshot = {'analysis_id': aid, 'status': 'complete', 'image': image,
                'functions': functions, 'engine': {'function_count_total_reported_by_engine': 3,
                                                  'functions_truncated': False,
                                                  'symbols': [{'name': 'reference+anchor',
                                                               'address': '0x100000020'}],
                                                  'strings': [{'value': 'Some reference+anchor data',
                                                               'address': '0x100000050'}],
                                                  'coverage': {'symbols': {'status': 'complete'},
                                                               'strings': {'status': 'complete'}}},
                'limitations': ['Synthetic test fixture only.']}
    payload = storage.canonical(snapshot) + b'\n'
    storage.atomic(project.path / 'snapshots' / (aid + '.json'), payload, mode=0o400)
    record = {'snapshot_sha256': hashlib.sha256(payload).hexdigest(), 'job_id': 'synthetic-job',
              'analysis_program_sha256': '0' * 64}
    with project.db(False) as db:
        db.execute('INSERT OR REPLACE INTO images(id,arch,metadata,imported,active_analysis) VALUES(?,?,?,1,?)',
                   (image['image_id'], image['arch'], json.dumps(image), aid))
        db.execute('INSERT OR REPLACE INTO analyses(id,image_id,payload) VALUES(?,?,?)',
                   (aid, image['image_id'], json.dumps(record)))
    return snapshot, record


class AtomicStorageTests(TemporaryCase):
    def test_strict_json_bounds_nesting_without_counting_string_delimiters(self):
        value = {'escaped':'"\\[{' * (storage.MAX_JSON_DEPTH+1)}
        self.assertEqual(storage.strict_json(storage.canonical(value)),value)
        depth = storage.MAX_JSON_DEPTH
        storage.strict_json(b'['*depth+b'0'+b']'*depth)
        for payload in (b'['*(depth+1)+b'0'+b']'*(depth+1), b'{"x":1,"x":2}',
                        b'{"x":NaN}',b'{"x":1e999}',b'{}\0'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                storage.strict_json(payload)

    def test_canonical_and_identity_are_key_order_independent(self):
        self.assertEqual(storage.canonical({'b': 2, 'a': 1}), b'{"a":1,"b":2}')
        self.assertEqual(storage.identity({'b': 2, 'a': 1}), storage.identity({'a': 1, 'b': 2}))

    def test_atomic_write_has_private_permissions(self):
        target = self.root / 'output.json'
        storage.atomic(target, b'first')
        self.assertEqual(target.read_bytes(), b'first')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.glob('.macscope-*')), [])

    def test_existing_output_never_overwritten_without_force(self):
        target = self.root / 'output'
        target.write_bytes(b'original')
        error = self.error('output_exists', storage.atomic, target, b'replacement')
        self.assertEqual(error.exit_code, 8)
        self.assertEqual(target.read_bytes(), b'original')

    def test_force_replaces_complete_contents_and_mode(self):
        target = self.root / 'output'
        storage.atomic(target, b'old', mode=0o400)
        storage.atomic(target, b'new contents', force=True, mode=0o600)
        self.assertEqual(target.read_bytes(), b'new contents')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_publication_race_preserves_competing_output(self):
        target = self.root / 'output'
        real_link = os.link
        def race(src, dst, *args, **kwargs):
            target.write_bytes(b'concurrent writer')
            return real_link(src, dst, *args, **kwargs)
        with mock.patch.object(storage.os, 'link', side_effect=race):
            self.error('output_exists', storage.atomic, target, b'ours')
        self.assertEqual(target.read_bytes(), b'concurrent writer')
        self.assertEqual(list(self.root.glob('.macscope-*')), [])

    def test_failed_replace_preserves_original_and_removes_temporary(self):
        target = self.root / 'output'
        target.write_bytes(b'original')
        with mock.patch.object(storage.os, 'replace', side_effect=OSError('synthetic replace failure')):
            with self.assertRaises(OSError):
                storage.atomic(target, b'new', force=True)
        self.assertEqual(target.read_bytes(), b'original')
        self.assertEqual(list(self.root.glob('.macscope-*')), [])

    def test_output_symlink_is_rejected_even_with_force(self):
        victim = self.root / 'victim'
        victim.write_bytes(b'preserve')
        link = self.root / 'link'
        link.symlink_to(victim)
        self.error('symlink', storage.atomic, link, b'new', force=True)
        self.assertEqual(victim.read_bytes(), b'preserve')

    def test_output_symlink_parent_is_rejected(self):
        real = self.root / 'real'
        real.mkdir()
        link = self.root / 'link'
        link.symlink_to(real, target_is_directory=True)
        self.error('symlink', storage.atomic, link / 'output', b'new')
        self.assertFalse((real / 'output').exists())

    def test_replaced_directory_is_detected_before_publication(self):
        directory = self.root / 'reports'
        directory.mkdir()
        target = directory / 'report.json'
        moved = self.root / 'moved'
        real_fsync = os.fsync

        def replace_directory(fd):
            directory.rename(moved)
            directory.mkdir()
            target.write_bytes(b'other report')
            return real_fsync(fd)

        with mock.patch.object(storage.os, 'fsync', side_effect=replace_directory):
            error = self.error('output_directory_changed', storage.atomic, target, b'ours', force=True)
        self.assertEqual(error.exit_code, 8)
        self.assertEqual(target.read_bytes(), b'other report')
        self.assertEqual(list(moved.iterdir()), [])

    def test_replacement_stays_in_pinned_directory_at_commit(self):
        directory = self.root / 'reports'
        directory.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        victim = outside / 'report.json'
        victim.write_bytes(b'preserve')
        moved = self.root / 'moved'
        real_replace = os.replace

        def redirect(src, dst, **kwargs):
            directory.rename(moved)
            directory.symlink_to(outside, target_is_directory=True)
            return real_replace(src, dst, **kwargs)

        with mock.patch.object(storage.os, 'replace', side_effect=redirect):
            error = self.error('output_directory_changed', storage.atomic, directory / victim.name, b'ours', force=True)
        self.assertEqual(error.exit_code, 8)
        self.assertEqual(error.partial, {'published_in_original_directory': True})
        self.assertEqual(victim.read_bytes(), b'preserve')
        self.assertEqual((moved / victim.name).read_bytes(), b'ours')
        self.assertEqual(list(moved.glob('.macscope-*')), [])


class ProjectTests(TemporaryCase):
    def test_sqlite_paths_preserve_literal_uri_characters(self):
        workspace = self.project('Project #1? Ω')
        self.assertEqual(workspace.images(), [])
        self.assertEqual(synthetic_snapshot(workspace)[0], workspace.snapshot(workspace.select())[0])

    def test_create_makes_private_workspace_and_schema(self):
        project = self.project()
        self.assertEqual(stat.S_IMODE(project.path.stat().st_mode), 0o700)
        for child in ('inputs', 'engine', 'snapshots', 'jobs', 'home', 'tmp'):
            self.assertEqual(stat.S_IMODE((project.path / child).stat().st_mode), 0o700)
        for child in ('project.json', 'index.sqlite'):
            self.assertEqual(stat.S_IMODE((project.path / child).stat().st_mode), 0o600)
        manifest = json.loads((project.path / 'project.json').read_text())
        self.assertEqual(manifest['schema_version'], '1.0')
        self.assertEqual(manifest['project_id'], project.project_id)
        self.assertEqual(project.images(), [])

    def test_existing_workspace_is_not_replaced(self):
        project = self.project()
        self.error('workspace_exists', storage.Project.create, project.path)
        self.assertEqual(storage.Project(project.path).project_id, project.project_id)

    def test_nonprivate_workspace_rejected(self):
        project = self.project()
        project.path.chmod(0o755)
        self.error('workspace_permissions', storage.Project, project.path)

    def test_unknown_workspace_schema_rejected(self):
        project = self.project()
        storage.write_json(project.path / 'project.json', {'schema_version': '99', 'project_id': project.project_id}, force=True)
        self.error('workspace_schema', storage.Project, project.path)

    def test_malformed_workspace_manifest_returns_typed_error(self):
        project = self.project()
        manifest = project.path / 'project.json'
        for invalid in (b'{', b'[1]', b'{"schema_version":"1.0"}',
                        b'{"schema_version":1}', b'{"schema_version":"1.0","project_id":"invalid"}',
                        b'[' * 3000 + b']' * 3000):
            with self.subTest(prefix=invalid[:40]):
                storage.atomic(manifest, invalid, force=True)
                self.error('workspace_manifest', storage.Project, project.path)

    def test_corrupt_workspace_index_returns_typed_error(self):
        project = self.project()
        index = project.path / 'index.sqlite'
        invalid = b'owned malformed index'
        index.write_bytes(invalid)
        self.error('workspace_index', storage.Project, project.path)
        self.error('workspace_index', project.images)
        self.assertEqual(index.read_bytes(), invalid)

    def test_workspace_index_requires_core_tables_and_columns(self):
        project = self.project()
        with project.db(False) as db:
            db.execute('ALTER TABLE images RENAME TO archived_images')
            db.execute('CREATE VIEW images AS SELECT * FROM archived_images')
        self.error('workspace_index', storage.Project, project.path)
        with project.db(False) as db:
            db.execute('DROP VIEW images')
            db.execute('CREATE TABLE images(id TEXT PRIMARY KEY)')
        self.error('workspace_index', storage.Project, project.path)

    def test_busy_workspace_index_can_be_retried(self):
        project = self.project()
        with project.db(False) as db:
            db.execute('BEGIN EXCLUSIVE')
            with self.assertRaises(Error) as caught:
                storage.Project(project.path)
            self.assertEqual(caught.exception.code, 'workspace_index_busy')
            self.assertTrue(caught.exception.retryable)
        self.assertEqual(storage.Project(project.path).project_id, project.project_id)

    def test_writer_conflict_is_retryable_and_lock_released(self):
        first = self.project()
        second = storage.Project(first.path)
        with first.writer():
            with self.assertRaises(Error) as caught:
                with second.writer():
                    self.fail('A second writer acquired the lock')
            self.assertEqual(caught.exception.code, 'writer_conflict')
            self.assertTrue(caught.exception.retryable)
        with second.writer():
            pass

    def test_writer_exception_releases_lock(self):
        project = self.project()
        with self.assertRaisesRegex(RuntimeError, 'test abort'):
            with project.writer():
                raise RuntimeError('test abort')
        with project.writer():
            pass

    def test_database_default_is_readonly(self):
        project = self.project()
        with project.db() as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("DELETE FROM images")

    def test_database_context_closes_connection(self):
        project = self.project()
        with project.db() as db:
            self.assertEqual(db.execute('SELECT 1').fetchone(), (1,))
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')

    def test_database_context_rolls_back_failed_transaction(self):
        project = self.project()
        with self.assertRaisesRegex(RuntimeError, 'rollback fixture'):
            with project.db(False) as db:
                db.execute('INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)',
                           ('rollback', 'arm64', '{}'))
                raise RuntimeError('rollback fixture')
        with project.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM images').fetchone(), (0,))

    def test_snapshot_round_trip_validates_digest(self):
        project = self.project()
        expected, record = synthetic_snapshot(project)
        self.assertEqual(project.snapshot(project.select()), (expected, record))

    def test_snapshot_corruption_is_rejected(self):
        project = self.project()
        snapshot, _ = synthetic_snapshot(project)
        target = project.path / 'snapshots' / (snapshot['analysis_id'] + '.json')
        storage.atomic(target, b'{"corrupted":true}\n', force=True, mode=0o400)
        self.error('snapshot_integrity', project.snapshot, project.select())

    def test_unanalyzed_image_is_rejected(self):
        project = self.project()
        self.error('not_analyzed', project.snapshot, {'image_id': 'not-analyzed', 'active_analysis': None})

    def test_missing_snapshot_record_is_rejected(self):
        project = self.project()
        self.error('snapshot_missing', project.snapshot,
                   {'image_id': SYNTHETIC_IMAGE_ID, 'active_analysis': SYNTHETIC_ANALYSIS_ID})

    def test_image_selector_reports_ambiguity(self):
        project = self.project()
        synthetic_snapshot(project)
        other = dict(image_id='e' * 64, arch='x86_64', sha256='0' * 64, artifact_sha256='1' * 64)
        with project.db(False) as db:
            db.execute('INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)',
                       (other['image_id'], other['arch'], json.dumps(other)))
        error = self.error('image_selector', project.select)
        self.assertEqual(len(error.partial), 2)
        self.assertEqual(project.select(arch='arm64')['image_id'], SYNTHETIC_IMAGE_ID)

    def test_invalid_indexed_ids_fail_before_opening_a_snapshot_path(self):
        project = self.project()
        snapshot, record = synthetic_snapshot(project)
        image = project.select()
        outside = self.root / 'outside.json'
        outside.write_bytes(storage.canonical(snapshot) + b'\n')
        traversal = '../../outside'
        with project.db(False) as db:
            db.execute('INSERT INTO analyses VALUES(?,?,?)', (traversal, image['image_id'], json.dumps(record)))
            db.execute('UPDATE images SET active_analysis=?', (traversal,))
        with mock.patch.object(storage, 'read_regular', side_effect=AssertionError('unexpected snapshot read')):
            self.error('workspace_image', project.select)
            self.error('snapshot_identity', project.snapshot, dict(image, active_analysis=traversal))

    def test_image_metadata_must_match_its_index_row(self):
        project = self.project()
        snapshot, _ = synthetic_snapshot(project)
        image = snapshot['image']
        for payload in (b'\xff', '[]', json.dumps(dict(image, arch='x86_64')),
                        json.dumps(dict(image, image_id='e' * 64)), json.dumps(dict(image, sha256=False))):
            with self.subTest(payload=payload):
                with project.db(False) as db:
                    db.execute('UPDATE images SET metadata=?', (payload,))
                self.error('workspace_image', project.images)
        with project.db(False) as db:
            db.execute("UPDATE images SET metadata=CAST(X'FF' AS TEXT)")
        self.error('workspace_index', project.images)

    def test_digest_valid_snapshot_must_match_selected_analysis_and_image(self):
        project = self.project()
        snapshot, record = synthetic_snapshot(project)
        target = project.path / 'snapshots' / (snapshot['analysis_id'] + '.json')
        first, second, _ = snapshot['functions']
        wrong_functions = (
            [first, first],
            [first, dict(second, function_id=first['function_id'])],
            [first, dict(second, entry_va='0x0100000000', engine_entry='0x0100000000')],
            [dict(first, analysis_id='e' * 64)],
            [dict(first, image_id='e' * 64)],
            [dict(first, arch='x86_64')],
            [dict(first, engine_entry=second['engine_entry'])],
        )
        for changed, code in ((dict(snapshot, analysis_id='e' * 64), 'snapshot_identity'),
                              (dict(snapshot, image=dict(snapshot['image'], arch='x86_64')), 'snapshot_identity'),
                              (dict(snapshot, functions=[None]), 'snapshot_format'), ([], 'snapshot_format'),
                              *((dict(snapshot, functions=functions), 'snapshot_function_identity')
                                for functions in wrong_functions)):
            with self.subTest(code=code, value=type(changed)):
                payload = storage.canonical(changed) + b'\n'
                storage.atomic(target, payload, force=True, mode=0o400)
                receipt = dict(record, snapshot_sha256=hashlib.sha256(payload).hexdigest())
                with project.db(False) as db:
                    db.execute('UPDATE analyses SET payload=?', (json.dumps(receipt),))
                self.error(code, project.snapshot, project.select())
        with project.db(False) as db:
            db.execute('UPDATE analyses SET payload=?', ('{"snapshot_sha256":0}',))
        self.error('snapshot_record', project.snapshot, project.select())

    def test_workspace_json_rejects_ambiguous_manifest_index_and_snapshot_records(self):
        project = self.project()
        snapshot, record = synthetic_snapshot(project)
        image = project.select()

        def invalid_payloads(value, duplicate):
            tail = storage.canonical(value)[1:]
            shadow = json.dumps({duplicate: 'shadowed'}).encode()[:-1]
            return (shadow + b',' + tail, b'{"extra":1e999,' + tail,
                    b'{"extra":' + b'[' * storage.MAX_JSON_DEPTH + b'0' + b']' * storage.MAX_JSON_DEPTH + b',' + tail)

        manifest = project.path / 'project.json'
        valid_manifest = manifest.read_bytes()
        for payload in invalid_payloads(json.loads(valid_manifest), 'project_id'):
            storage.atomic(manifest, payload, force=True)
            self.error('workspace_manifest', storage.Project, project.path)
        storage.atomic(manifest, valid_manifest, force=True)

        for payload in invalid_payloads(snapshot['image'], 'image_id'):
            with project.db(False) as db:
                db.execute('UPDATE images SET metadata=?', (payload.decode(),))
            self.error('workspace_image', project.images)
        with project.db(False) as db:
            db.execute('UPDATE images SET metadata=?', (json.dumps(snapshot['image']),))
        for payload in invalid_payloads(record, 'snapshot_sha256'):
            with project.db(False) as db:
                db.execute('UPDATE analyses SET payload=?', (payload.decode(),))
            self.error('snapshot_record', project.snapshot, image)

        path = project.path / 'snapshots' / (snapshot['analysis_id'] + '.json')
        valid_snapshot = path.read_bytes()
        for payload in invalid_payloads(snapshot, 'analysis_id'):
            storage.atomic(path, payload, force=True)
            receipt = dict(record, snapshot_sha256=hashlib.sha256(payload).hexdigest())
            with project.db(False) as db:
                db.execute('UPDATE analyses SET payload=?', (json.dumps(receipt),))
            self.error('snapshot_format', project.snapshot, image)
        storage.atomic(path, valid_snapshot, force=True, mode=0o400)
        with project.db(False) as db:
            db.execute('UPDATE analyses SET payload=?', (json.dumps(record),))
        self.assertEqual(project.snapshot(project.select()), (snapshot, record))


class PaginationAndSelectorsTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.snapshot, _ = synthetic_snapshot(self.project())
        self.rows = self.snapshot['functions']

    def page(self, cursor=None, aid='analysis-one', project_id='project-one', filters=None, limit=1):
        return cli.page(self.rows, argparse.Namespace(limit=limit, cursor=cursor), aid, project_id,
                        {'name_contains': None} if filters is None else filters)

    def select(self, **kwargs):
        values = dict(address=None, function_id=None, name=None)
        values.update(kwargs)
        return cli.select_function(self.rows, argparse.Namespace(**values))

    def test_page_traversal_has_no_duplicates_or_omissions(self):
        ids, cursor = [], None
        for _ in range(len(self.rows)):
            rows, cov = self.page(cursor)
            self.assertEqual(cov['returned_count'], 1)
            self.assertEqual(cov['known_total'], 3)
            ids.extend(row['function_id'] for row in rows)
            cursor = cov['next_cursor']
        self.assertIsNone(cursor)
        self.assertEqual(ids, [row['function_id'] for row in self.rows])
        self.assertEqual(cov['status'], 'complete')

    def test_cursor_rejects_new_analysis(self):
        _, cov = self.page()
        self.error('stale_cursor', self.page, cov['next_cursor'], aid='new-analysis')

    def test_cursor_rejects_other_project(self):
        _, cov = self.page()
        self.error('stale_cursor', self.page, cov['next_cursor'], project_id='other-project')

    def test_cursor_rejects_changed_filter(self):
        _, cov = self.page()
        self.error('stale_cursor', self.page, cov['next_cursor'], filters={'name_contains': 'unique'})

    def test_cursor_rejects_bad_encoding_and_shape(self):
        for bad in ('!!!', 'e30', 'not-base64', base64.urlsafe_b64encode(b'[]').decode()):
            with self.subTest(cursor=bad):
                self.error('stale_cursor', self.page, bad)

    def test_cursor_rejects_boolean_negative_and_out_of_bounds_offsets(self):
        _, cov = self.page()
        cursor = json.loads(base64.urlsafe_b64decode(cov['next_cursor'] + '=' * (-len(cov['next_cursor']) % 4)))
        for offset in (True, -1, len(self.rows), '1', 1.5):
            with self.subTest(offset=offset):
                bad = base64.urlsafe_b64encode(storage.canonical(dict(cursor, offset=offset))).decode()
                self.error('stale_cursor', self.page, bad)

    def test_ambiguous_name_returns_candidates(self):
        error = self.error('function_selector', self.select, name='duplicate')
        self.assertEqual(error.exit_code, 2)
        self.assertEqual([f['function_id'] for f in error.partial], ['function-0', 'function-1'])

    def test_unique_name_and_function_id_select_exactly(self):
        self.assertEqual(self.select(name='unique')['function_id'], 'function-2')
        self.assertEqual(self.select(function_id='function-1')['function_id'], 'function-1')

    def test_typed_unslid_hex_address_selects_entry(self):
        self.assertEqual(self.select(address='0x100000010')['function_id'], 'function-1')
        self.error('function_selector', self.select, address='0x100000011')

    def test_decimal_negative_overflow_and_non_hex_addresses_rejected(self):
        for address in ('4294967296', '-0x1', '0x10000000000000000', '0x', '0xnope', 'va:0x100000000'):
            with self.subTest(address=address):
                self.error('address', self.select, address=address)


class SchemaTests(unittest.TestCase):
    def function(self):
        return {'function_id': 'a' * 64, 'image_id': 'b' * 64, 'arch': 'arm64',
                'entry_va': '0x100000010', 'body_ranges': [['0x100000010', '0x100000013']],
                'names': [{'name': 'example', 'origin': 'ghidra'}], 'signature': 'void example(void)',
                'pseudocode': 'void example(void) {}', 'address_spans': [],
                'facets': {'address_spans': {'available': False, 'reason': 'Not exported'}},
                'origin': {'engine': 'Ghidra', 'version': '12.2'}}

    def test_complete_envelope_validates(self):
        schema.validate_envelope(cli.envelope('version', {'cli_version': 'test'}))

    def test_every_required_envelope_field_is_required(self):
        result = cli.envelope('version')
        for field in ('schema_version', 'command', 'status', 'analysis_id', 'data', 'diagnostics', 'coverage'):
            with self.subTest(field=field):
                invalid = copy.deepcopy(result)
                del invalid[field]
                with self.assertRaises(ValueError):
                    schema.validate_envelope(invalid)

    def test_envelope_unknown_fields_and_version_rejected(self):
        result = cli.envelope('version')
        for changes in ({'schema_version': '99'}, {'unexpected': True}, {'status': 'probably'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                schema.validate_envelope(dict(result, **changes))

    def test_coverage_shape_and_integer_types_validated(self):
        for changes in ({'returned_count': -1}, {'returned_count': True}, {'known_total': -1},
                        {'next_cursor': 123}, {'truncation_reason': False}):
            with self.subTest(changes=changes):
                result = cli.envelope('functions list')
                result['coverage'].update(changes)
                with self.assertRaises(ValueError):
                    schema.validate_envelope(result)

    def test_error_envelope_requires_structured_error_fields(self):
        result = cli.envelope('functions show', status='failed',
                              cov=cli.coverage(count=0, total=None, partial=True, reason='function_selector'))
        result['error'] = {'code': 'function_selector', 'message': 'Ambiguous function',
                           'affected_object': None, 'retryable': False, 'partial_results': []}
        schema.validate_envelope(result)
        self.assertEqual(result['coverage']['status'], 'partial')
        for field in ('code', 'message', 'affected_object', 'retryable', 'partial_results'):
            with self.subTest(field=field):
                invalid = copy.deepcopy(result)
                del invalid['error'][field]
                with self.assertRaises(ValueError):
                    schema.validate_envelope(invalid)

    def test_normal_function_schema_validates(self):
        schema.validate_function(self.function())

    def test_external_function_allows_null_va(self):
        function = self.function()
        function.update(entry_va=None, address_space='EXTERNAL', engine_entry='EXTERNAL:00000001',
                        body_ranges=[], signature=None, pseudocode=None, is_external=True)
        schema.validate_function(function)

    def test_every_required_function_field_is_required(self):
        function = self.function()
        for field in ('function_id', 'image_id', 'arch', 'entry_va', 'body_ranges', 'names',
                      'signature', 'pseudocode', 'address_spans', 'facets', 'origin'):
            with self.subTest(field=field):
                invalid = copy.deepcopy(function)
                del invalid[field]
                with self.assertRaises(ValueError):
                    schema.validate_function(invalid)

    def test_function_invalid_ids_addresses_and_ranges_rejected(self):
        for changes in ({'function_id': 'short'}, {'image_id': 'z' * 64}, {'entry_va': '4096'},
                        {'entry_va': 'EXTERNAL:00000001'}, {'entry_va': 4096}, {'arch': 'arm64e'},
                        {'body_ranges': [['0x1']]}, {'body_ranges': [['0x1', '0x2', '0x3']]},
                        {'names': [{'name': 'no provenance'}]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                schema.validate_function(dict(self.function(), **changes))


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.image = {'image_id': 'a' * 64, 'sha256': 'b' * 64, 'arch': 'arm64', 'offset': '0x2000',
                      'sections': [{'va': '0x100000000', 'size': '0x100', 'file_offset': '0x1000'}]}
        function = {'name': 'example', 'entry_va': '0x100000010',
                    'body_ranges': [['0x100000010', '0x100000013']], 'signature': 'void example(void)',
                    'pseudocode': 'void example(void) {}', 'decompile_status': 'complete',
                    'is_thunk': False, 'is_external': False, 'blocks': [],
                    'instructions': [{'addr': '0x100000010', 'bytes': 'c0035fd6', 'mnemonic': 'ret'}]}
        external = dict(function, name='puts', entry_va='EXTERNAL:00000001', body_ranges=[],
                        instructions=[], pseudocode=None, is_external=True)
        self.raw = {'language_id': 'AARCH64:LE:64:AppleSilicon', 'compiler_spec_id': 'default',
                    'status': 'complete', 'image_base': '0x100000000', 'functions': [external, function]}
        self.deps = {'ghidra_version': '12.2', 'ghidra_path': '/synthetic/ghidra',
                     'java_home': '/synthetic/jdk', 'host_os': 'Synthetic OS'}
        self.raw.update(analysis_profile={'name':'macscope-binary-only/1','applied':True,'ghidra_version':'12.2','parameter_inference_enabled':False},
                        effective_analysis_options={'Decompiler Parameter ID':'false'},
                        coverage={'effective_analysis_options':{'status':'complete','truncated':False,'error':None,'emitted':1}})
        self.manifest = {'limits': {'max_functions': 100}, 'analysis_profile': engine.analysis_profile()}

    def normalized(self):
        return cli.normalize(copy.deepcopy(self.raw), self.image, self.deps, self.manifest)

    def test_normalization_validates_and_orders_external_functions_last(self):
        result = self.normalized()
        self.assertEqual([f['name'] for f in result['functions']], ['example', 'puts'])
        for function in result['functions']:
            schema.validate_function(function)
            self.assertEqual(function['analysis_id'], result['analysis_id'])
            self.assertEqual(function['address_spans'], [])
            self.assertFalse(function['facets']['address_spans']['available'])
            self.assertTrue(function['facets']['address_spans']['reason'])

    def test_entry_labels_and_immediate_thunk_target_keep_distinct_provenance(self):
        external, function = self.raw['functions']
        function['entry_labels'] = [{'name': 'other', 'namespace': 'Global', 'source': 'IMPORTED'},
                                    {'name': 'alias', 'namespace': 'Global', 'source': 'ANALYSIS'}]
        function['is_thunk'] = True
        function['thunk_target'] = {'engine_entry': external['entry_va'], 'name': external['name'],
                                    'namespace': 'External', 'is_external': True}
        result = self.normalized()
        selected, target = result['functions']
        self.assertEqual([row['name'] for row in selected['names']], ['example','alias','other'])
        self.assertEqual(selected['names'][1]['origin'], 'ghidra_entry_label')
        args = argparse.Namespace(address=None,function_id=None,name='alias')
        self.assertEqual(cli.select_function(result['functions'],args)['function_id'],selected['function_id'])
        self.assertEqual(selected['thunk_target']['function_id'],target['function_id'])
        self.assertEqual(selected['thunk_target']['address']['address_space'],'EXTERNAL')
        self.assertIsNone(selected['thunk_target']['address']['va'])
        self.assertNotIn('thunk_target',target)
        self.raw['functions'] = [function]
        self.assertIsNone(self.normalized()['functions'][0]['thunk_target']['function_id'])

    def test_normal_entry_address_maps_typed_va_rva_and_file_offsets(self):
        function = self.normalized()['functions'][0]
        location = function['entry_address']
        self.assertEqual(location['address_space'], 'ram')
        self.assertEqual(location['va'], '0x100000010')
        self.assertEqual(location['rva'], '0x10')
        self.assertEqual(location['slice_file_offset'], '0x1010')
        self.assertEqual(location['container_file_offset'], '0x3010')
        self.assertEqual(function['instructions'][0]['location'], location)
        self.assertEqual(function['instruction_bytes_sha256'], hashlib.sha256(bytes.fromhex('c0035fd6')).hexdigest())

    def test_normalization_persists_an_overlap_under_its_own_analysis_identity(self):
        clean = self.normalized()
        first = self.raw['functions'][1]
        second = dict(first,name='secondary',entry_va='0x100000012',
                      body_ranges=[['0x100000012','0x100000020']])
        self.raw['functions'].append(second)
        result = self.normalized()
        self.assertNotIn('body_ownership',clean)
        self.assertNotEqual(result['analysis_id'],clean['analysis_id'])
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['body_ownership']['affected_functions'],2)
        original, overlapping, _ = result['functions']
        self.assertEqual(original['body_overlap'],{'other_function_id':overlapping['function_id'],
                                                    'start_va':'0x100000012','last_va':'0x100000013'})
        self.assertEqual(original['decompile_status'],'complete')

    def test_address_spans_use_utf16_and_stay_bound_to_displayed_text(self):
        function = self.raw['functions'][1]
        function['pseudocode'] = '😀return;'
        span = {'text_start': 2, 'text_end': 9, 'ranges': [['0x100000010', '0x100000010']]}
        function['address_spans'] = [span]
        function['coverage'] = {'address_spans': {'status': 'complete', 'emitted': 1}}
        result = self.normalized()['functions'][0]
        self.assertEqual(result['address_spans'], [span])
        self.assertEqual(result['facets']['address_spans']['text_offsets'], 'utf16')
        span['text_start'] = 1
        with self.assertRaisesRegex(ValueError, 'surrogate pair'):
            self.normalized()
        span['text_start'] = 2
        function['pseudocode'] += ' "/Users/private/app"'
        result = self.normalized()['functions'][0]
        self.assertEqual(result['address_spans'], [])
        self.assertFalse(result['facets']['address_spans']['available'])
        self.assertEqual(result['coverage']['address_spans']['emitted'], 0)
        self.assertEqual(function['coverage']['address_spans']['emitted'], 1)
        self.assertIn('$HOME/app', result['pseudocode'])

    def test_invalid_address_span_never_enters_a_snapshot(self):
        function = self.raw['functions'][1]
        function['address_spans'] = [{'text_start': 0, 'text_end': 10000,
                                      'ranges': [['0x100000010', '0x100000010']]}]
        function['coverage'] = {'address_spans': {'status': 'complete', 'emitted': 1}}
        with self.assertRaisesRegex(ValueError, 'text offsets'):
            self.normalized()

    def test_external_entry_is_not_misrepresented_as_a_virtual_address(self):
        function = self.normalized()['functions'][1]
        self.assertIsNone(function['entry_va'])
        self.assertEqual(function['address_space'], 'EXTERNAL')
        self.assertEqual(function['engine_entry'], 'EXTERNAL:00000001')
        for field in ('va', 'rva', 'slice_file_offset', 'container_file_offset'):
            self.assertIsNone(function['entry_address'][field])

    def test_address_selector_skips_external_function_without_crashing(self):
        functions = self.normalized()['functions']
        args = argparse.Namespace(address='0x100000010', function_id=None, name=None)
        self.assertEqual(cli.select_function(functions, args)['name'], 'example')
        args = argparse.Namespace(address=None, function_id=functions[1]['function_id'], name=None)
        self.assertEqual(cli.select_function(functions, args)['name'], 'puts')

    def test_analysis_identity_is_stable_across_host_install_paths(self):
        expected = self.normalized()['analysis_id']
        self.deps.update(ghidra_path='/other/ghidra', java_home='/other/jdk', host_os='Other OS')
        self.assertEqual(self.normalized()['analysis_id'], expected)
        self.deps['bridge_sha256'] = 'c' * 64
        self.assertNotEqual(self.normalized()['analysis_id'], expected)


class DependencyTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.g = self.root / 'ghidra'
        self.j = self.root / 'jdk'
        self.bridge = self.root / 'bridge'
        for relative in ('support/analyzeHeadless', 'support/launch.sh', 'support/launch.properties',
                         'Ghidra/application.properties', engine_checks.NATIVE):
            target = self.g / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'fixture')
        (self.g / 'support/analyzeHeadless').write_bytes(b'#!/bin/bash\n# ghidra.app.util.headless.AnalyzeHeadless\n')
        (self.g / 'support/launch.sh').write_bytes(b'#!/bin/bash\n# LaunchSupport\n')
        (self.g / 'support/launch.properties').write_bytes(b'JAVA_HOME_OVERRIDE=\n')
        (self.g / 'Ghidra/application.properties').write_text('application.version=12.2\n')
        (self.g / engine_checks.NATIVE).write_bytes(doctor_probe.fixture())
        for name, members in engine_checks.JARS.items():
            path = self.g / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, 'w') as jar:
                for member in members:
                    jar.writestr(member, bytes.fromhex('cafebabe00000045'))
        for relative in ('bin/java', 'bin/javac', 'lib/server/libjvm.dylib', 'lib/modules'):
            target = self.j / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            data = bytearray(doctor_probe.fixture())
            if relative.endswith('.dylib'):
                struct.pack_into('<I', data, 12, 6)
            target.write_bytes(data)
        for executable in (self.g / 'support/analyzeHeadless', self.g / 'support/launch.sh',
                           self.g / engine_checks.NATIVE, self.j / 'bin/java', self.j / 'bin/javac'):
            executable.chmod(0o700)
        self.bridge.mkdir()
        for name in engine_checks.SCRIPTS:
            (self.bridge / name).write_text('// fixture\n')
        for patcher in (mock.patch.object(engine.platform, 'system', return_value='Darwin'),
                        mock.patch.object(engine.platform, 'machine', return_value='arm64'),
                        mock.patch.object(engine.platform, 'platform', return_value='Darwin-test-arm64'),
                        mock.patch.object(engine, 'BRIDGE', self.bridge)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def check(self, **kwargs):
        return engine.dependencies(str(self.g), str(self.j), **kwargs)

    def test_missing_dependency_does_not_start_java(self):
        (self.j / 'bin/java').unlink()
        with mock.patch.object(engine.subprocess, 'run') as run:
            self.error('missing_dependency', self.check)
        run.assert_not_called()

    def test_missing_focused_bridge_fails_before_java(self):
        (self.bridge/'MacscopeFocus.java').unlink()
        with mock.patch.object(engine.subprocess,'run') as run:
            error = self.error('missing_dependency',self.check)
        self.assertIn('MacscopeFocus.java',str(error))
        run.assert_not_called()

    def test_nonexecutable_dependency_fails_before_java_probe(self):
        for target in (self.g / 'support/analyzeHeadless',
                       self.g / 'Ghidra/Features/Decompiler/os/mac_arm_64/decompile',
                       self.j / 'bin/java'):
            with self.subTest(target=target), mock.patch.object(engine.subprocess, 'run') as run:
                target.chmod(0o600)
                try:
                    self.error('dependency_permissions', self.check)
                    run.assert_not_called()
                finally:
                    target.chmod(0o700)

    def test_same_java_release_with_wrong_build_is_rejected(self):
        result = subprocess.CompletedProcess([], 0, b'', b'openjdk version "25.0.5" 25.0.5+99')
        with mock.patch.object(engine.subprocess, 'run', return_value=result):
            self.error('incompatible_jdk', self.check)

    def test_incompatible_ghidra_does_not_start_java(self):
        (self.g / 'Ghidra/application.properties').write_text('application.version=12.1\n')
        with mock.patch.object(engine.subprocess, 'run') as run:
            self.error('incompatible_ghidra', self.check)
        run.assert_not_called()

    def test_incompatible_java_version_is_explicit(self):
        result = subprocess.CompletedProcess([], 0, b'', b'openjdk version "21.0.7"')
        with mock.patch.object(engine.subprocess, 'run', return_value=result):
            self.error('incompatible_jdk', self.check)

    def test_java_startup_failure_is_dependency_error(self):
        with mock.patch.object(engine.subprocess, 'run', side_effect=OSError('not executable')):
            error = self.error('jdk_startup', self.check)
        self.assertEqual(error.exit_code, 4)

    def test_java_probe_timeout_is_dependency_error(self):
        with mock.patch.object(engine.subprocess, 'run', side_effect=subprocess.TimeoutExpired('java', 10)):
            self.error('jdk_startup', self.check)

    def test_valid_pins_report_full_digests(self):
        result = subprocess.CompletedProcess([], 0, b'', b'openjdk version "25.0.5.0.3"\n'
                                             b'OpenJDK Runtime Environment Homebrew (build 25.0.5.0.3)')
        with mock.patch.object(engine.subprocess, 'run', return_value=result) as run:
            dependencies = self.check(full=True)
        self.assertEqual(dependencies['ghidra_version'], '12.2')
        for key in ('ghidra_tree_sha256', 'native_decompiler_sha256', 'java_sha256', 'jvm_sha256', 'bridge_sha256'):
            self.assertRegex(dependencies[key], r'^[0-9a-f]{64}$')
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs['timeout'], 10)
        self.assertFalse(dependencies['hard_process_memory_limit'])

    def test_wrong_native_architecture_is_rejected_before_java(self):
        data = bytearray(doctor_probe.fixture())
        struct.pack_into('<2I', data, 4, 0x01000007, 3)
        (self.g / engine_checks.NATIVE).write_bytes(data)
        with mock.patch.object(engine.subprocess, 'run') as run:
            self.error('incompatible_native_decompiler', self.check)
        run.assert_not_called()

    def test_bad_jar_or_java_override_is_rejected_before_java(self):
        with mock.patch.object(engine.subprocess, 'run') as run:
            (self.g / 'support/launch.properties').write_text('JAVA_HOME_OVERRIDE: /different/java\n')
            self.error('ghidra_java_override', self.check)
            (self.g / 'support/launch.properties').write_text('JAVA_HOME_OVERRIDE=\n')
            (self.g / 'support/LaunchSupport.jar').write_bytes(b'damaged jar')
            self.error('incompatible_ghidra_jar', self.check)
        run.assert_not_called()

    def test_unsupported_host_is_explicit(self):
        with mock.patch.object(engine.platform, 'system', return_value='Linux'):
            self.error('unsupported_host', self.check)

    def test_full_doctor_probe_requires_explicit_trust_before_startup(self):
        args = cli.parser().parse_args(['doctor', '--verify-worker'])
        with mock.patch.object(engine, 'dependencies') as dependencies:
            self.error('isolation_required', cli.execute, args)
        dependencies.assert_not_called()


class CliTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.workspace = self.project()
        self.snapshot, _ = synthetic_snapshot(self.workspace)

    def args(self, *words):
        return cli.parser().parse_args([*words, '--project', str(self.workspace.path), '--format', 'json'])

    def invoke(self, words):
        stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        stderr = io.StringIO()
        with mock.patch.object(sys, 'stdout', stdout), mock.patch.object(sys, 'stderr', stderr):
            code = cli.main(words)
        stdout.flush()
        payload = stdout.buffer.getvalue()
        stdout.close()
        return code, payload, stderr.getvalue()

    def test_evidence_reads_pinned_analysis_and_reports_every_lead(self):
        image = self.snapshot['image']
        pin = {'image_id':image['image_id'], 'arch':image['arch'], 'artifact_sha256':image['artifact_sha256'],
               'slice_sha256':image['sha256'], 'analysis_id':self.snapshot['analysis_id']}
        leads = [dict(id=key, image_id=image['image_id'], kind=kind, value=value) for key, kind, value in (
            ('chosen','address','0x100000020'), ('ambiguous','name','duplicate'), ('missing','address','0x1'))]
        path = self.root/'leads.json'
        manifest = {'schema':evidence.LEADS_SCHEMA, 'images':[pin], 'leads':leads}
        path.write_bytes(storage.canonical(manifest))
        synthetic_snapshot(self.workspace,'e'*64)
        with mock.patch.object(engine,'dependencies',side_effect=AssertionError('unexpected worker probe')):
            report = cli.execute(self.args('evidence','--leads',str(path)))
        selected, ambiguous, missing = report['data']['leads']
        self.assertEqual(report['status'],'partial')
        self.assertEqual(report['data']['images'][0]['analysis_id'],self.snapshot['analysis_id'])
        self.assertEqual(selected['function']['function_id'],'function-2')
        self.assertIsNone(ambiguous['function'])
        self.assertEqual(ambiguous['reason'],'lead_ambiguous')
        self.assertEqual(missing['reason'],'lead_not_found')
        self.error('output_input_conflict',cli.execute,
                   self.args('evidence','--leads',str(path),'--output',str(path),'--force'))
        self.assertEqual(path.read_bytes(),storage.canonical(manifest))
        pin['slice_sha256'] = 'f'*64
        path.write_bytes(storage.canonical(manifest))
        rejected = cli.execute(self.args('evidence','--leads',str(path)))['data']
        self.assertTrue(all(row['reason']=='evidence_image_mismatch' for row in rejected['leads']))

    def test_selected_focused_calls_bind_verified_direct_bytes_within_one_image(self):
        def selected(lead, image, entry, instructions):
            function = {'function_id':storage.identity([image, entry]), 'entry_va':entry,
                        'instructions':instructions,
                        'origin':{'extent':{'length':sum(len(row['bytes']) // 2 for row in instructions)}}}
            return {'lead':{'id':lead, 'image_id':image, 'kind':'address'},
                    'function':function, 'status':'resolved', 'gaps':[]}

        def ins(address, data, flow='UNCONDITIONAL_CALL'):
            return {'addr':address, 'bytes':data, 'flow':flow}

        arm = selected('arm_caller', 'arm', '0x1000', [
            ins('0x1000', '04000094'), ins('0x1004', '00003fd6', 'COMPUTED_CALL')])
        first = selected('arm_target', 'arm', '0x1010', [])
        alias = selected('arm_alias', 'arm', '0x1010', [])
        intel = selected('intel_caller', 'intel', '0x1000', [ins('0x1000', 'e80b000000')])
        other = selected('intel_target', 'intel', '0x1010', [])
        missing = {'lead':{'id':'missing', 'image_id':'intel', 'kind':'address'}, 'function':None}
        fixup = {'lead':{'id':'slot', 'image_id':'arm', 'kind':'fixup'}, 'function':None}
        report = {'images':[{'image_id':key, 'arch':arch, evidence.IMPORT_PIN:'pin'}
                            for key, arch in [('arm','arm64'), ('intel','x86_64')]],
                  'leads':[arm, first, alias, intel, other, missing, fixup]}
        evidence.add_focused_calls(report)
        arm_link, = arm['selected_calls']['links']
        self.assertEqual(arm_link, {'callsite':'0x1000', 'call_bytes':'04000094', 'target_entry_va':'0x1010',
                                    'target_function_id':first['function']['function_id'],
                                    'target_leads':['arm_alias','arm_target']})
        self.assertEqual(arm['selected_calls']['status'], 'complete')
        intel_link, = intel['selected_calls']['links']
        self.assertEqual(intel_link['target_leads'], ['intel_target'])
        self.assertEqual(intel['gaps'], ['selected_receipts_unavailable'])
        self.assertNotIn('selected_calls', missing)
        with mock.patch.object(evidence, 'MAX_EDGES', 1):
            evidence.add_focused_calls(report)
        self.assertEqual(intel['selected_calls']['links'], [])
        self.assertIn('selected_call_limit', intel['selected_calls']['gaps'])

    def test_evidence_html_preserves_all_leads_and_escapes_evidence(self):
        image = self.snapshot['image']
        pin = dict(image_id=image['image_id'], arch=image['arch'], artifact_sha256=image['artifact_sha256'],
                   slice_sha256=image['sha256'], analysis_id=self.snapshot['analysis_id'])
        hostile = '</pre><script>alert(1)</script><img src="https://example.invalid/leak">'
        leads = [dict(id=key, image_id=image['image_id'], kind=kind, value=value) for key, kind, value in (
            ('chosen', 'address', '0x100000020'), ('missing', 'name', hostile))]
        manifest = self.root / 'leads.json'
        storage.write_json(manifest, dict(schema=evidence.LEADS_SCHEMA, images=[pin], leads=leads))
        self.snapshot['functions'][2]['pseudocode'] = hostile + ' /Users/private/fixture \x1b\u202e'
        source = {'snapshot_sha256': 'a' * 64}
        destination = self.root / 'evidence.html'
        args = ['evidence', '--project', str(self.workspace.path), '--leads', str(manifest), '--format', 'html']
        with mock.patch.object(storage.Project, 'snapshot', return_value=(self.snapshot, source)), \
             mock.patch.object(engine, 'dependencies', side_effect=AssertionError('handoff launched Ghidra')):
            code, html, stderr = self.invoke(args)
            self.assertEqual((code, stderr), (6, ''))
            self.assertEqual(self.invoke([*args, '--output', str(destination)]), (6, b'', ''))
        self.assertEqual(destination.read_bytes(), html)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        for expected in (b'<dt>Status</dt><dd>partial</dd>', b'href="#lead-1">chosen', b'href="#lead-2">missing',
                         b'function-2', b'0x100000020  c0035fd6  ret', b'lead_not_found', b'Pinned images',
                         b'&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;', b'$HOME/fixture \\u001b\\u202e',
                         b'Content-Security-Policy'):
            self.assertIn(expected, html)
        for unsafe in (b'<script', b'<img', b'/Users/private', b'\x1b', '\u202e'.encode()):
            self.assertNotIn(unsafe, html)

    def test_focused_receipt_binds_result_digest_to_its_producing_job(self):
        image = self.snapshot['image']
        proof = {'entry_va':'0x100000020','end_va_exclusive':'0x100000024',
                 'program_sha256':'c'*64,'extent_sha256':'d'*64}
        request = jobs.focused_request(self.workspace,image,proof)
        job_id = '1'*32
        job = self.workspace.path/'jobs'/job_id
        job.mkdir()
        deps = {'ghidra_version':'12.2','ghidra_tree_sha256':'e'*64,'bridge_sha256':'f'*64}
        storage.write_json(job/'job.json', {'job_id':job_id,'mode':'query','status':'complete',
            'selected_entry':proof['entry_va'],'image_id':image['image_id'],
            'focused_import':proof,'focused_request':request,'dependencies':deps})
        result = cli.envelope('decompile', {'image_id':image['image_id'],'arch':image['arch'],
            'slice_sha256':image['sha256'],'entry_va':proof['entry_va'],'function_id':request['function_id'],
            'address_space':'ram','engine_entry':proof['entry_va'],'is_external':False,'is_thunk':False,
            'decompile_status':'complete','signature':None,'address_spans':[],'names':[],'facets':{},
            'body_ranges':[[proof['entry_va'],'0x100000023']],
            'instructions':[{'addr':proof['entry_va'],'bytes':'c0035fd6','flow':'TERMINATOR'}],
            'coverage':{key:{'status':'complete'} for key in ('pseudocode','instructions','body_ranges',
                                                           'xrefs_from','xrefs_to_entry')},
            'xrefs_to_entry':[],'xrefs_from_sample':[],
            'pseudocode':'return 1;', 'origin':{'job_id':job_id,'mode':'focused_readonly_import','extent':proof,**deps}})
        self.assertIsNone(jobs.query_receipt(self.workspace,job_id,request))
        self.assertEqual(jobs.publish_query(self.workspace,job_id,request,result),result)
        self.assertEqual(jobs.query_receipt(self.workspace,job_id,request),result)
        path = job/'query-result.json'
        original = path.read_bytes()
        storage.atomic(path,b'{"result_sha256":"duplicate",'+original[1:],force=True)
        self.error('query_receipt',jobs.query_receipt,self.workspace,job_id,request)
        receipt = json.loads(original)
        receipt['result']['data']['pseudocode'] = 'return 2;'
        receipt['result_sha256'] = storage.identity(receipt['result'])
        storage.write_json(path,receipt,force=True)
        self.error('query_receipt',jobs.query_receipt,self.workspace,job_id,request)

        record = jobs.load(job/'job.json')
        for change in ({'engine_entry':None}, {'coverage':dict(result['data']['coverage'],xrefs_from=[])},
                       {'xrefs_from_sample':[{'from':proof['entry_va'],'to':None,'type':None}]},
                       {'xrefs_from_sample':[{'from':proof['entry_va'],'to':None,'type':'DATA',
                                              'operand_index':float('nan')}] }):
            with self.subTest(change=change):
                changed = dict(result,data=dict(result['data'],**change))
                self.error('query_receipt',jobs.publish_query,self.workspace,job_id,request,changed)
                corrupt_result = json.dumps(changed, sort_keys=True, separators=(',', ':')).encode()
                forged = dict(json.loads(original), result=changed,
                              result_sha256=hashlib.sha256(corrupt_result).hexdigest())
                storage.atomic(path,json.dumps(forged).encode(),force=True)
                storage.write_json(job/'job.json',dict(record,focused_result_sha256=forged['result_sha256']),force=True)
                self.error('query_receipt',jobs.query_receipt,self.workspace,job_id,request)

    def test_evidence_import_pin_requires_focused_job_and_no_analysis_id(self):
        image = self.snapshot['image']
        pin = {'image_id':image['image_id'],'arch':image['arch'],'artifact_sha256':image['artifact_sha256'],
               'slice_sha256':image['sha256'],'import_program_sha256':'c'*64}
        lead = {'id':'focused','image_id':image['image_id'],'kind':'address','value':'0x100000020'}
        manifest = {'schema':evidence.LEADS_SCHEMA,'images':[pin],'leads':[lead]}
        path = self.root/'focused-leads.json'
        path.write_bytes(storage.canonical(manifest))
        self.error('evidence_import_lead',evidence.load,path)
        lead['query_job'] = '1'*32
        path.write_bytes(storage.canonical(manifest))
        self.assertEqual(evidence.load(path),manifest)
        pin['analysis_id'] = self.snapshot['analysis_id']
        path.write_bytes(storage.canonical(manifest))
        self.error('evidence_image_pin',evidence.load,path)

    def test_evidence_string_does_not_assign_overlapping_reference_owner(self):
        snapshot = copy.deepcopy(self.snapshot)
        first, second = snapshot['functions'][:2]
        site = first['entry_va']
        second['body_ranges'].append(first['body_ranges'][0])
        ref = {'from':site,'to':'0x100000050','type':'READ'}
        first['xrefs_from_sample'] = [ref]
        candidates, matches, refs, gaps = evidence.string_selection(snapshot,'reference+anchor')
        self.assertEqual(candidates,[])
        self.assertEqual(len(matches),1)
        self.assertEqual(len(refs),1)
        self.assertNotIn('owner_function_id',refs[0])
        self.assertIn('ambiguous_reference_owner',gaps)

    def test_typed_function_selectors_share_entry_identity_and_annotations(self):
        selected = dict(self.workspace.select(), loader={'preferred_image_base': '0x100000000'},
                        sections=[{'va': '0x100000000', 'file_offset': '0x100', 'size': '0x24'}])
        with mock.patch.object(storage.Project, 'select', return_value=selected):
            chosen = ('--rva', '0x20')
            offset = ('--file-offset', '0x120')
            label = cli.execute(self.args('rename', 'Review', *offset))['data']['revision']
            self.assertEqual(label['engine_entry'], '0x100000020')
            by_va = cli.execute(self.args('decompile', '--address', '0x100000020'))
            self.assertEqual(cli.execute(self.args('decompile', *chosen)), by_va)
            self.assertEqual(cli.execute(self.args('decompile', *offset)), by_va)
            history = cli.execute(self.args('annotations', 'history', *chosen))
            self.assertEqual(history['data'], [label])
            self.error('function_selector', cli.execute, self.args('functions', 'show', '--rva', '0x21'))
            self.error('file_offset_unmapped', cli.execute, self.args('functions', 'show', '--file-offset', '0x0'))
            self.error('usage', self.args, 'functions', 'show', *chosen, *offset)
            self.error('usage', self.args, 'disasm', '--range', '0x1:0x2', *offset)

    def test_typed_selectors_refuse_a_disputed_image_base(self):
        selected = dict(self.workspace.select(), loader={'preferred_image_base': None},
                        sections=[{'va': '0x100000000', 'file_offset': '0x100', 'size': '0x24'}])
        args = self.args('functions', 'show', '--rva', '0x0')
        with mock.patch.object(storage.Project, 'select', return_value=selected):
            self.error('rva_base_unavailable', cli.execute, args)
            selected['loader']['preferred_image_base'] = '0x100000000'
            snapshot = dict(self.snapshot, engine={'image_base': '0x200000000'})
            with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
                self.error('rva_base_mismatch', cli.execute, args)
                self.error('file_offset_base_mismatch', cli.execute,
                           self.args('functions', 'show', '--file-offset', '0x100'))

    def test_runtime_function_selection_uses_the_saved_entry_and_annotation_identity(self):
        runtime = ('--runtime-address', '0x100004020', '--load-slide', '+0x4000')
        unslid = ('--address', '0x100000020')
        renamed = cli.execute(self.args('rename', 'Runtime review', *runtime))
        self.assertEqual(renamed['data']['revision']['engine_entry'], '0x100000020')
        for command in (('functions', 'show'), ('decompile',), ('disasm',), ('cfg',),
                        ('calls',), ('xrefs',), ('annotations', 'history')):
            with self.subTest(command=command):
                result = cli.execute(self.args(*command, *runtime))
                self.assertEqual(result.pop('address_selection'), {
                    'runtime_va': '0x100004020', 'load_slide': '0x4000', 'va': '0x100000020',
                    'image_id': self.workspace.select()['image_id'], 'arch': 'arm64', 'address_space': 'ram',
                })
                self.assertEqual(result, cli.execute(self.args(*command, *unslid)))

    def test_search_finds_literal_names_symbols_strings_and_pseudocode_without_engine(self):
        with mock.patch.object(engine, 'dependencies') as deps, mock.patch.object(engine, 'run') as run:
            anchors = cli.execute(self.args('search', 'REFERENCE+ANCHOR'))
            functions = cli.execute(self.args('search', 'UNIQUE', '--in', 'names'))
            code = cli.execute(self.args('search', 'RETURN;', '--in', 'pseudocode'))
        deps.assert_not_called()
        run.assert_not_called()
        self.assertEqual([hit['source'] for hit in anchors['data']], ['symbol', 'defined_string'])
        self.assertEqual(anchors['data'][0]['function_id'], 'function-2')
        self.assertIsNone(anchors['data'][1]['function_id'])
        self.assertEqual(functions['data'][0]['va'], '0x100000020')
        self.assertEqual([hit['function_id'] for hit in code['data']],
                         ['function-0', 'function-1', 'function-2'])

    def test_search_pages_are_bound_to_query_scope_and_order(self):
        page_one = cli.execute(self.args('search', 'duplicate', '--in', 'names', '--limit', '1'))
        cursor = page_one['coverage']['next_cursor']
        self.assertEqual(page_one['coverage']['truncation_reason'], 'page_limit')
        page_two = cli.execute(self.args('search', 'duplicate', '--in', 'names', '--cursor', cursor))
        self.assertEqual([row['function_id'] for row in page_two['data']], ['function-1'])
        self.assertIsNone(page_two['coverage']['next_cursor'])
        for query, scope in (('duplicate', 'all'), ('DUPLICATE', 'names')):
            self.error('stale_cursor', cli.execute,
                       self.args('search', query, '--in', scope, '--cursor', cursor))

    def test_empty_search_preserves_incomplete_scope(self):
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['engine']['coverage']['strings']['status'] = 'partial'
        snapshot['functions'][0].update(decompile_status='timeout', pseudocode=None)
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            for scope, reason in (('strings', 'string_coverage_incomplete'),
                                  ('pseudocode', 'pseudocode_coverage_incomplete')):
                result = cli.execute(self.args('search', 'no hit', '--in', scope))
                self.assertEqual(result['data'], [])
                self.assertEqual(result['status'], 'partial')
                self.assertIsNone(result['coverage']['known_total'])
                self.assertEqual(result['coverage']['truncation_reason'], reason)
            names = cli.execute(self.args('search', 'no hit', '--in', 'names'))
        self.assertEqual(names['status'], 'complete')
        self.assertEqual(names['coverage']['known_total'], 0)
        snapshot['functions'][0].setdefault('coverage', {})['entry_labels'] = {'status': 'partial'}
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            names = cli.execute(self.args('search', 'no hit', '--in', 'names'))
        self.assertEqual(names['status'], 'partial')
        self.assertEqual(names['coverage']['truncation_reason'], 'function_entry_label_coverage_incomplete')

    def test_search_rejects_empty_or_oversized_query(self):
        for value in ('', ' ', 'x' * 257, '\n'):
            self.error('search_query', cli.execute, self.args('search', value))

    def test_regex_search_uses_the_saved_scope_and_binds_the_cursor_to_regex_mode(self):
        expression = r'^DUPLI(CATE|CITY)$'
        scope = ('--in', 'names', '--limit', '1')
        literal = cli.execute(self.args('search', expression, *scope))
        self.assertEqual(literal['data'], [])
        first = cli.execute(self.args('search', expression, '--regex', *scope))
        self.assertEqual([hit['function_id'] for hit in first['data']], ['function-0'])
        cursor = first['coverage']['next_cursor']
        second = cli.execute(self.args('search', expression, '--regex', *scope, '--cursor', cursor))
        self.assertEqual([hit['function_id'] for hit in second['data']], ['function-1'])
        self.error('stale_cursor', cli.execute, self.args('search', expression, *scope, '--cursor', cursor))
        self.error('search_regex', cli.execute, self.args('search', '[', '--regex'))

    def test_regex_search_bounds_context_text_and_matching_time(self):
        note = 'a' * 1024 + '!'
        cli.execute(self.args('comment', 'set', note, '--name', 'unique'))
        scope = ('--regex', '--in', 'comments')
        result = cli.execute(self.args('search', r'^a+!$', *scope))
        hit, = result['data']
        self.assertEqual(hit['context'], 'a' * search.MAX_CONTEXT)
        self.assertTrue(hit['context_truncated'])
        self.assertEqual(hit['function_id'], 'function-2')
        with mock.patch.object(search, 'MAX_REGEX_BYTES', 128):
            error = self.error('search_regex_limit', cli.execute, self.args('search', 'a', *scope))
        self.assertEqual(error.exit_code, 7)
        with mock.patch.object(search, 'MAX_REGEX_RECORDS', 1):
            error = self.error('search_regex_limit', cli.execute,
                               self.args('search', 'unique', '--regex', '--in', 'names'))
        self.assertEqual(error.exit_code, 7)
        with mock.patch.object(search, 'REGEX_TIMEOUT_SECONDS', 0.5):
            error = self.error('search_regex_timeout', cli.execute, self.args('search', r'^(a+)+$', *scope))
        self.assertEqual(error.exit_code, 7)
        repeat = cli.execute(self.args('search', 'a!', '--in', 'comments'))
        self.assertEqual(repeat['data'][0]['function_id'], 'function-2')

    def call_snapshot(self):
        snapshot = copy.deepcopy(self.snapshot)
        a, b, c = snapshot['functions']
        for caller, callee in ((a, b), (b, c), (c, a)):
            ref = {'from': caller['entry_va'], 'to': callee['entry_va'],
                   'type': 'UNCONDITIONAL_CALL', 'source': 'DEFAULT', 'operand_index': 0}
            caller['instructions'][0]['flow'] = 'UNCONDITIONAL_CALL'
            caller['xrefs_from_sample'] = [ref]
            callee['xrefs_to_entry'] = [ref]
        return snapshot

    def test_calls_traverses_saved_callers_and_callees_without_revisiting_cycle(self):
        with mock.patch.object(storage.Project, 'snapshot', return_value=(self.call_snapshot(), {})):
            for direction, ids in (('callers', ['function-0', 'function-2', 'function-1']),
                                   ('callees', ['function-0', 'function-1', 'function-2'])):
                with self.subTest(direction=direction), mock.patch.object(engine, 'run') as run:
                    result = cli.execute(self.args('calls', '--function-id', 'function-0',
                                                   '--direction', direction, '--depth', '8'))
                    run.assert_not_called()
                self.assertEqual(result['status'], 'complete')
                self.assertEqual([n['function_id'] for n in result['data']['nodes']], ids)
                self.assertEqual([n['distance'] for n in result['data']['nodes']], [0, 1, 2])
                self.assertEqual(len(result['data']['edges']), 3)
            both = cli.execute(self.args('calls', '--function-id', 'function-0', '--depth', '8'))
        self.assertEqual(len(both['data']['edges']), 3)

    def test_calls_keeps_computed_targets_unresolved_and_reports_edge_limit(self):
        snapshot = self.call_snapshot()
        function = snapshot['functions'][0]
        function['instructions'][0]['flow'] = 'COMPUTED_CALL'
        function['instructions'].append({'addr': '0x100000004', 'flow': 'COMPUTED_CALL'})
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            result = cli.execute(self.args('calls', '--function-id', 'function-0', '--direction', 'callees'))
            limited = cli.execute(self.args('calls', '--function-id', 'function-0',
                                            '--direction', 'callees', '--max-edges', '1'))
        self.assertEqual(len(result['data']['nodes']), 1)
        from_ref, from_instruction = result['data']['edges']
        self.assertEqual(from_ref['reported_target'], '0x100000010')
        self.assertIsNone(from_ref['callee_function_id'])
        self.assertEqual(from_instruction['resolution'], 'indirect_or_inferred')
        self.assertEqual(from_instruction['evidence'], 'instruction')
        self.assertEqual(limited['status'], 'partial')
        self.assertEqual(limited['coverage']['truncation_reason'], 'edge_limit')

    def test_calls_reports_incomplete_scanned_references_and_honors_depth(self):
        snapshot = self.call_snapshot()
        snapshot['functions'][0]['xrefs_from_truncated'] = True
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            result = cli.execute(self.args('calls', '--function-id', 'function-0',
                                           '--direction', 'callees', '--depth', '1'))
        self.assertEqual(len(result['data']['nodes']), 2)
        self.assertEqual(result['data']['expanded_functions'], 1)
        self.assertEqual(len(result['data']['edges']), 1)
        self.assertEqual(result['coverage']['truncation_reason'], 'xrefs_from_incomplete')
        self.error('argument_limit', cli.execute, self.args('calls', '--name', 'unique', '--depth', '9'))

    def test_calls_does_not_invent_an_owner_for_an_overlapping_callsite(self):
        snapshot = self.call_snapshot()
        first, second, third = snapshot['functions']
        third['instructions'].extend(first['instructions'])
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            result = cli.execute(self.args('calls', '--function-id', second['function_id'],
                                           '--direction', 'callers'))
        edge, = result['data']['edges']
        self.assertEqual(edge['callee_function_id'], second['function_id'])
        self.assertIsNone(edge['caller_function_id'])
        self.assertEqual(edge['resolution'], 'unresolved_caller')

    def test_calls_withhold_ownership_at_any_shared_address_even_with_one_saved_instruction(self):
        snapshot = self.call_snapshot()
        first, second, third = snapshot['functions']
        shared = '0x100000008'
        clear = '0x10000000c'
        first['body_ranges'].append([shared, '0x10000000f'])
        third['body_ranges'].extend([first['body_ranges'][0], [shared, '0x10000000b']])
        ambiguous = {**first['xrefs_from_sample'][0], 'from':shared}
        direct = {**ambiguous, 'from':clear, 'to':third['entry_va']}
        first['instructions'] = [{'addr':row['from'],'flow':'UNCONDITIONAL_CALL'} for row in (ambiguous,direct)]
        first['xrefs_from_sample'] = [ambiguous,direct]
        second['xrefs_to_entry'] = [ambiguous]
        third['xrefs_to_entry'] = [direct]
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            incoming = cli.execute(self.args('calls','--function-id',second['function_id'],'--direction','callers'))
            outgoing = cli.execute(self.args('calls','--function-id',first['function_id'],'--direction','callees'))
        edge, = incoming['data']['edges']
        self.assertEqual(edge['callsite'],shared)
        self.assertEqual(edge['callee_function_id'],second['function_id'])
        self.assertIsNone(edge['caller_function_id'])
        self.assertEqual(edge['caller_ownership'],'overlapping_function_bodies')
        self.assertEqual(edge['resolution'],'unresolved_caller')
        self.assertEqual(incoming['coverage']['truncation_reason'],'ambiguous_callsite_ownership')
        self.assertEqual(len(incoming['data']['nodes']),1)
        self.assertEqual(outgoing['data']['edges'][0],edge)
        self.assertEqual(outgoing['data']['edges'][1]['resolution'],'direct')
        self.assertEqual([n['function_id'] for n in outgoing['data']['nodes']],
                         [first['function_id'],third['function_id']])

    def test_calls_withhold_ownership_when_the_body_review_reaches_its_limit(self):
        snapshot = self.call_snapshot()
        with (mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})),
              mock.patch.object(body_ownership, 'MAX_RANGES', 1)):
            result = cli.execute(self.args('calls','--function-id','function-0','--direction','callees'))
        edge, = result['data']['edges']
        self.assertIsNone(edge['caller_function_id'])
        self.assertEqual(edge['caller_ownership'],'body_review_incomplete')
        self.assertEqual(len(result['data']['nodes']),1)
        self.assertEqual(result['coverage']['truncation_reason'],'function_body_review_limit')

    def test_calls_uses_recovered_references_and_keeps_computed_targets_unresolved(self):
        snapshot = self.call_snapshot()
        first, second, third = snapshot['functions']
        first.update(xrefs_from_truncated=True, coverage={'body_ranges': {'status': 'complete', 'emitted': 1}})
        added = {'from': '0x100000002', 'to': third['entry_va'], 'type': 'UNCONDITIONAL_CALL'}
        hint = {'from': '0x100000003', 'to': third['entry_va'], 'type': 'UNCONDITIONAL_CALL'}
        first['instructions'].append({'addr': added['from'], 'flow': 'UNCONDITIONAL_CALL'})
        raw = snapshot['engine']
        raw['address_references'] = [*first['xrefs_from_sample'], added, hint]
        raw['computed_flow_sites'] = [{'addr': hint['from'], 'flow': 'COMPUTED_CALL'}]
        for key in ('address_references', 'computed_flow_sites'):
            raw['coverage'][key] = {'status': 'complete', 'emitted': len(raw[key])}
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            result = cli.execute(self.args('calls', '--function-id', first['function_id'], '--direction', 'callees'))
        self.assertEqual(result['status'], 'complete')
        first_call, recovered, computed = result['data']['edges']
        self.assertEqual(first_call['callee_function_id'], second['function_id'])
        self.assertEqual(recovered['callee_function_id'], third['function_id'])
        self.assertEqual(recovered['callsite'], added['from'])
        self.assertIsNone(computed['callee_function_id'])
        self.assertEqual(computed['resolution'], 'indirect_or_inferred')

    def test_fresh_decompile_requires_explicit_trust_and_single_function(self):
        with mock.patch.object(engine, 'dependencies') as deps:
            self.error('isolation_required', cli.execute,
                       self.args('decompile', '--fresh', '--name', 'unique'))
            self.error('fresh_selection', cli.execute,
                       self.args('decompile', '--fresh', '--all', '--experimental-trusted-input'))
        deps.assert_not_called()

    def test_dispatch_return_recovery_requires_an_unhinted_fresh_query(self):
        selector = ('--name', 'unique', '--recover-dispatch-return')
        with mock.patch.object(engine, 'dependencies') as deps:
            self.error('dispatch_return_scope', cli.execute, self.args('decompile', *selector))
            self.error('dispatch_return_scope', cli.execute,
                       self.args('decompile', *selector, '--fresh', '--with-type-hints'))
            self.error('isolation_required', cli.execute, self.args('decompile', *selector, '--fresh'))
        deps.assert_not_called()

    def test_direct_signature_recovery_is_exclusive_and_requires_trust(self):
        selector = ('--name', 'unique', '--recover-direct-signatures')
        with mock.patch.object(engine, 'dependencies') as deps:
            self.error('direct_signature_scope', cli.execute, self.args('decompile', *selector))
            self.error('direct_signature_scope', cli.execute,
                       self.args('decompile', *selector, '--fresh', '--recover-dispatch-return'))
            self.error('direct_signature_scope', cli.execute,
                       self.args('decompile', *selector, '--fresh', '--with-type-hints'))
            self.error('isolation_required', cli.execute, self.args('decompile', *selector, '--fresh'))
        deps.assert_not_called()

    def test_scalar_signature_recovery_requires_its_own_trusted_fresh_query(self):
        selector = ('--name', 'unique', '--recover-scalar-call-signatures')
        with mock.patch.object(engine, 'dependencies') as deps:
            self.error('scalar_signature_scope', cli.execute, self.args('decompile', *selector))
            for flag in ('--with-type-hints', '--recover-dispatch-return', '--recover-direct-signatures'):
                self.error('scalar_signature_scope', cli.execute,
                           self.args('decompile', *selector, '--fresh', flag))
            self.error('isolation_required', cli.execute, self.args('decompile', *selector, '--fresh'))
        deps.assert_not_called()

    def test_callee_parameter_recovery_requires_its_own_trusted_fresh_query(self):
        selector = ('--name', 'unique', '--recover-callee-parameters')
        with mock.patch.object(engine, 'dependencies') as deps:
            self.error('callee_parameter_scope', cli.execute, self.args('decompile', *selector))
            for flag in ('--with-type-hints', '--recover-dispatch-return', '--recover-direct-signatures',
                         '--recover-scalar-call-signatures'):
                self.error('callee_parameter_scope', cli.execute,
                           self.args('decompile', *selector, '--fresh', flag))
            self.error('isolation_required', cli.execute, self.args('decompile', *selector, '--fresh'))
        deps.assert_not_called()

    def test_forwarded_return_recovery_requires_its_own_trusted_fresh_query(self):
        selector = ('--name', 'unique', '--recover-forwarded-return')
        with mock.patch.object(engine, 'dependencies') as deps:
            self.error('forwarded_return_scope', cli.execute, self.args('decompile', *selector))
            for flag in ('--with-type-hints', '--recover-dispatch-return', '--recover-direct-signatures',
                         '--recover-scalar-call-signatures', '--recover-callee-parameters'):
                self.error('forwarded_return_scope', cli.execute,
                           self.args('decompile', *selector, '--fresh', flag))
            self.error('isolation_required', cli.execute, self.args('decompile', *selector, '--fresh'))
        deps.assert_not_called()

    def test_switch_table_recovery_requires_its_own_trusted_fresh_query(self):
        selector = ('--name', 'unique', '--recover-switch-table')
        with mock.patch.object(engine, 'dependencies') as deps:
            self.error('switch_table_scope', cli.execute, self.args('decompile', *selector))
            for flag in ('--with-type-hints', '--recover-dispatch-return', '--recover-direct-signatures',
                         '--recover-scalar-call-signatures', '--recover-callee-parameters', '--recover-forwarded-return'):
                self.error('switch_table_scope', cli.execute, self.args('decompile', *selector, '--fresh', flag))
            self.error('isolation_required', cli.execute, self.args('decompile', *selector, '--fresh'))
        deps.assert_not_called()

    def test_fresh_decompile_keeps_selected_snapshot_and_labels_new_evidence(self):
        record = {'pseudocode': 'char *f() { return "/Users/local/private"; }',
                  'decompile_status': 'complete', 'pseudocode_truncated': False,
                  'coverage': {'pseudocode': {'status': 'complete'}}}
        raw = {'functions': [record], 'bridge_version': '1.2.0'}
        job = {'job_id': 'a' * 32, 'analysis_profile': engine.analysis_profile()}
        (self.workspace.path / 'jobs' / job['job_id']).mkdir()
        with mock.patch.object(engine, 'dependencies', return_value={}), \
             mock.patch.object(engine, 'run', return_value=(raw, job)) as run:
            result = cli.execute(self.args('decompile', '--fresh', '--name', 'unique',
                                           '--experimental-trusted-input'))
        self.assertEqual(run.call_args.args[2], 'query')
        self.assertEqual(run.call_args.kwargs['entry'], '0x100000020')
        self.assertEqual(result['analysis_id'], self.snapshot['analysis_id'])
        self.assertEqual(result['data']['origin']['mode'], 'fresh_readonly')
        self.assertIn('$HOME/private', result['data']['pseudocode'])
        self.assertEqual(self.workspace.snapshot(self.workspace.select())[0], self.snapshot)

    def test_annotation_commands_preserve_engine_names_and_committed_snapshot(self):
        selector = ('--function-id', 'function-2')
        label = cli.execute(self.args('rename', 'Review anchor', *selector, '--author', 'reviewer'))
        self.assertTrue(label['data']['changed'])
        self.assertEqual(label['data']['revision']['author'], 'reviewer')
        note = 'Follow stack behavior'
        function_comment = cli.execute(self.args('comment', 'set', note, '--name', 'Review anchor'))
        instruction = '0x100000020'
        cli.execute(self.args('comment', 'set', 'Entry point', *selector, '--instruction', instruction))
        self.error('annotation_address', cli.execute,
                   self.args('comment', 'set', 'unlinked', *selector, '--instruction', '0x100000021'))
        shown = cli.execute(self.args('functions', 'show', '--name', 'Review anchor'))['data']
        self.assertEqual(shown['names'][0], {'name': 'unique', 'origin': 'ghidra'})
        self.assertEqual(shown['names'][1]['origin'], 'user_supplied')
        self.assertEqual(len(shown['annotations']), 3)
        search = cli.execute(self.args('search', 'stack', '--in', 'comments'))
        self.assertEqual(search['data'][0]['context'], note)
        self.assertEqual(search['data'][0]['function_id'], 'function-2')
        self.assertEqual(search['data'][0]['origin'], 'user_supplied')
        search = cli.execute(self.args('search', 'review anchor', '--in', 'names'))
        self.assertEqual(search['data'][0]['origin'], 'user_supplied')
        exported = cli.execute(self.args('export'))['data']
        self.assertEqual(exported, self.snapshot)
        annotated = cli.execute(self.args('export', '--include-annotations'))['data']
        self.assertEqual(len(annotated.pop('annotations')['records']), 3)
        self.assertEqual(annotated, self.snapshot)
        removed = cli.execute(self.args('comment', 'remove', *selector))
        self.assertEqual(removed['data']['revision']['previous_value'], note)
        self.assertEqual(len(cli.execute(self.args('comment', 'list', *selector))['data']), 1)
        cli.execute(self.args('rename', '--clear', *selector))
        self.error('function_selector', cli.execute, self.args('functions', 'show', '--name', 'Review anchor'))
        history = cli.execute(self.args('annotations', 'history', *selector))['data']
        self.assertEqual(len(history), 5)
        self.assertEqual(history[1], function_comment['data']['revision'])
        self.assertEqual(self.workspace.snapshot(self.workspace.select())[0], self.snapshot)

    def test_annotation_revision_invalidates_affected_cursors(self):
        before = cli.execute(self.args('functions', 'list', '--limit', '1'))
        cursor = before['coverage']['next_cursor']
        cli.execute(self.args('rename', 'New label', '--function-id', 'function-2'))
        self.error('stale_cursor', cli.execute, self.args('functions', 'list', '--cursor', cursor))
        cli.execute(self.args('rename', 'Second label', '--function-id', 'function-2'))
        first = cli.execute(self.args('annotations', 'history', '--limit', '1'))
        cursor = first['coverage']['next_cursor']
        self.assertIsNotNone(cursor)
        cli.execute(self.args('rename', '--clear', '--function-id', 'function-2'))
        self.error('stale_cursor', cli.execute, self.args('annotations', 'history', '--cursor', cursor))

    def test_type_hints_require_acceptance_and_cannot_reuse_cached_code(self):
        selector = ('--function-id','function-2')
        self.error('type_hint_acceptance',cli.execute,
                   self.args('type','set',*selector,'--return-type','uint64_t'))
        valid = cli.execute(self.args('type','set',*selector,'--return-type','uint64_t','--accept'))
        revision = valid['data']['revision']
        self.assertEqual(revision['kind'],'return_type')
        self.error('type_hint_type',cli.execute,
                   self.args('type','set',*selector,'--return-type','struct Guess','--accept'))
        self.assertEqual(cli.execute(self.args('type','list'))['data'],[revision])
        self.error('type_hints_require_fresh',cli.execute,
                   self.args('decompile',*selector,'--with-type-hints'))
        self.assertEqual(cli.execute(self.args('decompile',*selector))['data']['pseudocode'],
                         self.snapshot['functions'][2]['pseudocode'])
        bounded = dict(self.snapshot,functions=self.snapshot['functions'][:2])
        with mock.patch.object(storage.Project,'snapshot',return_value=(bounded,{})):
            cli.execute(self.args('type','clear','--address','0x100000020','--accept'))
        self.assertEqual(cli.execute(self.args('type','list'))['data'],[])
        self.assertEqual(self.workspace.snapshot(self.workspace.select())[0],self.snapshot)

    def test_parameter_list_hints_are_bounded_and_compose_with_the_return_hint(self):
        selector = ('--name', 'unique')
        prefix = ('type', 'set', *selector)
        self.error('type_hint_acceptance', cli.execute, self.args(*prefix, '--parameters', 'uint8_t*'))
        for value, code in (('void,uint32_t', 'type_hint_parameters'),
                            ('uint8_t***', 'type_hint_type'),
                            (','.join(['uint32_t'] * 17), 'type_hint_parameters')):
            self.error(code, cli.execute, self.args(*prefix, '--parameters', value, '--accept'))
        params = cli.execute(self.args(*prefix, '--parameters', 'uint8_t*, bool', '--accept'))['data']['revision']
        result = cli.execute(self.args(*prefix, '--parameters', 'uint8_t*,bool', '--accept'))['data']
        self.assertFalse(result['changed'])
        returns = cli.execute(self.args(*prefix, '--return-type', 'void**', '--accept'))['data']['revision']
        rows = cli.execute(self.args('type', 'list', *selector))['data']
        self.assertEqual(rows, [params, returns])
        self.assertEqual(cli.annotations.type_hints(rows, self.snapshot['functions']), [
            {'entry_va': '0x100000020', 'return_type': 'void**', 'revision': returns['revision']},
            {'entry_va': '0x100000020', 'parameter_types': ['uint8_t*', 'bool'], 'revision': params['revision']},
        ])
        cli.execute(self.args('type', 'clear', '--parameters', *selector, '--accept'))
        self.assertEqual(cli.execute(self.args('type', 'list', *selector))['data'], [returns])
        zero = cli.execute(self.args(*prefix, '--parameters', 'void', '--accept'))['data']['revision']
        self.assertEqual(zero['value'], '[]')
        self.assertEqual(self.workspace.snapshot(self.workspace.select())[0], self.snapshot)

    def test_aggregate_type_hints_share_a_layout_and_reject_conflicts_before_revision(self):
        pair = 'struct Pair{left:uint64_t;right:double}'
        target = ('--function-id','function-0','--accept')
        cli.execute(self.args('type','set',*target,'--return-type',pair))
        cli.execute(self.args('type','set',*target,'--parameters',pair+'*,uint64_t'))
        original = cli.execute(self.args('annotations','history'))['data']
        self.error('type_hint_struct_conflict',cli.execute,
                   self.args('type','set','--function-id','function-1','--accept','--return-type',
                             'struct Pair{left:uint32_t}'))
        for malformed in ('struct Pair{}','struct Pair{a:void}', 'struct Pair{a:int32_t;a:int8_t}',
                          'struct Pair{a:struct Nested{b:bool}}'):
            self.error('type_hint_type',cli.execute,self.args('type','set',*target,'--return-type',malformed))
        self.assertEqual(cli.execute(self.args('annotations','history'))['data'],original)
        _, rows = cli.annotations.read(self.workspace,self.snapshot['image']['image_id'])
        hints = cli.annotations.type_hints(rows,self.snapshot['functions'])
        self.assertEqual(hints[0]['return_type'],pair)
        self.assertEqual(hints[1]['parameter_types'],[pair+'*','uint64_t'])

    def test_manual_boundary_edits_preserve_snapshot_and_recover_the_original_revision(self):
        image = self.workspace.select()
        entry = self.snapshot['functions'][0]['entry_va']
        end = hex(int(entry,16)+7)
        words = ('boundary','set','--address',entry,'--body',f'{entry}:{end}')
        self.error('boundary_edit_acceptance',cli.execute,self.args(*words))
        covered = copy.deepcopy(self.snapshot)
        covered['functions'][0]['coverage'] = {'body_ranges':{'status':'complete'}}
        with mock.patch.object(storage.Project,'snapshot',return_value=(covered,{})):
            accepted = cli.execute(self.args(*words,'--accept'))['data']['revision']
        plan = cli.boundary_edit_request(self.workspace,image)
        self.assertEqual(plan['edits'],[{'entry':entry,'before':self.snapshot['functions'][0]['body_ranges'],
                                        'body':[[entry,end]],'revision':accepted['revision']}])
        self.assertEqual(cli.execute(self.args('boundary','list','--address',entry))['data'],[accepted])
        overlapping = hex(int(entry,16)+1)
        cli.execute(self.args('boundary','set','--address',overlapping,'--body',f'{overlapping}:{end}','--accept'))
        self.error('boundary_edit_overlap',cli.boundary_edit_request,self.workspace,image)
        cli.execute(self.args('boundary','clear','--address',overlapping,'--accept'))
        cli.execute(self.args('boundary','clear','--address',entry,'--accept'))
        self.error('boundary_edits_missing',cli.boundary_edit_request,self.workspace,image)
        self.assertEqual(cli.boundary_edit_request(self.workspace,image,at_revision=accepted['revision']),plan)
        self.assertEqual(self.workspace.snapshot(image)[0],self.snapshot)

    def test_unresolved_computed_jump_surfaces_without_rewriting_saved_evidence(self):
        snapshot = copy.deepcopy(self.snapshot)
        target = snapshot['functions'][2]
        target['blocks'][0].update(flow='COMPUTED_JUMP', dsts=[])
        target['coverage'] = {'pseudocode': {'status': 'complete', 'emitted': 1}}
        target['pseudocode'] = '/* WARNING: Treating indirect jump as call */\nreturn;'
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            for command in (('decompile',), ('disasm',), ('cfg',), ('functions', 'show'),
                            ('xrefs', '--direction', 'from'), ('calls', '--direction', 'callees')):
                with self.subTest(command=command):
                    result = cli.execute(self.args(*command, '--name', 'unique'))
                    self.assertEqual(result['status'], 'partial')
                    self.assertIn('unresolved_control_flow', result['coverage']['truncation_reason'])
            selected = cli.execute(self.args('decompile', '--name', 'unique'))['data']
            self.assertEqual(selected['decompile_status'], 'partial')
            self.assertEqual(selected['engine_decompile_status'], 'complete')
            self.assertEqual(selected['pseudocode'], target['pseudocode'])
            self.assertEqual([gap['source'] for gap in selected['control_flow_gaps']],
                             ['ghidra_cfg', 'ghidra_pseudocode'])
            batch = cli.execute(self.args('decompile', '--all'))
            self.assertEqual(batch['data']['summary']['partial'], 1)
            exported = cli.execute(self.args('export'))
            self.assertEqual(exported['data']['control_flow_review']['affected_functions'], 1)
            self.assertEqual(exported['status'], 'partial')
        self.assertNotIn('control_flow_gaps', target)
        self.assertEqual(target['decompile_status'], 'complete')

    def test_resolved_switch_and_indirect_call_do_not_imply_a_missing_jump(self):
        snapshot = copy.deepcopy(self.snapshot)
        target = snapshot['functions'][2]
        target['blocks'][0].update(flow='COMPUTED_JUMP', dsts=[
            {'flow': 'COMPUTED_JUMP', 'to': target['entry_va']},
        ])
        target['blocks'].append(dict(target['blocks'][0], flow='COMPUTED_CALL', dsts=[]))
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            result = cli.execute(self.args('decompile', '--name', 'unique'))
        self.assertEqual(result['status'], 'complete')
        self.assertNotIn('control_flow_gaps', result['data'])

    def test_decompile_all_reports_failures_outside_the_page_and_keeps_page_counts(self):
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['functions'][-1].update(decompile_status='timeout',pseudocode=None)
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            first = cli.execute(self.args('decompile','--all','--limit','1'))
            cursor = first['coverage']['next_cursor']
            last = cli.execute(self.args('decompile','--all','--limit','2','--cursor',cursor))
        self.assertEqual(first['status'],'partial')
        self.assertEqual(first['data']['summary'],{'complete':1})
        self.assertEqual(first['data']['batch_summary'],{'captured_functions':3,'engine_recognized_functions':3,
                        'uncaptured_functions':0,'outcomes':{'complete':2,'timeout':1}})
        self.assertEqual(first['coverage']['truncation_reason'],'pseudocode_incomplete;page_limit')
        self.assertEqual(last['status'],'partial')
        self.assertEqual(last['data']['batch_summary'],first['data']['batch_summary'])
        self.assertEqual(last['data']['summary'],{'complete':1,'timeout':1})

    def test_decompile_all_distinguishes_pagination_capture_and_analysis_limits(self):
        snapshot = copy.deepcopy(self.snapshot)
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})):
            paged = cli.execute(self.args('decompile','--all','--limit','1'))
            self.assertEqual(paged['status'],'complete')
            self.assertEqual(paged['coverage']['truncation_reason'],'page_limit')
            snapshot['functions'] = snapshot['functions'][:1]
            snapshot['engine']['functions_truncated'] = True
            limited = cli.execute(self.args('decompile','--all'))
            self.assertEqual(limited['status'],'partial')
            self.assertEqual(limited['coverage']['truncation_reason'],'discovery_limit')
            self.assertEqual(limited['data']['batch_summary']['uncaptured_functions'],2)
            snapshot['engine'].update(functions_truncated=False,analysis_timed_out=True,
                                      function_count_total_reported_by_engine=1)
            timed = cli.execute(self.args('decompile','--all'))
            self.assertEqual(timed['status'],'partial')
            self.assertEqual(timed['coverage']['truncation_reason'],'analysis_timeout')
            raw = snapshot['engine']
            raw['analysis_timed_out'] = False
            raw.pop('function_count_total_reported_by_engine')
            raw['coverage']['functions'] = {'status':'error','emitted':1,'total':2,'error':'capture interrupted'}
            incomplete = cli.execute(self.args('decompile','--all'))
            self.assertEqual(incomplete['coverage']['truncation_reason'],'function_capture_incomplete')
            self.assertEqual(incomplete['data']['batch_summary']['uncaptured_functions'],1)
            raw['function_count_total_reported_by_engine'] = 3
            inconsistent = cli.execute(self.args('decompile','--all'))
            self.assertIsNone(inconsistent['coverage']['known_total'])
            self.assertIn('function_count_mismatch',inconsistent['coverage']['truncation_reason'])

    def test_cached_metadata_filters_keep_address_space_and_coverage(self):
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['engine']['imports'] = [
            {'name': '_puts', 'address': 'EXTERNAL:00000001', 'library': '/usr/lib/libSystem.B.dylib'}
        ]
        snapshot['engine']['coverage']['imports'] = {'status': 'complete', 'emitted': 1}
        snapshot['engine']['strings'] = [
            {'value': 'long hint', 'length_bytes': 10, 'address': '0x100000080'},
            {'value': None, 'length_bytes': 4097, 'value_truncated': True, 'address': '0x100000100'},
        ]
        snapshot['engine']['coverage']['strings']['emitted'] = 2
        with mock.patch.object(storage.Project, 'snapshot', return_value=(snapshot, {})), \
             mock.patch.object(engine, 'dependencies') as dependency:
            imports = cli.execute(self.args('imports', '--name-contains', 'puts'))
            strings = cli.execute(self.args('strings', '--min-length', '8', '--contains', 'hint'))
        dependency.assert_not_called()
        imported, = imports['data']
        self.assertIsNone(imported['va'])
        self.assertEqual(imported['address_space'], 'EXTERNAL')
        self.assertEqual(imports['status'], 'complete')
        self.assertEqual(strings['data'][0]['value'], 'long hint')
        self.assertEqual(strings['status'], 'partial')
        self.assertIsNone(strings['coverage']['known_total'])

    def assert_envelope(self, result):
        required = {'schema_version', 'command', 'status', 'analysis_id', 'data', 'diagnostics', 'coverage'}
        self.assertTrue(required <= result.keys())
        self.assertEqual(result['schema_version'], SCHEMA_VERSION)
        self.assertIn(result['status'], ('complete', 'partial', 'failed', 'cancelled'))
        self.assertIsInstance(result['command'], str)
        self.assertIsInstance(result['diagnostics'], list)
        self.assertTrue({'scope', 'status', 'returned_count', 'known_total', 'next_cursor', 'truncation_reason'} <= result['coverage'].keys())
        self.assertIsInstance(result['coverage']['returned_count'], int)
        schema.validate_envelope(result)

    def test_all_cached_queries_never_probe_engine_or_start_jvm(self):
        cases = [('status',), ('functions', 'list'), ('functions', 'show', '--function-id', 'function-0'),
                 ('disasm', '--address', '0x100000000'), ('decompile', '--name', 'unique'),
                 ('decompile', '--all'), ('xrefs', '--function-id', 'function-0'),
                 ('cfg', '--function-id', 'function-0'), ('export',)]
        with mock.patch.object(engine, 'dependencies', side_effect=AssertionError('dependency probe during cached query')), \
             mock.patch.object(engine, 'run', side_effect=AssertionError('engine run during cached query')), \
             mock.patch.object(engine.subprocess, 'Popen', side_effect=AssertionError('process start during cached query')):
            for words in cases:
                with self.subTest(command=words):
                    result = cli.execute(self.args(*words))
                    self.assert_envelope(result)
                    self.assertEqual(result['status'], 'complete')

    def test_fresh_writer_commands_refuse_disconnected_import_before_staging(self):
        job_id = 'a' * 32
        path = self.workspace.path / 'jobs' / job_id / 'job.json'
        path.parent.mkdir()
        storage.write_json(path, {'job_id':job_id, 'mode':'import', 'status':'running'})
        commands = [('import', str(self.root / 'unused')), ('analyze',)]
        with mock.patch.object(engine, 'dependencies', side_effect=AssertionError('unexpected engine preflight')):
            for command in commands:
                with self.subTest(command=command):
                    args = self.args(*command, '--experimental-trusted-input')
                    error = self.error('writer_conflict', cli.execute, args)
                    self.assertEqual(error.partial, {'job_id':job_id})
            self.assertEqual(cli.execute(self.args('decompile', '--name', 'unique'))['status'], 'complete')
        self.assertEqual(list((self.workspace.path / 'inputs').iterdir()), [])

    def test_version_never_probes_dependencies(self):
        with mock.patch.object(engine, 'dependencies', side_effect=AssertionError('version probe')):
            code, output, stderr = self.invoke(['version', '--json'])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, '')
        self.assert_envelope(json.loads(output))

    def test_status_reports_verified_coverage_and_packaged_worker_freshness(self):
        image = self.workspace.select()
        aid = image['active_analysis']
        target = self.workspace.path / 'snapshots' / (aid + '.json')
        snapshot, record = self.workspace.snapshot(image)
        snapshot.update(status='partial', analysis_profile={'name':'baseline'},
                        identity={'engine':{'ghidra_version':'12.2','bridge_sha256':engine.bridge_digest()}})
        snapshot['engine'].update(bridge_version=engine.BRIDGE_VERSION,
                                  function_count_total_reported_by_engine=5,
                                  decompile_summary={'completed':3},
                                  coverage={'functions':{'status':'partial'}, 'strings':{'status':'complete'}})
        with mock.patch.object(engine, 'dependencies', side_effect=AssertionError('status probed Ghidra')):
            for sha, freshness in ((engine.bridge_digest(), 'current'), ('0' * 64, 'stale')):
                with self.subTest(freshness=freshness):
                    snapshot['identity']['engine']['bridge_sha256'] = sha
                    payload = storage.canonical(snapshot) + b'\n'
                    storage.atomic(target, payload, force=True)
                    with self.workspace.db(False) as db:
                        receipt = dict(record, snapshot_sha256=hashlib.sha256(payload).hexdigest())
                        db.execute('UPDATE analyses SET payload=?', (json.dumps(receipt),))
                    result = cli.execute(self.args('status', '--arch', 'arm64'))
                    self.assertEqual(result['status'], 'complete')
                    analysis = result['data']['images'][0]['analysis']
                    self.assertEqual((analysis['status'], analysis['function_count'], analysis['function_total']),
                                     ('partial', 3, 5))
                    self.assertEqual(analysis['decompile_summary'], {'completed':3})
                    self.assertEqual(analysis['coverage_gaps'], ['functions'])
                    self.assertEqual(analysis['freshness']['status'], freshness)
                    self.assertEqual(analysis['freshness']['scope'], 'packaged_worker')
                    self.assertEqual(analysis['freshness']['changed'], ['bridge_sha256'] if freshness == 'stale' else [])

    def test_status_verifies_current_programs_independently_of_cached_analysis(self):
        image = self.workspace.select()
        import_job, analysis_job = 'a' * 32, 'b' * 32
        baseline = self.workspace.path / 'jobs' / import_job / 'program'
        analyzed = self.workspace.path / 'jobs' / analysis_job / 'program'
        baseline_db = synthetic_program(baseline)
        analyzed_db = synthetic_program(analyzed)
        _, record = self.workspace.snapshot(image)
        image.update(engine_baseline_job_id=import_job, engine_baseline_sha256=engine.tree_digest(baseline))
        record.update(job_id=analysis_job, analysis_program_sha256=engine.tree_digest(analyzed))
        with self.workspace.db(False) as db:
            db.execute('UPDATE images SET metadata=?', (json.dumps(image),))
            db.execute('UPDATE analyses SET payload=?', (json.dumps(record),))
        with mock.patch.object(engine, 'dependencies', side_effect=AssertionError('unexpected engine preflight')), \
             mock.patch.object(engine, 'run', side_effect=AssertionError('unexpected worker')), \
             mock.patch.object(engine, 'saved_program_digest', wraps=engine.saved_program_digest) as digest:
            default = cli.execute(self.args('status'))
            self.assertNotIn('programs', default['data']['images'][0])
            digest.assert_not_called()
            result = cli.execute(self.args('status', '--verify-programs'))
            self.assertEqual(result['status'], 'complete')
            verified = {'status':'verified'}
            self.assertEqual(result['data']['images'][0]['programs'], {'import':verified, 'analysis':verified})
            self.assertEqual([call.args[0] for call in digest.call_args_list], [baseline, analyzed])

            baseline_bytes = baseline_db.read_bytes()
            baseline_db.unlink()
            result = cli.execute(self.args('status', '--verify-programs'))
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['coverage']['truncation_reason'], 'program_unavailable')
            row, = result['data']['images']
            self.assertEqual(row['analysis'], default['data']['images'][0]['analysis'])
            self.assertEqual(row['programs'], {'import':{'status':'unavailable','error':'baseline_integrity'},
                                               'analysis':verified})
            baseline_db.write_bytes(baseline_bytes)
            analyzed_db.write_bytes(b'changed Program')
            result = cli.execute(self.args('status', '--verify-programs'))
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['data']['images'][0]['programs'],
                             {'import':verified,
                              'analysis':{'status':'unavailable','error':'analysis_program_integrity'}})
            self.assertEqual(cli.execute(self.args('status')), default)
            self.assertEqual(cli.execute(self.args('export'))['status'], 'complete')

            snapshot = self.workspace.path / 'snapshots' / (image['active_analysis'] + '.json')
            storage.atomic(snapshot, b'changed snapshot', force=True)
            digest.reset_mock()
            result = cli.execute(self.args('status', '--verify-programs'))
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['coverage']['truncation_reason'], 'snapshot_unavailable')
            self.assertEqual(result['data']['images'][0]['programs'],
                             {'import':verified,
                              'analysis':{'status':'unverified','reason':'snapshot_unavailable'}})
            digest.assert_called_once_with(baseline, 'baseline_integrity')

    def test_status_bounds_snapshot_checks_and_keeps_healthy_image_visible(self):
        aid = 'e' * 64
        image = dict(self.snapshot['image'], image_id='f' * 64, arch='x86_64')
        snapshot = dict(self.snapshot, image=image, analysis_id=aid, functions=[])
        payload = storage.canonical(snapshot) + b'\n'
        storage.atomic(self.workspace.path / 'snapshots' / (aid + '.json'), payload)
        with self.workspace.db(False) as db:
            db.execute('INSERT INTO images VALUES(?,?,?,1,?)', (image['image_id'],image['arch'],json.dumps(image),aid))
            db.execute('INSERT INTO analyses VALUES(?,?,?)',
                       (aid,image['image_id'],json.dumps({'snapshot_sha256':hashlib.sha256(payload).hexdigest()})))
        with mock.patch.object(cli, 'STATUS_SNAPSHOT_LIMIT', 1):
            result = cli.execute(self.args('status'))
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['coverage']['truncation_reason'], 'snapshot_check_limit')
            self.assertEqual(result['data']['images'][1]['analysis']['status'], 'unverified')
            selected = cli.execute(self.args('status', '--image', image['image_id']))
            self.assertEqual(selected['status'], 'complete')
            self.assertEqual(selected['data']['images'][0]['analysis']['function_count'], 0)
        with mock.patch.object(cli, 'STATUS_PROGRAM_LIMIT', 1), \
             mock.patch.object(engine, 'imported_program') as imported, \
             mock.patch.object(engine, 'analyzed_program') as analyzed:
            result = cli.execute(self.args('status', '--verify-programs'))
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['coverage']['truncation_reason'], 'program_check_limit')
            skipped = {'status':'unverified','reason':'program_check_limit'}
            self.assertEqual(result['data']['images'][1]['programs'], {'import':skipped,'analysis':skipped})
            self.assertEqual(result['data']['images'][1]['analysis']['status'], 'complete')
            imported.assert_called_once()
            analyzed.assert_called_once()
            selected = cli.execute(self.args('status', '--verify-programs', '--image', image['image_id']))
            self.assertEqual(selected['status'], 'complete')
            verified = {'status':'verified'}
            self.assertEqual(selected['data']['images'][0]['programs'], {'import':verified,'analysis':verified})
        storage.atomic(self.workspace.path / 'snapshots' / (self.snapshot['analysis_id'] + '.json'),
                       b'invalid snapshot', force=True)
        result = cli.execute(self.args('status'))
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['data']['images'][0]['analysis']['error'], 'snapshot_integrity')
        self.assertEqual(result['data']['images'][1]['analysis']['status'], 'complete')

    def test_error_envelope_has_required_fields_and_candidates(self):
        code, output, _ = self.invoke(['functions', 'show', '--project', str(self.workspace.path), '--name', 'duplicate', '--json'])
        result = json.loads(output)
        self.assertEqual(code, 2)
        self.assert_envelope(result)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['coverage']['status'], 'partial')
        self.assertEqual(result['coverage']['returned_count'], 0)
        self.assertEqual(result['coverage']['truncation_reason'], 'function_selector')
        self.assertTrue({'code', 'message', 'affected_object', 'retryable', 'partial_results'} <= result['error'].keys())
        self.assertEqual(result['error']['code'], 'function_selector')
        self.assertEqual(len(result['error']['partial_results']), 2)

    def test_usage_errors_are_json_not_tracebacks(self):
        code, output, stderr = self.invoke(['functions', 'show'])
        self.assertEqual(code, 2)
        result = json.loads(output)
        self.assert_envelope(result)
        self.assertEqual(result['error']['code'], 'usage')
        self.assertNotIn('Traceback', stderr)

    def test_help_for_every_command_parses(self):
        commands = [[], ['version'], ['doctor'], ['inspect'], ['project'], ['project', 'create'],
                    ['import'], ['analyze'], ['status'], ['functions'], ['functions', 'list'],
                    ['functions', 'show'], ['disasm'], ['decompile'], ['xrefs'], ['cfg'], ['export']]
        for words in commands:
            with self.subTest(command=words), contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as caught:
                    cli.parser().parse_args([*words, '--help'])
                self.assertEqual(caught.exception.code, 0)
                self.assertIn('usage:', output.getvalue())

    def test_supported_commands_parse_required_arguments(self):
        commands = [['version'], ['doctor'], ['inspect', 'input.macho'], ['project', 'create', 'new-project'],
                    ['import', 'input.macho', '--project', 'p'], ['analyze', '--project', 'p'], ['status', '--project', 'p'],
                    ['functions', 'list', '--project', 'p'], ['functions', 'show', '--project', 'p', '--name', 'f'],
                    ['disasm', '--project', 'p', '--address', '0x1000'], ['decompile', '--project', 'p', '--all'],
                    ['xrefs', '--project', 'p', '--function-id', 'id'], ['cfg', '--project', 'p', '--name', 'f'],
                    ['export', '--project', 'p']]
        for words in commands:
            with self.subTest(command=words):
                self.assertEqual(cli.parser().parse_args(words).command, words[0])

    def test_output_file_requires_force_and_stdout_is_empty_on_success(self):
        target = self.root / 'version.json'
        target.write_bytes(b'original')
        code, output, _ = self.invoke(['version', '--json', '--output', str(target)])
        self.assertEqual(code, 8)
        self.assertEqual(json.loads(output)['error']['code'], 'output_exists')
        self.assertEqual(target.read_bytes(), b'original')
        code, output, stderr = self.invoke(['version', '--json', '--output', str(target), '--force'])
        self.assertEqual((code, output, stderr), (0, b'', ''))
        self.assert_envelope(json.loads(target.read_bytes()))

    def test_output_refuses_selected_inputs_and_aliases(self):
        binary = self.root / 'owned.macho'
        binary.write_bytes(b'owned input')
        alias = self.root / 'linked.macho'
        os.link(binary, alias)
        app = self.root / 'Owned.app'
        resources = app / 'Contents' / 'Resources'
        resources.mkdir(parents=True)
        cases = [
            (['inspect', str(binary)], binary),
            (['fixups', '--input', str(binary)], alias),
            (['diff', str(binary), str(alias), '--scope', 'metadata'], alias),
            (['annotations', 'import', str(alias), '--project', str(self.workspace.path)], alias),
            (['bundle', 'list', str(app)], resources / 'report.json'),
        ]
        for words, target in cases:
            with self.subTest(command=words):
                code, output, _ = self.invoke([*words, '--output', str(target), '--force'])
                self.assertEqual(code, 8)
                self.assertEqual(json.loads(output)['error']['code'], 'output_input_conflict')
        self.assertEqual(binary.read_bytes(), b'owned input')
        self.assertTrue(alias.samefile(binary))
        self.assertEqual(list(resources.iterdir()), [])

    def test_output_protects_managed_workspace_paths_before_changes(self):
        workspace = self.workspace.path
        index = workspace / 'index.sqlite'
        original = index.read_bytes()
        for target in (index, workspace / 'inputs' / 'new.macho', workspace / 'writer.lock'):
            with self.subTest(target=target):
                code, output, _ = self.invoke(['rename', 'new label', '--name', 'unique',
                                               '--project', str(workspace), '--output', str(target), '--force'])
                self.assertEqual(code, 8)
                self.assertEqual(json.loads(output)['error']['code'], 'output_workspace_conflict')
        self.assertEqual(index.read_bytes(), original)
        self.assertFalse((workspace / 'writer.lock').exists())
        self.assertEqual(list((workspace / 'inputs').iterdir()), [])
        project = self.root / 'new-workspace'
        for alias in (project, project.with_name('NEW-WORKSPACE')):
            with self.subTest(alias=alias):
                code, output, _ = self.invoke(['project', 'create', str(project), '--output',
                                               str(alias / 'project.json'), '--force'])
                self.assertEqual(code, 8)
                self.assertEqual(json.loads(output)['error']['code'], 'output_workspace_conflict')
                self.assertFalse(project.exists())
        report = workspace / 'report.json'
        code, output, stderr = self.invoke(['export', '--project', str(workspace), '--output', str(report)])
        self.assertEqual((code, output, stderr), (0, b'', ''))
        self.assertEqual(json.loads(report.read_bytes())['command'], 'export')

    def test_output_rechecks_selected_input_alias_before_publication(self):
        binary = self.root / 'owned.macho'
        binary.write_bytes(b'owned input')
        target = self.root / 'report.json'

        def inspect_and_link(*args, **kwargs):
            os.link(binary, target)
            return {'slices': []}, b''

        with mock.patch.object(cli, 'inspect_path', side_effect=inspect_and_link):
            code, output, _ = self.invoke(['inspect', str(binary), '--output', str(target), '--force'])
        self.assertEqual(code, 8)
        self.assertEqual(json.loads(output)['error']['code'], 'output_input_conflict')
        self.assertTrue(target.samefile(binary))

    def test_output_directory_symlink_swap_preserves_selected_workspace(self):
        workspace = self.workspace.path
        manifest = workspace / 'project.json'
        original = manifest.read_bytes()
        directory = self.root / 'reports'
        directory.mkdir()
        moved = self.root / 'moved'
        real_open = os.open

        def redirect(path, flags, *args, **kwargs):
            if isinstance(path, str) and path.startswith('.macscope-'):
                directory.rename(moved)
                directory.symlink_to(workspace, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(storage.os, 'open', side_effect=redirect):
            code, output, _ = self.invoke(['status', '--project', str(workspace), '--output',
                                           str(directory / manifest.name), '--force', '--json'])
        self.assertEqual(code, 8)
        self.assertEqual(json.loads(output)['error']['code'], 'output_directory_changed')
        self.assertEqual(manifest.read_bytes(), original)
        self.assertEqual(list(moved.iterdir()), [])

    def test_partial_facet_returns_partial_status_and_exit_six(self):
        self.snapshot['functions'][0]['instructions_truncated'] = True
        with mock.patch.object(storage.Project, 'snapshot', return_value=(self.snapshot, {})):
            code, output, stderr = self.invoke(['disasm', '--project', str(self.workspace.path), '--function-id', 'function-0', '--json'])
        result = json.loads(output)
        self.assertEqual(code, 6)
        self.assertEqual(stderr, '')
        self.assert_envelope(result)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['coverage']['truncation_reason'], 'facet_incomplete')

    def test_jsonl_rows_each_have_envelope_and_analysis_identity(self):
        result = cli.execute(self.args('functions', 'list'))
        lines = cli.render(result, 'jsonl').splitlines()
        self.assertEqual(len(lines), 3)
        for line in lines:
            row = json.loads(line)
            self.assert_envelope(row)
            self.assertEqual(row['analysis_id'], self.snapshot['analysis_id'])
            self.assertEqual(row['coverage']['returned_count'], 1)

    def test_jsonl_stdout_writes_each_row_before_serializing_the_next(self):
        real_canonical = cli.canonical
        written_before_encoding = []

        def encode(row):
            written_before_encoding.append(sys.stdout.buffer.getvalue().count(b'\n'))
            return real_canonical(row)

        words = ['functions', 'list', '--project', str(self.workspace.path), '--format', 'jsonl']
        with mock.patch.object(cli, 'canonical', side_effect=encode):
            code, output, stderr = self.invoke(words)
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(written_before_encoding, [0, 1, 2])
        self.assertEqual(len(output.splitlines()), 3)

    def test_jsonl_streams_manifest_with_existing_bytes(self):
        result = cli.execute(self.args('export'))
        expected = storage.canonical(result) + b'\n'
        chunks = cli.render_jsonl(result)
        self.assertEqual(next(chunks), b'{')
        self.assertEqual(b'{' + b''.join(chunks), expected)
        words = ['export', '--project', str(self.workspace.path), '--format', 'jsonl']
        target = self.root / 'export.jsonl'
        self.assertEqual(self.invoke([*words, '--output', str(target)]), (0, b'', ''))
        self.assertEqual(target.read_bytes(), expected)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_interrupted_jsonl_encoding_preserves_existing_output(self):
        target = self.root / 'export.jsonl'
        target.write_bytes(b'previous export')

        def failing_stream(result):
            yield b'{"data":'
            raise ValueError('synthetic serialization failure')

        words = ['export', '--project', str(self.workspace.path), '--format', 'jsonl',
                 '--output', str(target), '--force']
        with mock.patch.object(cli, 'render_jsonl', side_effect=failing_stream):
            code, output, stderr = self.invoke(words)
        self.assertEqual(code, 10)
        self.assertEqual(json.loads(output)['error']['code'], 'internal_failure')
        self.assertIn('synthetic serialization failure', stderr)
        self.assertEqual(target.read_bytes(), b'previous export')
        self.assertEqual(list(self.root.glob('.macscope-*')), [])

    def test_terminal_controls_are_escaped(self):
        value = '\x1b[31munsafe\x07\u202e\r\n\ud800'
        result = cli.envelope('inspect', {'name': value})
        for fmt in (None, 'json', 'jsonl'):
            output = cli.render(result, fmt)
            self.assertNotIn(b'\x1b', output)
            self.assertNotIn(b'\x07', output)
            self.assertEqual(json.loads(output)['data']['name'], value)
        output = cli.render(result, 'text')
        self.assertIn(rb'\u{1b}[31munsafe\u{7}\u{202e}\r\n\u{d800}', output)
        self.assertNotIn(b'\x1b', output)
        self.assertNotIn(b'\x07', output)
        with mock.patch.object(cli, 'execute', side_effect=Error('owned_test', value)):
            code, stdout, stderr = self.invoke(['version', '--format', 'text'])
        self.assertEqual(code, 5)
        self.assertEqual(json.loads(stdout)['error']['message'], value)
        self.assertEqual(stderr, r'\u{1b}[31munsafe\u{7}\u{202e}\r\n\u{d800}' + '\n')

    def test_explicit_text_view_preserves_cursor_and_default_json(self):
        at = ['--project', str(self.workspace.path)]
        command = ['functions', 'list', *at, '--limit', '1']
        code, default, _ = self.invoke(command)
        self.assertEqual(code, 0)
        envelope = json.loads(default)
        cursor = envelope['coverage']['next_cursor']
        self.assertEqual(envelope, json.loads(self.invoke([*command, '--json'])[1]))
        code, page, _ = self.invoke([*command, '--format', 'text'])
        self.assertEqual(code, 0)
        self.assertIn(b'Coverage  selected image function collection  (partial)', page)
        self.assertIn(b'Next cursor  ' + cursor.encode(), page)
        second = self.invoke([*command, '--format', 'text', '--cursor', cursor])[1]
        self.assertIn(b'0x100000010  duplicate', second)

    def test_text_disassembly_and_pseudocode_use_saved_evidence(self):
        at = ['--project', str(self.workspace.path), '--name', 'unique', '--format', 'text']
        with mock.patch.object(engine, 'dependencies', side_effect=AssertionError('cached text started Ghidra')):
            code, assembly, _ = self.invoke(['disasm', *at])
            self.assertEqual(code, 0)
            self.assertRegex(assembly, rb'0x100000020 +c0035fd6 +ret\n')
            code, pseudocode, _ = self.invoke(['decompile', *at])
            self.assertEqual(code, 0)
            self.assertIn(b'    void unique(void) { return; }\n', pseudocode)

    def test_html_export_escapes_saved_evidence_and_preserves_partial_status(self):
        hostile = '</pre><script>alert(1)</script><img src="https://example.invalid/leak">'
        note = 'Private annotation ' + hostile
        cli.execute(self.args('comment', 'set', note, '--name', 'unique'))
        self.snapshot['image']['input_name'] = hostile
        self.snapshot['functions'][0].update(name=hostile, pseudocode=hostile + '\x1b\u202e\ud800')
        self.snapshot['engine']['strings'][0]['value'] = hostile
        self.snapshot['status'] = 'partial'
        path = self.root / 'report.html'
        args = ['export', '--project', str(self.workspace.path), '--format', 'html']
        with mock.patch.object(storage.Project, 'snapshot', return_value=(self.snapshot, {})), \
             mock.patch.object(engine, 'dependencies', side_effect=AssertionError('cached HTML launched Ghidra')):
            code, output, stderr = self.invoke(args)
            self.assertEqual((code, stderr), (6, ''))
            self.assertNotIn(b'Private annotation', output)
            args.append('--include-annotations')
            code, annotated, stderr = self.invoke(args)
            self.assertEqual((code, stderr), (6, ''))
            self.assertEqual(self.invoke([*args, '--output', str(path)]), (6, b'', ''))

        self.assertEqual(path.read_bytes(), annotated)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertIn(b'Private annotation', annotated)
        self.assertIn(b'<dt>Status</dt><dd>partial</dd>', annotated)
        self.assertIn(b'href="#function-1"', annotated)
        self.assertIn(b'<details id="function-1">', annotated)
        self.assertIn(b'0x100000000  c0035fd6  ret', annotated)
        self.assertIn(b'&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;', annotated)
        self.assertIn(b'\\u001b\\u202e\\ud800', annotated)
        self.assertIn(b'Content-Security-Policy', annotated)
        for unsafe in (b'<script', b'<img', b'\x1b', '\u202e'.encode()):
            self.assertNotIn(unsafe, annotated)

    def test_html_output_limit_preserves_existing_report(self):
        path = self.root / 'report.html'
        path.write_bytes(b'existing report')
        args = ['export', '--project', str(self.workspace.path), '--format', 'html',
                '--output', str(path), '--force']
        with mock.patch.object(cli.html_export, 'MAX_HTML_BYTES', 1500):
            code, output, stderr = self.invoke(args)
        self.assertEqual(code, 7)
        self.assertEqual(json.loads(output)['error']['code'], 'html_output_limit')
        self.assertIn('output byte limit', stderr)
        self.assertEqual(path.read_bytes(), b'existing report')
        self.assertEqual(list(self.root.glob('.macscope-*')), [])

    def test_invalid_budgets_fail_before_dependency_probe(self):
        for extra in (['--timeout', '0'], ['--max-functions', '10001'], ['--heap-mib', '255']):
            with self.subTest(extra=extra), mock.patch.object(engine, 'dependencies') as probe:
                args = self.args('analyze', '--experimental-trusted-input', *extra)
                self.error('argument_limit', cli.execute, args)
                probe.assert_not_called()

    def test_untrusted_engine_operation_fails_before_dependency_probe(self):
        with mock.patch.object(engine, 'dependencies') as probe:
            self.error('isolation_required', cli.execute, self.args('analyze'))
        probe.assert_not_called()

    @contextlib.contextmanager
    def failing_universal_import(self):
        project = self.project('multi-slice')
        # Two ordinary 64-bit headers inside a real, aligned universal image.
        arm64 = struct.pack('<8I', 0xFEEDFACF, 0x100000C, 0, 2, 0, 0, 0, 0)
        x86_64 = struct.pack('<8I', 0xFEEDFACF, 0x1000007, 3, 2, 0, 0, 0, 0)
        original = (struct.pack('>II', 0xCAFEBABE, 2)
                    + struct.pack('>IIIII', 0x100000C, 0, 64, len(arm64), 5)
                    + struct.pack('>IIIII', 0x1000007, 3, 96, len(x86_64), 5)
                    + bytes(16) + arm64 + x86_64)
        metadata = macho.inspect_bytes(original)
        metadata.update(input_name='synthetic-universal.macho', warnings=[])
        deps = {'ghidra_version': '12.2', 'jdk_version': 'synthetic dependency record',
                'ghidra_path': '/synthetic/ghidra', 'java_home': '/synthetic/java'}
        first_id, second_id = [item['image_id'] for item in metadata['slices']]
        def worker(p, image, mode, args, dependencies, **request):
            self.assertEqual(mode, 'import')
            self.assertEqual(p.path, project.path)
            self.assertEqual(dependencies, deps)
            if image['image_id'] == second_id:
                raise Error('worker_failed', 'Synthetic second-slice worker failure', 10, retryable=True)
            self.assertEqual(image['image_id'], first_id)
            self.assertEqual(request['import_request']['image_id'], first_id)
            baseline = p.path / 'jobs' / ('a' * 32) / 'program'
            synthetic_program(baseline, b'synthetic imported baseline')
            return ({'validation': {'headless_analysis_enabled': False},
                     'executable_format': 'Mac OS X Mach-O',
                     'language_id': 'AARCH64:LE:64:AppleSilicon', 'compiler_spec_id': 'default',
                     'executable_sha256': image['sha256']},
                    {'job_id': 'a' * 32, 'status': 'complete', 'mode': mode,
                     'sandbox_sha256': engine.job_sandbox_sha256(p, deps, 'a' * 32)})
        argv = ['import', 'synthetic-universal.macho', '--project', str(project.path),
                '--arch', 'all', '--experimental-trusted-input', '--json']
        with mock.patch.object(cli, 'inspect_path', return_value=(metadata, original)), \
             mock.patch.object(engine, 'dependencies', return_value=deps), \
             mock.patch.object(engine, 'run', side_effect=worker) as run:
            yield project, metadata, argv, run

    def assert_partial_import(self, result, project, metadata):
        first, second = metadata['slices']
        self.assert_envelope(result)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['coverage']['status'], 'partial')
        self.assertEqual(result['coverage']['returned_count'], 1)
        self.assertEqual(result['coverage']['known_total'], 2)
        self.assertEqual(result['coverage']['truncation_reason'], 'worker_failed')
        self.assertEqual(result['error']['code'], 'worker_failed')
        self.assertTrue(result['error']['retryable'])
        self.assertEqual(result['error']['affected_object'], second['image_id'])
        completed = result['error']['partial_results']['completed_slices']
        self.assertEqual(completed, result['data'])
        self.assertEqual(completed, [{'image_id': first['image_id'], 'arch': 'arm64',
                                     'status': 'imported', 'job_id': 'a' * 32}])
        self.assertEqual(result['error']['partial_results']['failed_slice'], second['image_id'])
        # Reopen to prove the first transaction is committed, not just visible
        # within the import's connection, while the failed slice is unpublished.
        reopened = storage.Project(project.path)
        with reopened.db() as db:
            rows = db.execute('SELECT id,imported,active_analysis FROM images').fetchall()
        self.assertEqual(rows, [(first['image_id'], 1, None)])
        self.assertEqual(reopened.images()[0]['loader_evidence']['executable_sha256'], first['sha256'])
        self.assertEqual(reopened.images()[0]['engine_baseline_sha256'],
                         engine.tree_digest(project.path / 'engine' / first['image_id']))
        with reopened.writer():
            pass  # Early partial return must also release the project writer.

    def test_universal_import_second_worker_failure_keeps_first_commit(self):
        with self.failing_universal_import() as (project, metadata, argv, run):
            result = cli.execute(cli.parser().parse_args(argv))
            self.assert_partial_import(result, project, metadata)
        self.assertEqual([call.args[1]['image_id'] for call in run.call_args_list],
                         [item['image_id'] for item in metadata['slices']])

    def test_universal_import_partial_failure_main_returns_exit_six(self):
        with self.failing_universal_import() as (project, metadata, argv, run):
            code, output, stderr = self.invoke(argv)
            self.assertEqual(code, 6)
            self.assertEqual(stderr, '')
            self.assert_partial_import(json.loads(output), project, metadata)
        self.assertEqual(run.call_count, 2)

    def test_stale_job_pid_is_reported_without_signals(self):
        job_id = 'a' * 32
        job = self.workspace.path / 'jobs' / job_id
        job.mkdir(mode=0o700)
        storage.write_json(job / 'job.json', {'status': 'running', 'pid': os.getpid(), 'job_id': job_id,
                                              'ownership_token': 'b' * 32})
        with mock.patch.object(engine.os, 'killpg', side_effect=AssertionError('must not signal cached PID')):
            result = cli.execute(self.args('status'))
            self.error('job_not_active', cli.execute, self.args('jobs', 'cancel', job_id))
        self.assertEqual(result['data']['jobs'][0]['status'], 'unknown_after_disconnect')

    def test_job_commands_only_request_cancellation_from_a_live_owner(self):
        job_id = 'c' * 32
        token = 'd' * 32
        directory = self.workspace.path / 'jobs' / job_id
        directory.mkdir(mode=0o700)
        path = directory / 'job.json'
        lease = jobs.claim(path)
        try:
            record = {'status': 'running', 'pid': os.getpid(), 'job_id': job_id,
                      'ownership_token': token, 'limits': {'timeout_seconds': 300},
                      'dependencies': {'ghidra_version': '12.2', 'ghidra_path': '/Users/owner/private'},
                      'environment': {'HOME': 'private'}}
            storage.write_json(path, record)
            listing = cli.execute(self.args('jobs', 'list'))['data']
            self.assertEqual([(r['job_id'], r['status']) for r in listing], [(job_id, 'running')])
            shown = cli.execute(self.args('jobs', 'show', job_id))['data']
            self.assertEqual(shown['engine'], {'ghidra_version': '12.2'})
            self.assertNotIn('pid', shown)
            self.assertNotIn('environment', shown)
            with mock.patch.object(engine.os, 'killpg', side_effect=AssertionError('caller must not signal')):
                for _ in range(2):
                    data = cli.execute(self.args('jobs', 'cancel', job_id))['data']
                    self.assertEqual(data['status'], 'cancellation_requested')
            self.assertTrue(jobs.cancel_requested(path, token))
            self.assertFalse(jobs.cancel_requested(path, 'e' * 32))
            self.assertTrue(cli.execute(self.args('jobs', 'show', job_id))['data']['cancellation_requested'])
        finally:
            os.close(lease)
        self.error('job_id', cli.execute, self.args('jobs', 'show', '../other'))
        self.error('job_missing', cli.execute, self.args('jobs', 'show', 'f' * 32))


@unittest.skipUnless(os.name == 'posix', 'Owned process groups require POSIX')
class WorkerTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.job = self.root / 'job'
        self.job.mkdir(mode=0o700)
        self.manifest = {'job_id': 'test-job'}
        self.processes = []
        self.real_popen = subprocess.Popen

    def observe_popen(self, *args, **kwargs):
        proc = self.real_popen(*args, **kwargs)
        self.processes.append(proc)
        return proc

    def run_worker(self, script, timeout=5, **kwargs):
        with mock.patch.object(engine.subprocess, 'Popen', side_effect=self.observe_popen):
            return engine.run_process([sys.executable, '-c', script], cwd=self.job,
                                      env={'PATH': '/usr/bin:/bin'}, timeout=timeout,
                                      log_path=self.job / 'launcher.log', manifest_path=self.job / 'job.json',
                                      manifest=self.manifest, **kwargs)

    def record(self):
        return json.loads((self.job / 'job.json').read_text())

    def assert_reaped(self):
        self.assertTrue(self.processes)
        for proc in self.processes:
            self.assertIsNotNone(proc.poll(), 'owned worker must be reaped before returning')
            with self.assertRaises(ChildProcessError):
                os.waitpid(proc.pid, os.WNOHANG)

    def test_success_records_complete_and_reaps_process(self):
        self.run_worker('print("worker output")')
        record = self.record()
        self.assertEqual(record['status'], 'complete')
        self.assertEqual(record['returncode'], 0)
        self.assertGreaterEqual(record['elapsed_seconds'], 0)
        self.assertTrue(record['ownership_token'])
        self.assertIn(b'worker output', (self.job / 'launcher.log').read_bytes())
        self.assert_reaped()

    def test_worker_failure_records_error_and_reaps_process(self):
        error = self.error('worker_failed', self.run_worker, 'import sys; sys.exit(9)')
        self.assertEqual(error.exit_code, 10)
        record = self.record()
        self.assertEqual(record['status'], 'failed')
        self.assertEqual(record['returncode'], 9)
        self.assertEqual(record['error']['code'], 'worker_failed')
        self.assert_reaped()

    def test_timeout_terminates_and_reaps_owned_process(self):
        error = self.error('worker_timeout', self.run_worker, 'import time; time.sleep(10)', timeout=0.2)
        self.assertEqual(error.exit_code, 7)
        self.assertTrue(error.retryable)
        self.assertEqual(self.record()['status'], 'timeout')
        self.assert_reaped()

    def test_startup_timeout_requires_a_complete_exact_launcher_line(self):
        script = ('import sys,time; '
                  'sys.stdout.write("other INFO  Headless startup complete (3 ms) (AnalyzeHeadless)\\n"); '
                  'sys.stdout.write("INFO  Headless startup complete (4 ms) (AnalyzeHeadless)"); '
                  'sys.stdout.flush(); time.sleep(10)')
        error = self.error('worker_startup_timeout', self.run_worker, script,
                           timeout=3, startup_timeout=0.2)
        self.assertEqual(error.exit_code, 7)
        self.assertTrue(error.retryable)
        self.assertEqual(self.record()['startup']['status'], 'timeout')
        self.assert_reaped()

    def test_ready_worker_keeps_the_total_deadline(self):
        script = 'import time; print("INFO  Headless startup complete (20 ms) (AnalyzeHeadless)", flush=True); time.sleep(10)'
        error = self.error('worker_timeout', self.run_worker, script, timeout=1.2, startup_timeout=0.9)
        self.assertEqual(error.exit_code, 7)
        startup = self.record()['startup']
        self.assertEqual((startup['status'], startup['ghidra_reported_ms']), ('ready', 20))
        self.assertLess(startup['observed_seconds'], 0.9)
        self.assert_reaped()

    def test_clean_exit_without_startup_marker_fails_closed(self):
        error = self.error('worker_startup_unconfirmed', self.run_worker, 'print("worker output")',
                           startup_timeout=2)
        self.assertEqual(error.exit_code, 4)
        self.assertEqual(self.record()['startup']['status'], 'unconfirmed')
        self.assertEqual(self.record()['returncode'], 0)
        self.assert_reaped()

    def test_startup_probe_recognizes_marker_split_across_log_reads(self):
        probe = engine.worker_lifecycle.StartupProbe()
        with (self.job / 'launcher.log').open('w+b', buffering=0) as log:
            log.write(b'INFO  Headless startup')
            self.assertIsNone(probe.poll(log.fileno()))
            log.write(b' complete (123 ms) (AnalyzeHeadless)  \n')
            self.assertEqual(probe.poll(log.fileno()), 123)

    def test_keyboard_interrupt_records_cancelled_and_reaps_process(self):
        real_sleep = time.sleep
        interrupted = False
        def interrupt_once(seconds):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            return real_sleep(seconds)
        with mock.patch.object(engine.time, 'sleep', side_effect=interrupt_once):
            error = self.error('interrupted', self.run_worker, 'import time; time.sleep(10)')
        self.assertEqual(error.exit_code, 130)
        self.assertEqual(self.record()['status'], 'cancelled')
        self.assert_reaped()

    def test_startup_failure_records_failed_manifest(self):
        error = self.error('worker_startup', engine.run_process, [str(self.root / 'does-not-exist')],
                           cwd=self.job, env={}, timeout=2, log_path=self.job / 'launcher.log',
                           manifest_path=self.job / 'job.json', manifest=self.manifest)
        self.assertEqual(error.exit_code, 4)
        self.assertEqual(self.record()['status'], 'failed')
        self.assertEqual(self.record()['error']['code'], 'worker_startup')

    def test_owner_actually_cancels_and_reaps_worker(self):
        real_sleep = time.sleep
        requested = False

        def request_once(seconds):
            nonlocal requested
            if not requested:
                requested = True
                path = self.job / 'job.json'
                jobs.request_cancel(path, self.record())
            real_sleep(seconds)

        with mock.patch.object(engine.time, 'sleep', side_effect=request_once):
            error = self.error('worker_cancelled', self.run_worker, 'import time; time.sleep(10)')
        self.assertEqual(error.exit_code, 130)
        self.assertEqual(self.record()['status'], 'cancelled')
        self.assertFalse(jobs.leased(self.job / 'job.json'))
        self.assert_reaped()

    def test_log_budget_terminates_worker_and_records_limit(self):
        self.error('worker_output_limit', self.run_worker,
                   'import os,time; os.write(1,b"x"*8192); time.sleep(10)', max_log=100)
        self.assertEqual(self.record()['error']['code'], 'worker_output_limit')
        self.assert_reaped()

    def test_final_log_budget_catches_output_from_an_already_exited_worker(self):
        observe = engine.worker_exited

        def observe_only_after_exit(proc):
            until = time.monotonic() + 2
            while not observe(proc) and time.monotonic() < until:
                time.sleep(0.01)
            return observe(proc)

        with mock.patch.object(engine, 'worker_exited', side_effect=observe_only_after_exit):
            self.error('worker_output_limit', self.run_worker, 'print("x"*8192)', max_log=100)
        self.assertEqual(self.record()['returncode'], 0)
        self.assert_reaped()

    def test_parent_exit_does_not_leave_owned_descendant_running(self):
        # The child ignores SIGTERM, proving cleanup reaches SIGKILL after the
        # group leader has already exited. Heartbeats also avoid treating an
        # unreaped OS zombie as a still-executing process.
        heartbeat = self.job / 'heartbeat'
        child = ('import os,signal,time; from pathlib import Path; '
                 'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                 f'p=Path({str(heartbeat)!r}); '
                 '[(p.write_text(str(i)),time.sleep(0.05)) for i in range(200)]')
        parent = ('import os,subprocess,sys,time; from pathlib import Path; '
                  f'p=Path({str(heartbeat)!r}); '
                  f'subprocess.Popen([sys.executable,"-c",{child!r}]); '
                  '\nfor _ in range(200):\n if p.exists(): break\n time.sleep(0.01)\n'
                  'os._exit(0)')
        killpg = os.killpg

        def require_unreaped_leader(group, signum):
            self.assertEqual(group, self.processes[0].pid)
            # waitid raises ChildProcessError if the leader has been reaped.
            os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            killpg(group, signum)

        with mock.patch.object(engine.os, 'killpg', side_effect=require_unreaped_leader):
            self.run_worker(parent)
        self.assertTrue(heartbeat.exists(), 'descendant did not start')
        before = heartbeat.read_bytes()
        time.sleep(0.3)
        self.assertEqual(heartbeat.read_bytes(), before, 'descendant still executing after leader exit')
        self.assert_reaped()


if __name__ == '__main__':
    unittest.main()
