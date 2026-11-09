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

# Direct invocation and unittest discovery both work without installing a wheel.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from macscope import SCHEMA_VERSION
from macscope import cli, engine, macho, schema, storage
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


def synthetic_snapshot(project, aid='analysis-one'):
    """Commit a deterministic, engine-independent snapshot through the public DB."""
    image = {'image_id': 'image-one', 'arch': 'arm64', 'sha256': '0' * 64,
             'artifact_sha256': '1' * 64, 'input_name': 'synthetic.macho'}
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
    record = {'snapshot_sha256': hashlib.sha256(payload).hexdigest(), 'job_id': 'synthetic-job'}
    with project.db(False) as db:
        db.execute('INSERT OR REPLACE INTO images(id,arch,metadata,imported,active_analysis) VALUES(?,?,?,1,?)',
                   (image['image_id'], image['arch'], json.dumps(image), aid))
        db.execute('INSERT OR REPLACE INTO analyses(id,image_id,payload) VALUES(?,?,?)',
                   (aid, image['image_id'], json.dumps(record)))
    return snapshot, record


class AtomicStorageTests(TemporaryCase):
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
            Path(dst).write_bytes(b'concurrent writer')
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
        self.error('snapshot_missing', project.snapshot, {'image_id': 'missing', 'active_analysis': 'absent'})

    def test_image_selector_reports_ambiguity(self):
        project = self.project()
        synthetic_snapshot(project)
        with project.db(False) as db:
            db.execute('INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)',
                       ('image-two', 'x86_64', json.dumps({'image_id': 'image-two', 'arch': 'x86_64'})))
        error = self.error('image_selector', project.select)
        self.assertEqual(len(error.partial), 2)
        self.assertEqual(project.select(arch='arm64')['image_id'], 'image-one')


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
        for relative in ('support/analyzeHeadless', 'Ghidra/application.properties',
                         'Ghidra/Features/Decompiler/os/mac_arm_64/decompile'):
            target = self.g / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'fixture')
        (self.g / 'Ghidra/application.properties').write_text('application.version=12.2\n')
        for relative in ('bin/java', 'lib/server/libjvm.dylib'):
            target = self.j / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'fixture')
        for executable in (self.g / 'support/analyzeHeadless',
                           self.g / 'Ghidra/Features/Decompiler/os/mac_arm_64/decompile',
                           self.j / 'bin/java'):
            executable.chmod(0o700)
        self.bridge.mkdir()
        for name in ('MacscopeBridge.java', 'MacscopeProfile.java'):
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
        result = subprocess.CompletedProcess([], 0, b'', b'openjdk version "25.0.5" 25.0.5.0.3')
        with mock.patch.object(engine.subprocess, 'run', return_value=result) as run:
            dependencies = self.check(full=True)
        self.assertEqual(dependencies['ghidra_version'], '12.2')
        for key in ('ghidra_tree_sha256', 'native_decompiler_sha256', 'java_sha256', 'jvm_sha256', 'bridge_sha256'):
            self.assertRegex(dependencies[key], r'^[0-9a-f]{64}$')
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs['timeout'], 10)
        self.assertFalse(dependencies['hard_process_memory_limit'])

    def test_unsupported_host_is_explicit(self):
        with mock.patch.object(engine.platform, 'system', return_value='Linux'):
            self.error('unsupported_host', self.check)


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

    def test_search_rejects_empty_or_oversized_query(self):
        for value in ('', ' ', 'x' * 257, '\n'):
            self.error('search_query', cli.execute, self.args('search', value))

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

    def test_fresh_decompile_requires_explicit_trust_and_single_function(self):
        with mock.patch.object(engine, 'dependencies') as deps:
            self.error('isolation_required', cli.execute,
                       self.args('decompile', '--fresh', '--name', 'unique'))
            self.error('fresh_selection', cli.execute,
                       self.args('decompile', '--fresh', '--all', '--experimental-trusted-input'))
        deps.assert_not_called()

    def test_fresh_decompile_keeps_selected_snapshot_and_labels_new_evidence(self):
        record = {'pseudocode': 'char *f() { return "/Users/local/private"; }',
                  'decompile_status': 'complete', 'pseudocode_truncated': False,
                  'coverage': {'pseudocode': {'status': 'complete'}}}
        raw = {'functions': [record], 'bridge_version': '1.2.0'}
        job = {'job_id': 'private-job', 'analysis_profile': engine.analysis_profile()}
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

    def test_version_never_probes_dependencies(self):
        with mock.patch.object(engine, 'dependencies', side_effect=AssertionError('version probe')):
            code, output, stderr = self.invoke(['version', '--json'])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, '')
        self.assert_envelope(json.loads(output))

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

    def test_terminal_controls_are_escaped(self):
        result = cli.envelope('inspect', {'name': '\x1b[31munsafe\x07'})
        for fmt in ('text', 'json', 'jsonl'):
            output = cli.render(result, fmt)
            self.assertNotIn(b'\x1b', output)
            self.assertNotIn(b'\x07', output)
            self.assertEqual(json.loads(output)['data']['name'], '\x1b[31munsafe\x07')

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
        deps = {'ghidra_version': '12.2', 'jdk_version': 'synthetic dependency record'}
        first_id, second_id = [item['image_id'] for item in metadata['slices']]
        def worker(p, image, mode, args, dependencies):
            self.assertEqual(mode, 'import')
            self.assertEqual(p.path, project.path)
            self.assertEqual(dependencies, deps)
            if image['image_id'] == second_id:
                raise Error('worker_failed', 'Synthetic second-slice worker failure', 10, retryable=True)
            self.assertEqual(image['image_id'], first_id)
            baseline = p.path / 'engine' / image['image_id']
            baseline.mkdir(mode=0o700)
            (baseline / 'image.gpr').write_bytes(b'synthetic imported baseline')
            return ({'validation': {'headless_analysis_enabled': False},
                     'executable_format': 'Mac OS X Mach-O',
                     'language_id': 'AARCH64:LE:64:AppleSilicon', 'compiler_spec_id': 'default',
                     'executable_sha256': image['sha256']}, {'job_id': 'first-slice-job'})
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
                                     'status': 'imported', 'job_id': 'first-slice-job'}])
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
        job = self.workspace.path / 'jobs' / 'stale'
        job.mkdir(mode=0o700)
        storage.write_json(job / 'job.json', {'status': 'running', 'pid': os.getpid(), 'job_id': 'stale'})
        with mock.patch.object(engine.os, 'killpg', side_effect=AssertionError('must not signal cached PID')):
            result = cli.execute(self.args('status'))
        self.assertEqual(result['data']['jobs'][0]['status'], 'unknown_after_disconnect')


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

    def test_log_budget_terminates_worker_and_records_limit(self):
        self.error('worker_output_limit', self.run_worker,
                   'import os,time; os.write(1,b"x"*8192); time.sleep(10)', max_log=100)
        self.assertEqual(self.record()['error']['code'], 'worker_output_limit')
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
        try:
            self.run_worker(parent)
            self.assertTrue(heartbeat.exists(), 'descendant did not start')
            before = heartbeat.read_bytes()
            time.sleep(0.3)
            self.assertEqual(heartbeat.read_bytes(), before, 'descendant still executing after leader exit')
            self.assert_reaped()
        finally:
            # Only the session created by this test's observed Popen is touched.
            # This bounded immediate cleanup prevents a failed regression from
            # leaking the synthetic child; no persisted PID is ever used.
            for proc in self.processes:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if proc.poll() is None:
                    proc.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
