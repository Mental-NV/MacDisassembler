"""Stdlib regression tests for the CLI, cache, storage and owned worker runner.

No Ghidra/JVM is launched. Engine checks use tiny temporary dependency trees;
worker lifecycle checks launch only this interpreter and self-owned children.
Run: PYTHONPATH=src python3 -m unittest discover -s tests -v
"""
import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

# Direct invocation and unittest discovery both work without installing a wheel.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from macscope import SCHEMA_VERSION
from macscope import cli, engine, storage
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
            'name': name, 'names': [{'name': name, 'origin': 'ghidra'}],
            'body_ranges': [{'min': address, 'max': hex(int(address, 16) + 3)}],
            'signature': f'void {name}(void)', 'is_thunk': False, 'is_external': False,
            'decompile_status': 'complete', 'pseudocode': f'void {name}(void) {{ return; }}',
            'instructions': [{'address': address, 'mnemonic': 'ret', 'bytes': 'c0035fd6'}],
            'blocks': [{'min': address, 'max': address, 'dsts': []}],
            'xrefs_to_entry': [], 'xrefs_from_sample': [], 'address_spans': [],
            'facets': {},
        })
    snapshot = {'analysis_id': aid, 'status': 'complete', 'image': image,
                'functions': functions, 'engine': {'function_count_total_reported_by_engine': 3,
                                                  'functions_truncated': False},
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
        result = subprocess.CompletedProcess([], 0, b'', b'openjdk version "25.0.5" 25.0.5+3')
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

    def assert_envelope(self, result):
        required = {'schema_version', 'command', 'status', 'analysis_id', 'data', 'diagnostics', 'coverage'}
        self.assertTrue(required <= result.keys())
        self.assertEqual(result['schema_version'], SCHEMA_VERSION)
        self.assertIn(result['status'], ('complete', 'partial', 'failed', 'cancelled'))
        self.assertIsInstance(result['command'], str)
        self.assertIsInstance(result['diagnostics'], list)
        self.assertTrue({'scope', 'status', 'returned_count', 'known_total', 'next_cursor', 'truncation_reason'} <= result['coverage'].keys())
        self.assertIsInstance(result['coverage']['returned_count'], int)

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
