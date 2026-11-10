"""Linux groundwork is testable without launching the unvalidated sandbox."""
import contextlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from macscope import cli, engine, engine_checks, host_platform, linux_isolation, swift_symbols
from test_core import TemporaryCase
import test_core
from test_host_platform import elf


class LinuxReadinessTests(TemporaryCase):
    def linux(self):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(host_platform.platform, 'system', return_value='Linux'))
        stack.enter_context(mock.patch.object(host_platform.platform, 'machine', return_value='x86_64'))
        return stack

    def test_host_only_doctor_never_touches_dependencies_or_launches(self):
        with self.linux(), mock.patch.object(engine_checks, 'layout') as layout, \
                mock.patch.object(engine.subprocess, 'run') as run:
            result = cli.execute(cli.parser().parse_args(['doctor', '--host-only', '--json']))
        layout.assert_not_called()
        run.assert_not_called()
        self.assertEqual(result['status'], 'complete')
        report = result['data']
        self.assertTrue(report['capabilities']['static_macho'])
        self.assertTrue(report['capabilities']['cached_queries'])
        self.assertFalse(report['capabilities']['engine_operations'])
        self.assertFalse(report['capabilities']['swift_demangling'])
        self.assertEqual(report['isolation']['blocker'], 'linux_isolation_unverified')
        self.assertEqual(report['verification']['worker_probe'], 'not_run')

    def test_linux_workers_fail_before_dependency_reads_or_java(self):
        for options in ([], ['--verify-worker', '--experimental-trusted-input']):
            with self.subTest(options=options), self.linux(), \
                    mock.patch.object(engine_checks, 'layout') as layout, \
                    mock.patch.object(engine.subprocess, 'run') as run:
                self.error('linux_isolation_unverified', cli.execute,
                           cli.parser().parse_args(['doctor', *options]))
                layout.assert_not_called()
                run.assert_not_called()

    def test_environment_cannot_enable_linux_execution(self):
        with self.linux(), mock.patch.dict(os.environ, {
                'MACSCOPE_ALLOW_UNSAFE': '1', 'MACSCOPE_LINUX_VERIFIED': '1',
                'MACSCOPE_GHIDRA': '/pretend', 'MACSCOPE_JAVA_HOME': '/pretend'}), \
                mock.patch.object(engine.subprocess, 'run') as run:
            self.error('linux_isolation_unverified', engine.dependencies)
            self.error('linux_isolation_unverified', linux_isolation.require_worker)
        run.assert_not_called()

    def test_worker_boundary_rejects_supplied_mac_dependencies_without_side_effects(self):
        project = self.project()
        before = sorted(str(path.relative_to(project.path)) for path in project.path.rglob('*'))
        supplied = {'ghidra_path': '/pretend/ghidra', 'java_home': '/pretend/java',
                    'host_arch': 'arm64', 'host_os': 'Darwin', 'jdk_version': '25.0.5.0.3'}
        for mode in ('import', 'analyze', 'query'):
            with self.subTest(mode=mode), self.linux(), \
                    mock.patch.object(engine, 'run_process') as launch, \
                    mock.patch.object(engine, 'copy_program') as copy:
                # No image/argument inspection is needed to refuse this host.
                self.error('linux_isolation_unverified', engine.run, project, {}, mode, None, supplied)
                launch.assert_not_called()
                copy.assert_not_called()
        self.assertEqual(before, sorted(str(path.relative_to(project.path)) for path in project.path.rglob('*')))

    def test_version_scopes_the_existing_jdk_pin(self):
        with self.linux():
            result = cli.execute(cli.parser().parse_args(['version', '--json']))
        self.assertEqual(result['data']['required_jdk'], '25.0.5.0.3')
        self.assertIn('macOS arm64', result['data']['required_jdk_scope'])

    def test_linux_cli_engine_requests_fail_but_cached_query_survives(self):
        project = self.project()
        snapshot, _ = test_core.synthetic_snapshot(project)
        source = self.root / 'owned-probe.macho'
        source.write_bytes(test_core.doctor_probe.fixture())
        pinned = project.path / 'snapshots' / (snapshot['analysis_id'] + '.json')
        before = pinned.read_bytes()
        common = ['--project', str(project.path), '--experimental-trusted-input']
        with self.linux(), mock.patch.object(engine, 'run') as run, \
                mock.patch.object(engine.subprocess, 'run') as native:
            for words in (['import', str(source)], ['analyze'],
                          ['decompile', '--fresh', '--name', 'unique']):
                with self.subTest(words=words):
                    self.error('linux_isolation_unverified', cli.execute,
                               cli.parser().parse_args([*words, *common]))
            result = cli.execute(cli.parser().parse_args(
                ['decompile', '--name', 'unique', '--project', str(project.path)]))
        run.assert_not_called()
        native.assert_not_called()
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(pinned.read_bytes(), before)
        self.assertEqual(list((project.path / 'jobs').iterdir()), [])
        self.assertEqual(list((project.path / 'inputs').iterdir()), [])

    def test_linux_unpublished_retry_never_launches_recorded_mac_command(self):
        from test_job_resume import JobResumeTests
        fixture = JobResumeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        before = sorted(path.name for path in (fixture.workspace.path / 'jobs').iterdir())
        with self.linux(), mock.patch.object(engine, 'run') as run, \
                mock.patch.object(engine.subprocess, 'run') as native:
            self.error('linux_isolation_unverified', fixture.resume)
        run.assert_not_called()
        native.assert_not_called()
        self.assertEqual(before, sorted(path.name for path in (fixture.workspace.path / 'jobs').iterdir()))

    def test_linux_static_runtime_requires_explicit_paths(self):
        with self.linux(), mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(engine.subprocess, 'run') as run:
            self.error('dependency_configuration', engine.static_dependencies)
        run.assert_not_called()

    def test_static_runtime_checks_elf_without_claiming_jdk_execution(self):
        fixture = test_core.DependencyTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        native = fixture.g / host_platform.LINUX_X86_64.native_path
        native.parent.mkdir(parents=True)
        native.write_bytes(elf())
        native.chmod(0o700)
        (fixture.g / engine_checks.NATIVE).unlink()
        (fixture.j / 'lib/server/libjvm.dylib').unlink()
        (fixture.j / 'lib/server/libjvm.so').write_bytes(elf(3))
        for name in ('java', 'javac'):
            (fixture.j / 'bin' / name).write_bytes(elf(3))
        with self.linux(), mock.patch.object(engine.subprocess, 'run') as run:
            result = cli.execute(cli.parser().parse_args([
                'doctor', '--static', '--full-digest', '--ghidra', str(fixture.g),
                '--java-home', str(fixture.j)]))
            report = result['data']
            self.assertEqual(report['verification']['dependencies'], 'static_layout_only')
            self.assertEqual(report['verification']['auxiliary_libraries'], 'not_checked')
            self.assertFalse(report['capabilities']['engine_operations'])
            self.assertIsNone(report['static_runtime']['jdk_version'])
            self.assertEqual(report['static_runtime']['jdk_version_status'], 'not_executed')
            self.assertRegex(report['static_runtime']['ghidra_tree_sha256'], r'^[a-f0-9]{64}$')
            self.assertNotIn('ghidra_path', report)  # Not a launchable dependency record.
            native.write_bytes(b'bad ELF')
            self.error('incompatible_native_decompiler', engine.static_dependencies,
                       str(fixture.g), str(fixture.j))
        run.assert_not_called()

    def test_doctor_modes_are_mutually_exclusive(self):
        for flags in (['--static', '--verify-worker'], ['--host-only', '--static'],
                      ['--host-only', '--verify-worker']):
            with self.subTest(flags=flags):
                self.error('usage', cli.parser().parse_args, ['doctor', *flags])

    def test_static_macos_check_does_not_start_java_or_relax_launch_pin(self):
        fixture = test_core.DependencyTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with mock.patch.object(engine.subprocess, 'run') as run:
            report = engine.static_dependencies(str(fixture.g), str(fixture.j))
        run.assert_not_called()
        self.assertEqual(report['host']['java_build'], '25.0.5.0.3')
        self.assertEqual(report['isolation']['backend'], 'macos-seatbelt')
        self.assertEqual(report['verification']['worker_probe'], 'not_run')

    def test_linux_native_swift_demangler_fails_without_xcrun(self):
        with self.linux(), mock.patch.object(swift_symbols, 'invoke') as invoke:
            self.error('demangler_unsupported_host', swift_symbols.demangle, ['_$s4Test5probeSiyF'])
        invoke.assert_not_called()


class LinuxIsolationPlanTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.project = SimpleNamespace(path=self.root / 'workspace')
        self.job = self.project.path / 'jobs' / ('a' * 32)
        self.deps = {'ghidra_path': str(self.root / 'ghidra'), 'java_home': str(self.root / 'jdk')}
        self.bridge = self.root / 'bridge'

    def plan(self, **kwargs):
        options = dict(write_root=self.job, bridge=self.bridge)
        options.update(kwargs)
        return linux_isolation.plan(self.project, self.deps, **options)

    def test_plan_is_deterministic_nonexecutable_and_job_scoped(self):
        result = self.plan(staged_image_id='b' * 64, read_only_program=True)
        self.assertEqual(result, self.plan(staged_image_id='b' * 64, read_only_program=True))
        self.assertFalse(result['engine_execution'])
        self.assertNotIn('argv', result)
        self.assertEqual(result['runtime_implementation'], 'not_implemented')
        self.assertEqual(result['network'], 'deny_all')
        self.assertIn('network', result['namespaces'])
        self.assertEqual(result['filesystem']['writable'], [str(self.job)])
        self.assertEqual(result['filesystem']['query_database_write_denial'],
                         {'root': str(self.job / 'program'), 'suffix': '.gbf'})
        self.assertEqual(result['exec_denied_roots'],
                         [str(self.project.path / n) for n in ('inputs', 'jobs')])
        self.assertNotIn(str(self.job), result['exec_allowlist'])
        other = self.plan(write_root=self.project.path / 'jobs' / ('c' * 32))
        self.assertNotEqual(result['plan_sha256'], other['plan_sha256'])

    def test_invalid_write_roots_and_input_ids_fail_closed(self):
        for path in (self.project.path, self.project.path / 'jobs', self.root / 'outside',
                     self.project.path / 'jobs' / 'not-a-job', Path('relative'),
                     self.job / '..' / ('b' * 32)):
            with self.subTest(path=path):
                self.error('worker_isolation_scope', self.plan, write_root=path)
        for image_id in ('../escape', 'b' * 63, True):
            self.error('worker_isolation_scope', self.plan, staged_image_id=image_id)

    def test_runtime_roots_cannot_expose_workspace_or_overlap_writable_job(self):
        for path in (self.root, self.project.path, self.job / 'runtime',
                     self.project.path / 'inputs', self.project.path / 'jobs' / ('c' * 32)):
            with self.subTest(path=path):
                old = self.deps['ghidra_path']
                self.deps['ghidra_path'] = str(path)
                try:
                    self.error('worker_isolation_scope', self.plan)
                finally:
                    self.deps['ghidra_path'] = old

    def test_symlink_runtime_or_job_is_not_described_as_scoped(self):
        target = self.root / 'actual'
        target.mkdir()
        self.bridge.symlink_to(target, target_is_directory=True)
        self.error('worker_isolation_scope', self.plan)


if __name__ == '__main__':
    unittest.main()
