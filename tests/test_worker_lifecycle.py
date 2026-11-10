"""Verify the launch fence and the conditions for a disconnected restart."""
import json
import os
import sys
from unittest.mock import patch

from macscope import engine, jobs, storage, worker_lifecycle
from test_core import TemporaryCase


class WorkerLifecycleTests(TemporaryCase):
    def test_parent_pipe_close_before_publication_never_runs_command(self):
        marker = self.root / "started"
        command = [sys.executable, "-c", "import pathlib, sys; pathlib.Path(sys.argv[1]).touch()", str(marker)]
        with (self.root / "launch.log").open("wb") as log:
            child, gate = worker_lifecycle.start(command, gated=True, cwd=self.root, env={}, log=log)
            os.close(gate)
            try:
                self.assertEqual(child.wait(timeout=5), 125)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
        self.assertFalse(marker.exists())

    def test_actual_worker_observes_durably_recorded_group_before_execution(self):
        manifest = self.root / "job.json"
        code = (
            "import json, os, sys; "
            "d=json.load(open(sys.argv[1])); "
            "assert d['status']=='running' and d['pid']==os.getpid()==os.getpgrp()"
        )
        engine.run_process(
            [sys.executable, "-c", code, str(manifest)], cwd=self.root, env={}, timeout=5,
            log_path=self.root / "launch.log", manifest_path=manifest,
            manifest={"job_id": self.root.name, "mode": "query"},
        )

    def test_retry_link_is_visible_before_the_worker_launches(self):
        project = self.project()
        original, child = 'a' * 32, 'b' * 32
        jobs_root = project.path / 'jobs'
        source = jobs_root / original / 'job.json'
        attempt = jobs_root / child / 'job.json'
        source.parent.mkdir()
        attempt.parent.mkdir()
        record = {'job_id': original, 'mode': 'query', 'status': 'timeout', 'image_id': 'c' * 64,
                  'restart_protocol': jobs.RESTART_PROTOCOL}
        storage.write_json(source, record)
        code = ('import json,sys; '
                'link=json.load(open(sys.argv[1])); '
                'assert link["original"]==sys.argv[2] and link["attempt"]==sys.argv[3]')
        engine.run_process([sys.executable, '-c', code, str(source.with_name(jobs.RESTART_RECORD)), original, child],
                           cwd=attempt.parent, env={}, timeout=5, log_path=attempt.with_name('launcher.log'),
                           manifest_path=attempt, manifest=dict(record, job_id=child, resumed_from=original))
        self.assertEqual(jobs.load(attempt)['status'], 'complete')
        jobs.verify_restart_stopped(project, source, record)
        source.with_name(jobs.RESTART_RECORD).write_text(json.dumps({
            'schema': jobs.RESTART_PROTOCOL, 'original': original, 'attempt': 'd' * 32,
        }))
        self.error('job_restart_record', jobs.verify_restart_stopped, project, source, record)

    def test_legacy_restart_fence_checks_live_grandchildren(self):
        project = self.project()
        original, child, grandchild = 'a' * 32, 'b' * 32, 'c' * 32
        for job in (original, child, grandchild):
            (project.path / 'jobs' / job).mkdir()
        source = project.path / 'jobs' / original / 'job.json'
        record = {'job_id': original, 'mode': 'analyze', 'status': 'timeout'}
        storage.write_json(source, record)
        storage.write_json(project.path / 'jobs' / child / 'job.json',
                           dict(record, job_id=child, resumed_from=original))
        storage.write_json(project.path / 'jobs' / grandchild / 'job.json',
                           dict(record, job_id=grandchild, resumed_from=child, status='running', pid=1080,
                                process_group=1080, launch_protocol=worker_lifecycle.PROTOCOL,
                                boot_session_id='current-boot'))
        with patch.object(worker_lifecycle, 'boot_session', return_value='current-boot'), \
             patch.object(worker_lifecycle.os, 'killpg') as probe:
            error = self.error('job_resume_ownership', jobs.verify_restart_stopped, project, source, record)
            self.assertEqual(error.partial, {'job_id':grandchild})
            probe.assert_called_once_with(1080, 0)
            probe.side_effect = ProcessLookupError()
            jobs.verify_restart_stopped(project, source, record)

    def test_disconnect_requires_current_boot_and_a_confirmed_empty_group(self):
        path = self.root / "job.json"
        starting = {
            "job_id": self.root.name, "status": "starting", "launch_protocol": worker_lifecycle.PROTOCOL,
            "boot_session_id": "current-boot",
        }
        running = dict(starting, status="running", pid=1080, process_group=1080)

        def record(state):
            storage.write_json(path, state, force=True)

        with patch.object(worker_lifecycle, "boot_session", return_value="current-boot"):
            record(starting)
            self.assertEqual(jobs.record_for_resume(path, starting), starting)
            for unsafe in (dict(starting, pid=1080), dict(starting, boot_session_id=None)):
                record(unsafe)
                self.error("job_resume_ownership", jobs.record_for_resume, path, starting)
            record(running)
            with patch.object(worker_lifecycle.os, "killpg") as probe:
                self.error("job_resume_ownership", jobs.record_for_resume, path, starting)
                probe.assert_called_once_with(1080, 0)
                self.assertEqual(jobs.view(path, starting)["status"], "unknown_after_disconnect")
                probe.side_effect = PermissionError()
                self.error("job_resume_ownership", jobs.record_for_resume, path, starting)
                probe.side_effect = ProcessLookupError()
                self.assertEqual(jobs.record_for_resume(path, starting), running)
                self.assertEqual(jobs.view(path, starting)["status"], "stopped_after_disconnect")
                probe.reset_mock()
                for unsafe in (dict(running, process_group=0), dict(running, boot_session_id="other"),
                               dict(running, launch_protocol=None)):
                    record(unsafe)
                    self.error("job_resume_ownership", jobs.record_for_resume, path, starting)
                probe.assert_not_called()

    def test_workspace_writer_checks_live_groups_and_accepts_a_verified_previous_boot(self):
        project = self.project()
        job_id = 'a' * 32
        path = project.path / 'jobs' / job_id / 'job.json'
        path.parent.mkdir()
        current = '11111111-1111-1111-1111-111111111111'
        previous = '22222222-2222-2222-2222-222222222222'
        record = {'job_id':job_id, 'mode':'analyze', 'status':'running', 'pid':1080, 'process_group':1080,
                  'launch_protocol':worker_lifecycle.PROTOCOL, 'boot_session_id':current}
        with project.writer(), patch.object(worker_lifecycle, 'boot_session', return_value=current), \
             patch.object(worker_lifecycle.os, 'killpg') as probe:
            storage.write_json(path, record)
            error = self.error('writer_conflict', jobs.verify_engine_writer_stopped, project)
            self.assertEqual(error.partial, {'job_id':job_id})
            self.assertTrue(error.retryable)
            probe.assert_called_once_with(1080, 0)
            probe.reset_mock()
            storage.write_json(path, dict(record, mode='query'), force=True)
            jobs.verify_engine_writer_stopped(project)
            storage.write_json(path, dict(record, boot_session_id=previous), force=True)
            jobs.verify_engine_writer_stopped(project)
            self.error('job_resume_ownership', jobs.record_for_resume, path, jobs.load(path))
            storage.write_json(path, dict(record, boot_session_id=None), force=True)
            self.error('writer_conflict', jobs.verify_engine_writer_stopped, project)
            probe.assert_not_called()
            storage.write_json(path, record, force=True)
            probe.side_effect = ProcessLookupError()
            jobs.verify_engine_writer_stopped(project)
            probe.assert_called_once_with(1080, 0)

    def test_workspace_writer_refuses_incomplete_history(self):
        project = self.project()
        jobs_dir = project.path / 'jobs'
        for job_id in ('a' * 32, 'b' * 32):
            (jobs_dir / job_id).mkdir()
        with project.writer(), patch.object(jobs, 'SCAN_LIMIT', 1):
            self.error('writer_history', jobs.verify_engine_writer_stopped, project)
