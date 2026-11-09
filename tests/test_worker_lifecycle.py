"""Verify the launch fence and the conditions for a disconnected restart."""
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
