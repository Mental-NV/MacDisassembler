"""Failure-path controls for the opt-in native experiment; no engine launched."""
import json
from pathlib import Path
import signal
import subprocess
import tempfile
from unittest import TestCase, mock
import integration_batch_export as harness


class NativeBatchHarnessTests(TestCase):
    def test_timeout_retains_partial_output_and_requests_graceful_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'new'
            process = mock.Mock(returncode=130)
            process.communicate.side_effect = [subprocess.TimeoutExpired(['compiler'],1200),
                                               (b'partial out',b'partial error')]
            with mock.patch.object(harness.subprocess,'Popen',return_value=process) as launch:
                with self.assertRaisesRegex(RuntimeError,'teardown unverified'):
                    harness.run(output,1)
            launch.assert_called_once()
            process.send_signal.assert_called_once_with(signal.SIGINT)
            process.kill.assert_not_called()
            self.assertEqual((output/'001.stdout').read_bytes(),b'partial out')
            self.assertEqual((output/'001.stderr').read_bytes(),b'partial error')
            record = json.loads((output/'commands.json').read_text())[0]
            self.assertTrue(record['timed_out'])
            self.assertFalse(record['forced_supervisor_kill'])
            self.assertEqual(record['teardown_verification'],'not_checked')

    def test_forced_timeout_is_recorded_and_no_next_command_starts(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'new'
            process = mock.Mock(returncode=-9)
            process.communicate.side_effect = [subprocess.TimeoutExpired([],1200),
                                               subprocess.TimeoutExpired([],30),(b'out',b'err')]
            with mock.patch.object(harness.subprocess,'Popen',return_value=process) as launch:
                with self.assertRaisesRegex(RuntimeError,'teardown unverified'):
                    harness.run(output,1)
            process.kill.assert_called_once()
            launch.assert_called_once()
            record = json.loads((output/'commands.json').read_text())[0]
            self.assertTrue(record['forced_supervisor_kill'])
            self.assertEqual(record['teardown_verification'],'not_checked')

    def test_existing_destination_never_runs_or_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            sentinel = output/'commands.json'; sentinel.write_text('existing evidence')
            with mock.patch.object(harness.subprocess,'Popen') as launch:
                with self.assertRaises(FileExistsError):harness.run(output,1)
            launch.assert_not_called()
            self.assertEqual(sentinel.read_text(),'existing evidence')

    def test_final_pipe_drain_is_bounded_and_partial_bytes_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'new'
            process = mock.Mock(returncode=-9)
            process.communicate.side_effect = [subprocess.TimeoutExpired([],1200),
                subprocess.TimeoutExpired([],30),
                subprocess.TimeoutExpired([],5,output=b'partial',stderr=b'error')]
            with mock.patch.object(harness.subprocess,'Popen',return_value=process):
                with self.assertRaisesRegex(RuntimeError,'teardown unverified'):
                    harness.run(output,1)
            process.stdout.close.assert_called_once()
            process.stderr.close.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)
            self.assertEqual((output/'001.stdout').read_bytes(),b'partial')
            record=json.loads((output/'commands.json').read_text())[0]
            self.assertTrue(record['pipe_drain_timed_out'])
            self.assertEqual(process.communicate.call_args_list[-1].kwargs,{'timeout':5})

    def test_keyboard_interrupt_requests_teardown_and_retains_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'new'
            process = mock.Mock(returncode=130)
            process.communicate.side_effect = [KeyboardInterrupt(),(b'out',b'err')]
            with mock.patch.object(harness.subprocess,'Popen',return_value=process) as launch:
                with self.assertRaisesRegex(RuntimeError,'teardown unverified'):
                    harness.run(output,1)
            launch.assert_called_once()
            process.send_signal.assert_called_once_with(signal.SIGINT)
            record=json.loads((output/'commands.json').read_text())[0]
            self.assertTrue(record['interrupted'])
            self.assertFalse(record['timed_out'])
