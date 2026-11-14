import unittest
from unittest.mock import patch
from macscope.engine import focused_phase


class FocusedPhaseTests(unittest.TestCase):
    def test_complete_records_only_duration_and_outcome(self):
        phases = {}
        with patch('macscope.engine.time.perf_counter_ns', side_effect=[100, 125]):
            with focused_phase(phases, 'selection_proof'):
                pass
        self.assertEqual(phases, {'selection_proof': {'elapsed_ns': 25, 'outcome': 'complete'}})

    def test_exception_and_interrupt_propagate_and_record(self):
        for error in (ValueError('private input'), KeyboardInterrupt()):
            phases = {}
            with self.subTest(error=type(error)), patch('macscope.engine.time.perf_counter_ns', side_effect=[10, 30]):
                with self.assertRaises(type(error)):
                    with focused_phase(phases, 'result_validation'):
                        raise error
            self.assertEqual(phases, {'result_validation': {'elapsed_ns': 20, 'outcome': 'failed'}})
            self.assertNotIn('private', str(phases))

    def test_nonfocused_no_clock_or_diagnostics(self):
        with patch('macscope.engine.time.perf_counter_ns') as clock:
            with focused_phase(None, 'unused'):
                pass
            clock.assert_not_called()

    def test_negative_clock_delta_clamps(self):
        phases = {}
        with patch('macscope.engine.time.perf_counter_ns', side_effect=[20, 10]):
            with focused_phase(phases, 'bridge_read'):
                pass
        self.assertEqual(phases['bridge_read']['elapsed_ns'], 0)
