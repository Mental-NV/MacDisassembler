"""SP writeback is opt-in; saved stack contents never become restored values."""
import copy
import unittest
from macscope import callback_evidence
from test_callback_evidence import receipt
from test_callback_provenance import project, encoded


def pair(load=False, mode=3, delta=-32, rt=20, rt2=19, rn=31):
    return (0xa8000000 | (mode << 23) | (int(load) << 22)
            | (((delta // 8) & 127) << 15) | (rt2 << 10) | (rn << 5) | rt)


class StackPairTests(unittest.TestCase):
    def test_native_owned_swift_prologue_epilogue(self):
        # Independent Swift 6.4 -O, llvm-objdump and Mach-O byte oracle.
        prologue = project(encoded('f44fbea9fd7b01a9fd430091'))
        save = prologue['sites'][0]
        self.assertEqual(save['instruction_bytes'], 'f44fbea9')
        self.assertEqual(save['addressing_mode'], 'pre_index')
        self.assertEqual(save['location']['base']['offset'], 0)
        self.assertEqual(save['location']['offset'], -32)
        self.assertEqual(save['writeback']['after']['offset'], -32)
        self.assertEqual(prologue['sites'][2]['location']['base']['offset'], -32)
        # Consecutive slices used only to test state propagation, not a claim
        # that the original compiler's intervening body is transparent.
        r = project(encoded('f44fbea9fd7b01a9fd430091fd7b41a9f44fc2a8c0035fd6'))
        restore = r['sites'][-1]
        self.assertEqual(restore['addressing_mode'], 'post_index')
        self.assertEqual(restore['writeback']['after']['offset'], 0)
        self.assertEqual(restore['location']['base']['offset'], -32)
        self.assertEqual(restore['location']['offset'], 8)
        self.assertEqual(r['stop_reason'], 'return_boundary')
        self.assertEqual(r['status'], 'inconclusive')

    def test_all_forms_offsets_and_next_access(self):
        for load in (False, True):
            for mode in (1, 3):
                for delta in (-512, -32, 0, 32, 504):
                    with self.subTest(load=load, mode=mode, delta=delta):
                        r = project([pair(load, mode, delta), 0xf90003e0])
                        self.assertEqual(len(r['sites']), 3)
                        lanes = r['sites'][:2]
                        for i, lane in enumerate(lanes):
                            self.assertEqual(lane['width'], 8)
                            self.assertEqual(lane['location']['offset'], (delta if mode == 3 else 0) + i*8)
                            self.assertEqual(lane['writeback']['before']['offset'], 0)
                            self.assertEqual(lane['writeback']['after']['offset'], delta)
                        self.assertEqual(r['sites'][2]['location']['base']['offset'], delta)

    def test_loads_do_not_restore_saved_registers(self):
        r = project([pair(), pair(True, 1, 32), 0xf9000014])
        self.assertEqual(r['sites'][0]['value']['kind'], 'range_input_register')
        self.assertEqual(r['sites'][-1]['value']['kind'], 'memory_read')
        self.assertEqual(r['sites'][-1]['value']['lane'], 0)

    def test_store_values_are_pre_state_and_duplicate_store_valid(self):
        r = project([0x910003f4, pair(rt2=20)])  # MOV x20,sp alias ADD
        self.assertEqual(r['sites'][0]['value']['offset'], 0)
        self.assertEqual(r['sites'][1]['value']['offset'], 0)
        self.assertEqual(r['sites'][0]['writeback']['after']['offset'], -32)

    def test_cumulative_budget_rejects_before_any_lane(self):
        r = project([pair(delta=-512)]*9)
        self.assertEqual(len(r['sites']), 16)
        self.assertEqual(r['stop_reason'], 'stack_delta_budget')
        self.assertEqual(r['interpreted_end_va'], '0x1020')
        self.assertEqual(r['sites'][-1]['writeback']['after']['offset'], -4096)
        r = project([0x914007ff, pair(delta=8)])  # ADD sp,sp,#4096
        self.assertEqual(r['sites'], [])
        self.assertEqual(r['stop_reason'], 'stack_delta_budget')

    def test_unsupported_encodings_never_emit_lanes(self):
        for word in (pair(rn=20), pair(True, rn=20), pair(rt=31),
                     pair(rt2=31), pair(True, rt2=20), pair() ^ (1 << 26),
                     pair() & ~(1 << 31), 0xd503233f):
            with self.subTest(word=hex(word)):
                r = project([word, 0xf90003e0])
                self.assertEqual(r['sites'], [])
                self.assertEqual(r['stop_reason'], 'unsupported_instruction_boundary')

    def test_other_modes_preserve_barrier(self):
        for provenance in (False, True):
            for load in (False, True):
                for mode in (1, 3):
                    r = callback_evidence.project(receipt([pair(load, mode)]), provenance=provenance)['data']['callback_evidence']
                    self.assertEqual(r['sites'], [])
                    self.assertEqual(r['stop_reason'], 'unsupported_instruction_boundary')

    def test_call_conditions_and_immutable_determinism(self):
        r = receipt([0x94000008, pair(), pair(True, 1, 32)])
        before = copy.deepcopy(r)
        a = callback_evidence.project(r, abi='aapcs64')
        self.assertEqual(a, callback_evidence.project(r, abi='aapcs64'))
        self.assertEqual(r, before)
        self.assertEqual(a['data']['callback_evidence']['sites'][1]['conditional_on_calls'], ['0x1000'])
        self.assertEqual(a['data']['callback_evidence']['policy'], 'macscope-callback-sites/6')
