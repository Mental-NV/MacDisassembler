"""The frozen lowering changes representation and keeps semantic blockers."""
import unittest

from aggregate_compat import Unsupported, lower_closure
from compare_printer_behavior import condition_summaries
from compare_state_operations import bind_return_address


def lowered(body, *, header="undefined1 [16] FUN_100(long param_1)"):
    return lower_closure("FUN_100", {"FUN_100": header + "\n{" + body + "}"}, 1)[0]


class AggregateCompatibilityTests(unittest.TestCase):
    def test_only_written_bytes_become_known_and_unknown_stack_padding_stays_unknown(self):
        result = lowered("""
            undefined1 auVar1 [16];
            undefined4 uStack_4;
            auVar1._0_8_ = param_1;
            auVar1[8] = 7;
            auVar1._9_3_ = 0;
            auVar1._12_4_ = uStack_4;
            return auVar1;
        """)
        self.assertIn("gh_bits FUN_100(long param_1)", result)
        self.assertIn("gh_bits auVar1 = {0};", result)
        self.assertIn("gh_set(&auVar1, 8, 1, (7));", result)
        self.assertIn("gh_undef(&auVar1, 12, 4);", result)
        self.assertNotIn("uStack_4", result)

    def test_does_not_replace_undefined_values_in_expressions(self):
        with self.assertRaisesRegex(Unsupported, "undefined_stack_value_consumed"):
            lowered("undefined4 uStack_4; return ZEXT816(uStack_4 + param_1);")

    def test_preserves_predeclared_store_width_address_and_value(self):
        for width in (16, 32, 64):
            store = f"STORE_LE{width}((void *)(param_1 + 3), param_1);"
            self.assertIn(store, lowered(store + " return ZEXT816(param_1);"))
        with self.assertRaisesRegex(Unsupported, "unknown_identifier:STORE_LE128"):
            lowered("STORE_LE128((void *)param_1, param_1); return ZEXT816(param_1);")

    def test_twelve_byte_temporary_uses_declared_subfields_and_truncates_the_call(self):
        source = {
            "FUN_100": """undefined1 [16] FUN_100(long param_1) {
                undefined1 auVar1 [12];
                auVar1 = FUN_200(param_1);
                return ZEXT816(auVar1._8_4_);
            }""",
            "FUN_200": "undefined1 [16] FUN_200(long param_1) { return ZEXT816(param_1); }",
        }
        result, _ = lower_closure("FUN_100", source, 1)
        self.assertIn("gh_low_bytes(FUN_200(param_1), 12)", result)
        self.assertIn("gh_read(auVar1, 8, 4)", result)
        with self.assertRaisesRegex(Unsupported, "invalid_aggregate_subfield"):
            lowered("undefined1 auVar1 [12]; auVar1._8_8_ = param_1; return auVar1;")

    def test_twelve_byte_return_does_not_mark_padding_known(self):
        code = lowered("return ZEXT816(param_1);", header="undefined1 [12] FUN_100(long param_1)")
        self.assertIn("return gh_low_bytes(gh_known((ZEXT816(param_1))), 12);", code)

    def test_twelve_byte_shift_and_field_copy_preserve_width(self):
        code = lowered("""
            undefined1 auVar1 [16];
            undefined1 auVar2 [12];
            auVar2 = ZEXT412(3) << 0x40;
            auVar1._0_12_ = auVar2;
            return auVar1;
        """)
        self.assertIn("gh_shift(gh_low_bytes(gh_known(ZEXT412(3)), 12), 8)", code)
        self.assertIn("gh_copy_field(&auVar1, 0, 12, auVar2);", code)
        with self.assertRaisesRegex(Unsupported, "unsupported_aggregate_shift"):
            lowered("undefined1 auVar1 [12]; auVar1 = ZEXT412(3) << 128; return auVar1;")

    def test_shifted_aggregate_assignment_keeps_the_comma_guard(self):
        code = lowered("""
            undefined1 auVar1 [16];
            if (param_1 && (auVar1 = ZEXT816(3) << 0x40, param_1 == 4)) {
                return auVar1;
            }
            return ZEXT816(0);
        """)
        self.assertIn("param_1 && (auVar1 = gh_shift(gh_known(ZEXT816(3)), 8), param_1 == 4)", code)

    def test_byte_vector_pointer_forms_preserve_the_source_address(self):
        code = lowered("""
            undefined1 (*pauVar2) [16];
            undefined1 auVar1 [16];
            pauVar2 = (undefined1 (*) [16])param_1;
            auVar1 = NEON_rev64(pauVar2[-1],1);
            auVar1 = NEON_ext(auVar1,*pauVar2,0x9,1);
            *pauVar2 = auVar1;
            return auVar1;
        """)
        self.assertIn("NEON_rev64(gh_load_vector(pauVar2[-1]), 1)", code)
        self.assertIn("NEON_ext(auVar1, gh_load_vector(*pauVar2), 9, 1)", code)
        self.assertIn("gh_store_vector(*pauVar2, auVar1);", code)

    def test_byte_shuffle_accepts_a_vector_pointer_parameter_and_a_nested_mask(self):
        code = lowered("""
            undefined1 auVar1 [16];
            auVar1 = pshufb(*param_1, CONCAT88(0x102,0x304));
            *(long *)*param_1 = auVar1._0_8_;
            *param_1 = auVar1;
            return auVar1;
        """, header="undefined1 [16] FUN_100(undefined1 (*param_1) [16])")
        self.assertIn("pshufb(gh_load_vector(*param_1), CONCAT88(0x102,0x304))", code)
        self.assertIn("gh_store_vector(*param_1, auVar1);", code)
        self.assertIn("*(long *)*param_1 = ((uint64_t)gh_read(auVar1, 0, 8));", code)

    def test_stack_return_address_requires_a_matching_failure_stub(self):
        text = "undefined8 uStack_40; uStack_40 = &UNK_1005;"
        image = {"arch": "x86_64", "sections": [
            {"name": "__stubs", "va": "0x1020", "size": "0x6", "file_offset": "0x0"}
        ]}
        call = {0x1000: (b"\xe8" + (0x1020 - 0x1005).to_bytes(4, "little"), "callq", "")}
        stub = b"\xff\x25" + (0x1100 - 0x1026).to_bytes(4, "little")
        binds = [{"symbol": "___stack_chk_fail", "va": "0x1100"}]
        bound, stack, evidence = bind_return_address(text, stub, image, call, binds)
        self.assertIn("uStack_40 = (ulong)0x1005;", bound)
        self.assertEqual(stack, ("uStack_40",))
        self.assertEqual(evidence["stub_va"], "0x1020")
        with self.assertRaisesRegex(Unsupported, "unverified_stack_return_address"):
            bind_return_address(text, stub, image, call, [{"symbol": "_other", "va": "0x1100"}])

    def test_optimized_gate_keeps_symbol_states_separate(self):
        rows = {
            ("ReleaseAnalysis-arm64", "stripped", "baseline/1", "example"):
                {"status": "not_testable", "llvm_instruction_bytes": 8},
            ("ReleaseAnalysis-arm64", "sym", "baseline/1", "example"):
                {"status": "passed", "llvm_instruction_bytes": 8, "results": {}},
        }
        report = condition_summaries(rows)
        stripped = report["binary_only"]["baseline/1"]["O2"]["total"]
        symbols = report["embedded_symbols"]["baseline/1"]["O2"]["total"]
        self.assertEqual((stripped["cases"], stripped["passed_bytes"]), (1, 0))
        self.assertEqual((symbols["cases"], symbols["passed_bytes"]), (1, 8))

    def test_does_not_rewrite_a_missing_aggregate_signature_or_unknown_dependency(self):
        with self.assertRaisesRegex(Unsupported, "aggregate_abi_unverified"):
            lowered("return param_1;", header="long FUN_100(long param_1)")
        with self.assertRaisesRegex(Unsupported, "unknown_identifier:FUN_200"):
            lowered("return FUN_200(param_1);")

    def test_direct_call_keeps_wrong_arity_for_compiler_diagnosis(self):
        source = {
            "FUN_100": "undefined1 [16] FUN_100(long param_1) { return FUN_200(0, param_1); }",
            "FUN_200": "undefined1 [16] FUN_200(long param_1) { return ZEXT816(param_1); }",
        }
        result, definitions = lower_closure("FUN_100", source, 1)
        self.assertEqual(definitions, ["FUN_200", "FUN_100"])
        self.assertIn("return FUN_200(0, param_1);", result)

    def test_shift_and_subfield_bounds_are_explicit(self):
        text = "undefined1 auVar1 [16]; auVar1._0_8_=param_1; return auVar1 << "
        self.assertIn("gh_shift(auVar1, 8)", lowered(text + "0x40;"))
        with self.assertRaisesRegex(Unsupported, "unsupported_aggregate_shift"):
            lowered(text + "3;")
        with self.assertRaisesRegex(Unsupported, "invalid_aggregate_subfield"):
            lowered("undefined1 auVar1 [16]; auVar1._15_2_=param_1; return auVar1;")

    def test_does_not_guess_aggregate_division_signedness(self):
        code = lowered("""
            undefined1 auVar1 [16];
            auVar1 = SEXT816(param_1);
            auVar1._0_8_ = SUB168(auVar1 / SEXT816(param_1),0);
            return auVar1;
        """)
        self.assertIn("auVar1 / SEXT816(param_1)", code)
        self.assertNotIn("gh_signed(auVar1)", code)

    def test_explicit_signed_division_is_lowered_as_a_wide_value(self):
        code = lowered("""
            undefined1 auVar1 [16];
            auVar1 = SEXT816(param_1);
            return SDIV16(auVar1,SEXT816(3));
        """)
        self.assertIn("return gh_known((SDIV16(auVar1,SEXT816(3))));", code)
