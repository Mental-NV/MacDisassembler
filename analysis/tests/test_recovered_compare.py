"""The scalar harness only accepts bounded, unmodified comparison C."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from recovered_compare import eligible


class ScalarEligibilityTests(unittest.TestCase):
    def test_accepted_scalar_is_used_without_a_signature_repair(self):
        name = "_calc_compare_s64"
        code = f"uint {name}(long param_1,long param_2) {{ return (param_1 < param_2) ? 1 : 0; }}"
        # Conditional syntax is accepted only when part of the declared grammar.
        self.assertFalse(eligible(code,name,"long"))
        code = f"uint {name}(long param_1,long param_2) {{ if (param_1 < param_2) return 0xffffffff; return 0; }}"
        self.assertTrue(eligible(code,name,"long"))
        self.assertFalse(eligible(code,name,"ulong"))

    def test_unsafe_or_out_of_scope_code_is_never_compiled(self):
        name = "_calc_compare_s64"
        for body in ("#include </tmp/file>","return write(1,0,0);",
                     "return *(long *)param_1;","while (1) {}",
                     "} int param_1() { return 0;"):
            with self.subTest(body=body):
                text = f"int {name}(long param_1,long param_2) {{ {body} }}"
                self.assertFalse(eligible(text,name,"long"))
