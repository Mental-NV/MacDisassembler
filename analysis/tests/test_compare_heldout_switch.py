"""Eligibility for executing unchanged held-out scalar pseudocode."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compare_heldout_switch import eligible


def row(body, *, name="FUN_100", status="complete", truncated=False):
    return {
        "name": name, "decompile_status": status, "pseudocode_truncated": truncated,
        "pseudocode": f"undefined4 {name}(uint param_1,int param_2) {{ {body} }}",
    }


class HeldoutEligibilityTests(unittest.TestCase):
    def test_preserves_printed_arity_and_types(self):
        record = row("return param_1 + param_2;")
        self.assertTrue(eligible(record, 2))
        self.assertFalse(eligible(record, 3))
        self.assertFalse(eligible(row("return 1;", status="partial"), 2))
        self.assertFalse(eligible(row("return 1;", truncated=None), 2))

    def test_calls_require_recovered_dependency_and_reject_unexpected_constructs(self):
        direct = row("return FUN_200(param_1, param_2);")
        self.assertFalse(eligible(direct, 2))
        self.assertTrue(eligible(direct, 2, ("FUN_200",)))
        for body in ("return *(long *)param_1;", "return system(param_1);",
                     "#include <stdio.h>", "} int main() { return 0;"):
            with self.subTest(body=body):
                self.assertFalse(eligible(row(body), 2, ("FUN_200",)))
