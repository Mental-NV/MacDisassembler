"""Source guardrails only; these do not replace the native Ghidra smoke gate."""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'src/macscope/bridge/MacscopeBridge.java').read_text()

class BulkBridgeContractTests(unittest.TestCase):
    def test_bounded_explicit_selection(self):
        for fragment in ('readNBytes(16385)', 'bytes.length > 16384',
                         'macscope-bulk-selection/1', 'entries.size() > 128',
                         'entries.size() > limit', 'Long.compareUnsigned(previous, current) >= 0',
                         '0x(?:0|[1-9a-f][0-9a-f]{0,15})'):
            self.assertIn(fragment, SOURCE)

    def test_bulk_does_not_use_hints_or_focused_import(self):
        self.assertIn('boolean fromImport = args.length == 6 && !bulk', SOURCE)
        self.assertIn('args.length == 6 && !fromImport && !bulk', SOURCE)
        self.assertIn('if (entry == null && !bulk)', SOURCE)
        self.assertIn('bulk && !mode.equals("query")', SOURCE)
        self.assertIn('mode.equals("query") && isHeadlessAnalysisEnabled()', SOURCE)

    def test_one_session_and_no_bulk_mutation(self):
        body = SOURCE.split('void functions(int limit, int timeout, String entry, boolean fromImport, List<String> bulkEntries)', 1)[1].split('Function functionAt', 1)[0]
        self.assertEqual(body.count('new DecompInterface()'), 1)
        self.assertEqual(body.count('decomp.openProgram(currentProgram)'), 1)
        self.assertEqual(body.count('decomp.dispose()'), 1)
        loop = body.split('for (String selected : bulkEntries)', 1)[1].split('} else if (entry == null)', 1)[0]
        self.assertIn('Function f = functionAt(selected)', loop)
        self.assertIn('decompile(f, decomp, timeout, item, facets)', loop)
        for mutation in ('startTransaction', 'createFunction', 'setName', 'setSignature', 'recoverBoundaries'):
            self.assertNotIn(mutation, loop)
        self.assertIn('Bulk decompilation stopped at', loop)
        self.assertIn('bulkEntries != null && err != null) { fatal = true', body)

    def test_exact_selection_provenance(self):
        self.assertIn('root.add("bulk_entries", selected)', SOURCE)
        self.assertIn('root.addProperty("bulk_semantics", "shared-program-session/1")', SOURCE)
        self.assertIn('functions(limit, timeout, entry, fromImport, null)', SOURCE)

if __name__ == '__main__':
    unittest.main()
