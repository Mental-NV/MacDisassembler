"""Owned alias fixtures: canonical test setup, unchanged production path policy."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from macscope import cli, storage
from macscope.errors import Error


class TemporaryPathGateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.physical = self.root / 'physical'
        self.physical.mkdir()
        self.alias = self.root / 'alias'
        self.alias.symlink_to(self.physical, target_is_directory=True)

    def test_canonical_cli_output_from_both_temp_spellings(self):
        for spelling in (self.physical, self.alias):
            with self.subTest(spelling=spelling.name), tempfile.TemporaryDirectory(dir=spelling) as directory:
                output = Path(directory).resolve() / 'result.json'
                self.assertEqual(cli.main(['version', '--output', str(output)]), 0)
                self.assertEqual(json.loads(output.read_bytes())['command'], 'version')
                self.assertTrue(output.is_relative_to(self.physical))

    def test_uncanonicalized_alias_still_rejected_and_target_preserved(self):
        target = self.physical / 'output'
        target.write_bytes(b'preserve')
        for force in (False, True):
            with self.subTest(force=force), self.assertRaises(Error) as caught:
                storage.atomic(self.alias / 'output', b'replace', force=force)
            self.assertEqual(caught.exception.code, 'symlink')
            self.assertEqual(target.read_bytes(), b'preserve')

    def test_partial_output_fixture_tests_under_both_temp_spellings(self):
        from test_evidence_summary import SummaryTests
        from test_trust import TrustTests
        from test_saved_flow_gap_evidence import SavedEvidenceTests
        for spelling in (self.physical, self.alias):
            with self.subTest(spelling=spelling.name), patch.object(tempfile, 'tempdir', str(spelling)):
                suite = unittest.TestSuite([
                    SummaryTests('test_cli_partial_text_retains_exit_six'),
                    TrustTests('test_partial_output_preserved_and_explained'),
                    SavedEvidenceTests('test_cached_exact_warning_and_deterministic_source_preservation')])
                result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
                self.assertTrue(result.wasSuccessful(), str(result.failures + result.errors))


if __name__ == '__main__':
    unittest.main()
