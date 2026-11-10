"""Check that review packets preserve frozen evidence and exclude richer runs."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from prepare_clean_review import packet_members

CASE = 'DebugAnalysis-arm64-stripped-app'


def digest(data):
    return hashlib.sha256(data).hexdigest()


class CleanReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        case = self.root / ('ghidra-' + CASE)
        case.mkdir()
        self.input = case / 'input.bin'
        self.binary = b'owned test input'
        self.input.write_bytes(self.binary)
        self.baseline = case / 'baseline.json'
        self.llvm = self.root / ('llvm-' + CASE + '.txt')
        self.llvm.write_bytes(os.fsencode(self.input) + b':\n1000: ret\n')
        self.write_baseline('binary-only-v2')
        (self.root / 'identity.json').write_text(json.dumps({'isolation': 'macscope-baseline-case/1'}))
        (self.root / 'summary.json').write_text(json.dumps({'status': 'complete', 'records': [{
            'tag': CASE, 'status': 'complete', 'condition': 'binary-only',
            'input_sha256': digest(self.binary), 'isolation_probe': {'exit_code': 0, 'failure': None},
        }]}))

    def write_baseline(self, profile):
        self.baseline.write_text(json.dumps({
            'schema': 'macscope-baseline/2', 'blind_profile': profile,
            'executable_md5': hashlib.md5(self.binary).hexdigest(),
        }))
        (self.root / 'freeze.json').write_text(json.dumps({'schema': 'macscope-freeze/2', 'artifacts': [
            {'path': str(path), 'sha256': digest(path.read_bytes())} for path in (self.baseline, self.llvm)
        ]}))

    def test_packet_contains_only_the_selected_evidence_and_rubric(self):
        members = packet_members(self.root, CASE)
        self.assertEqual(set(members), {'input.bin', 'baseline.json', 'llvm.txt', 'manifest.json', 'REVIEW.md'})
        self.assertEqual(members['input.bin'], self.binary)
        self.assertEqual(members['baseline.json'], self.baseline.read_bytes())
        self.assertEqual(members['llvm.txt'], b'1000: ret\n')
        manifest = json.loads(members.pop('manifest.json'))
        self.assertEqual(manifest['condition'], 'binary-only')
        self.assertEqual(manifest['files'], {name: digest(data) for name, data in members.items()})

    def test_assisted_profile_rejected_even_when_listed_in_the_freeze(self):
        self.write_baseline('dsym-assisted-v1')
        with self.assertRaisesRegex(ValueError, 'does not identify this unassisted input'):
            packet_members(self.root, CASE)

    def test_staged_binary_swap_rejected(self):
        self.input.write_bytes(b'different binary')
        with self.assertRaisesRegex(ValueError, 'Digest mismatch.*input.bin'):
            packet_members(self.root, CASE)
