"""Regression checks for import-time source mapping verification."""
from copy import deepcopy
import unittest

from macscope import loader_mapping
from macscope.errors import Error


class LoaderMappingTests(unittest.TestCase):
    def setUp(self):
        image_id = "a" * 64
        self.image = {
            "image_id": image_id, "size": "0x200",
            "loader": {"preferred_image_base": "0x1000"},
            "sections": [
                {"va": "0x1100", "size": "0x10", "file_offset": "0x100"},
                {"va": "0x1110", "size": "0x8", "file_offset": None},
            ],
        }
        filename = image_id + ".macho"
        self.result = {
            "image_base": "0x1000",
            "coverage": {"sections": {"status": "complete", "emitted": 1, "total": 1,
                                      "truncated": False, "error": None}},
            "sections": [{
                "type": "Default", "loaded": True, "initialized": True, "x": True,
                "start": "0x1100", "end": "0x110f", "sources_truncated": False,
                "sources": [
                    {"start": "0x1100", "end": "0x1107", "file_name": filename, "file_offset": 0x100},
                    {"start": "0x1108", "end": "0x110f", "file_name": filename, "file_offset": 0x108},
                ],
            }],
        }

    def test_adjacent_sources_verify_the_whole_file_backed_section(self):
        report = loader_mapping.verify(self.result, self.image)
        self.assertEqual(report, {
            "status": "verified", "image_base": "0x1000", "declared_file_backed_sections": 1,
            "verified_sections": 1, "coverage_gaps": [], "entry_point": {"status": "not_declared"},
        })

    def test_source_gaps_and_truncation_are_explicit(self):
        block = self.result["sections"][0]
        block["sources"].pop()
        block["sources_truncated"] = True
        report = loader_mapping.verify(self.result, self.image)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["verified_sections"], 0)
        self.assertEqual(report["coverage_gaps"], ["worker_mapping_incomplete", "declared_sections_unmapped"])

    def test_process_entry_requires_executable_file_backing(self):
        entry = {"source": "LC_MAIN", "status": "complete", "va": "0x1108", "slice_file_offset": "0x108"}
        self.image["loader"]["entry_point"] = entry
        report = loader_mapping.verify(self.result, self.image)
        self.assertEqual(report["entry_point"], dict(entry, status="verified"))

        block = self.result["sections"][0]
        block["x"] = False
        with self.assertRaises(Error) as error:
            loader_mapping.verify(self.result, self.image)
        self.assertEqual(error.exception.code, "loader_mapping_mismatch")

        block["x"] = True
        block["sources"].pop()
        with self.assertRaises(Error) as error:
            loader_mapping.verify(self.result, self.image)
        self.assertEqual(error.exception.code, "loader_mapping_mismatch")

        block["sources_truncated"] = True
        report = loader_mapping.verify(self.result, self.image)
        self.assertEqual(report["entry_point"], dict(entry, status="unverified", reason="worker_mapping_incomplete"))
        self.assertIn("entry_mapping_unverified", report["coverage_gaps"])

    def test_wrong_base_or_file_backing_is_rejected(self):
        for field, value in (("image_base", "0x2000"), ("file_name", "other.macho"), ("file_offset", 0x109)):
            with self.subTest(field=field):
                result = deepcopy(self.result)
                target = result if field == "image_base" else result["sections"][0]["sources"][1]
                target[field] = value
                with self.assertRaises(Error) as error:
                    loader_mapping.verify(result, self.image)
                self.assertEqual(error.exception.code, "loader_mapping_mismatch")

    def test_worker_cannot_claim_a_source_outside_its_block_or_slice(self):
        for field, value in (("end", "0x1110"), ("file_offset", 0x1ff), ("start", "0x1104")):
            with self.subTest(field=field):
                result = deepcopy(self.result)
                result["sections"][0]["sources"][1][field] = value
                with self.assertRaises(Error) as error:
                    loader_mapping.verify(result, self.image)
                self.assertEqual(error.exception.code, "loader_mapping_evidence")
