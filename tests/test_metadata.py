"""Imported metadata and file-backed bytes are queryable before analysis."""
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from macscope import address_xrefs, cli, macho, metadata
from macscope.errors import Error
from macscope.storage import Project, atomic, canonical
from test_macho import segment_image


class MetadataQueryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(directory.cleanup)
        self.project = Project.create(Path(directory.name) / "project")
        data = segment_image()
        metadata = macho.inspect_bytes(data)
        image = dict(metadata["slices"][0], artifact_sha256=metadata["artifact_sha256"], offset="0x1000")
        image.pop("segments")
        image.pop("flags")  # Workspace created before these fields were recorded.
        image.pop("loader")
        self.input = self.project.path / "inputs" / (image["image_id"] + ".macho")
        atomic(self.input,data,mode=0o400)
        with self.project.db(False) as db:
            db.execute("INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)",
                       (image["image_id"],image["arch"],canonical(image).decode()))

    def query(self, *args):
        return cli.execute(cli.parser().parse_args([*args,"--project",str(self.project.path)]))

    def test_headers_and_segments_can_use_a_legacy_import(self):
        headers = self.query("headers")
        self.assertIsNone(headers["analysis_id"])
        self.assertEqual(headers["data"]["flags"], "0x0")
        self.assertEqual(headers["data"]["loader"]["preferred_image_base"], "0x100000000")
        row, = self.query("segments","--name-contains","TEXT")["data"]
        self.assertEqual(row["name"], "__TEXT")
        self.assertEqual(row["file_offset"], "0x0")
        self.assertEqual(row["origin"], "macho_preflight")
        sections = self.query("sections","--name-contains","text")["data"]
        self.assertEqual(sections[0]["va"], "0x100000100")

    def test_bytes_map_to_slice_and_container_and_check_digest(self):
        result = self.query("bytes","--address","0x100000100","--length","4")
        self.assertEqual(result["data"]["bytes"], "1f2003d5")
        self.assertEqual(result["data"]["slice_file_offset"], "0xb8")
        self.assertEqual(result["data"]["container_file_offset"], "0x10b8")
        with self.assertRaises(Error) as caught:
            self.query("bytes","--address","0x100000100","--length","5")
        self.assertEqual(caught.exception.code, "bytes_unmapped")
        atomic(self.input,b"corrupt",force=True)
        with self.assertRaises(Error) as caught:
            self.query("bytes","--address","0x100000100","--length","4")
        self.assertEqual(caught.exception.code, "input_integrity")

    def test_typed_byte_selectors_work_before_analysis_and_retain_offsets(self):
        expected = self.query("bytes", "--address", "0x100000100", "--length", "4")["data"]
        self.assertEqual(expected["rva"], "0x100")
        for flag, value in (("--rva", "0x100"), ("--file-offset", "0xb8")):
            result = self.query("bytes", flag, value, "--length", "4")
            self.assertIsNone(result["analysis_id"])
            self.assertEqual(result["data"], expected)
        raw = self.query("bytes", "--file-offset", "0x0", "--length", "4")["data"]
        self.assertEqual(raw["bytes"], "cffaedfe")
        self.assertEqual(raw["container_file_offset"], "0x1000")
        self.assertIsNone(raw["va"])
        self.assertIsNone(raw["rva"])
        self.assertIsNone(raw["address_space"])
        for args, code in ((["--file-offset", "0x10b8"], "bytes_unmapped"),
                           (["--rva", "0xffffffffffffffff"], "address"),
                           (["--rva", "256"], "address"),
                           (["--rva", "0x100", "--file-offset", "0xb8"], "usage")):
            with self.subTest(args=args), self.assertRaises(Error) as rejected:
                self.query("bytes", *args, "--length", "4")
            self.assertEqual(rejected.exception.code, code)

    def test_backing_map_requires_an_unambiguous_round_trip(self):
        file_backed = {"va": "0x10", "file_offset": "0x8", "size": "0x8"}
        zero_fill = {"va": "0x18", "file_offset": None, "size": "0x8"}
        sections = [file_backed, zero_fill]
        image = {"sections": sections}
        self.assertEqual(metadata.mapped_location(image, 0x8, 8, from_file=True), 0x10)
        self.assertIsNone(metadata.mapped_location(image, 0x18, 1, from_file=False))
        self.assertIsNone(metadata.mapped_location(image, 0xf, 2, from_file=True))
        zero_fill['va'] = '0x14'
        self.assertIsNone(metadata.mapped_location(image, 0x8, 8, from_file=True))
        zero_fill['va'] = '0x18'
        sections.append({"va": "0x14", "file_offset": "0x20", "size": "0x4"})
        self.assertIsNone(metadata.mapped_location(image, 0x8, 8, from_file=True))
        self.assertIsNone(metadata.mapped_location(image, 0x14, 1, from_file=False))

    def test_runtime_byte_selection_preserves_the_unslid_evidence(self):
        expected = self.query("bytes", "--address", "0x100000100", "--length", "4")
        for runtime, slide in (("0x100010100", "0x10000"), ("0xfff00100", "-0x100000"),
                               ("0x100000100", "0x0")):
            with self.subTest(runtime=runtime, slide=slide):
                observed = self.query("bytes", "--runtime-address", runtime, "--load-slide=" + slide,
                                      "--length", "4")
                self.assertEqual(observed.pop("address_selection"), {
                    "runtime_va": runtime, "load_slide": slide, "va": "0x100000100",
                    "image_id": expected["data"]["image_id"], "arch": "arm64", "address_space": "ram",
                })
                self.assertEqual(observed, expected)

        for selector, code in (
            (("--runtime-address", "0x1"), "load_slide"),
            (("--address", "0x100000100", "--load-slide", "0x0"), "load_slide"),
            (("--runtime-address", "1", "--load-slide", "0x0"), "address"),
            (("--runtime-address", "0x1", "--load-slide", "4096"), "load_slide"),
            (("--runtime-address", "0x0", "--load-slide", "0x1"), "address"),
            (("--runtime-address", "0xffffffffffffffff", "--load-slide=-0x1"), "address"),
            (("--runtime-address", "0x1", "--load-slide", "0x10000000000000000"), "load_slide"),
            (("--runtime-address", "0x1", "--load-slide", "0x0", "--rva", "0x100"), "usage"),
        ):
            with self.subTest(selector=selector), self.assertRaises(Error) as rejected:
                self.query("bytes", *selector, "--length", "4")
            self.assertEqual(rejected.exception.code, code)

    def test_string_encoding_cursors_and_verified_byte_evidence(self):
        payload = b"abc\0"
        data = self.input.read_bytes()[:-len(payload)] + payload
        atomic(self.input, data, force=True)
        image = self.project.select()
        image["sha256"] = sha256(data).hexdigest()
        image["loader"] = {"preferred_image_base": "0x100000000"}
        address = "0x100000100"
        row = {"address": address, "length_bytes": 4, "value": "abc", "encoding": "ascii",
               "bytes_sha256": sha256(payload).hexdigest()}
        legacy = {"address": "0x100000101", "length_bytes": 3, "value": "bc"}
        ref = {"from": "0x100000088", "to": address, "type": "DATA"}
        snapshot = {"analysis_id": "b" * 64, "engine": {
            "image_base": "0x100000000", "strings": [row, legacy], address_xrefs.REFERENCES: [ref],
            "coverage": {"strings": {"status": "complete", "emitted": 2},
                         address_xrefs.REFERENCES: {"status": "complete", "emitted": 1}},
        }}
        with mock.patch.object(Project, "select", return_value=image), \
             mock.patch.object(Project, "snapshot", return_value=(snapshot, {})):
            first = self.query("strings", "--limit", "1")
            cursor = first["coverage"]["next_cursor"]
            saved, = first["data"]
            self.assertEqual(saved["encoding"], "ascii")
            self.assertEqual(saved["bytes"], payload.hex())
            self.assertEqual(saved["rva"], "0x100")
            self.assertEqual(saved["slice_file_offset"], "0xb8")
            self.assertEqual(saved["container_file_offset"], "0x10b8")
            self.assertEqual(saved["xrefs_to_start"], [ref])
            self.assertEqual(saved["xrefs_status"], "complete")

            second = self.query("strings", "--encoding", "auto", "--limit", "1", "--cursor", cursor)
            previous, = second["data"]
            self.assertEqual(previous["value"], "bc")
            self.assertIsNone(previous["encoding"])
            self.assertIsNone(previous["bytes"])
            with self.assertRaises(Error) as caught:
                self.query("strings", "--encoding", "ascii", "--cursor", cursor)
            self.assertEqual(caught.exception.code, "stale_cursor")
            result = self.query("strings", "--encoding", "ascii")
            self.assertEqual(result["data"], [saved])
            self.assertEqual(result["coverage"]["truncation_reason"], "string_encodings_incomplete")

            row["bytes_sha256"] = sha256(b"xyz\0").hexdigest()
            mismatch, = self.query("strings", "--encoding", "ascii")["data"]
            self.assertIsNone(mismatch["bytes"])
            self.assertEqual(mismatch["bytes_status"], "file_bytes_differ_from_program")
            atomic(self.input, b"corrupt", force=True)
            with self.assertRaises(Error) as caught:
                self.query("strings", "--encoding", "ascii")
            self.assertEqual(caught.exception.code, "input_integrity")
