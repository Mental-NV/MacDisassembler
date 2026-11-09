"""Imported metadata and file-backed bytes are queryable before analysis."""
from pathlib import Path
import tempfile
import unittest

from macscope import cli, macho
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
