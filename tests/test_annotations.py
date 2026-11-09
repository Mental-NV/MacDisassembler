"""User revisions are isolated from immutable Ghidra analysis records."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from macscope import annotations, cli, storage
from macscope.errors import Error
from macscope.storage import Project
from test_core import TemporaryCase, synthetic_snapshot


class AnnotationStorageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(directory.cleanup)
        self.project = Project.create(Path(directory.name) / "project")

    def revise(self, value, *, image="image-a", analysis="analysis-a", instruction=None, kind="comment"):
        with self.project.writer():
            return annotations.revise(self.project, image, analysis, "0x100", instruction,
                                      kind, value, "owner")

    def test_legacy_workspace_and_idempotent_revisions(self):
        self.assertEqual(annotations.read(self.project, "image-a"), (0, []))
        first, changed = self.revise("Initial comment")
        self.assertTrue(changed)
        self.assertEqual(first["origin"], "user_supplied")
        self.assertEqual(first["author"], "owner")
        self.assertIsNone(first["previous_value"])
        self.assertEqual(self.revise("Initial comment"), (first, False))
        later, changed = self.revise("Revised comment", analysis="analysis-b")
        self.assertTrue(changed)
        self.assertEqual(later["previous_value"], first["value"])
        self.assertEqual(later["analysis_id"], "analysis-b")
        self.assertEqual(annotations.read(self.project, "image-a"), (later["revision"], [later]))
        self.assertEqual(annotations.read(self.project, "image-a", history=True)[1], [first, later])

    def test_removal_and_instruction_scope_are_independent(self):
        self.revise("Function comment")
        instruction, _ = self.revise("Instruction comment", instruction="0x100")
        label, _ = self.revise("User label", kind="name")
        self.revise("Another image", image="image-b")
        removed, changed = self.revise(None)
        self.assertTrue(changed)
        self.assertIsNone(removed["value"])
        self.assertEqual(removed["previous_value"], "Function comment")
        self.assertEqual(annotations.read(self.project, "image-a")[1], [instruction, label])
        self.assertEqual(annotations.read(self.project, "image-a", kind="comment")[1], [instruction])

    def test_revision_limit_keeps_previous_value(self):
        with patch.object(annotations, "MAX_REVISIONS", 1):
            first, _ = self.revise("First")
            with self.assertRaises(Error) as caught:
                self.revise("Second")
        self.assertEqual(caught.exception.code, "annotation_limit")
        self.assertEqual(annotations.read(self.project, "image-a")[1], [first])


class AnnotationTransferTests(TemporaryCase):
    selector = ("--name", "unique")

    def setUp(self):
        super().setUp()
        self.source = self.project("source")
        self.destination = self.project("destination")
        synthetic_snapshot(self.source, "a" * 64, slice_bytes=b"owned")
        self.snapshot, _ = synthetic_snapshot(self.destination, "b" * 64, slice_bytes=b"owned")

    def query(self, project, *words):
        return cli.execute(cli.parser().parse_args([*words, "--project", str(project.path), "--json"]))

    def save(self, bundle):
        path = self.root / "transfer.json"
        storage.write_json(path, bundle, force=True)
        return str(path)

    def test_round_trip_preserves_history_and_remaps_local_revisions(self):
        note = "Résumé of /Users/author/fixture\nSecond line"
        self.query(self.source, "rename", "Review anchor", *self.selector)
        self.query(self.source, "comment", "set", "Later removed", *self.selector)
        self.query(self.source, "comment", "remove", *self.selector)
        self.query(self.source, "comment", "set", note, "--instruction", "0x100000020", *self.selector)
        self.query(self.source, "type", "set", "--return-type", "uint64_t", "--accept", *self.selector)
        source = self.query(self.source, "annotations", "export")
        bundle = self.save(source)
        with self.destination.writer():
            annotations.revise(self.destination, "other-image", "c" * 64, "0x100", None,
                               "name", "Other label", "local")
        self.error("type_hint_acceptance", self.query, self.destination, "annotations", "import", bundle)
        self.assertEqual(self.query(self.destination, "annotations", "history")["data"], [])
        before = self.query(self.destination, "functions", "list", "--limit", "1")
        imported = self.query(self.destination, "annotations", "import", bundle, "--accept-type-hints")
        self.assertEqual(imported["data"]["appended_revisions"], 5)
        self.assertEqual(self.query(self.destination, "annotations", "export")["data"], source["data"])
        shown = self.query(self.destination, "functions", "show", "--name", "Review anchor")["data"]
        self.assertEqual([row["value"] for row in shown["annotations"]], ["Review anchor", note, "uint64_t"])
        self.assertEqual(shown["annotations"][0]["revision"], 2)
        self.error("stale_cursor", self.query, self.destination, "functions", "list",
                   "--cursor", before["coverage"]["next_cursor"])
        self.assertEqual(self.query(self.destination, "annotations", "import", bundle)["data"]["appended_revisions"], 0)
        self.assertEqual(self.query(self.destination, "export")["data"], self.snapshot)

        self.query(self.destination, "comment", "set", "Source transfer extension", *self.selector)
        extended = self.save(self.query(self.destination, "annotations", "export"))
        self.assertEqual(self.query(self.source, "annotations", "import", extended)["data"]["appended_revisions"], 1)

    def test_conflict_and_invalid_targets_do_not_append_any_revision(self):
        self.query(self.source, "rename", "Source label", *self.selector)
        self.query(self.source, "comment", "set", "Source note", "--instruction", "0x100000020", *self.selector)
        bundle = self.query(self.source, "annotations", "export")
        bundle["data"]["revisions"][1]["instruction"] = "0x100000021"
        self.error("annotation_address", self.query, self.destination, "annotations", "import", self.save(bundle))
        self.assertEqual(self.query(self.destination, "annotations", "history")["data"], [])

        bundle["data"]["image"]["sha256"] = "0" * 64
        self.error("annotation_transfer_image", self.query, self.destination, "annotations", "import", self.save(bundle))
        self.assertEqual(self.query(self.destination, "annotations", "history")["data"], [])

        self.query(self.destination, "rename", "Different label", *self.selector)
        clean = self.save(self.query(self.source, "annotations", "export"))
        self.error("annotation_transfer_conflict", self.query, self.destination, "annotations", "import", clean)
        self.assertEqual([row["value"] for row in self.query(self.destination, "annotations", "history")["data"]],
                         ["Different label"])

    def test_invalid_revision_chain_is_rejected(self):
        self.query(self.source, "rename", "Source label", *self.selector)
        bundle = self.query(self.source, "annotations", "export")
        bundle["data"]["revisions"][0]["previous_value"] = "Never recorded"
        self.error("annotation_transfer_format", self.query, self.destination, "annotations", "import",
                   self.save(bundle))
        self.assertEqual(self.query(self.destination, "annotations", "history")["data"], [])
