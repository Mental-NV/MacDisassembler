"""User revisions are isolated from immutable Ghidra analysis records."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from macscope import annotations
from macscope.errors import Error
from macscope.storage import Project


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
