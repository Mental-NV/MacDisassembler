"""Bundle inventory works without opening an analyzed executable."""
import hashlib
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from macscope import bundle, cli
from macscope.errors import Error
from test_macho import image


class BundleInventoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.app = self.root / "Fixture.app"
        self.contents = self.app / "Contents"
        self.main = self.contents / "MacOS" / "Fixture"
        self.main.parent.mkdir(parents=True)
        self.main.write_bytes(image())
        (self.contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "Fixture"}))
        self.assets = self.contents / "Resources"
        self.assets.mkdir()
        self.asset = self.assets / "Greeting.txt"
        self.asset.write_text("hello")

    def run_inventory(self, *args):
        return cli.execute(cli.parser().parse_args(["bundle", "list", str(self.app), *args]))

    def test_inventory_hashes_images_and_resources_and_labels_main(self):
        framework = self.contents / "Frameworks" / "Test.framework"
        real = framework / "Versions" / "A" / "Test"
        real.parent.mkdir(parents=True)
        real.write_bytes(image(filetype=6))
        (framework / "Test").symlink_to("Versions/A/Test")
        result = self.run_inventory("--kind", "images")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["data"]["main_executable"], "Contents/MacOS/Fixture")
        records = result["data"]["records"]
        self.assertEqual([row["relative_path"] for row in records],
                         ["Contents/Frameworks/Test.framework/Versions/A/Test", "Contents/MacOS/Fixture"])
        self.assertEqual(records[0]["sha256"], hashlib.sha256(real.read_bytes()).hexdigest())
        self.assertTrue(records[1]["main_executable"])
        resources = self.run_inventory("--kind", "resources")["data"]["records"]
        self.assertEqual(resources[-1]["resource_type"], "txt")
        self.assertEqual(resources[-1]["sha256"], hashlib.sha256(b"hello").hexdigest())

    def test_inventory_lists_symlinks_and_special_files_without_following_them(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"must not be visited")
        (self.assets / "alias").symlink_to(outside, target_is_directory=True)
        os.mkfifo(self.assets / "pipe")
        rows = {row["relative_path"]: row for row in self.run_inventory()["data"]["records"]}
        self.assertEqual(rows["Contents/Resources/alias"]["type"], "symlink")
        self.assertEqual(rows["Contents/Resources/pipe"]["type"], "special")
        self.assertIsNone(rows["Contents/Resources/alias"]["sha256"])
        self.assertFalse(any("secret" in path for path in rows))

    def test_file_swap_to_symlink_fails_without_opening_its_target(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"not in the bundle")
        real_open = os.open

        def replace_asset(name, flags, *args, **kwargs):
            if name == self.asset.name and kwargs.get("dir_fd") is not None:
                self.asset.unlink()
                self.asset.symlink_to(outside)
            return real_open(name, flags, *args, **kwargs)

        with patch.object(bundle.os, "open", side_effect=replace_asset):
            result = self.run_inventory()
        self.assertEqual(result["status"], "partial")
        row = next(row for row in result["data"]["records"] if row["relative_path"].endswith(self.asset.name))
        self.assertIsNone(row["sha256"])
        self.assertEqual(row["type"], "unavailable")

    def test_inventory_caps_and_cursor_binding(self):
        page = self.run_inventory("--limit", "1")
        cursor = page["coverage"]["next_cursor"]
        self.assertTrue(cursor)
        resumed = self.run_inventory("--limit", "1", "--cursor", cursor)
        self.assertNotEqual(page["data"]["records"], resumed["data"]["records"])
        self.asset.write_text("changed")
        with self.assertRaises(Error) as caught:
            self.run_inventory("--cursor", cursor)
        self.assertEqual(caught.exception.code, "stale_cursor")
        with patch.object(bundle, "MAX_HASH_BYTES", 1):
            partial = self.run_inventory()
        self.assertEqual(partial["status"], "partial")
        self.assertIn("hash_limit", partial["coverage"]["truncation_reason"])
        self.assertTrue(all(row["sha256"] is None for row in partial["data"]["records"]))
        with patch.object(bundle, "MAX_ENTRIES", 1):
            partial = self.run_inventory()
        self.assertEqual(partial["coverage"]["truncation_reason"], "entry_limit")
