"""Bundle inventory works without opening an analyzed executable."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from macscope import bundle, cli, engine
from macscope.errors import Error
from macscope.storage import Project
from test_core import synthetic_program
from test_macho import X86_64, image


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

    def run_resources(self, *args):
        return cli.execute(cli.parser().parse_args(["resources", "list", str(self.app), *args]))

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

    def test_companion_inventory_marks_physical_macho_and_inspect_checks_filetype(self):
        companion = self.main.with_name("Fixture.debug.dylib")
        companion.write_bytes(image(filetype=6))
        records = self.run_inventory("--kind", "images")["data"]["records"]
        self.assertTrue(records[1]["debug_companion_candidate"])
        self.assertFalse(records[1]["main_executable"])
        companion.write_bytes(image())
        result = cli.execute(cli.parser().parse_args(["inspect", str(self.app), "--json"]))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["coverage"]["truncation_reason"], "debug_companion_unavailable")
        self.assertEqual(result["data"]["debug_companion"]["error_code"], "debug_companion_filetype")

    def test_resource_type_filter_hashes_matching_assets_only(self):
        (self.assets / "Earlier.bin").write_bytes(b"unrelated resource")
        (self.assets / "Helper.txt").write_bytes(image())
        (self.assets / "Note.TXT").write_bytes(b"!")
        os.mkfifo(self.assets / "Pipe.txt")
        (self.assets / "Alias.txt").symlink_to(self.asset)
        with patch.object(bundle, "MAX_HASH_BYTES", 6), \
             patch.object(engine, "dependencies", side_effect=AssertionError("resource query probed Ghidra")):
            result = self.run_resources("--type", "TXT")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["coverage"]["known_total"], 2)
        self.assertEqual([(row["relative_path"], row["resource_type"], row["size"], row["sha256"])
                          for row in result["data"]], [
            ("Contents/Resources/Greeting.txt", "txt", 5, hashlib.sha256(b"hello").hexdigest()),
            ("Contents/Resources/Note.TXT", "txt", 1, hashlib.sha256(b"!").hexdigest()),
        ])
        lines = [json.loads(line) for line in cli.render(result, "jsonl").splitlines()]
        self.assertEqual([line["data"] for line in lines], result["data"])
        self.assertTrue(all(line["command"] == "resources list" for line in lines))
        self.assertEqual(self.run_resources("--type", "missing")["data"], [])

    def test_resource_pages_bind_filter_and_inventory_and_protect_output(self):
        (self.assets / "Note.txt").write_bytes(b"text")
        (self.assets / "Unrelated.bin").write_bytes(b"unrelated")
        first = self.run_resources("--type", "txt", "--limit", "1")
        cursor = first["coverage"]["next_cursor"]
        self.assertIsNotNone(cursor)
        second = self.run_resources("--type", "TXT", "--cursor", cursor)
        self.assertEqual(second["data"][0]["relative_path"], "Contents/Resources/Note.txt")
        for query in [("--type", "bin"), ()]:
            with self.assertRaises(Error) as caught:
                self.run_resources(*query, "--cursor", cursor)
            self.assertEqual(caught.exception.code, "stale_cursor")
        self.asset.write_bytes(b"changed")
        with self.assertRaises(Error) as caught:
            self.run_resources("--type", "txt", "--cursor", cursor)
        self.assertEqual(caught.exception.code, "stale_cursor")
        with patch.object(bundle, "MAX_HASH_BYTES", 1):
            partial = self.run_resources("--type", "txt")
        self.assertEqual(partial["status"], "partial")
        self.assertEqual(partial["diagnostics"], ["hash_limit"])
        self.assertTrue(all(row["sha256"] is None for row in partial["data"]))
        with self.assertRaises(Error) as caught:
            self.run_resources("--output", str(self.asset), "--force")
        self.assertEqual(caught.exception.code, "output_input_conflict")
        self.assertEqual(self.asset.read_bytes(), b"changed")

    def test_resource_directory_starts_within_scope_and_binds_pages(self):
        calendar = self.assets / "Calendar"
        calendar.mkdir()
        (calendar / "A.strings").write_text("one")
        (calendar / "B.STRINGS").write_text("two")
        (calendar / "Screen.nib").write_bytes(b"nib")
        scoped = ("--under", "Contents/Resources/Calendar", "--type", "strings")
        with patch.object(bundle, "MAX_ENTRIES", 4):
            full = self.run_resources("--type", "strings")
            self.assertEqual((full["status"], full["data"], full["diagnostics"]), ("partial", [], ["entry_limit"]))
            first = self.run_resources(*scoped, "--limit", "1")
            cursor = first["coverage"]["next_cursor"]
            self.asset.write_bytes(b"unrelated edit outside the selected directory")
            second = self.run_resources(*scoped, "--cursor", cursor)
            self.assertEqual(second["coverage"]["known_total"], 2)
            self.assertEqual(second["status"], "complete")
            self.assertEqual([row["relative_path"] for row in first["data"] + second["data"]], [
                "Contents/Resources/Calendar/A.strings", "Contents/Resources/Calendar/B.STRINGS"])
            self.assertEqual(second["data"][0]["sha256"], hashlib.sha256(b"two").hexdigest())
            with self.assertRaises(Error) as caught:
                self.run_resources("--under", "Contents/Resources", "--type", "strings", "--cursor", cursor)
            self.assertEqual(caught.exception.code, "stale_cursor")
            (calendar / "A.strings").write_text("changed")
            with self.assertRaises(Error) as caught:
                self.run_resources(*scoped, "--cursor", cursor)
            self.assertEqual(caught.exception.code, "stale_cursor")
        with patch.object(bundle, "MAX_ENTRIES", 1):
            partial = self.run_resources(*scoped)
        self.assertEqual(partial["status"], "partial")
        self.assertIsNone(partial["coverage"]["known_total"])
        self.assertEqual(partial["coverage"]["truncation_reason"], "entry_limit")

    def test_resource_directory_rejects_nonphysical_and_noncanonical_paths(self):
        (self.contents / "Alias").symlink_to(self.assets, target_is_directory=True)
        for requested, code in (("", 2), ("/Contents/Resources", 2), ("Contents/../Resources", 2),
                                ("Contents/./Resources", 2), ("Contents/Resources/", 2),
                                ("Contents/Alias", 5), ("Contents/Resources/Greeting.txt", 5),
                                ("Contents/Missing", 5)):
            with self.subTest(requested=requested), self.assertRaises(Error) as caught:
                self.run_resources("--under", requested)
            self.assertEqual((caught.exception.code, caught.exception.exit_code), ("resource_directory", code))

    def test_resource_directory_replacement_keeps_inventory_partial(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "Private.txt").write_bytes(b"outside the bundle")
        real_scandir = os.scandir

        def replace_directory(directory):
            self.assets.rename(self.contents / "Moved")
            self.assets.symlink_to(outside, target_is_directory=True)
            return real_scandir(directory)

        with patch.object(bundle.os, "scandir", side_effect=replace_directory):
            result = self.run_resources("--under", "Contents/Resources")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["diagnostics"], ["bundle_changed"])
        self.assertEqual([row["relative_path"] for row in result["data"]], ["Contents/Resources/Greeting.txt"])

    def test_exact_resource_strings_has_digest_bound_pages_and_protects_files(self):
        resource = self.assets / "Week.strings"
        raw = b'"week"="Week"; "month"="Month";'
        resource.write_bytes(raw)
        words = ["resources", "strings", str(self.app), "--file", "Contents/Resources/Week.strings"]

        def run(*args):
            return cli.execute(cli.parser().parse_args([*words, *args]))

        with patch.object(engine, "dependencies", side_effect=AssertionError("localization query probed Ghidra")):
            first = run("--limit", "1")
            cursor = first["coverage"]["next_cursor"]
            self.assertIsNotNone(cursor)
            self.assertEqual(first["data"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(first["data"]["records"], [{"key": "month", "value": "Month"}])
            self.assertEqual(run("--cursor", cursor)["data"]["records"], [{"key": "week", "value": "Week"}])
            self.assertEqual(run("--key", "absent")["coverage"]["known_total"], 0)
        with self.assertRaises(Error) as caught:
            run("--key", "week", "--cursor", cursor)
        self.assertEqual(caught.exception.code, "stale_cursor")
        resource.write_bytes(raw + b'\n')
        with self.assertRaises(Error) as caught:
            run("--cursor", cursor)
        self.assertEqual(caught.exception.code, "stale_cursor")
        with self.assertRaises(Error) as caught:
            run("--force", "--output", str(resource))
        self.assertEqual(caught.exception.code, "output_input_conflict")
        self.assertEqual(resource.read_bytes(), raw + b'\n')
        outside = self.root / "Outside.strings"
        outside.write_bytes(raw)
        resource.unlink()
        resource.symlink_to(outside)
        with self.assertRaises(Error) as caught:
            run()
        self.assertEqual(caught.exception.code, "resource_file")

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

    def test_include_images_resolves_versioned_framework_links_inside_bundle(self):
        framework = self.contents / "Frameworks" / "Test.framework"
        real = framework / "Versions" / "A" / "Test"
        real.parent.mkdir(parents=True)
        real.write_bytes(image(cpu=X86_64, filetype=6))
        (framework / "Versions" / "Current").symlink_to("A")
        (framework / "Test").symlink_to("Versions/Current/Test")
        alias = "Contents/Frameworks/Test.framework/Test"
        selected = bundle.select_images(self.app, [alias])
        self.assertEqual([row[0] for row in selected], [self.main, real])
        self.assertEqual(selected[1][1], real.relative_to(self.app).as_posix())
        self.assertEqual(bundle.select_images(self.app, ["all"])[1][2],
                         hashlib.sha256(real.read_bytes()).hexdigest())

        project = Project.create(self.root / "project")
        args = cli.parser().parse_args(["import", str(self.app), "--project", str(project.path),
                                        "--include-images", alias, "--experimental-trusted-input"])

        def worker(workspace, imported, mode, options, dependencies, **request):
            self.assertEqual(mode, "import")
            job_id = imported["image_id"][:32]
            synthetic_program(workspace.path / "jobs" / job_id / "program")
            language, compiler = {"arm64": ("AARCH64:LE:64:AppleSilicon", "default"),
                                  "x86_64": ("x86:LE:64:default", "gcc")}[imported["arch"]]
            result = {"validation": {"headless_analysis_enabled": False},
                      "executable_format": "Mac OS X Mach-O", "language_id": language,
                      "compiler_spec_id": compiler, "executable_sha256": imported["sha256"]}
            return result, {"job_id": job_id, "status": "complete", "mode": mode,
                            "sandbox_sha256": engine.job_sandbox_sha256(workspace, dependencies, job_id)}

        with patch.object(engine, "dependencies", return_value={"ghidra_path": "/engine", "java_home": "/java"}), \
             patch.object(engine, "run", side_effect=worker) as run:
            imported = cli.execute(args)
            repeated = cli.execute(args)
        self.assertEqual(run.call_count, 2)
        self.assertEqual([row["arch"] for row in imported["data"]], ["arm64", "x86_64"])
        self.assertTrue(imported["data"][0]["bundle_image"]["main_executable"])
        self.assertEqual(imported["data"][1]["bundle_image"]["relative_path"], selected[1][1])
        self.assertEqual([row["status"] for row in repeated["data"]], ["already_imported"] * 2)

    def test_include_images_rejects_escaping_links_and_ambiguous_selection(self):
        (self.root / "outside").write_bytes(image())
        (self.assets / "escape").symlink_to("../../../outside")
        (self.assets / "cycle").symlink_to("cycle")
        for paths, code in (
            (["Contents/Resources/escape"], "bundle_link_escape"),
            (["Contents/Resources/cycle"], "bundle_link_limit"),
            (["../outside"], "bundle_image_path"),
            (["all", "Contents/MacOS/Fixture"], "bundle_image_selection"),
        ):
            with self.subTest(paths=paths), self.assertRaises(Error) as caught:
                bundle.select_images(self.app, paths)
            self.assertEqual(caught.exception.code, code)
