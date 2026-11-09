"""Modern and legacy export evidence with bounded malformed-input handling."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from macscope import cli, export_trie, macho
from macscope.errors import Error
from macscope.storage import Project, atomic, canonical
from test_dyld import library_command
from test_macho import command, image


BASE = 0x100000000
OFFSET = 0x200


def leaf_trie(entries):
    root = bytearray([0, len(entries)])
    nodes = bytearray()
    next_node = 2 + sum(len(name) + 2 for name, _ in entries)
    for name, payload in entries:
        root.extend(name + b"\0" + bytes([next_node]))
        node = bytes([len(payload)]) + payload + b"\0"
        nodes.extend(node)
        next_node += len(node)
    return bytes(root + nodes)


def fixture(trie, *, legacy=False, modern=True, conflicting=False):
    segment = command(0x19, struct.pack("<16s4Q4I", b"__TEXT", BASE, 4096, 0,
                                        OFFSET + len(trie), 7, 5, 0, 0))
    commands = [segment, library_command()]
    if modern:
        commands.append(command(0x80000033, struct.pack("<2I", OFFSET, len(trie))))
    if legacy:
        legacy_offset = OFFSET - int(conflicting)
        commands.append(command(0x80000022, struct.pack("<10I", *([0] * 8), legacy_offset, len(trie))))
    data = image(commands=commands)
    return data.ljust(OFFSET, b"\0") + trie


class ExportTrieTests(unittest.TestCase):
    def decode(self, data):
        return export_trie.exports(data, {"offset": "0x4000"})

    def test_terminal_kinds_and_mirrored_commands(self):
        trie = leaf_trie([
            (b"a", b"\x04\x28"), (b"b", b"\x01\x30"), (b"c", b"\x02\x12"),
            (b"d", b"\x08\x01\0"), (b"e", b"\x0c\x01_other\0"), (b"f", b"\x10\x40\x44"),
        ])
        extent, rows, gaps = self.decode(fixture(trie, legacy=True))
        self.assertEqual(extent["sources"], ["LC_DYLD_EXPORTS_TRIE", "dyld_info"])
        self.assertEqual(gaps, [])
        regular, tls, absolute, same, renamed, resolver = rows
        self.assertTrue(regular["weak_definition"])
        self.assertEqual(regular["va"], hex(BASE + 0x28))
        self.assertEqual(int(regular["container_file_offset"], 16) -
                         int(regular["slice_file_offset"], 16), 0x4000)
        self.assertEqual(tls["kind"], "thread_local")
        self.assertEqual(absolute["absolute_value"], "0x12")
        self.assertIsNone(absolute["va"])
        self.assertEqual(same["import_name"], "d")
        self.assertEqual(renamed["import_name"], "_other")
        self.assertEqual(renamed["library_path"], "/usr/lib/libExample.dylib")
        self.assertIsNone(renamed["va"])
        self.assertEqual(resolver["va"], hex(BASE + 0x40))
        self.assertEqual(resolver["resolver_va"], hex(BASE + 0x44))

    def test_prefix_terminal_child_and_shared_node(self):
        # Nodes start at 0, 8 and 15. Root "b" shares the terminal for "ax".
        trie = b"\0\x02a\0\x08b\0\x0f\x02\0\x20\x01x\0\x0f\x02\0\x28\0"
        extent, rows, gaps = self.decode(fixture(trie, legacy=True, modern=False))
        self.assertEqual(extent["sources"], ["dyld_info"])
        self.assertEqual([row["name"] for row in rows], ["a", "ax", "b"])
        self.assertEqual(gaps, [])

    def test_unsupported_terminals_and_walk_limit_report_partial(self):
        trie = leaf_trie([(b"a", b"\x20\x02"), (b"b", b"\0\x28")])
        _, rows, gaps = self.decode(fixture(trie))
        self.assertEqual([row["kind"] for row in rows], ["unsupported", "regular"])
        self.assertEqual(gaps, ["export_trie_unsupported_flags"])
        with patch.object(export_trie, "MAX_NODES", 2):
            _, rows, gaps = self.decode(fixture(trie))
        self.assertEqual([row["name"] for row in rows], ["a"])
        self.assertIn("export_trie_node_limit", gaps)

    def test_invalid_structures_produce_typed_error(self):
        for trie in (
            b"\xff", b"\0\x01name", b"\0\x01a\0\x08",
            b"\0\x01a\0\x05\0\x01b\0\x05",  # Back-edge to a non-root ancestor.
            b"\0\x01a\0\x01",  # Child points into the root node.
            leaf_trie([(b"a", b"\x08\x02\0")]),  # Library ordinal exceeds dependency count.
            leaf_trie([(b"a", b"\x00\x28\x01")]),  # Trailing terminal payload.
        ):
            with self.subTest(trie=trie), self.assertRaises(Error) as error:
                self.decode(fixture(trie))
            self.assertEqual(error.exception.code, "export_trie_malformed")
        with self.assertRaises(Error) as error:
            self.decode(fixture(leaf_trie([(b"a", b"\0\x28")]), legacy=True, conflicting=True))
        self.assertEqual(error.exception.code, "export_trie_extent")

    def test_cli_reads_before_analysis_and_binds_cursor_to_filters(self):
        data = fixture(leaf_trie([(b"alpha", b"\x00\x28"), (b"beta", b"\x00\x30")]))
        with tempfile.TemporaryDirectory() as directory:
            project = Project.create(Path(directory).resolve() / "project")
            record = macho.inspect_bytes(data)["slices"][0]
            image_id = record["image_id"]
            atomic(project.path / "inputs" / (image_id + ".macho"), data, mode=0o400)
            with project.db(False) as db:
                db.execute("INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)",
                           (image_id, record["arch"], canonical(record).decode()))

            def query(*flags):
                args = cli.parser().parse_args(["exports", "--source", "dyld", "--project",
                                                str(project.path), "--limit", "1", *flags])
                return cli.execute(args)

            first = query()
            cursor = first["coverage"]["next_cursor"]
            self.assertIsNone(first["analysis_id"])
            self.assertEqual(first["data"]["records"][0]["name"], "alpha")
            self.assertEqual(query("--cursor", cursor)["data"]["records"][0]["name"], "beta")
            with self.assertRaises(Error) as error:
                query("--cursor", cursor, "--name-contains", "beta")
            self.assertEqual(error.exception.code, "stale_cursor")
