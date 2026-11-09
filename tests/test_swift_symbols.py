"""Swift candidates retain Mach-O symbol identity and explicit demangler status."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from macscope import cli, swift_symbols
from macscope.errors import Error
from test_macho import command, image


def swift_fixture():
    names = b"\0_$s4Test5probeSiyF\0_plain\0_$sbad\0"
    defined = struct.pack("<IBBHQ",1,0xF,1,0,0x100000100)
    ordinary = struct.pack("<IBBHQ",names.index(b"_plain"),0xF,1,0,0x100000120)
    imported = struct.pack("<IBBHQ",names.index(b"_$sbad"),1,0,0,0)
    symbols = defined+ordinary+imported
    table = command(2,struct.pack("<4I",56,3,56+len(symbols),len(names)))
    return image(commands=[table],payload=symbols+names)


class SwiftEvidenceTests(unittest.TestCase):
    def test_candidates_keep_raw_names_and_undefined_status(self):
        info,rows,gaps = swift_symbols.symbols(swift_fixture())
        self.assertFalse(gaps)
        self.assertTrue(info["symbol_table_present"])
        self.assertEqual([row["mangled"] for row in rows],["_$s4Test5probeSiyF","_$sbad"])
        self.assertEqual(rows[0]["va"],"0x100000100")
        self.assertEqual(rows[1]["kind"],"undefined")
        self.assertIsNone(rows[1]["va"])
        self.assertEqual(rows[1]["demangle_status"],"not_requested")

    def test_native_demangler_requires_explicit_trust_and_rejects_symbolic_references(self):
        args = cli.parser().parse_args(["demangle","_$s4Test5probeSiyF"])
        with self.assertRaises(Error) as caught:
            cli.execute(args)
        self.assertEqual(caught.exception.code,"isolation_required")
        with patch.object(swift_symbols,"invoke") as run, self.assertRaises(Error):
            swift_symbols.demangle(["$sbad\x01"])
        run.assert_not_called()

    def test_demangler_preserves_unrecognized_names_and_tool_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory)/"swift-demangle"
            tool.write_bytes(b"fixture executable")
            with patch.object(swift_symbols,"invoke",
                              side_effect=[str(tool)+"\n","LLVM 21\n","Test.probe() -> Swift.Int\n$sbad\n"]) as run:
                rows,tool_info = swift_symbols.demangle(["_$s4Test5probeSiyF","_$sbad"])
        self.assertEqual(tool_info["tool"],"swift-demangle")
        self.assertEqual(len(tool_info["sha256"]),64)
        self.assertEqual(rows[0]["demangle_status"],"demangled")
        self.assertEqual(rows[1]["demangle_status"],"unrecognized")
        self.assertIsNone(rows[1]["demangled"])
        self.assertIn("(deny network*)",run.call_args.args[0][2])
        self.assertEqual(run.call_args.kwargs["stdin"],b"_$s4Test5probeSiyF\n_$sbad\n")
