"""Synthetic chained pointer layouts and fail-closed decoding."""
import struct
import unittest
from unittest.mock import patch

from macscope import cli, dyld, engine, import_state, macho
from macscope.errors import Error
from test_core import TemporaryCase
from test_macho import command, image, universal


BASE = 0x100000000
PAYLOAD = 0x200
START = 0x100


def library_command():
    lib = struct.pack("<4I",24,0,0,0)+b"/usr/lib/libExample.dylib\0"
    return command(0xC,lib+bytes((-len(lib))%8))


def fixture(pointer_format=6, import_format=1, page_start=START, step=2, bind_ordinal=0):
    symbol = b"_imported\0"
    if import_format == 3:
        imports = struct.pack("<Qq",0xFFFF|1<<16,-3)
    elif import_format == 2:
        imports = struct.pack("<Ii",1,-3)
    else:
        imports = struct.pack("<I",1)
    table = 64
    header = struct.pack("<7I",0,32,table,table+len(imports),1,import_format,0)+bytes(4)
    starts = struct.pack("<2I",1,8)
    pages = struct.pack("<IHHQIHH",24,4096,pointer_format,0,0,1,page_start)
    payload = header+starts+pages+imports+symbol
    length = PAYLOAD+len(payload)
    segment = command(0x19,struct.pack("<16s4Q4I",b"__TEXT",BASE,4096,0,length,7,5,0,0))
    fixups = command(0x80000034,struct.pack("<2I",PAYLOAD,len(payload)))
    data = bytearray(image(commands=[segment,library_command(),fixups]))
    data.extend(bytes(PAYLOAD-len(data))+payload)
    target = BASE+0x80 if pointer_format==2 else 0x80
    struct.pack_into("<2Q",data,START,target|(step<<51),1<<63|4<<24|bind_ordinal)
    return bytes(data)


def arm64e_fixture(pointer_format=12, *, reserved=0, first=START):
    data = bytearray(fixture(pointer_format=pointer_format, page_start=first))
    struct.pack_into("<I", data, 8, 0x80000002)
    target = 0x80 if pointer_format != 1 else BASE + 0x80
    auth_rebase = (1 << 63) | (1 << 51) | (1 << 48) | (0x1357 << 32) | 0x80
    auth_bind = (3 << 62) | (1 << 51) | (2 << 49) | (1 << 48) | (0x2468 << 32) | reserved
    rebase = (1 << 51) | (0xAB << 43) | target
    bind = (1 << 62) | (0x7FFF8 << 32)
    struct.pack_into("<4Q", data, START, auth_rebase, auth_bind, rebase, bind)
    return bytes(data)


def legacy_fixture(*, rebase=b"", bind=b"", weak=b"", lazy=b""):
    parts = (rebase,bind,weak,lazy,b"")
    pairs = []
    offset = PAYLOAD
    for stream in parts:
        pairs.extend((offset if stream else 0,len(stream)))
        offset += len(stream)
    segment = command(0x19,struct.pack("<16s4Q4I",b"__TEXT",BASE,4096,0,offset,7,5,0,0))
    streams = command(0x80000022,struct.pack("<10I",*pairs))
    data = bytearray(image(commands=[segment,library_command(),streams]))
    data.extend(bytes(PAYLOAD-len(data))+b"".join(parts))
    struct.pack_into("<Q",data,START,BASE+0x80)
    return bytes(data)


class ChainedFixupsTests(unittest.TestCase):
    def decode(self, data):
        metadata = dict(macho.thin(data),offset="0x1000")
        return dyld.fixups(data,metadata)

    def test_known_pointer_and_import_formats(self):
        for pointer_format in (2,6):
            for import_format in (1,2,3):
                with self.subTest(pointer_format=pointer_format,import_format=import_format):
                    info,rows,gaps = self.decode(fixture(pointer_format,import_format))
                    rebase,bind = rows
                    self.assertFalse(gaps)
                    self.assertEqual(info["pointer_formats"],[pointer_format])
                    self.assertEqual(rebase["target_va"],hex(BASE+0x80))
                    self.assertEqual(rebase["container_file_offset"],"0x1100")
                    self.assertEqual(bind["symbol"],"_imported")
                    self.assertEqual(bind["library_ordinal"],-1 if import_format==3 else 1)
                    self.assertEqual(bind["import_addend"],0 if import_format==1 else -3)
                    self.assertEqual(bind["inline_addend"],4)
                    self.assertIsNone(bind["target_va"])

    def test_unsupported_format_and_fixup_limit_are_partial(self):
        info,rows,gaps = self.decode(fixture(pointer_format=7))
        self.assertEqual(info["pointer_formats"],[7])
        self.assertEqual(rows,[])
        self.assertEqual(gaps,["pointer_format_7"])
        with patch.object(dyld,"MAX_FIXUPS",1):
            _,rows,gaps = self.decode(fixture())
        self.assertEqual(len(rows),1)
        self.assertEqual(gaps,["fixup_limit"])

    def test_chain_cannot_escape_page_or_import_table(self):
        for data,code in ((fixture(step=4095),"macho_bounds"),
                          (fixture(bind_ordinal=1),"fixup_ordinal"),
                          (fixture(page_start=0x8000),"fixup_pages")):
            with self.subTest(code=code), self.assertRaises(Error) as caught:
                self.decode(data)
            self.assertEqual(caught.exception.code,code)


class Arm64eFixupsTests(TemporaryCase):
    def test_metadata_only_arch_and_supported_pointer_layouts(self):
        for pointer_format in (1, 9, 12):
            with self.subTest(pointer_format=pointer_format):
                binary = arm64e_fixture(pointer_format)
                image_data = dict(macho.thin(binary, allow_arm64e=True), offset="0x1000")
                self.assertEqual(image_data["arch"], "arm64e")
                info, rows, gaps = dyld.fixups(binary, image_data, parsed=image_data)
                self.assertEqual(info["pointer_formats"], [pointer_format])
                self.assertEqual(gaps, [])
                auth_rebase, auth_bind, rebase, bind = rows
                self.assertEqual([row["slice_file_offset"] for row in rows],
                                 ["0x100", "0x108", "0x110", "0x118"])
                self.assertEqual(auth_rebase["target_va"], hex(BASE+0x80))
                self.assertEqual(auth_rebase["authentication"],
                                 {"key":"IA", "address_diversity":True, "diversity":0x1357})
                self.assertEqual(auth_bind["authentication"],
                                 {"key":"DA", "address_diversity":True, "diversity":0x2468})
                self.assertEqual(auth_bind["inline_addend"], 0)
                self.assertEqual(rebase["target_va"], hex((0xAB << 56) | (BASE+0x80)))
                self.assertFalse(rebase["authenticated"])
                self.assertEqual(bind["inline_addend"], -8)
                self.assertIsNone(bind["target_va"])
                self.error("unsupported_arch", macho.thin, binary)

    def test_reserved_bits_and_misaligned_chain_refuse(self):
        for binary, code in (
            (arm64e_fixture(9, reserved=1<<16), "fixup_pointer"),
            (arm64e_fixture(12, reserved=1<<24), "fixup_pointer"),
            (arm64e_fixture(12, first=START+4), "fixup_pages"),
        ):
            with self.subTest(code=code):
                image_data = dict(macho.thin(binary, allow_arm64e=True), offset="0x0")
                self.error(code, dyld.fixups, binary, image_data, parsed=image_data)

    def test_direct_file_pagination_uses_exact_subtype_and_artifact(self):
        path = self.root / "owned-universal"
        path.write_bytes(universal(images=[image(), arm64e_fixture()]))
        args = ["fixups", "--input", str(path), "--json"]
        with patch.object(engine, "dependencies") as dependencies:
            self.error("arch_required", cli.execute, cli.parser().parse_args(args))
            first = cli.execute(cli.parser().parse_args([*args, "--arch", "arm64e", "--limit", "1"]))
            cursor = first["coverage"]["next_cursor"]
            self.assertIsNotNone(cursor)
            second = cli.execute(cli.parser().parse_args([*args, "--arch", "arm64e", "--cursor", cursor]))
            self.assertEqual(second["data"]["arch"], "arm64e")
            self.assertEqual(second["data"]["records"][0]["kind"], "bind")
            self.assertNotEqual(first["data"]["records"][0]["slice_file_offset"],
                                first["data"]["records"][0]["container_file_offset"])
            self.error("stale_cursor", cli.execute,
                       cli.parser().parse_args([*args, "--arch", "arm64", "--cursor", cursor]))
            dependencies.assert_not_called()

    def test_arm64e_metadata_recognition_does_not_enable_engine_import(self):
        path = self.root / "owned-arm64e"
        path.write_bytes(arm64e_fixture())
        result = cli.execute(cli.parser().parse_args(["inspect", str(path), "--json"]))
        self.assertEqual(result["data"]["slices"][0]["arch"], "arm64e")
        workspace = self.project()
        args = cli.parser().parse_args(["import", str(path), "--project", str(workspace.path),
                                       "--experimental-trusted-input", "--json"])
        with patch.object(engine, "dependencies", return_value={}), patch.object(engine, "run") as run:
            self.error("unsupported_arch", cli.execute, args)
            run.assert_not_called()
        self.assertEqual(workspace.images(), [])

    def test_supported_slice_request_survives_an_arm64e_sibling(self):
        workspace = self.project()
        path = self.root / "owned-mixed"
        raw = universal(images=[fixture(), arm64e_fixture()])
        path.write_bytes(raw)
        args = ["import", str(path), "--project", str(workspace.path), "--experimental-trusted-input", "--arch"]
        with patch.object(engine, "dependencies", return_value={}):
            self.error("unsupported_arch", cli.execute, cli.parser().parse_args([*args, "all"]))
            with patch.object(import_state, "import_slice", return_value="new-job") as worker:
                response = cli.execute(cli.parser().parse_args([*args, "arm64"]))
        self.assertEqual(response["data"][0]["arch"], "arm64")
        _, image_data, archive, _, _ = worker.call_args.args
        import_state.stage_inputs(workspace, image_data, archive)
        request = import_state.request_for(workspace, image_data)
        restored, original = import_state.restore_request(workspace, request, image_data["image_id"])
        self.assertEqual((restored, original), (image_data, raw))


class LegacyFixupsTests(unittest.TestCase):
    def decode(self, **streams):
        data = legacy_fixture(**streams)
        return dyld.fixups(data,{"offset":"0x1000"})

    def test_legacy_lazy_entries_reset_state_and_keep_distinct_rebase_evidence(self):
        rebase = bytes.fromhex("11 20 80 02 51 00")
        lazy = b"\x70\x80\x02\x11\x41_first\0\x60\x7d\x90\0"
        lazy += b"\x70\x88\x02\x3e\x40_second\0\x90\0"
        weak = b"\x70\x90\x02\x40_weak\0\x90\0"
        info,rows,gaps = self.decode(rebase=rebase,lazy=lazy,weak=weak)
        self.assertEqual(info["format"],"legacy")
        self.assertFalse(gaps)
        self.assertEqual([row["stream"] for row in rows],
                         ["rebase","weak_bind","lazy_bind","lazy_bind"])
        self.assertEqual(rows[0]["va"],rows[2]["va"])
        self.assertEqual(rows[0]["target_va"],hex(BASE+0x80))
        self.assertEqual(rows[1]["library_ordinal"],-3)
        self.assertEqual(rows[2]["import_addend"],-3)
        self.assertTrue(rows[2]["weak_import"])
        self.assertEqual(rows[3]["library_ordinal"],-2)
        self.assertEqual(rows[3]["import_addend"],0)

    def test_legacy_linker_backward_delta_is_bounded(self):
        # ld encodes a -24-byte ADD_ADDR delta using ten ULEB128 bytes.
        backward = bytes.fromhex("80 e8 ff ff ff ff ff ff ff ff 01")
        bind = b"\x11\x40_symbol\0\x70\x90\x02\x90"+backward+b"\x90\0"
        _,rows,gaps = self.decode(bind=bind)
        self.assertFalse(gaps)
        self.assertEqual([row["va"] for row in rows],[hex(BASE+0x110),hex(BASE+0x100)])
        with self.assertRaises(Error) as caught:
            self.decode(bind=b"\x70\0"+backward+b"\0")
        self.assertEqual(caught.exception.code,"legacy_fixup_stream")

    def test_unsupported_opcode_does_not_claim_coverage(self):
        _,rows,gaps = self.decode(bind=b"\xd0\0")
        self.assertEqual(rows,[])
        self.assertEqual(gaps,["bind_opcode_0xd0"])
