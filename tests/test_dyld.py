"""Synthetic chained pointer layouts and fail-closed decoding."""
import struct
import unittest
from unittest.mock import patch

from macscope import chained_layout, cli, dyld, dyld_legacy, engine, evidence, handoff_diff, import_state, macho, storage
from macscope.errors import Error
from test_core import TemporaryCase
from test_macho import X86_64, command, image, universal


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


class FixupHandoffTests(TemporaryCase):
    def test_import_pin_can_replay_an_exact_slot_and_compare_data_only_leads(self):
        project = self.project()
        binary = fixture()
        source = macho.inspect_bytes(binary)
        image = dict(source["slices"][0], artifact_sha256=source["artifact_sha256"],
                     input_name="owned", engine_baseline_sha256="b" * 64)
        import_state.stage_inputs(project, image, binary)
        with project.db(False) as db:
            db.execute("INSERT INTO images (id,arch,metadata,imported) VALUES (?,?,?,1)",
                       (image["image_id"], image["arch"], storage.canonical(image).decode()))
        pin = {"image_id":image["image_id"], "arch":image["arch"],
               "artifact_sha256":image["artifact_sha256"], "slice_sha256":image["sha256"],
               evidence.IMPORT_PIN:image["engine_baseline_sha256"]}
        lead = {"id":"selected_slot", "kind":"fixup", "value":hex(BASE + START), "image_id":image["image_id"]}
        absent = dict(lead, id="empty_slot", value=hex(BASE + START + 16))
        manifest = {"schema":evidence.LEADS_SCHEMA, "images":[pin], "leads":[lead, absent]}
        path = self.root / "leads.json"
        path.write_bytes(storage.canonical(manifest))
        args = cli.parser().parse_args(["evidence", "--project", str(project.path), "--leads", str(path)])
        with patch.object(engine, "dependencies", side_effect=AssertionError("unexpected engine probe")), \
             patch.object(dyld, "MAX_FIXUPS", 1):
            result = cli.execute(args)
        selected, empty = result["data"]["leads"]
        self.assertEqual(selected["status"], "resolved")
        self.assertIsNone(selected["function"])
        self.assertEqual(selected["fixup"]["records"][0]["target_va"], hex(BASE + 0x80))
        self.assertEqual(empty["reason"], "lead_not_found")
        self.assertEqual(result["status"], "partial")
        report = self.root / "evidence.json"
        report.write_bytes(storage.canonical(result))
        _, facts = handoff_diff.read_handoff(report, "LEFT")
        self.assertFalse(facts["selected_slot"]["has_function"])
        self.assertEqual(handoff_diff.compare_lead("selected_slot", facts["selected_slot"],
                                                   facts["selected_slot"])["status"], "unchanged_observations")
        self.assertEqual(facts["selected_slot"]["facets"]["fixup"]["coverage"], "complete")

        lead["query_job"] = "a" * 32
        self.error("evidence_lead", evidence.validate_manifest, manifest)


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

    def test_engine_admission_validates_even_an_unreferenced_import_name(self):
        for import_format in (1, 2, 3):
            with self.subTest(import_format=import_format):
                raw = bytearray(fixture(import_format=import_format, step=0))
                macho.thin(raw, for_engine=True)
                name_field = PAYLOAD + 64 + (4 if import_format == 3 else 0)
                struct.pack_into("<I", raw, name_field, 0xFFFFFFFF)
                data = bytes(raw)
                self.assertEqual(len(self.decode(data)[1]), 1)
                with self.assertRaises(Error) as caught:
                    macho.thin(data, for_engine=True)
                self.assertEqual(caught.exception.code, "fixup_symbol")

    def test_engine_admission_checks_header_spans_and_record_limits(self):
        for field, value, code in (
                (4, 24, "fixup_layout"), (8, 63, "macho_bounds"),
                (12, 0xFFFFFFFF, "fixup_layout"), (24, 1, "fixup_header_unsupported"),
                (36, 4, "fixup_segments"), (40, 30, "macho_bounds")):
            with self.subTest(field=field, code=code):
                raw = bytearray(fixture())
                struct.pack_into("<I", raw, PAYLOAD + field, value)
                macho.thin(raw)
                with self.assertRaises(Error) as caught:
                    macho.thin(raw, for_engine=True)
                self.assertEqual(caught.exception.code, code)
        for limit, code in (("MAX_CHAINED_IMPORTS", "fixup_import_limit"),
                            ("MAX_PAGE_RECORDS", "fixup_page_limit"),
                            ("MAX_ENGINE_SEGMENT_PAGES", "fixup_page_limit")):
            with self.subTest(limit=limit), patch.object(chained_layout, limit, 0), self.assertRaises(Error) as caught:
                macho.thin(fixture(), for_engine=True)
            self.assertEqual((caught.exception.code, caught.exception.exit_code), (code, 7))

    def test_chain_cannot_escape_page_or_import_table(self):
        for data,code in ((fixture(step=4095),"macho_bounds"),
                          (fixture(bind_ordinal=1),"fixup_ordinal"),
                          (fixture(page_start=0x8000),"fixup_pages")):
            with self.subTest(code=code), self.assertRaises(Error) as caught:
                self.decode(data)
            self.assertEqual(caught.exception.code,code)

    def test_engine_admission_walks_chains_without_inventory_truncation(self):
        valid = fixture()
        with patch.object(dyld, "MAX_FIXUPS", 1):
            self.assertEqual(self.decode(valid)[2], ["fixup_limit"])
            self.assertEqual(macho.thin(valid, for_engine=True), macho.thin(valid))
            with self.assertRaises(Error) as caught:
                macho.thin(fixture(bind_ordinal=1), for_engine=True)
            self.assertEqual(caught.exception.code, "fixup_ordinal")
        for raw, expected in (
                (fixture(step=4095), "macho_bounds"),
                (fixture(step=1), "fixup_pointer"),
                (fixture(page_start=0x8000), "fixup_pages"),
                (fixture(pointer_format=7), "fixup_pointer_unsupported")):
            with self.subTest(code=expected), self.assertRaises(Error) as caught:
                macho.thin(raw, for_engine=True)
            self.assertEqual(caught.exception.code, expected)
        with patch.object(dyld, "MAX_ENGINE_CHAINED_FIXUPS", 1), self.assertRaises(Error) as caught:
            macho.thin(valid, for_engine=True)
        self.assertEqual((caught.exception.code, caught.exception.exit_code), ("fixup_chain_limit", 7))

    def test_exact_chain_validates_its_page_beyond_the_inventory_cap(self):
        payload_offset = 0x2200
        table = 66
        header = struct.pack("<7I",0,32,table,table+4,1,1,0)+bytes(4)
        pages = struct.pack("<IHHQIHHH",26,4096,6,0,0,2,START,START)
        payload = header+struct.pack("<2I",1,8)+pages+struct.pack("<I",1)+b"_imported\0"
        length = payload_offset+len(payload)
        segment = command(0x19,struct.pack("<16s4Q4I",b"__TEXT",BASE,0x3000,0,length,7,5,0,0))
        fixups = command(0x80000034,struct.pack("<2I",payload_offset,len(payload)))
        data = bytearray(image(commands=[segment,library_command(),fixups]))
        data.extend(bytes(payload_offset-len(data))+payload)
        struct.pack_into("<Q",data,START,0x80)
        struct.pack_into("<2Q",data,0x1000+START,0x80 | 2<<51,1<<63)
        image_data = {"offset":"0x1000"}
        address = BASE+0x1000+START+8
        with patch.object(dyld,"MAX_FIXUPS",1), patch.object(dyld,"MAX_PAGE_RECORDS",1):
            _,inventory,gaps = dyld.fixups(bytes(data),image_data)
            self.assertEqual(len(inventory),1)
            self.assertEqual(gaps,["page_limit"])
            _,rows,gaps = dyld.fixups(bytes(data),image_data,address=address)
            self.assertEqual((len(rows),gaps),(1,[]))
            self.assertEqual(rows[0]["symbol"],"_imported")
            self.assertEqual(rows[0]["container_file_offset"],"0x2108")
        struct.pack_into("<Q",data,START,0x80 | 4095<<51)
        self.assertEqual(dyld.fixups(bytes(data),image_data,address=address)[1],rows)
        self.assertEqual(dyld.fixups(bytes(data),image_data,address=address+8)[1:],([],[]))
        struct.pack_into("<Q",data,0x1000+START+8,1<<63 | 1)
        with self.assertRaises(Error) as caught:
            dyld.fixups(bytes(data),image_data,address=address-8)
        self.assertEqual(caught.exception.code,"fixup_ordinal")


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

    def test_direct_file_exact_slot_has_slice_identity_and_typed_absence(self):
        path = self.root / "owned-arm64e"
        path.write_bytes(arm64e_fixture())
        args = ["fixups", "--input", str(path), "--address"]
        selected = cli.execute(cli.parser().parse_args([*args,hex(BASE+START+8)]))
        self.assertEqual(selected["data"]["records"][0]["kind"],"bind")
        self.assertEqual(selected["data"]["artifact_sha256"],selected["data"]["slice_sha256"])
        missing = cli.execute(cli.parser().parse_args([*args,hex(BASE+START+32)]))
        self.assertEqual((missing["status"],missing["data"]["records"]),("complete",[]))
        self.error("fixup_address_unmapped",cli.execute,cli.parser().parse_args([*args,"0x10"]))
        self.error("fixup_address_scope",cli.execute,
                   cli.parser().parse_args([*args,hex(BASE+START),"--kind","non-weak-definition"]))

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


class LegacyFixupsTests(TemporaryCase):
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

    def test_engine_validates_all_legacy_streams_before_admission(self):
        rebase = bytes.fromhex("11 20 80 02 51 00")
        bind = b"\x70\x80\x02\x11\x40_symbol\0\x90\0"
        complete = legacy_fixture(rebase=rebase, bind=bind, weak=b"\x48_override\0\0", lazy=bind)
        self.assertEqual(macho.thin(complete, for_engine=True), macho.thin(complete))
        for streams, expected in (
            ({"rebase": rebase[:-1] + b"\x60\x80"}, "legacy_fixup_stream"),
            ({"bind": bind[:-1] + b"\x60\x80"}, "legacy_fixup_stream"),
            ({"weak": b"\x48_unterminated"}, "legacy_fixup_stream"),
            ({"lazy": bind + b"\x70\x80"}, "legacy_fixup_stream"),
            ({"bind": b"\xd0\0"}, "legacy_fixup_unsupported"),
            ({"bind": bind.replace(b"\x11", b"\x3c")}, "fixup_ordinal"),
        ):
            with self.subTest(streams=streams):
                binary = legacy_fixture(**streams)
                macho.thin(binary)
                self.error(expected, macho.thin, binary, for_engine=True)
        with patch.object(dyld_legacy, "MAX_ENGINE_OPERATIONS", 3):
            self.error("legacy_fixup_limit", macho.thin, complete, for_engine=True)
        with patch.object(dyld_legacy, "MAX_STREAM_BYTES", 1):
            self.error("legacy_fixup_limit", macho.thin, complete, for_engine=True)

    def test_exact_legacy_retains_lazy_and_rebase_at_the_same_address(self):
        rebase = bytes.fromhex("11 20 80 02 51 00")
        lazy = b"\x70\x80\x02\x11\x40_symbol\0\x90\0"
        binary = legacy_fixture(rebase=rebase,lazy=lazy)
        metadata = {"offset":"0x0"}
        with patch.object(dyld,"MAX_FIXUPS",1):
            self.assertEqual(dyld.fixups(binary,metadata)[2],["fixup_limit"])
            _,rows,gaps = dyld.fixups(binary,metadata,address=BASE+START)
            self.assertEqual([row["stream"] for row in rows],["rebase","lazy_bind"])
            self.assertEqual(gaps,[])
        with patch.object(dyld,"MAX_LEGACY_LOOKUP_OPERATIONS",1):
            _,rows,gaps = dyld.fixups(binary,metadata,address=BASE+START)
            self.assertEqual(len(rows),1)
            self.assertEqual(gaps,["legacy_selection_scan_limit"])

    def test_weak_bind_declarations_use_opcode_offsets_and_a_separate_cursor(self):
        weak_bind = b"\x70\x80\x02\x40_coalesced\0\x90"
        weak = b"\x48_override\0" + weak_bind + b"\x48_second\0\0"
        path = self.root / "owned-universal"
        path.write_bytes(universal(images=[legacy_fixture(weak=weak), image(cpu=X86_64)]))
        args = ["fixups", "--input", str(path), "--arch", "arm64"]
        definitions = [*args, "--kind", "non-weak-definition", "--limit", "1"]
        first = cli.execute(cli.parser().parse_args(definitions))
        row, = first["data"]["records"]
        self.assertEqual(row, {
            "kind": "non_weak_definition", "stream": "weak_bind", "symbol": "_override",
            "symbol_flags": "0x8", "slice_file_offset": hex(PAYLOAD),
            "container_file_offset": hex(path.read_bytes().index(weak)),
        })
        cursor = first["coverage"]["next_cursor"]
        second = cli.execute(cli.parser().parse_args([*definitions, "--cursor", cursor]))
        self.assertEqual(second["data"]["records"][0]["symbol"], "_second")
        pointer_rows = cli.execute(cli.parser().parse_args(args))["data"]["records"]
        self.assertEqual([(row["kind"], row["symbol"]) for row in pointer_rows], [("bind", "_coalesced")])
        self.error("stale_cursor", cli.execute, cli.parser().parse_args([*args, "--cursor", cursor]))

    def test_weak_bind_declaration_scan_is_bounded_and_scope_specific(self):
        weak = b"\x70\x80\x02\x40_coalesced\0\xc0\x03\0\x48_override\0\0"
        data = legacy_fixture(weak=weak, bind=b"\xd0\0")
        with patch.object(dyld, "MAX_FIXUPS", 2):
            _, rows, gaps = dyld.fixups(data, {"offset": "0x0"}, weak_definitions=True)
        self.assertEqual((rows, gaps), ([], ["fixup_limit"]))
        _, rows, gaps = dyld.fixups(data, {"offset": "0x0"}, weak_definitions=True)
        self.assertEqual([row["symbol"] for row in rows], ["_override"])
        self.assertEqual(gaps, [])
        malformed = legacy_fixture(weak=b"\x48_unterminated")
        self.error("legacy_fixup_stream", dyld.fixups, malformed, {"offset": "0x0"}, weak_definitions=True)
