"""Data-only Mach-O preflight tests, independent of Ghidra and Xcode.

All binary fixtures are artificial byte strings. Nothing in this suite executes
an input binary. Run with ``PYTHONPATH=src python3 -m unittest discover -s tests``.
"""
import hashlib
import os
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from macscope import macho
from macscope.errors import Error


ARM64 = 0x0100000C
X86_64 = 0x01000007


def image(*, cpu=ARM64, subtype=None, filetype=2, commands=(), payload=b"",
          ncmds=None, cmdbytes=None, magic=0xFEEDFACF):
    if subtype is None:
        subtype = 0 if cpu == ARM64 else 3
    commands = tuple(commands)
    table = b"".join(commands)
    header = struct.pack("<8I", magic, cpu, subtype, filetype,
                         len(commands) if ncmds is None else ncmds,
                         len(table) if cmdbytes is None else cmdbytes, 0, 0)
    return header + table + payload


def command(kind, payload=b"", *, size=None):
    return struct.pack("<2I", kind, 8 + len(payload) if size is None else size) + payload


def entry_segment(name, va, file_offset, file_size, protections=5):
    return command(0x19, struct.pack("<16s4Q4I", name, va, 4096, file_offset,
                                     file_size, 7, protections, 0, 0))


def thread_state(flavor, count, pc_index, va):
    payload = bytearray(4 * count)
    struct.pack_into("<Q", payload, 8 * pc_index, va)
    return struct.pack("<II", flavor, count) + payload


def segment_image(*, file_offset=184, section_size=4, section_address=0x100000100,
                  section_flags=0, alignment=2, reloc_offset=0, reloc_count=0,
                  segment_address=0x100000000, segment_size=0x1000,
                  segment_file_offset=0, segment_file_size=188, nsects=1):
    section = struct.pack("<16s16s2Q8I", b"__text", b"__TEXT",
                          section_address, section_size, file_offset, alignment,
                          reloc_offset, reloc_count, section_flags, 0, 0, 0)
    segment = struct.pack("<16s4Q4I", b"__TEXT", segment_address,
                          segment_size, segment_file_offset, segment_file_size,
                          7, 5, nsects, 0)
    return image(commands=[command(0x19, segment + section)], payload=b"\x1f\x20\x03\xd5")


def universal(images=None, *, endian=">", fat64=False):
    if images is None:
        images = [image(cpu=ARM64), image(cpu=X86_64)]
    stride = 32 if fat64 else 20
    cursor = (8 + stride * len(images) + 7) & ~7
    records, slices = [], []
    for data in images:
        _, cpu, subtype = struct.unpack_from("<3I", data)
        fields = (cpu, subtype, cursor, len(data), 3)
        records.append(struct.pack(endian + ("IIQQII" if fat64 else "IIIII"),
                                   *(fields + (0,) if fat64 else fields)))
        slices.append((cursor, data))
        cursor = (cursor + len(data) + 7) & ~7
    result = bytearray(cursor)
    struct.pack_into(endian + "2I", result, 0, 0xCAFEBABF if fat64 else 0xCAFEBABE,
                     len(images))
    table = b"".join(records)
    result[8:8 + len(table)] = table
    for offset, data in slices:
        result[offset:offset + len(data)] = data
    return bytes(result)


def change32(data, offset, value, endian="<"):
    result = bytearray(data)
    struct.pack_into(endian + "I", result, offset, value)
    return bytes(result)


def change64(data, offset, value, endian=">"):
    result = bytearray(data)
    struct.pack_into(endian + "Q", result, offset, value)
    return bytes(result)


class ErrorAssertions(unittest.TestCase):
    def assert_error(self, code, function, *args, exit_code=None, **kwargs):
        with self.assertRaises(Error) as caught:
            function(*args, **kwargs)
        self.assertEqual(code, caught.exception.code)
        if exit_code is not None:
            self.assertEqual(exit_code, caught.exception.exit_code)
        self.assertTrue(str(caught.exception))
        return caught.exception


class ThinMachOTests(ErrorAssertions):
    def test_valid_arm64_and_x86_64_and_supported_filetypes(self):
        for cpu, arch in ((ARM64, "arm64"), (X86_64, "x86_64")):
            for kind in (2, 6, 8):
                with self.subTest(arch=arch, kind=kind):
                    data = image(cpu=cpu, filetype=kind)
                    result = macho.inspect_bytes(data)
                    self.assertEqual(1, len(result["slices"]))
                    item = result["slices"][0]
                    self.assertEqual(arch, item["arch"])
                    self.assertEqual(kind, item["file_type"])
                    self.assertEqual("0x0", item["offset"])
                    self.assertEqual(hex(len(data)), item["size"])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), result["artifact_sha256"])
                    self.assertEqual(result["artifact_sha256"], item["sha256"])
                    self.assertEqual(64, len(item["image_id"]))

    def test_deterministic_identity_changes_with_input_bytes(self):
        data = image(payload=b"a")
        first = macho.inspect_bytes(data)
        self.assertEqual(first, macho.inspect_bytes(data))
        other = macho.inspect_bytes(image(payload=b"b"))
        self.assertNotEqual(first["artifact_sha256"], other["artifact_sha256"])
        self.assertNotEqual(first["slices"][0]["image_id"], other["slices"][0]["image_id"])

    def test_truncated_headers_wrong_magic_and_32_bit_rejected(self):
        for data in (b"", b"\xcf\xfa\xed\xfe", image()[:31], b"not a Mach-O",
                     image(magic=0xFEEDFACE), image(magic=0xCFFAEDFE)):
            with self.subTest(data=data[:8]):
                self.assert_error("unsupported_format", macho.thin, data, exit_code=3)

    def test_unsupported_architectures_and_subtypes(self):
        for cpu, subtype in ((12, 0), (7, 3), (0x01000012, 0),
                             (ARM64, 2), (ARM64, 1), (X86_64, 8), (X86_64, 0)):
            with self.subTest(cpu=cpu, subtype=subtype):
                self.assert_error("unsupported_arch", macho.thin,
                                  image(cpu=cpu, subtype=subtype), exit_code=3)

    def test_cpu_subtype_capability_bits_preserved(self):
        for cpu, subtype in ((ARM64, 0x80000000), (X86_64, 0x80000003)):
            with self.subTest(cpu=cpu):
                self.assertEqual(subtype, macho.thin(image(cpu=cpu, subtype=subtype))["cpu_subtype"])

    def test_unsupported_filetypes(self):
        for kind in (0, 1, 3, 4, 5, 7, 9, 0xFFFFFFFF):
            with self.subTest(kind=kind):
                self.assert_error("unsupported_filetype", macho.thin,
                                  image(filetype=kind), exit_code=3)

    def test_command_count_and_total_size_bounds(self):
        cases = [
            (image(ncmds=macho.MAX_COMMANDS + 1, cmdbytes=(macho.MAX_COMMANDS + 1) * 8), "command_limit"),
            (image(ncmds=1, cmdbytes=0), "command_limit"),
            (image(cmdbytes=16 * 1024 * 1024 + 1), "command_limit"),
            (image(ncmds=1, cmdbytes=8), "macho_bounds"),
            (image(commands=[command(0x7777)], ncmds=0), "command_size"),
        ]
        for data, code in cases:
            with self.subTest(code=code, header=data[:32]):
                self.assert_error(code, macho.thin, data)

    def test_individual_command_sizes(self):
        for size in (0, 4, 7, 9, 12):
            with self.subTest(size=size):
                self.assert_error("command_size", macho.thin,
                                  image(commands=[command(0x7777, size=size)]))
        self.assert_error("macho_bounds", macho.thin,
                          image(commands=[command(0x7777, size=16)]))

    def test_unknown_commands_are_retained_as_evidence(self):
        result = macho.thin(image(commands=[command(0x12345678)]))
        self.assertEqual(["0x12345678"], result["load_commands"])

    def test_uuid_and_truncated_uuid(self):
        uuid = bytes(range(16))
        self.assertEqual(uuid.hex(), macho.thin(image(commands=[command(0x1B, uuid)]))["uuid"])
        self.assert_error("uuid_bounds", macho.thin, image(commands=[command(0x1B)]))

    def test_encryption_commands_reject_protected_data(self):
        for kind in (0x21, 0x2C):
            with self.subTest(kind=kind):
                encrypted = command(kind, struct.pack("<4I", 56, 4, 1, 0))
                with self.assertRaises(Error) as caught:
                    macho.thin(image(commands=[encrypted], payload=bytes(4)))
                self.assertEqual((caught.exception.code, caught.exception.exit_code), ("encrypted", 3))
                self.assertEqual(caught.exception.partial["encryption"]["cryptid"], 1)
                self.assertEqual(caught.exception.partial["encryption"]["slice_file_offset"], "0x38")
                plain = command(kind, struct.pack("<4I", 56, 4, 0, 0))
                binary = image(commands=[plain], payload=bytes(4))
                self.assertEqual([hex(kind)], macho.thin(binary)["load_commands"])
                fat = macho.inspect_bytes(universal([binary, image(cpu=X86_64)]))["slices"][0]
                declaration = fat["loader"]["encryption"]
                self.assertEqual(declaration["cryptid"], 0)
                self.assertEqual(int(declaration["container_file_offset"], 16), int(fat["offset"], 16)+56)
                self.assert_error("encryption_bounds", macho.thin, image(commands=[command(kind)]))
                invalid = command(kind, struct.pack("<4I", 10000, 1, 0, 0))
                self.assert_error("macho_bounds", macho.thin, image(commands=[invalid]))
                self.assert_error("encryption_bounds", macho.thin, image(commands=[plain, plain]))
        self.assert_error("encryption_bounds", macho.thin,
                          image(commands=[command(0x2c, bytes(24))]))

    def test_deployment_and_source_versions_preserve_multiple_declarations(self):
        modern = command(0x32, struct.pack("<8I", 1, 0x0d0203, 0x0f0000, 2, 3, 0x010203, 99, 0x020000))
        other = command(0x32, struct.pack("<4I", 99, 0x0e0000, 0, 0))
        legacy = command(0x25, struct.pack("<II", 0x0a0000, 0x0a0100))
        source = 1 << 40 | 2 << 30 | 3 << 20 | 4 << 10 | 5
        meta = macho.thin(image(commands=[modern, other, legacy, command(0x2a, struct.pack("<Q", source))]))
        first, second, third = meta["loader"]["deployment"]
        self.assertEqual((first["platform"], first["minimum_os"], first["sdk"]), ("macos", "13.2.3", "15.0.0"))
        self.assertEqual(first["tools"], [{"tool_id": 3, "name": "ld", "version": "1.2.3"},
                                          {"tool_id": 99, "name": None, "version": "2.0.0"}])
        self.assertIsNone(second["platform"])
        self.assertEqual(second["platform_id"], 99)
        self.assertEqual((third["command"], third["platform"], third["platform_id"]),
                         ("LC_VERSION_MIN_IPHONEOS", "ios", None))
        self.assertEqual(meta["loader"]["source_version"]["version"], "1.2.3.4.5")
        self.assertEqual(meta["loader"]["source_version"]["raw"], hex(source))

    def test_deployment_sizes_and_tool_limits_fail_with_typed_errors(self):
        for bad in (command(0x32), command(0x32, struct.pack("<4I", 1, 0, 0, 1)),
                    command(0x32, struct.pack("<4I", 1, 0, 0, 0) + bytes(8)), command(0x24)):
            self.assert_error("deployment_bounds", macho.thin, image(commands=[bad]))
        tool_count = 129
        many = command(0x32, struct.pack("<4I", 1, 0, 0, tool_count) + bytes(8 * tool_count))
        self.assert_error("deployment_limit", macho.thin, image(commands=[many]), exit_code=7)
        legacy = command(0x24, bytes(8))
        self.assert_error("deployment_limit", macho.thin, image(commands=[legacy] * 17), exit_code=7)
        source = command(0x2a, bytes(8))
        self.assert_error("source_version_bounds", macho.thin, image(commands=[source, source]))

    def test_valid_segment_and_section(self):
        result = macho.thin(segment_image())
        self.assertEqual([{"name": "__text", "segment": "__TEXT", "va": "0x100000100",
                           "size": "0x4", "file_offset": "0xb8", "protections": 5}], result["sections"])

    def test_loader_metadata_decodes_entry_function_starts_and_data_in_code(self):
        starts = b"\x20\x14\0\0"
        table = struct.pack("<IHH", 144, 4, 1)
        segment = command(0x19, struct.pack("<16s4Q4I", b"__TEXT", 0x100000000, 4096,
                                             0, 160+len(starts)+len(table), 7, 5, 0, 0))
        main = command(0x80000028, struct.pack("<2Q", 150, 0))
        fs = command(0x26, struct.pack("<2I", 160, len(starts)))
        dice = command(0x29, struct.pack("<2I", 160+len(starts), len(table)))
        data = image(commands=[segment,main,fs,dice],payload=starts+table)
        loader = macho.thin(data)["loader"]
        self.assertEqual(loader["entry_point"]["va"], "0x100000096")
        self.assertEqual(loader["function_starts"]["addresses"], ["0x100000020","0x100000034"])
        self.assertEqual(loader["data_in_code"]["records"],
                         [{"slice_file_offset":"0x90","length":4,"kind":"0x1"}])
        malformed = data[:160]+b"\x80"*4+data[164:]
        self.assertEqual(macho.thin(malformed)["loader"]["function_starts"]["status"], "malformed")
        self.assert_error("entry_command",macho.thin,image(commands=[main,main],payload=bytes(100)))

    def test_unixthread_uses_architecture_register_and_universal_offsets(self):
        base, offset = 0x100000000, 0x200
        text = entry_segment(b"__TEXT", base, 0, 1024)
        thins = []
        for cpu, flavor, count, index in ((ARM64, 6, 68, 32), (X86_64, 4, 42, 16)):
            state = thread_state(flavor, count, index, base + offset)
            data = image(cpu=cpu, commands=[text, command(5, state)], payload=bytes(1024))
            thins.append(data)
            entry = macho.thin(data)["loader"]["entry_point"]
            self.assertEqual((entry["source"], entry["status"], entry["va"], entry["rva"]),
                             ("LC_UNIXTHREAD", "complete", hex(base+offset), hex(offset)))
            self.assertEqual(entry["slice_file_offset"], hex(offset))
            state_at = int(entry["thread_states"][0]["pc_slice_file_offset"], 16)
            self.assertEqual(struct.unpack_from("<Q", data, state_at)[0], base + offset)
        for fat in (False, True):
            slices = macho.inspect_bytes(universal(thins, fat64=fat))["slices"]
            for row in slices:
                entry = row["loader"]["entry_point"]
                self.assertEqual(int(entry["container_file_offset"], 16), int(row["offset"], 16) + offset)

    def test_invalid_or_unsupported_unixthread_layouts(self):
        state = thread_state(6, 68, 32, 0x100000200)
        unix = command(5, state)
        main = command(0x80000028, struct.pack("<2Q", 0, 0))
        self.assert_error("entry_command", macho.thin, image(commands=[unix, main]))
        self.assert_error("entry_command", macho.thin, image(commands=[command(5, state * 2)]))
        for invalid in (b"", state[:-8], struct.pack("<4I", 6, 2, 0, 0)):
            self.assert_error("entry_thread_bounds", macho.thin, image(commands=[command(5, invalid)]))
        unknown = struct.pack("<4I", 99, 2, 0, 0)
        padded = command(5, state + struct.pack("<4I", 99, 1, 5, 0))
        parsed = macho.thin(image(commands=[padded]))["loader"]["entry_point"]
        self.assertEqual([record["word_count"] for record in parsed["thread_states"]], [68, 1])
        for binary in (image(commands=[command(5, unknown + state)]),
                       image(subtype=2, commands=[unix])):
            record = macho.thin(binary, allow_arm64e=True)["loader"]["entry_point"]
            self.assertEqual(record["status"], "unsupported")
            self.assertIsNone(record["va"])
        self.assertIsNone(macho.thin(image(commands=[command(4, state)]))["loader"]["entry_point"])

    def test_main_uses_virtual_base_and_requires_unique_executable_backing(self):
        base = 0x100000000
        text = entry_segment(b"__TEXT", base, 0, 256)
        main = command(0x80000028, struct.pack("<2Q", 0x4000, 0x1000))
        hot = entry_segment(b"__HOT", base + 0x4000, 256, 16)
        binary = image(commands=[text, hot, main], payload=bytes(128))
        entry = macho.thin(binary)["loader"]["entry_point"]
        self.assertEqual((entry["va"], entry["rva"], entry["slice_file_offset"], entry["stack_size"]),
                         ("0x100004000", "0x4000", "0x100", "0x1000"))
        for segments in ([text], [text, hot, hot],
                         [text, entry_segment(b"__HOT", base + 0x4000, 256, 16, 3)],
                         [text, entry_segment(b"__HOT", base + 0x4000, 256, 0)]):
            entry = macho.thin(image(commands=[*segments, main], payload=bytes(128)))["loader"]["entry_point"]
            self.assertEqual(entry["status"], "unavailable")
            self.assertIsNone(entry["slice_file_offset"])

    def test_library_and_rpath_strings_are_bounded_and_keep_new_dylib_flags(self):
        def string_command(kind, fixed, value):
            payload = fixed+value+b"\0"
            return command(kind,payload+bytes((-len(payload))%8))

        old = string_command(0xC,struct.pack("<4I",24,2,0x10203,0x10000),b"/usr/lib/libSystem.B.dylib")
        new = string_command(0xC,struct.pack("<5I",28,0x1A741800,0x10000,0,0x9),b"@rpath/libExample.dylib")
        rpath = string_command(0x8000001C,struct.pack("<I",12),b"@loader_path/Frameworks")
        loader = macho.thin(image(commands=[old,new,rpath]))["loader"]
        self.assertEqual(loader["dylibs"][0]["current_version"],"1.2.3")
        self.assertEqual(loader["dylibs"][1]["use_flags"],"0x9")
        self.assertIsNone(loader["dylibs"][1]["timestamp"])
        self.assertEqual(loader["rpaths"],["@loader_path/Frameworks"])
        for value in (command(0x8000001C,struct.pack("<I",4)+b"path"),
                      command(0x8000001C,struct.pack("<I",12)+b"path")):
            self.assert_error("command_string",macho.thin,image(commands=[value]))

    def test_dyld_extent_and_indirect_symbol_ranges_are_verified(self):
        dyld = command(0x80000022,struct.pack("<10I",160,3,0,0,0,0,0,0,0,0))
        fields = [0]*18
        fields[12:14] = [164,1]
        dysymtab = command(0xB,struct.pack("<18I",*fields))
        data = image(commands=[dyld,dysymtab],payload=b"\0"*8)
        loader = macho.thin(data)["loader"]
        self.assertEqual(loader["dyld_streams"][0]["slice_file_offset"],"0xa0")
        self.assertEqual(loader["indirect_symbol_table"]["count"],1)
        self.assert_error("macho_bounds",macho.thin,data[:-1])

    def test_zero_fill_sections_have_no_file_offset(self):
        for flags in (1, 0xC, 0x12):
            with self.subTest(flags=flags):
                data = segment_image(file_offset=0xFFFFFFFF, section_size=256, section_flags=flags)
                self.assertIsNone(macho.thin(data)["sections"][0]["file_offset"])

    def test_segment_header_file_range_and_section_table_bounds(self):
        self.assert_error("segment_bounds", macho.thin, image(commands=[command(0x19)]))
        cases = [
            ({"segment_file_offset": 190}, "macho_bounds"),
            ({"segment_file_size": 189}, "macho_bounds"),
            ({"nsects": 2}, "section_bounds"),
            ({"nsects": 4097}, "section_bounds"),
            ({"segment_address": 2**64 - 1}, "section_bounds"),
        ]
        for kwargs, code in cases:
            with self.subTest(**kwargs):
                self.assert_error(code, macho.thin, segment_image(**kwargs))

    def test_section_virtual_file_alignment_and_relocation_bounds(self):
        cases = [
            ({"file_offset": 187, "section_size": 4}, "macho_bounds"),
            ({"file_offset": 0xFFFFFFFF}, "macho_bounds"),
            ({"section_address": 0xFFFFFFFF}, "section_bounds"),
            ({"section_address": 0x100001000}, "section_bounds"),
            ({"section_address": 2**64 - 1}, "section_bounds"),
            ({"alignment": 64}, "section_bounds"),
            ({"reloc_offset": 187, "reloc_count": 1}, "macho_bounds"),
            ({"reloc_count": 0xFFFFFFFF}, "macho_bounds"),
        ]
        for kwargs, code in cases:
            with self.subTest(**kwargs):
                self.assert_error(code, macho.thin, segment_image(**kwargs))

    def test_symbol_and_string_table_bounds(self):
        valid = command(2, struct.pack("<4I", 56, 1, 72, 4))
        self.assertEqual(["0x2"], macho.thin(image(commands=[valid], payload=b"\0" * 20))["load_commands"])
        self.assert_error("symtab_bounds", macho.thin, image(commands=[command(2)]))
        empty = command(2, bytes(16))
        dysymtab = command(0xB, bytes(72))
        self.assert_error("symtab_bounds", macho.thin, image(commands=[empty, empty]))
        self.assert_error("dysymtab_bounds", macho.thin, image(commands=[dysymtab, dysymtab]))
        for fields in ((61, 1, 72, 4), (56, 0xFFFFFFFF, 72, 4),
                       (56, 1, 73, 4), (56, 1, 72, 0xFFFFFFFF)):
            with self.subTest(fields=fields):
                self.assert_error("macho_bounds", macho.thin,
                                  image(commands=[command(2, struct.pack("<4I", *fields))], payload=b"\0" * 20))

    def test_linkedit_bounds_for_all_recognized_commands(self):
        for kind in (0x1D, 0x26, 0x29, 0x80000033, 0x80000034):
            with self.subTest(kind=kind):
                valid = command(kind, struct.pack("<2I", 48, 4))
                self.assertEqual([hex(kind)], macho.thin(image(commands=[valid], payload=b"data"))["load_commands"])
                self.assert_error("linkedit_bounds", macho.thin, image(commands=[command(kind)]))
                invalid = command(kind, struct.pack("<2I", 49, 4))
                self.assert_error("macho_bounds", macho.thin, image(commands=[invalid], payload=b"data"))

    def test_bounded_arithmetic_and_exact_end(self):
        for off, size, total in ((-1, 0, 1), (0, -1, 1), (2, 0, 1),
                                 (1, 1, 1), (2**64 - 1, 2, 2**64)):
            with self.subTest(off=off, size=size, total=total):
                self.assert_error("macho_bounds", macho.bounded, off, size, total, "test")
        self.assertIsNone(macho.bounded(1, 0, 1, "empty at end"))
        self.assertIsNone(macho.bounded(0, 1, 1, "exact range"))

    def test_input_size_limit_without_large_allocation(self):
        data = image(payload=b"x")
        with patch.object(macho, "MAX_INPUT", 32):
            self.assert_error("input_limit", macho.inspect_bytes, data)


class UniversalMachOTests(ErrorAssertions):
    def test_fat_and_fat64_both_byte_orders(self):
        for fat64 in (False, True):
            for endian in (">", "<"):
                with self.subTest(fat64=fat64, endian=endian):
                    data = universal(fat64=fat64, endian=endian)
                    result = macho.inspect_bytes(data)
                    self.assertEqual(["arm64", "x86_64"], [s["arch"] for s in result["slices"]])
                    self.assertEqual(2, len({s["image_id"] for s in result["slices"]}))
                    for item in result["slices"]:
                        off, size = int(item["offset"], 16), int(item["size"], 16)
                        self.assertEqual(hashlib.sha256(data[off:off + size]).hexdigest(), item["sha256"])
                    self.assertEqual(result, macho.inspect_bytes(data))

    def test_truncated_fat_headers_and_tables(self):
        for magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf",
                      b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
            with self.subTest(magic=magic):
                self.assert_error("fat_header", macho.inspect_bytes, magic)
        for fat64 in (False, True):
            with self.subTest(fat64=fat64):
                self.assert_error("macho_bounds", macho.inspect_bytes, universal(fat64=fat64)[:12])

    def test_fat_slice_count_limits(self):
        for n in (0, 17, 0xFFFFFFFF):
            with self.subTest(n=n):
                self.assert_error("fat_limit", macho.inspect_bytes,
                                  change32(universal(), 4, n, ">"))

    def test_fat_invalid_ranges_and_alignment(self):
        data = universal()
        cases = [(16, 0, "fat_slice"), (16, 49, "fat_slice"),
                 (20, 0, "fat_slice"), (24, 31, "fat_slice"),
                 (16, 0xFFFFFFF8, "macho_bounds"), (20, 0xFFFFFFFF, "macho_bounds")]
        for offset, value, code in cases:
            with self.subTest(offset=offset, value=value):
                self.assert_error(code, macho.inspect_bytes, change32(data, offset, value, ">"))

    def test_fat64_invalid_ranges_alignment_and_reserved(self):
        data = universal(fat64=True)
        for changed in (change64(data, 16, 0), change64(data, 16, 73),
                        change64(data, 24, 0), change32(data, 32, 31, ">"),
                        change32(data, 36, 1, ">")):
            with self.subTest(header=changed[:40]):
                self.assert_error("fat_slice", macho.inspect_bytes, changed)
        for changed in (change64(data, 16, 2**64 - 8), change64(data, 24, 2**64 - 1)):
            self.assert_error("macho_bounds", macho.inspect_bytes, changed)

    def test_overlapping_slices_rejected_before_second_parse(self):
        for fat64 in (False, True):
            data = universal(fat64=fat64)
            first_offset = struct.unpack_from(">Q" if fat64 else ">I", data, 16)[0]
            changed = change64(data, 48, first_offset) if fat64 else change32(data, 36, first_offset, ">")
            with self.subTest(fat64=fat64):
                self.assert_error("fat_overlap", macho.inspect_bytes, changed)

    def test_fat_cpu_and_subtype_mismatch(self):
        for offset, value in ((8, X86_64), (12, 2)):
            with self.subTest(offset=offset):
                self.assert_error("fat_identity", macho.inspect_bytes,
                                  change32(universal(), offset, value, ">"))

    def test_duplicate_architecture_rejected(self):
        self.assert_error("fat_identity", macho.inspect_bytes,
                          universal([image(), image()]))

    def test_invalid_embedded_slice_is_not_accepted_as_container_metadata(self):
        data = bytearray(universal())
        off = struct.unpack_from(">I", data, 16)[0]
        data[off:off + 4] = b"nope"
        self.assert_error("unsupported_format", macho.inspect_bytes, bytes(data))

    def test_encrypted_embedded_slice_rejected(self):
        encrypted = image(commands=[command(0x2C, struct.pack("<4I", 0, 0, 1, 0))])
        self.assert_error("encrypted", macho.inspect_bytes,
                          universal([encrypted, image(cpu=X86_64)]), exit_code=3)


class PathAndBundleTests(ErrorAssertions):
    def setUp(self):
        # macOS often exposes /var and /tmp via symlinks. Use a canonical temp
        # parent because rejecting symlinks in *every* input component is policy.
        self.temp = tempfile.TemporaryDirectory(prefix="macscope-macho-test-",
                                                dir=Path(tempfile.gettempdir()).resolve())
        self.root = Path(self.temp.name).resolve()
        self.addCleanup(self.temp.cleanup)

    def make_bundle(self, *, name="Fixture.app", executable="Fixture", info=None):
        app = self.root / name
        (app / "Contents/MacOS").mkdir(parents=True)
        with (app / "Contents/Info.plist").open("wb") as stream:
            plistlib.dump({"CFBundleExecutable": executable} if info is None else info, stream)
        binary = app / "Contents/MacOS/Fixture"
        binary.write_bytes(image())
        return app, binary

    def test_excessive_binary_plist_nesting_is_typed(self):
        app, _ = self.make_bundle()
        depth = sys.getrecursionlimit() + 20
        # Each one-element array references the next object, ending at a null.
        objects = b"".join(b"\xa1" + struct.pack(">I", i + 1) for i in range(depth)) + b"\x00"
        offsets = struct.pack(f">{depth + 1}I", *(8 + 5 * i for i in range(depth + 1)))
        trailer = struct.pack(">6xBBQQQ", 4, 4, depth + 1, 0, 8 + len(objects))
        (app / "Contents/Info.plist").write_bytes(b"bplist00" + objects + offsets + trailer)
        self.assert_error("bundle_plist", macho.resolve_input, app)

    def test_xml_plist_stack_and_encoding_errors_are_typed(self):
        app, _ = self.make_bundle()
        for raw in (b'<?xml version="1.0"?><plist><key>name</key></plist>',
                    b'<?xml version="1.0" encoding="U2F-8"?><plist><dict/></plist>'):
            with self.subTest(raw=raw):
                (app / "Contents/Info.plist").write_bytes(raw)
                self.assert_error("bundle_plist", macho.resolve_input, app)

    def test_regular_file_read_and_inspect(self):
        path = self.root / "fixture"
        data = image(cpu=X86_64)
        path.write_bytes(data)
        self.assertEqual(data, macho.read_regular(path))
        result, read = macho.inspect_path(path)
        self.assertEqual(data, read)
        self.assertEqual("fixture", result["input_name"])
        self.assertEqual([], result["warnings"])
        self.assertEqual("x86_64", result["slices"][0]["arch"])

    def test_regular_read_limit_including_exact_limit(self):
        path = self.root / "bytes"
        path.write_bytes(b"1234")
        self.assertEqual(b"1234", macho.read_regular(path, 4))
        self.assert_error("input_limit", macho.read_regular, path, 3)

    def test_read_detects_file_change(self):
        path = self.root / "bytes"
        path.write_bytes(b"1234")
        original = os.fstat
        calls = 0

        def changed(fd):
            nonlocal calls
            value = original(fd)
            calls += 1
            if calls == 2:
                class Changed:
                    st_dev, st_ino, st_size = value.st_dev, value.st_ino, value.st_size
                    st_mtime_ns = value.st_mtime_ns + 1
                return Changed()
            return value

        with patch.object(macho.os, "fstat", side_effect=changed):
            self.assert_error("input_changed", macho.read_regular, path)

    def test_missing_path_and_directory_are_rejected(self):
        self.assert_error("path_unavailable", macho.checked_path, self.root / "missing")
        self.assert_error("file_type", macho.read_regular, self.root)
        path = self.root / "file"
        path.write_bytes(b"x")
        self.assert_error("file_type", macho.checked_path, path, directory=True)

    def test_excessive_path_rejected_before_filesystem_access(self):
        self.assert_error("path_limit", macho.checked_path, self.root / ("x" * 4097))

    def test_file_and_parent_symlinks_are_rejected(self):
        real = self.root / "real"
        real.mkdir()
        target = real / "fixture"
        target.write_bytes(image())
        linked_file = self.root / "linked-file"
        linked_file.symlink_to(target)
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(real, target_is_directory=True)
        self.assert_error("symlink", macho.read_regular, linked_file)
        self.assert_error("symlink", macho.read_regular, linked_parent / "fixture")

    def test_parent_symlink_swap_between_check_and_open_is_rejected(self):
        parent = self.root / "input-directory"
        outside = self.root / "outside-directory"
        parent.mkdir()
        outside.mkdir()
        (parent / "fixture").write_bytes(image())
        (outside / "fixture").write_bytes(b"must not read this")
        original_open = os.open
        swapped = False

        def swapping_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == parent.name and kwargs.get("dir_fd") is not None and not swapped:
                parent.rename(self.root / "saved-input-directory")
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_open(path, flags, *args, **kwargs)

        with patch.object(macho.os, "open", side_effect=swapping_open):
            self.assert_error("path_changed", macho.read_regular, parent / "fixture")
        self.assertTrue(swapped, "Test must exercise the race after the initial path checks")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation requires POSIX")
    def test_fifo_is_rejected_without_opening(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        with patch.object(macho.os, "open", side_effect=AssertionError("FIFO must never be opened")):
            self.assert_error("file_type", macho.read_regular, fifo)

    def test_valid_bundle_resolves_without_execution(self):
        app, binary = self.make_bundle()
        self.assertEqual(binary, macho.resolve_input(app))
        result, data = macho.inspect_path(app)
        self.assertEqual(image(), data)
        self.assertEqual("Fixture", result["input_name"])
        self.assertEqual([], result["warnings"])

    def test_bundle_suffix_is_case_insensitive(self):
        app, binary = self.make_bundle(name="Fixture.APP")
        self.assertEqual(binary, macho.resolve_input(app))

    def test_companion_debug_image_is_reported_not_imported(self):
        app, binary = self.make_bundle()
        companion = binary.with_name("Fixture.debug.dylib")
        companion.write_bytes(universal([image(filetype=6), image(cpu=X86_64, filetype=6)]))
        result, data = macho.inspect_path(app)
        self.assertEqual(image(), data)
        self.assertEqual(1, len(result["slices"]))
        self.assertTrue(any(".debug.dylib" in warning for warning in result["warnings"]))
        direct, _ = macho.inspect_path(companion)
        evidence = result["debug_companion"]
        self.assertEqual(evidence["relative_path"], "Contents/MacOS/Fixture.debug.dylib")
        self.assertEqual(evidence["status"], "verified")
        self.assertEqual(evidence["artifact_sha256"], direct["artifact_sha256"])
        self.assertEqual(evidence["slices"], [{key: row[key] for key in ("arch", "image_id", "sha256", "uuid")}
                                               for row in direct["slices"]])
        main_only, _ = macho.inspect_path(app, include_companion=False)
        self.assertNotIn("debug_companion", main_only)

    def test_companion_probe_reports_unavailable_without_following_a_link(self):
        app, binary = self.make_bundle()
        candidate = binary.with_name("Fixture.debug.dylib")
        external = self.root / "External.dylib"
        external.write_bytes(image(filetype=6))
        candidate.symlink_to(external)
        with patch.object(macho, "read_regular", wraps=macho.read_regular) as read:
            result, data = macho.inspect_path(app)
        self.assertEqual(data, image())
        self.assertEqual(result["debug_companion"]["error_code"], "symlink")
        self.assertEqual([call.args[0] for call in read.call_args_list], [app / "Contents/Info.plist", binary])
        candidate.unlink()
        candidate.write_bytes(image())
        result, _ = macho.inspect_path(app)
        self.assertEqual(result["debug_companion"]["error_code"], "debug_companion_filetype")

    def test_bundle_executable_traversal_and_invalid_names(self):
        app, _ = self.make_bundle()
        info = app / "Contents/Info.plist"
        for value in ("../outside", "/absolute", "nested/file", "nested\\file",
                      ".", "..", "", "nul\x00name", 123, ["Fixture"]):
            with self.subTest(value=value):
                info.write_bytes(plistlib.dumps({"CFBundleExecutable": value}, fmt=plistlib.FMT_BINARY))
                self.assert_error("bundle_executable", macho.resolve_input, app)

    def test_bundle_missing_key_and_nondictionary_plist(self):
        app, _ = self.make_bundle()
        for value in ({}, [], "Fixture"):
            with self.subTest(value=value):
                (app / "Contents/Info.plist").write_bytes(plistlib.dumps(value))
                self.assert_error("bundle_executable", macho.resolve_input, app)

    def test_bundle_invalid_and_oversized_plist(self):
        app, _ = self.make_bundle()
        info = app / "Contents/Info.plist"
        info.write_bytes(b"not a property list")
        self.assert_error("bundle_plist", macho.resolve_input, app)
        info.write_bytes(b"x" * 65)
        with patch.object(macho, "MAX_PLIST", 64):
            self.assert_error("input_limit", macho.resolve_input, app)

    def test_bundle_truncated_xml_plist_has_typed_error(self):
        app, _ = self.make_bundle()
        (app / "Contents/Info.plist").write_bytes(
            b'<?xml version="1.0"?><plist><dict><key>CFBundleExecutable</key>')
        self.assert_error("bundle_plist", macho.resolve_input, app)

    def test_bundle_missing_plist_and_executable(self):
        app, binary = self.make_bundle()
        binary.unlink()
        self.assert_error("path_unavailable", macho.resolve_input, app)
        (app / "Contents/Info.plist").unlink()
        self.assert_error("path_unavailable", macho.resolve_input, app)

    def test_bundle_executable_symlink_cannot_escape(self):
        app, binary = self.make_bundle()
        outside = self.root / "outside"
        outside.write_bytes(image())
        binary.unlink()
        binary.symlink_to(outside)
        self.assert_error("symlink", macho.resolve_input, app)

    def test_bundle_internal_symlink_is_also_rejected_by_mvp_policy(self):
        app, binary = self.make_bundle()
        other = binary.with_name("other")
        binary.rename(other)
        binary.symlink_to(other.name)
        self.assert_error("symlink", macho.resolve_input, app)

    def test_bundle_plist_symlink_and_bundle_symlink_rejected(self):
        app, _ = self.make_bundle()
        link = self.root / "Alias.app"
        link.symlink_to(app, target_is_directory=True)
        self.assert_error("symlink", macho.resolve_input, link)
        info = app / "Contents/Info.plist"
        outside = self.root / "outside.plist"
        info.rename(outside)
        info.symlink_to(outside)
        self.assert_error("symlink", macho.resolve_input, app)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation requires POSIX")
    def test_bundle_executable_fifo_rejected_without_opening(self):
        app, binary = self.make_bundle()
        binary.unlink()
        os.mkfifo(binary)
        self.assert_error("file_type", macho.resolve_input, app)


if __name__ == "__main__":
    unittest.main()
