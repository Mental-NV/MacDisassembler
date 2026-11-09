"""Objective-C declarations resolve through bounded file mappings."""
import struct
import unittest

from macscope import objc
from test_macho import command, image


BASE = 0x100000000


def fixture(*, relative=False, invalid_selector=False, other_flags=0):
    def section(name,offset):
        return struct.pack("<16s16s2Q8I",name,b"__TEXT",BASE+offset,8,offset,3,0,0,0,0,0,0)

    segment = struct.pack("<16s4Q4I",b"__TEXT",BASE,0x1000,0,0x800,7,5,2,0)
    segment += section(b"__objc_classlist",0x300)+section(b"__objc_selrefs",0x308)
    data = bytearray(image(commands=[command(0x19,segment)]))
    data.extend(bytes(0x800-len(data)))
    struct.pack_into("<2Q",data,0x300,BASE+0x400,BASE+(0x900 if invalid_selector else 0x520))
    struct.pack_into("<5Q",data,0x400,0,0,0,0,(BASE+0x440)|3)
    struct.pack_into("<4I3Q",data,0x440,0x80,8,24,0,0,BASE+0x500,BASE+0x480)
    if relative:
        struct.pack_into("<2I3i",data,0x480,0x8000000C|other_flags,1,
                         0x308-0x488,0x540-0x48C,0x600-0x490)
    else:
        struct.pack_into("<2I3Q",data,0x480,24|other_flags,1,BASE+0x520,BASE+0x540,BASE+0x600)
    data[0x500:0x50B] = b"OwnedProbe\0"
    data[0x520:0x526] = b"probe\0"
    data[0x540:0x548] = b"v16@0:8\0"
    return bytes(data)


class ObjCMetadataTests(unittest.TestCase):
    def inventory(self, scope, **kwargs):
        return objc.inventory(fixture(**kwargs),{"offset":"0x0"},scope)

    def test_absolute_and_relative_method_records(self):
        for relative in (False,True):
            classes,gaps = self.inventory("classes",relative=relative)
            self.assertFalse(gaps)
            self.assertEqual(classes[0]["name"],"OwnedProbe")
            self.assertEqual(classes[0]["instance_size"],24)
            methods,gaps = self.inventory("methods",relative=relative)
            self.assertFalse(gaps)
            self.assertEqual(methods[0]["implementation_va"],hex(BASE+0x600))
            self.assertEqual(methods[0]["type_encoding"],"v16@0:8")
            self.assertEqual(methods[0]["selector_reference_va"],hex(BASE+0x308) if relative else None)
            self.assertEqual(methods[0]["encoding"],"relative" if relative else "absolute")

    def test_selector_declaration_and_reference_are_separate(self):
        rows,gaps = self.inventory("selectors",relative=True)
        self.assertFalse(gaps)
        self.assertEqual({row["name"] for row in rows},{"probe"})
        self.assertEqual({row["origin"] for row in rows},{"method_declaration","selector_reference"})

    def test_invalid_selector_and_unsupported_format_keep_partial_coverage(self):
        self.assertEqual(self.inventory("methods",other_flags=0x10000),
                         ([],["unsupported_method_list_format"]))
        rows,gaps = self.inventory("selectors",relative=True,invalid_selector=True)
        self.assertFalse(rows)
        self.assertEqual(gaps,["invalid_method_record","unresolved_selector_reference"])
