"""Synthetic chained pointer layouts and fail-closed decoding."""
import struct
import unittest
from unittest.mock import patch

from macscope import dyld, macho
from macscope.errors import Error
from test_macho import command, image


BASE = 0x100000000
PAYLOAD = 0x200
START = 0x100


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
    lib = struct.pack("<4I",24,0,0,0)+b"/usr/lib/libExample.dylib\0"
    lib = command(0xC,lib+bytes((-len(lib))%8))
    fixups = command(0x80000034,struct.pack("<2I",PAYLOAD,len(payload)))
    data = bytearray(image(commands=[segment,lib,fixups]))
    data.extend(bytes(PAYLOAD-len(data))+payload)
    target = BASE+0x80 if pointer_format==2 else 0x80
    struct.pack_into("<2Q",data,START,target|(step<<51),1<<63|4<<24|bind_ordinal)
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
        info,rows,gaps = self.decode(fixture(pointer_format=1))
        self.assertEqual(info["pointer_formats"],[1])
        self.assertEqual(rows,[])
        self.assertEqual(gaps,["pointer_format_1"])
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
