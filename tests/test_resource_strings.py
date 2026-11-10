import codecs
import plistlib
import struct
import unittest
from unittest.mock import patch

from macscope import resource_strings
from macscope.errors import Error


class ResourceStringsTests(unittest.TestCase):
    def test_text_and_flat_plists_preserve_the_same_unicode_values(self):
        text = r'''/* comment */ {"Week" = "Semaine"; empty = ""; // end of line
                    "Icon" = "\UD83D\UDE00\t\042"; identity; }'''
        expected = {"Week": "Semaine", "empty": "", "Icon": '😀\t"', "identity": "identity"}
        encodings = ((codecs.BOM_UTF8, "utf-8"), (codecs.BOM_UTF16_LE, "utf-16-le"),
                     (codecs.BOM_UTF16_BE, "utf-16-be"))
        for bom, encoding in encodings:
            self.assertEqual(resource_strings.parse(bom + text.encode(encoding)),
                             (expected, "openstep-strings", encoding))
        for fmt, name, encoding in ((plistlib.FMT_XML, "xml-plist", "utf-8"),
                                    (plistlib.FMT_BINARY, "binary-plist", None)):
            self.assertEqual(resource_strings.parse(plistlib.dumps(expected, fmt=fmt)), (expected, name, encoding))
        xml = b'<plist><dict><key>tag</key><string><![CDATA[<!ENTITY example>]]></string></dict></plist>'
        self.assertEqual(resource_strings.parse(xml)[0], {"tag": "<!ENTITY example>"})
        unicode_xml = '<?xml version="1.0" encoding="UTF-16"?>' + xml.decode()
        self.assertEqual(resource_strings.parse(codecs.BOM_UTF16_BE + unicode_xml.encode("utf-16-be"))[0],
                         {"tag": "<!ENTITY example>"})

    def test_duplicate_keys_and_nonflat_tables_fail_closed(self):
        xml_duplicate = b'<plist><dict><key>same</key><string>a</string><key>same</key><string>b</string></dict></plist>'
        binary_duplicate = plistlib.dumps({"x": "a", "y": "b"}, fmt=plistlib.FMT_BINARY).replace(b'\x51y', b'\x51x')
        for raw in (b'"same"="a"; same="b";', xml_duplicate, binary_duplicate):
            with self.subTest(raw=raw), self.assertRaises(Error) as caught:
                resource_strings.parse(raw)
            self.assertEqual(caught.exception.code, "resource_strings_duplicate")
        for raw in (b'"missing terminator" = "value"', b'"surrogate" = "\\UD800";',
                    b'<!DOCTYPE plist [<!ENTITY x "custom">]><plist><dict/></plist>',
                    b'<?xml version="1.0" encoding="ISO-8859-1"?><plist><dict/></plist>',
                    plistlib.dumps({"nested": ["string"]}),
                    plistlib.dumps({"nested": ["string"]}, fmt=plistlib.FMT_BINARY)):
            with self.subTest(raw=raw), self.assertRaises(Error) as caught:
                resource_strings.parse(raw)
            self.assertEqual(caught.exception.code, "resource_strings_invalid")

    def test_binary_offsets_and_expanded_values_stay_bounded(self):
        raw = bytearray(plistlib.dumps({"A": "aa", "B": "bb"}, fmt=plistlib.FMT_BINARY))
        offset_width, _, _, _, table = struct.unpack(">6xBBQQQ", raw[-32:])
        raw[table:table + offset_width] = raw[table + offset_width:table + 2 * offset_width]
        with self.assertRaises(Error) as caught:
            resource_strings.parse(raw)
        self.assertEqual(caught.exception.code, "resource_strings_invalid")
        raw = plistlib.dumps({"A": "abcde", "B": "abcde"}, fmt=plistlib.FMT_BINARY)
        with patch.object(resource_strings, "MAX_CHARACTERS", 10), self.assertRaises(Error) as caught:
            resource_strings.parse(raw)
        self.assertEqual(caught.exception.code, "resource_strings_limit")
