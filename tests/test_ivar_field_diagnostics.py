"""Owned metadata only; stable field codes without untrusted contents."""
import struct
import unittest
from unittest.mock import patch
from macscope import objc
from test_objc import BASE, overlapping_zero_fill
from test_selected_ivars import fixture


class IvarFieldTests(unittest.TestCase):
    def query(self, data):
        diagnostics = []
        rows, gaps = objc.selected_ivars(bytes(data), {'offset':'0x0'}, BASE+0x300,
                                         diagnostics=diagnostics)
        return rows, gaps, diagnostics

    def assert_field(self, diagnostic, field, code, va=None):
        self.assertIn('field='+field+' ', diagnostic)
        self.assertIn('field_reason_code='+code+' ', diagnostic)
        self.assertIn('field_va='+('unknown' if va is None else hex(va))+' ', diagnostic)
        self.assertIn('field_mapping='+('unknown' if va is None else 'verified'), diagnostic)

    def test_independent_fields_preserve_later_rows(self):
        cases = (
            (0x610, 0, 'name_pointer', 'missing_name_pointer', BASE+0x610),
            (0x618, 0, 'type_pointer', 'missing_type_pointer', BASE+0x618),
            (0x610, BASE+0xDEAD, 'name_string', 'unmapped_bytes', None),
            (0x618, BASE+0xDEAD, 'type_encoding', 'unmapped_bytes', None),
        )
        for slot, target, field, code, va in cases:
            with self.subTest(field=field):
                data = fixture()
                struct.pack_into('<Q', data, slot, target)
                rows, gaps, diagnostics = self.query(data)
                self.assertEqual([r['name'] for r in rows], ['second'])
                self.assertIn('invalid_ivar_record', gaps)
                self.assert_field(diagnostics[0], field, code, va)

    def test_alignment_and_strings(self):
        data = fixture()
        struct.pack_into('<I', data, 0x620, 32)
        rows, _, diagnostics = self.query(data)
        self.assertEqual(len(rows), 1)
        self.assert_field(diagnostics[0], 'alignment', 'invalid_alignment', BASE+0x620)
        for slot, field in ((0x610, 'name_string'), (0x618, 'type_encoding')):
            data = fixture()
            struct.pack_into('<Q', data, slot, BASE+0x8FE)
            data[0x8FE:0x900] = b'xx'
            rows, _, diagnostics = self.query(data)
            self.assertEqual(len(rows), 1)
            self.assert_field(diagnostics[0], field, 'invalid_string')
            self.assertNotIn('xx', diagnostics[0])

    def test_record_mapping_never_invents_field_address(self):
        data = overlapping_zero_fill(bytes(fixture()), BASE+0x610)
        rows, _, diagnostics = self.query(data)
        self.assertEqual([r['name'] for r in rows], ['second'])
        self.assert_field(diagnostics[0], 'record', 'ambiguous_mapping')
        self.assertIn('record_va=unknown', diagnostics[0])

    def test_offset_storage_value_and_pointer_are_distinct(self):
        for target, value, field, code, va in (
                (0, 0, 'offset_pointer', 'missing_offset_pointer', BASE+0x608),
                (BASE+0xDEAD, 0, 'offset_storage', 'unmapped_bytes', None),
                (BASE+0x680, -1, 'offset_value', 'negative_offset', BASE+0x680)):
            data = fixture()
            struct.pack_into('<Q', data, 0x608, target)
            struct.pack_into('<i', data, 0x680, value)
            rows, _, diagnostics = self.query(data)
            self.assertEqual(len(rows), 2)
            self.assertIsNone(rows[0]['declared_offset_bytes'])
            self.assert_field(diagnostics[0], field, code, va)
            self.assertEqual(rows[0]['offset_evidence']['field'], field)

    def test_external_and_budget_pointer_failures(self):
        original = objc.ObjCImage.target
        for reason, code in (('external_class_pointer', 'external_binding'),
                             ('selected_pointer_limit', 'selected_pointer_limit')):
            def target(instance, site):
                if site == BASE+0x610:
                    raise objc.ResolutionFailure(reason, 'Do not expose this message')
                return original(instance, site)
            with patch.object(objc.ObjCImage, 'target', target):
                rows, _, diagnostics = self.query(fixture())
            self.assertEqual(len(rows), 1)
            self.assert_field(diagnostics[0], 'name_pointer', code, BASE+0x610)
            self.assertNotIn('Do not expose', diagnostics[0])

    def test_caps_and_repeat_queries(self):
        data = fixture()
        struct.pack_into('<I', data, 0x604, 0xffffffff)
        with patch.object(objc, 'MAX_IVARS', 6), patch.object(objc, 'MAX_IVAR_DIAGNOSTICS', 1):
            first = self.query(data)
            self.assertEqual(first, self.query(data))
        self.assertEqual(len(first[2]), 3)
        self.assertIn('declared_unvisited_count=4294967289', first[2][1])
        self.assertIn('omitted: 4 events', first[2][2])

    def test_ambiguous_offset_and_real_pointer_budget(self):
        rows, _, diagnostics = self.query(overlapping_zero_fill(bytes(fixture()), BASE+0x680))
        self.assertEqual(len(rows), 2)
        self.assertIsNone(rows[0]['declared_offset_bytes'])
        self.assert_field(diagnostics[0], 'offset_storage', 'ambiguous_mapping')
        with patch.object(objc, 'MAX_SELECTED_POINTERS', 8):
            rows, gaps, diagnostics = self.query(fixture())
        self.assertIn('selected_pointer_limit', gaps)
        matching = [d for d in diagnostics if 'field_reason_code=selected_pointer_limit' in d]
        self.assertTrue(matching)
        self.assertTrue(all('field_mapping=verified' in d for d in matching))
