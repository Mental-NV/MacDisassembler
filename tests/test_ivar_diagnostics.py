"""Owned metadata checks for bounded diagnostics, without native execution."""
import struct
import unittest
from unittest.mock import patch
from macscope import objc
from test_objc import BASE, overlapping_zero_fill
from test_selected_ivars import fixture


class IvarDiagnosticTests(unittest.TestCase):
    def query(self, data):
        diagnostics = []
        rows, gaps = objc.selected_ivars(bytes(data), {'offset':'0x0'}, BASE+0x300,
                                         diagnostics=diagnostics)
        return rows, gaps, diagnostics

    def test_offset_codes_preserve_zero_and_unknown(self):
        for pointer, value, reason in (
                (0, 0, 'missing_offset_pointer'),
                (BASE+0xDEAD, 0, 'unmapped_bytes'),
                (BASE+0x680, -1, 'negative_offset')):
            data = fixture()
            struct.pack_into('<Q', data, 0x608, pointer)
            struct.pack_into('<i', data, 0x680, value)
            rows, gaps, diagnostics = self.query(data)
            self.assertIsNone(rows[0]['declared_offset_bytes'])
            self.assertEqual(rows[0]['offset_evidence']['reason_code'], reason)
            self.assertIn(reason, diagnostics[0])
            self.assertIn('index=0 record_va='+hex(BASE+0x608), diagnostics[0])
            self.assertEqual(len(rows), 2)
        rows, _, diagnostics = self.query(fixture())
        self.assertEqual(rows[0]['declared_offset_bytes'], 0)
        self.assertEqual(diagnostics, [])

    def test_invalid_record_and_unmapped_tail_keep_prefix(self):
        data = fixture()
        struct.pack_into('<I', data, 0x628+24, 32)
        rows, _, diagnostics = self.query(data)
        self.assertEqual([r['name'] for r in rows], ['first'])
        self.assertIn('invalid_record', diagnostics[0])
        self.assertIn('index=1 record_va='+hex(BASE+0x628), diagnostics[0])
        data = fixture()
        struct.pack_into('<I', data, 0x604, 100)
        rows, _, diagnostics = self.query(data)
        self.assertEqual(rows[0]['name'], 'first')
        self.assertTrue(any('unmapped_bytes' in d and 'record_va=unknown' in d for d in diagnostics))

    def test_layout_budget_and_diagnostic_cap(self):
        data = fixture()
        struct.pack_into('<I', data, 0x600, 16)
        rows, gaps, diagnostics = self.query(data)
        self.assertFalse(rows)
        self.assertIn('unsupported_layout', diagnostics[0])
        self.assertIn('index=unknown record_va=unknown', diagnostics[0])
        data = fixture()
        struct.pack_into('<I', data, 0x604, 0xffffffff)
        with patch.object(objc, 'MAX_IVARS', 4), patch.object(objc, 'MAX_IVAR_DIAGNOSTICS', 1):
            rows, gaps, diagnostics = self.query(data)
        self.assertEqual(len(diagnostics), 3)
        self.assertIn("declared_unvisited_count=4294967291", diagnostics[-2])
        self.assertIn('omitted: 2 events', diagnostics[-1])
        with patch.object(objc, 'MAX_IVARS', 1):
            rows, gaps, diagnostics = self.query(data)
        self.assertEqual(len(rows), 1)
        self.assertIn('declared_unvisited_count=4294967294', diagnostics[0])
        self.assertIn('record_va=unknown', diagnostics[0])

    def test_pointer_failure_retains_precise_reason(self):
        original = objc.ObjCImage.target
        def target(instance, site):
            if site == BASE+0x628+8:
                raise objc.ResolutionFailure('external_class_pointer', 'External pointer')
            return original(instance, site)
        with patch.object(objc.ObjCImage, 'target', target):
            rows, gaps, diagnostics = self.query(fixture())
        self.assertEqual(len(rows), 1)
        self.assertIn('external_binding', diagnostics[0])
        self.assertIn('invalid_ivar_record', gaps)

    def test_pointer_budget_is_not_invalid_metadata(self):
        with patch.object(objc, 'MAX_SELECTED_POINTERS', 8):
            rows, gaps, diagnostics = self.query(fixture())
        self.assertTrue(any('selected_pointer_limit' in d for d in diagnostics))
        self.assertIn('selected_pointer_limit', gaps)

    def test_repeat_query_deterministic(self):
        data = fixture()
        struct.pack_into('<Q', data, 0x608, 0)
        self.assertEqual(self.query(data), self.query(data))

    def test_ambiguous_record_has_no_verified_address(self):
        rows, gaps, diagnostics = self.query(overlapping_zero_fill(bytes(fixture()), BASE+0x62F))
        self.assertEqual(len(rows), 1)
        self.assertIn('ambiguous_mapping', diagnostics[0])
        self.assertIn('record_va=unknown', diagnostics[0])
        self.assertIn('class_va='+hex(BASE+0x340), diagnostics[0])

    def test_external_offset_is_separate_from_missing_offset(self):
        original = objc.ObjCImage.relocation
        def external(instance, site):
            if site == BASE+0x608:
                return {'kind':'bind','symbol':'_owned_offset','library':'owned'}
            return original(instance, site)
        with patch.object(objc.ObjCImage, 'relocation', external):
            rows, gaps, diagnostics = self.query(fixture())
        self.assertIsNone(rows[0]['declared_offset_bytes'])
        self.assertEqual(rows[0]['offset_evidence']['reason_code'], 'external_binding')
        self.assertIn('external_binding', diagnostics[0])
