"""Owned static ivar evidence, never native execution or third-party inputs."""
import json
import struct
from unittest.mock import patch

from macscope import cli, engine, objc
from test_core import TemporaryCase
from test_objc import BASE, property_fixture, overlapping_zero_fill
import test_objc


def fixture(cpu=0x0100000C):
    data = bytearray(property_fixture())
    struct.pack_into('<II',data,4,cpu,3 if cpu == 0x01000007 else 0)
    struct.pack_into('<Q',data,0x3B0,BASE+0x600)
    struct.pack_into('<II',data,0x600,32,2)
    for record,name,storage in ((0x608,0x790,0x680),(0x628,0x7B0,0x684)):
        struct.pack_into('<3Q2I',data,record,BASE+storage,BASE+name,BASE+0x7A0,2,4)
    struct.pack_into('<ii',data,0x680,0,16)
    data[0x790:0x796] = b'first\0'
    data[0x7B0:0x7B7] = b'second\0'
    data[0x7A0:0x7A2] = b'i\0'
    return data


class SelectedIvarTests(TemporaryCase):
    stage = test_objc.ObjCCoverageTests.stage

    def rows(self,data):
        return objc.selected_ivars(bytes(data),{'offset':'0x0'},BASE+0x300)

    def test_both_arches_exact_zero_and_positive_evidence(self):
        for cpu in (0x0100000C,0x01000007):
            rows,gaps = self.rows(fixture(cpu))
            self.assertFalse(gaps)
            self.assertEqual([r['declared_offset_bytes'] for r in rows],[0,16])
            self.assertEqual(rows[0]['offset_pointer_va'],hex(BASE+0x608))
            self.assertEqual(rows[0]['offset_storage_va'],hex(BASE+0x680))
            self.assertEqual(rows[0]['offset_evidence']['bytes'],'00000000')
            self.assertEqual(rows[1]['offset_evidence']['bytes'],'10000000')
            self.assertEqual({r['class_slot'] for r in rows},{hex(BASE+0x300)})

    def test_unavailable_corrupt_negative_truncated_preserve_valid_rows(self):
        for address,value in ((0,0),(BASE+0xDEAD,0),(BASE+0x8FE,0),(BASE+0x680,-1)):
            data = fixture()
            struct.pack_into('<Q',data,0x608,address)
            struct.pack_into('<i',data,0x680,value)
            rows,gaps = self.rows(data)
            self.assertIn('ivar_offset_unavailable',gaps)
            self.assertEqual(len(rows),2)
            self.assertIsNone(rows[0]['declared_offset_bytes'])
            self.assertEqual(rows[0]['offset_evidence']['status'],'missing')
            self.assertIn('required',rows[0]['offset_evidence'])
            self.assertEqual(rows[1]['declared_offset_bytes'],16)

    def test_ambiguous_storage_cannot_be_accepted(self):
        rows,gaps = self.rows(overlapping_zero_fill(bytes(fixture()),BASE+0x681))
        self.assertIn('ivar_offset_unavailable',gaps)
        self.assertIsNone(rows[0]['declared_offset_bytes'])
        self.assertEqual(rows[1]['declared_offset_bytes'],16)

    def test_scoped_lazy_external_bind_retains_row(self):
        original = objc.ObjCImage.relocation
        def external(view,site):
            if site == BASE+0x608:
                return {'kind':'bind','symbol':'_owned_external_offset','library':'owned_library'}
            return original(view,site)
        with patch.object(objc.ObjCImage,'relocation',external):
            rows,gaps = self.rows(fixture())
        self.assertIn('ivar_offset_unavailable',gaps)
        self.assertEqual(rows[0]['offset_status'],'external_bind')
        self.assertIsNone(rows[0]['declared_offset_bytes'])
        self.assertEqual(rows[1]['declared_offset_bytes'],16)

    def test_declared_only_does_not_walk_superclass_or_metaclass(self):
        data = fixture()
        # Unresolvable superclass remains metadata uncertainty; no ivar inheritance.
        struct.pack_into('<Q',data,0x348,BASE+0xDEAD)
        rows,gaps = self.rows(data)
        self.assertEqual([r['name'] for r in rows],['first','second'])
        self.error('objc_class_slot',objc.selected_ivars,bytes(data),{'offset':'0x0'},BASE+0x340)

    def test_late_unavailable_record_preserves_prior_valid_rows(self):
        data = fixture()
        struct.pack_into('<I',data,0x604,100)
        rows,gaps = self.rows(data)
        self.assertEqual([r['name'] for r in rows],['first','second'])
        self.assertIn('unavailable_ivar_record_bytes',gaps)
        data = fixture()
        rows,gaps = self.rows(overlapping_zero_fill(bytes(data),BASE+0x62F))
        self.assertEqual([r['name'] for r in rows],['first'])
        self.assertIn('unavailable_ivar_record_bytes',gaps)

    def test_row_and_pointer_limits_remain_partial(self):
        with patch.object(objc,'MAX_IVARS',1):
            rows,gaps = self.rows(fixture())
        self.assertEqual(len(rows),1)
        self.assertIn('ivar_limit',gaps)
        with patch.object(objc,'MAX_SELECTED_POINTERS',0):
            rows,gaps = self.rows(fixture())
        self.assertFalse(rows)
        self.assertIn('selected_pointer_limit',gaps)

    def test_cli_cursor_and_export_identity_without_engine(self):
        project,image = self.stage(bytes(fixture()))
        def query(*extra):
            args = cli.parser().parse_args(['objc','ivars','--project',str(project.path),
                                           '--class-slot',hex(BASE+0x300),*extra])
            return cli.execute(args)
        with patch.object(engine,'dependencies',side_effect=AssertionError('engine')):
            full = query()
            first = query('--limit','1')
            cursor = first['coverage']['next_cursor']
            second = query('--cursor',cursor)
            self.assertEqual(first['data']+second['data'],full['data'])
            self.assertEqual(second,query('--cursor',cursor))
            self.error('stale_cursor',query,'--cursor',cursor,'--decode-types')
            inventory_args = cli.parser().parse_args(['objc','ivars','--project',str(project.path),
                                                     '--cursor',cursor])
            self.error('stale_cursor',cli.execute,inventory_args)
            self.assertEqual(json.loads(cli.render(full,'json')),full)
            self.assertEqual(full['data'][0]['image_id'],image['image_id'])
