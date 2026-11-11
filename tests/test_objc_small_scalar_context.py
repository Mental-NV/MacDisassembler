"""Owned narrow scalars and legacy report compatibility."""
import copy
import unittest
from macscope import objc_type_evidence as types, objc_types
import test_objc_type_evidence as fixtures
from test_core import TemporaryCase


class SmallScalarTests(unittest.TestCase):
    def project(self, code, arch, policy=types.ABI_POLICY):
        return types.project_abi(objc_types.decode_method(code+'@:'+code,'take:','instance'), arch, policy)

    def test_widths_and_containers_never_infer_upper_bits(self):
        for arch in types.GP:
            for code, width in [('c',8),('C',8),('s',16),('S',16),('i',32),('I',32),('B',8)]:
                row = self.project(code, arch)
                self.assertEqual(row['status'], 'projected')
                self.assertEqual(row['arguments'][2]['register'], types.GP[arch][2])
                for item in [row['arguments'][2], row['return_value']]:
                    self.assertEqual(item['width_bits'],width)
                    self.assertEqual(item['signed'],None if code in ('B','c') else code.islower())
                    self.assertEqual(item['representation'],'boolean' if code == 'B' else 'integer')
                    self.assertNotIn('extension',item)
                self.assertEqual(self.project(code,arch,types.LEGACY_ABI_POLICY)['status'],'unsupported')

    def test_mixed_register_limit_and_unsupported_types(self):
        for arch, regs in types.GP.items():
            codes = 'cBsSiI'[:len(regs)-2]
            row = types.project_abi(objc_types.decode_method('v@:'+codes,'take:'*len(codes),'instance'), arch)
            self.assertEqual([a['register'] for a in row['arguments']],regs)
            for suffix in ('B','d','@?','{Pair=ii}'):
                decoded = objc_types.decode_method('v@:'+codes+suffix,'take:'*(len(codes)+1),'instance')
                row = types.project_abi(decoded,arch)
                self.assertEqual(row['status'],'unsupported')
                self.assertIn('stack_arguments_unsupported',row['reasons'])
                self.assertNotIn('arguments',row)
        with self.assertRaises(ValueError): self.project('B','arm64','unknown')


class LegacyReportTests(TemporaryCase):
    fixture = fixtures.SidecarDiffTests.fixture
    save = fixtures.SidecarDiffTests.save
    compare = fixtures.SidecarDiffTests.compare
    typed = fixtures.SidecarDiffTests.typed

    def test_legacy_roundtrip_redaction_and_changed_policy_diff(self):
        left, old = self.typed('legacy')
        right, new = self.typed('modern')
        old['leads'][0]['matches'][0]['type_encoding'] = 'B24@0:8B16'
        new['leads'][0]['matches'][0]['type_encoding'] = 'B24@0:8B16'
        old[types.FIELD] = types.build(old,{},abi_policy=types.LEGACY_ABI_POLICY)
        new[types.FIELD] = types.build(new,{})
        frozen = copy.deepcopy(old)
        self.assertEqual(types.validate(old)['handler']['abi_projection']['status'],'unsupported')
        self.assertEqual(types.validate(new)['handler']['abi_projection']['status'],'projected')
        self.assertEqual(types.redact_report(old,copy.deepcopy),frozen)
        self.assertEqual(old,frozen)
        self.save(left,old); self.save(right,new)
        self.assertIn('objc_types',self.compare(left,right)['data']['records'][0]['changed_observations'])
        old[types.FIELD]['abi_policy'] = 'unknown'
        with self.assertRaises(ValueError): types.validate(old)

    def test_legacy_word_records_remain_exact(self):
        _, report = self.typed()
        old = types.build(report,{},abi_policy=types.LEGACY_ABI_POLICY)
        self.assertEqual(old['records'][0]['abi_projection']['policy'],types.LEGACY_ABI_POLICY)
        report[types.FIELD] = old
        self.assertTrue(types.validate(report))
