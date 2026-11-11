"""Opaque pointer metadata never invents a callable contract."""
import copy
import unittest
from unittest.mock import patch
from macscope import objc_types as types, objc_type_evidence as sidecars, cli
from test_core import TemporaryCase
import test_objc_type_evidence as test_sidecars

class OpaqueTests(unittest.TestCase):
    def test_owned_recorded_method_preserves_surrounding_types(self):
        encoding = 'Q40@0:8r^{?=qQII}16Q24^?32'
        d = types.decode_method(encoding, 'accepted:length:predicate:', 'instance')
        self.assertEqual(d['status'], 'decoded')
        self.assertEqual(d['policy'], types.POLICY)
        self.assertEqual(d['return_type']['code'], 'Q')
        pointer = d['arguments'][-1]['type']
        self.assertEqual(pointer['kind'], 'pointer')
        self.assertEqual(pointer['pointee']['kind'], 'unknown')
        self.assertIsNone(pointer['pointee']['signature'])
        self.assertIn('signature unavailable', d['declaration'])
        for arch, reg in [('arm64', 'x4'), ('x86_64', 'r8')]:
            p = sidecars.project_abi(d, arch)
            self.assertEqual(p['status'], 'projected')
            self.assertEqual(p['arguments'][-1]['register'], reg)
            self.assertEqual(p['arguments'][-1]['representation'], 'pointer')
            self.assertFalse(p['implementation_signature_verified'])
        old = types.decode_method(encoding, 'accepted:length:predicate:', 'instance', policy=types.LEGACY_POLICY)
        self.assertEqual(old['status'], 'unsupported')
        self.assertEqual(old['diagnostics'], ['unknown_type'])
        self.assertNotIn('arguments', old)

    def test_only_immediate_unknown_pointee_and_budgets(self):
        for encoding in ('^?', 'r^?', '^^?', '[2^?]', '{T=^?}'):
            self.assertEqual(types.decode_ivar(encoding)['status'], 'decoded')
        for encoding in ('?', 'r?', '^r?', '[2?]', '{T=?}', '^', '^?garbage'):
            self.assertNotEqual(types.decode_ivar(encoding)['status'], 'decoded', encoding)
        with patch.object(types, 'MAX_NODES', 1):
            self.assertEqual(types.decode_ivar('^?')['diagnostics'], ['type_node_limit'])
        with patch.object(types, 'MAX_DEPTH', 1):
            self.assertEqual(types.decode_ivar('^?')['diagnostics'], ['nesting_limit'])
        with self.assertRaises(ValueError): types.decode_ivar('^?', policy='future')

class SidecarPolicyTests(TemporaryCase):
    fixture = test_sidecars.SidecarDiffTests.fixture
    save = test_sidecars.SidecarDiffTests.save
    compare = test_sidecars.SidecarDiffTests.compare
    typed = test_sidecars.SidecarDiffTests.typed

    def test_saved_v1_replay_redaction_and_diff_remain_v1(self):
        left, a = self.typed('legacy')
        a['leads'][0]['matches'][0]['type_encoding'] = 'Q24@0:8^?16'
        a[sidecars.FIELD] = sidecars.build(a, {}, decoder_policy=types.LEGACY_POLICY, abi_policy=sidecars.LEGACY_ABI_POLICY)
        sidecars.validate(a)
        self.assertEqual(a[sidecars.FIELD]['records'][0]['decoded_types']['status'], 'unsupported')
        clean = sidecars.redact_report(a, lambda x: copy.deepcopy(x))
        self.assertEqual(clean, a)
        sidecars.validate(clean)
        self.save(left, a)
        right, b = self.typed('modern')
        b['leads'][0]['matches'][0]['type_encoding'] = 'Q24@0:8^?16'
        before = copy.deepcopy(b['leads'][0]['function'])
        b[sidecars.FIELD] = sidecars.build(b, {})
        sidecars.validate(b)
        self.assertEqual(b['leads'][0]['function'], before)
        self.save(right, b)
        result = self.compare(left, right)['data']['records'][0]
        self.assertIn('objc_types', result['changed_observations'])
        tamper = copy.deepcopy(a)
        tamper[sidecars.FIELD]['decoder_policy'] = types.POLICY
        with self.assertRaises(ValueError): sidecars.validate(tamper)
        tamper = copy.deepcopy(b)
        tamper[sidecars.FIELD]['records'][0]['decoded_types']['arguments'][-1]['type']['pointee']['signature'] = 'bool()'
        with self.assertRaises(ValueError): sidecars.validate(tamper)

    def test_policy_rejection_even_for_empty_report(self):
        with self.assertRaises(ValueError):
            sidecars.build({'images': [], 'leads': []}, {}, decoder_policy='future')
