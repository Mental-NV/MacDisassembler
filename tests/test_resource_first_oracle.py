import copy
import unittest
from unittest.mock import patch

import resource_first_oracle as oracle


def capture(arch):
    if arch == 'arm64':
        streams = {'load': ['000440f9', '22008052', '1a000014'],
                   'change': ['f44fbea9', 'fd7b01a9', 'fd430091', 'f30300aa', 'e00302aa', '1c000094',
                              '680e40f9', '1f0008eb', '40000054', '600e00f9', 'fd7b41a9', 'f44fc2a8', 'c0035fd6']}
    else:
        streams = {'load': ['55', '4889e5', '488b7f08', '488b35a1190000', 'ba01000000', '5d', 'ff2575080000'],
                   'change': ['55', '4889e5', '53', '50', '4889fb', '488b3588190000', '4889d7', 'ff1557080000',
                              '483b4318', '7404', '48894318', '4883c408', '5b', '5d', 'c3']}
    queries, apple = {}, {}
    for name, parts in streams.items():
        start = 0x1000 if name == 'load' else 0x2000
        rows, address = [], start
        for part in parts:
            rows.append({'addr': hex(address), 'bytes': part})
            address += len(bytes.fromhex(part))
        queries[name] = {'data': {'entry_va': hex(start), 'instructions': rows}}
        apple[name] = [{'address': row['addr']} for row in rows]
    ivars = [{'class_name': oracle.CLASS, 'name': name, 'offset_status': 'recorded',
              'size_bytes': 8, 'declared_offset_bytes': offset}
             for name, offset in [('advancedRow', 8), ('_configuredState', 24)]]
    return queries, apple, ivars


class ResourceFirstOracleTests(unittest.TestCase):
    def verify(self, arch, queries, apple, ivars):
        raw = {int(row['addr'], 16): bytes.fromhex(row['bytes'])
               for query in queries.values() for row in query['data']['instructions']}
        def read(binary, parsed, address, length):
            return raw[address][:length]
        with (patch.object(oracle, 'thin', return_value={}), patch.object(oracle, 'read', side_effect=read),
              patch.object(oracle, 'selector_stub', return_value={'runtime_target': 'unresolved'}),
              patch.object(oracle, 'selector_binding', return_value={'runtime_target': 'unresolved'})):
            return oracle.verify(b'owned', {'arch': arch}, queries, ivars, [], apple)

    def test_owned_architectures_have_byte_backed_local_effects_not_runtime_resolution(self):
        for arch in ('arm64', 'x86_64'):
            with self.subTest(arch=arch):
                result = self.verify(arch, *capture(arch))
                self.assertTrue(result['load']['hidden_argument'])
                self.assertEqual(result['load']['receiver_ivar']['declared_offset_bytes'], 8)
                self.assertEqual(result['change']['configuration_ivar']['declared_offset_bytes'], 24)
                self.assertEqual(result['load']['dispatch']['runtime_target'], 'unresolved')

    def test_wrong_receiver_false_hidden_wrong_state_and_unconditional_write_fail(self):
        changes = {'arm64': [('load', 0, '000840f9'), ('load', 1, '02008052'),
                             ('change', 9, '601200f9'), ('change', 8, '1f2003d5'),
                             ('change', 8, '20000054'), ('change', 7, '1f0009eb')],
                   'x86_64': [('load', 2, '488b7f10'), ('load', 4, 'ba00000000'),
                              ('change', 10, '48894320'), ('change', 9, '9090'),
                              ('change', 9, '7400'), ('change', 8, '483b4320')]}
        for arch, mutations in changes.items():
            for name, index, raw in mutations:
                with self.subTest(arch=arch, method=name, index=index, raw=raw):
                    queries, apple, ivars = capture(arch)
                    queries[name]['data']['instructions'][index]['bytes'] = raw
                    with self.assertRaises(AssertionError):
                        self.verify(arch, queries, apple, ivars)

    def test_inserted_skipped_or_missing_instructions_fail(self):
        for arch in ('arm64', 'x86_64'):
            for kind in ('inserted', 'skipped', 'missing'):
                with self.subTest(arch=arch, kind=kind):
                    queries, apple, ivars = capture(arch)
                    rows = queries['change']['data']['instructions']
                    if kind == 'inserted':
                        rows.insert(0, copy.deepcopy(rows[0]))
                    elif kind == 'skipped':
                        rows[1]['addr'] = hex(int(rows[1]['addr'], 16) + 4)
                    else:
                        rows.pop()
                    with self.assertRaises(AssertionError):
                        self.verify(arch, queries, apple, ivars)

    def test_unavailable_or_other_class_ivar_does_not_support_effect(self):
        for arch in ('arm64', 'x86_64'):
            for field, value in [('offset_status', 'unavailable'), ('class_name', 'Unrelated'), ('size_bytes', 4)]:
                queries, apple, ivars = capture(arch)
                ivars[1][field] = value
                with self.subTest(arch=arch, field=field), self.assertRaises(AssertionError):
                    self.verify(arch, queries, apple, ivars)

    def test_apple_address_coverage_required(self):
        for arch in ('arm64', 'x86_64'):
            queries, apple, ivars = capture(arch)
            apple['load'].pop()
            with self.assertRaises(AssertionError):
                self.verify(arch, queries, apple, ivars)

    def test_arm_branch_kind_and_x86_pointer_transfer_kind_are_not_interchangeable(self):
        with self.assertRaises(AssertionError):
            oracle.arm_branch({'addr': '0x1000', 'bytes': '1a000094'})
        with self.assertRaises(AssertionError):
            oracle.x86_dispatch(b'', {}, {}, {'addr': '0x1000', 'bytes': '488b3500000000'},
                                {'addr': '0x2000', 'bytes': 'ff2500000000'}, 'state', [], call=True)

    def test_exact_selector_and_strong_bind_are_required(self):
        ref = {'origin': 'selector_reference', 'name': 'state', 'record_va': '0x1000', 'selector_va': '0x3000'}
        rebase = {'kind': 'rebase', 'target_va': '0x3000'}
        binding = {'kind': 'bind', 'symbol': '_objc_msgSend'}
        for mutation in ('none', 'selector', 'rebase', 'bind', 'weak', 'gaps'):
            r, rb, b = copy.deepcopy(ref), copy.deepcopy(rebase), copy.deepcopy(binding)
            if mutation == 'selector': r['name'] = 'unrelated'
            if mutation == 'rebase': rb['target_va'] = '0x3001'
            if mutation == 'bind': b['symbol'] = '_other'
            answers = [({}, [rb], []), ({}, [b], ['unavailable'] if mutation == 'gaps' else [])]
            with (patch.object(oracle.dyld, 'fixups', side_effect=answers),
                  patch.object(oracle, 'read', return_value=b'state\0'),
                  patch.object(oracle.metadata, 'mapped_location', return_value=0),
                  patch.object(oracle.import_links, 'strong_bind', return_value=mutation != 'weak')):
                if mutation == 'none':
                    self.assertEqual(oracle.selector_binding(b'', {}, {}, 0x1000, 0x2000, 'state', [r])['runtime_target'], 'unresolved')
                else:
                    with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                        oracle.selector_binding(b'', {}, {}, 0x1000, 0x2000, 'state', [r])


if __name__ == '__main__':
    unittest.main()
