"""Deliberately narrow byte oracle for the owned -O1 Calendar fixture.

This is a test oracle, not a general Objective-C semantics recognizer. Changed
compiler instruction patterns fail closed and require independent review.
Runtime dispatch remains unresolved even when a selector request is verified.
"""
from macscope import dyld, import_links, metadata
from macscope.macho import thin


CLASS = 'OwnedCalendarResourceController'
POLICY = 'macscope-owned-calendar-byte-oracle/1'


def one(rows):
    assert len(rows) == 1, rows
    return rows[0]


def signed(number, bits):
    return number - (1 << bits) if number & (1 << (bits - 1)) else number


def arm_adrp(word, pc, register):
    assert word & 0x9f00001f == 0x90000000 | register
    immediate = ((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3)
    return (pc & ~0xfff) + (signed(immediate, 21) << 12)


def arm_branch(row, *, link=False):
    raw = bytes.fromhex(row['bytes'])
    assert len(raw) == 4
    word = int.from_bytes(raw, 'little')
    assert word & 0xfc000000 == (0x94000000 if link else 0x14000000)
    return int(row['addr'], 16) + (signed(word & 0x3ffffff, 26) << 2)


def x86_branch(row, *, link=False):
    raw = bytes.fromhex(row['bytes'])
    assert len(raw) == 5 and raw[0] == (0xe8 if link else 0xe9)
    return int(row['addr'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True)


def read(binary, parsed, address, length):
    offset = metadata.mapped_location(parsed, address, length, from_file=False)
    assert offset is not None and offset + length <= len(binary)
    return binary[offset:offset + length]


def selector_stub(binary, image, parsed, target, selector, selectors):
    size = 20 if image['arch'] == 'arm64' else 13
    section = import_links.section_at(parsed, target, '__TEXT', '__objc_stubs')
    assert section is not None and target + size <= int(section['va'], 16) + int(section['size'], 16)
    raw = read(binary, parsed, target, size)
    if image['arch'] == 'arm64':
        words = [int.from_bytes(raw[i:i + 4], 'little') for i in range(0, size, 4)]
        selector_page = arm_adrp(words[0], target, 1)
        bind_page = arm_adrp(words[2], target + 8, 16)
        assert words[1] & 0xffc003ff == 0xf9400021  # LDR x1,[x1,#imm]
        assert words[3] & 0xffc003ff == 0xf9400210  # LDR x16,[x16,#imm]
        assert words[4] == 0xd61f0200  # BR x16
        selector_slot = selector_page + ((words[1] >> 10) & 0xfff) * 8
        bind_slot = bind_page + ((words[3] >> 10) & 0xfff) * 8
    else:
        assert raw[:3] == b'\x48\x8b\x35' and raw[7:9] == b'\xff\x25'
        selector_slot = target + 7 + int.from_bytes(raw[3:7], 'little', signed=True)
        bind_slot = target + 13 + int.from_bytes(raw[9:13], 'little', signed=True)
    return {'target_va': hex(target), 'stub_bytes': raw.hex(),
            **selector_binding(binary, image, parsed, selector_slot, bind_slot, selector, selectors)}


def selector_binding(binary, image, parsed, selector_slot, bind_slot, selector, selectors):
    reference = one([row for row in selectors if row['origin'] == 'selector_reference'
                     and row['name'] == selector and int(row['record_va'], 16) == selector_slot])
    _, rows, gaps = dyld.fixups(binary, image, parsed=parsed, address=selector_slot)
    relocation = one(rows)
    assert not gaps and relocation['kind'] == 'rebase' and relocation['target_va'] == reference['selector_va']
    assert read(binary, parsed, int(reference['selector_va'], 16), len(selector) + 1) == selector.encode() + b'\0'
    _, rows, gaps = dyld.fixups(binary, image, parsed=parsed, address=bind_slot)
    binding = one(rows)
    offset = metadata.mapped_location(parsed, bind_slot, 8, from_file=False)
    assert not gaps and binding['kind'] == 'bind' and binding['symbol'] == '_objc_msgSend'
    assert offset is not None and import_links.strong_bind(parsed, binding, offset)
    return {'selector_reference': reference,
            'selector_fixup': relocation, 'dispatch_binding': binding, 'runtime_target': 'unresolved'}


def x86_dispatch(binary, image, parsed, selector_row, call_row, selector, selectors, *, call):
    sel = bytes.fromhex(selector_row['bytes'])
    transfer = bytes.fromhex(call_row['bytes'])
    assert len(sel) == 7 and sel[:3] == b'\x48\x8b\x35'
    assert len(transfer) == 6 and transfer[:2] == (b'\xff\x15' if call else b'\xff\x25')
    selector_slot = int(selector_row['addr'], 16) + 7 + int.from_bytes(sel[3:], 'little', signed=True)
    bind_slot = int(call_row['addr'], 16) + 6 + int.from_bytes(transfer[2:], 'little', signed=True)
    return {'selector_instruction': selector_row, 'transfer_instruction': call_row,
            **selector_binding(binary, image, parsed, selector_slot, bind_slot, selector, selectors)}


def ivar(rows, name):
    row = one([r for r in rows if r['class_name'] == CLASS and r['name'] == name])
    assert row['offset_status'] == 'recorded' and row['size_bytes'] == 8
    return row


def verify(binary, image, queries, ivars, selectors, apple_instructions):
    parsed = thin(binary, include_section_linkage=True)
    load, change = (queries[name]['data']['instructions'] for name in ('load', 'change'))
    advanced, state = ivar(ivars, 'advancedRow'), ivar(ivars, '_configuredState')
    row_offset, state_offset = (r['declared_offset_bytes'] for r in (advanced, state))
    # The exact register templates below are tied to this owned fixture and
    # compiler pattern; no heuristic search or skipping unrelated ops is used.
    assert 0 <= row_offset < 128 and 0 <= state_offset < 128
    for name in ('load', 'change'):
        next_address = int(queries[name]['data']['entry_va'], 16)
        for ins in queries[name]['data']['instructions']:
            address, raw = int(ins['addr'], 16), bytes.fromhex(ins['bytes'])
            assert address == next_address
            next_address += len(raw)
            assert read(binary, parsed, address, len(raw)) == raw
            assert any(r['address'] == ins['addr'] for r in apple_instructions[name])
    if image['arch'] == 'arm64':
        assert row_offset % 8 == state_offset % 8 == 0
        assert len(load) == 3 and len(change) == 13
        expected_load = [0xf9400000 | (row_offset // 8) << 10, 0x52800022]
        assert [int.from_bytes(bytes.fromhex(r['bytes']), 'little') for r in load[:2]] == expected_load
        # x0=self preserved in x19; x0=sender before state request. Compare
        # returned x0 to the eight-byte ivar; equality skips only the store.
        expected = ['f44fbea9', 'fd7b01a9', 'fd430091', 'f30300aa', 'e00302aa', None,
                    (0xf9400000 | (state_offset // 8) << 10 | 19 << 5 | 8).to_bytes(4, 'little').hex(),
                    '1f0008eb', '40000054',
                    (0xf9000000 | (state_offset // 8) << 10 | 19 << 5).to_bytes(4, 'little').hex(),
                    'fd7b41a9', 'f44fc2a8', 'c0035fd6']
        assert all(want is None or row['bytes'] == want for row, want in zip(change, expected))
        load_target, state_target = arm_branch(load[-1]), arm_branch(change[5], link=True)
        compare, branch, store, continuation = change[7], change[8], change[9], change[10]
        assert int(branch['addr'], 16) + 8 == int(continuation['addr'], 16)
        load_dispatch = selector_stub(binary, image, parsed, load_target, 'setHidden:', selectors)
        state_dispatch = selector_stub(binary, image, parsed, state_target, 'state', selectors)
    else:
        assert image['arch'] == 'x86_64' and len(load) == 7 and len(change) == 15
        expected_load = ['55', '4889e5', '488b7f' + bytes([row_offset]).hex(), None,
                         'ba01000000', '5d', None]
        expected_change = ['55', '4889e5', '53', '50', '4889fb', None, '4889d7', None,
                           '483b43' + bytes([state_offset]).hex(), '7404',
                           '488943' + bytes([state_offset]).hex(), '4883c408', '5b', '5d', 'c3']
        for rows, expected in ((load, expected_load), (change, expected_change)):
            assert all(want is None or row['bytes'] == want for row, want in zip(rows, expected))
        compare, branch, store, continuation = change[8:12]
        assert int(branch['addr'], 16) + 2 + 4 == int(continuation['addr'], 16)
        load_dispatch = x86_dispatch(binary, image, parsed, load[3], load[6], 'setHidden:', selectors, call=False)
        state_dispatch = x86_dispatch(binary, image, parsed, change[5], change[7], 'state', selectors, call=True)
    return {'policy': POLICY, 'arch': image['arch'], 'load': {
                'receiver_ivar': advanced, 'hidden_argument': True,
                'instructions': load, 'dispatch': load_dispatch},
            'change': {'configuration_ivar': state, 'instructions': change,
                       'requested_state': state_dispatch,
                       'comparison': compare, 'equality_branch': branch, 'store_on_inequality': store,
                       'equality_continuation_va': continuation['addr']},
            'scope': 'Owned fixed instruction template only; message implementation and runtime reachability unresolved'}
