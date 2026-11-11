"""Conditional entry-register relations, not recovered Objective-C signatures."""

POLICY = 'macscope-send-register-origins/1'
MAX_PREFIX = 32


def build(context, function, transfer):
    result = {'policy': POLICY, 'status': 'unavailable',
              'condition': 'Execution follows the selected entry prefix to this transfer.',
              'runtime_values': 'unknown', 'argument_count_and_types': 'unknown'}
    try:
        entry = int(function['entry_va'], 16)
        site = int(transfer['source_va'], 16)
        count, remainder = divmod(site-entry, 4)
        if remainder or count < 0 or count > MAX_PREFIX:
            raise ValueError('prefix_limit_or_alignment')
        rows = function['instructions']
        if len(rows) <= count:
            raise ValueError('missing_prefix')
        registers = [{'kind': 'entry_register', 'register': f'x{i}'} for i in range(31)]
        zero = {'kind': 'constant', 'value': '0x0'}
        proof = []
        for index, ins in enumerate(rows[:count+1]):
            address = entry + index*4
            raw = bytes.fromhex(ins['bytes'])
            if int(ins['addr'], 16) != address or len(raw) != 4:
                raise ValueError('noncontiguous_prefix')
            _, offset = context.section(address, 4, executable=True)
            if context.binary[offset:offset+4] != raw:
                raise ValueError('prefix_bytes_mismatch')
            if index == count:
                if raw.hex() != transfer['source_bytes']:
                    raise ValueError('transfer_bytes_mismatch')
                break
            word = int.from_bytes(raw, 'little')
            if word == 0xd503201f:  # NOP
                pass
            elif word & 0xffe0ffe0 == 0xaa0003e0:  # ORR Xd,XZR,Xm,LSL #0
                dst, src = word & 31, (word >> 16) & 31
                if dst != 31:
                    registers[dst] = zero.copy() if src == 31 else registers[src].copy()
            else:
                raise ValueError('unsupported_prefix_instruction')
            proof.append({'va': hex(address), 'bytes': raw.hex()})
        result.update(status='verified_conditional_register_origins',
                      entry_va=hex(entry), transfer_va=hex(site), instructions=proof,
                      receiver_register={'register': 'x0', 'origin': registers[0]},
                      raw_registers=[{'register': f'x{i}', 'origin': registers[i]} for i in range(2, 8)],
                      selector_register={'register': 'x1', 'source': 'verified_selector_stub'},
                      stub_overwrites=['x1', 'x16'])
    except (ValueError, KeyError, TypeError) as exc:
        result['reason'] = str(exc) if isinstance(exc, ValueError) else 'malformed_prefix'
    return result
