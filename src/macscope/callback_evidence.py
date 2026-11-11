"""Bounded byte facts, deliberately not a Swift closure/alias analysis."""
import copy
import hashlib
import json
import re

POLICY = 'macscope-callback-sites/5'
MAX_INSTRUCTIONS = 1024
MASK = (1 << 64) - 1


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits-1)) else value


def project(response, *, abi=None, provenance=False):
    """Annotate a validated import disassembly without mutating its receipt."""
    if abi not in (None, 'aapcs64'):
        raise ValueError('Unsupported callback ABI hypothesis')
    tracing = provenance or abi is not None
    result = copy.deepcopy(response)
    data = result['data']
    proof = data['selection']
    report = {'policy': POLICY,
              'source_envelope_sha256': hashlib.sha256(json.dumps(response, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest(),
              'selection': copy.deepcopy(proof),
              'status': 'inconclusive', 'sites': [], 'gaps': [],
              'provenance_mode': 'aapcs64_conditional' if abi else ('register_inputs' if provenance else 'strict'),
              'assumptions': ['selected-range input registers are symbolic',
                              'direct callees obey AAPCS64 and return normally; arbitrary memory effects'] if abi else [],
              'interpreted_end_va': proof['start_va'], 'stop_reason': 'not_interpreted',
              'missing_evidence': ['closure_layout_and_context', 'runtime_invocation_target',
                                   'eventual_state_writer']}
    data['callback_evidence'] = report
    rows = data['instructions']
    if proof['arch'] != 'arm64':
        report['gaps'].append({'reason': 'unsupported_architecture'})
        return result
    if len(rows) > MAX_INSTRUCTIONS:
        report['gaps'].append({'reason': 'instruction_budget'})
        return result
    # Validate the entire selected prefix before interpreting any of it.
    cursor = int(proof['start_va'], 16)
    for row in rows:
        if (row.get('addr') != hex(cursor) or cursor % 4
                or not isinstance(row.get('bytes'), str)
                or not re.fullmatch('[0-9a-f]{8}', row['bytes'])
                or cursor + 4 > int(proof['end_va'], 16)):
            report['gaps'].append({'reason': 'invalid_instruction_evidence'})
            return result
        cursor += 4
    regs = ({reg: {'kind': 'range_input_register', 'register': f'x{reg}',
                   'selection_start_va': proof['start_va'], 'source_envelope_sha256': report['source_envelope_sha256']} for reg in range(31)} if tracing else {})
    sp = {'kind': 'stack_pointer_relative', 'selection_start_va': proof['start_va'],
          'source_envelope_sha256': report['source_envelope_sha256'], 'offset': 0}
    conditions = []
    report['stop_reason'] = 'selected_prefix_end'
    for row in rows:
        va = int(row['addr'], 16)
        word = int.from_bytes(bytes.fromhex(row['bytes']), 'little')
        rd, rn = word & 31, (word >> 5) & 31
        site = {'instruction_va': row['addr'], 'instruction_bytes': row['bytes']}
        if conditions:
            site['conditional_on_calls'] = list(conditions)
        report['interpreted_end_va'] = hex(va + 4)
        def get(reg):
            return copy.deepcopy(regs.get(reg, {'kind': 'unknown', 'register': f'x{reg}'}))
        def put(reg, value):
            if reg != 31:
                regs[reg] = value
        if word & 0x1f000000 == 0x10000000:  # ADR/ADRP
            imm = signed(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3), 21)
            address = ((va & ~0xfff) + (imm << 12)) if word >> 31 else va + imm
            put(rd, {'kind': 'address', 'value': hex(address & MASK), 'origin_va': row['addr']})
        elif tracing and word & 0x7f200000 == 0x0b000000:
            width = 64 if word & 0x80000000 else 32
            shift_kind, shift_amount = (word >> 22) & 3, (word >> 10) & 63
            if shift_kind == 3 or shift_amount >= width:
                report['gaps'].append(dict(site, reason='invalid_add_shift_encoding'))
                report['interpreted_end_va'] = hex(va)
                report['stop_reason'] = 'unsupported_instruction_boundary'
                break
            rm = (word >> 16) & 31
            zero = {'kind': 'integer_constant', 'value': '0x0', 'basis': 'zero_register'}
            left, right = (copy.deepcopy(zero) if rn == 31 else get(rn)), (copy.deepcopy(zero) if rm == 31 else get(rm))
            concrete = ('address', 'integer_constant')
            mask = (1 << width)-1
            if left['kind'] in concrete and right['kind'] in concrete:
                lhs, rhs = int(left['value'], 16) & mask, int(right['value'], 16) & mask
                shifted = ((rhs << shift_amount) & mask if shift_kind == 0 else
                           rhs >> shift_amount if shift_kind == 1 else
                           (signed(rhs, width) >> shift_amount) & mask)
                numeric = (lhs + shifted) & mask
                kind = ('address' if width == 64 and left['kind'] == 'address'
                        and right['kind'] == 'integer_constant' else 'integer_constant')
                value = {'kind': kind, 'value': hex(numeric), 'origin_va': row['addr']}
            else:
                value = {'kind': 'register_add_result', 'origin_va': row['addr'], 'width': width,
                         'selection_start_va': proof['start_va'], 'source_envelope_sha256': report['source_envelope_sha256']}
            report['sites'].append(dict(site, kind='register_add', width=width,
                left=left, right=right, shift=('lsl', 'lsr', 'asr')[shift_kind],
                shift_amount=shift_amount, result=copy.deepcopy(value),
                destination_register=f'x{rd}' if rd != 31 else 'zr', discarded_write=rd == 31))
            put(rd, value)
        elif abi and word & 0xff800000 in (0x91000000, 0xd1000000):
            base = copy.deepcopy(sp) if rn == 31 else get(rn)
            imm = ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)
            delta = -imm if word & 0x40000000 else imm
            if base['kind'] == 'stack_pointer_relative':
                offset = base['offset'] + delta
                if abs(offset) > 4096:
                    report['gaps'].append(dict(site, reason='stack_delta_budget'))
                    report['interpreted_end_va'] = hex(va)
                    report['stop_reason'] = 'stack_delta_budget'
                    break
                value = dict(base, offset=offset)
            elif base['kind'] in ('address', 'integer_constant'):
                value = dict(base, value=hex((int(base['value'], 16) + delta) & MASK))
            else:
                value = {'kind': 'unknown_arithmetic', 'origin_va': row['addr'],
                         'source_register': f'x{rn}', 'delta': delta}
            if rd == 31:
                if value['kind'] != 'stack_pointer_relative':
                    report['gaps'].append(dict(site, reason='unknown_stack_assignment'))
                    report['interpreted_end_va'] = hex(va)
                    report['stop_reason'] = 'unknown_stack_assignment'
                    break
                sp = value
            else:
                put(rd, value)
        elif abi and word & 0x7f800000 == 0x52800000 and rd != 31:
            shift = ((word >> 21) & 3) * 16
            if not word & 0x80000000 and shift > 16:
                report['gaps'].append(dict(site, reason='invalid_movz_encoding'))
                report['interpreted_end_va'] = hex(va)
                report['stop_reason'] = 'unsupported_instruction_boundary'
                break
            put(rd, {'kind': 'integer_constant', 'value': hex(((word >> 5) & 0xffff) << shift),
                     'origin_va': row['addr']})
        elif word & 0xff800000 == 0x91000000 and rn != 31 and rd != 31:
            base = get(rn)
            imm = ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)
            put(rd, {'kind': 'address', 'value': hex((int(base['value'], 16)+imm) & MASK),
                     'origin_va': base['origin_va']} if base['kind'] == 'address' else
                    {'kind': 'unknown', 'register': f'x{rd}'})
        elif word & 0xffe0ffe0 == 0xaa0003e0 and ((word >> 16) & 31) != 31 and rd != 31:  # unshifted MOV Xd,Xm
            put(rd, get((word >> 16) & 31))
        elif word & 0xffc00000 in (0xf9000000, 0xf9400000) and rd != 31:
            location = {'base': get(rn) if rn != 31 else (copy.deepcopy(sp) if abi else {'kind': 'unknown_stack_pointer'}),
                        'base_register': f'x{rn}' if rn != 31 else 'sp',
                        'offset': ((word >> 10) & 0xfff)*8}
            if word & 0xffc00000 == 0xf9400000:
                value = {'kind': 'memory_read', 'origin_va': row['addr'], 'location': location}
                # A compact reference avoids nesting a long chain of loads.
                report['sites'].append(dict(site, kind='memory_load', register=f'x{rd}', location=location))
                put(rd, {'kind': 'memory_read', 'origin_va': value['origin_va']})
            else:
                report['sites'].append(dict(site, kind='memory_store', location=location, value=get(rd)))
        elif (word & 0xffc00000 in (0xa9000000, 0xa9400000)
              or (abi and rn == 31 and word & 0xffc00000 in
                  (0xa9800000, 0xa9c00000, 0xa8800000, 0xa8c00000))) and rd != 31 and ((word >> 10) & 31) != 31:
            rt2 = (word >> 10) & 31
            load = bool(word & (1 << 22))
            mode = (word >> 23) & 3
            writeback = mode in (1, 3)
            if load and rd == rt2:
                report['gaps'].append(dict(site, reason='unsupported_duplicate_pair_destination'))
                report['interpreted_end_va'] = hex(va)
                report['stop_reason'] = 'unsupported_instruction_boundary'
                break
            base = get(rn) if rn != 31 else (copy.deepcopy(sp) if abi else {'kind': 'unknown_stack_pointer'})
            delta = signed((word >> 15) & 0x7f, 7) * 8
            offset = 0 if mode == 1 else delta
            if writeback:
                next_offset = sp['offset'] + delta
                if abs(next_offset) > 4096:
                    report['gaps'].append(dict(site, reason='stack_delta_budget'))
                    report['interpreted_end_va'] = hex(va)
                    report['stop_reason'] = 'stack_delta_budget'
                    break
                next_sp = dict(sp, offset=next_offset)
                site['addressing_mode'] = 'post_index' if mode == 1 else 'pre_index'
                site['writeback'] = {'register': 'sp', 'delta': delta,
                                     'before': copy.deepcopy(sp), 'after': copy.deepcopy(next_sp)}
            # Both lane addresses and store values use pre-instruction state.
            values = [get(rd), get(rt2)]
            for lane, reg in enumerate((rd, rt2)):
                location = {'base': copy.deepcopy(base), 'base_register': f'x{rn}' if rn != 31 else 'sp',
                            'offset': offset + lane * 8}
                if load:
                    report['sites'].append(dict(site, kind='memory_load', register=f'x{reg}',
                                               location=location, lane=lane, width=8))
                else:
                    report['sites'].append(dict(site, kind='memory_store', location=location,
                                               value=values[lane], lane=lane, width=8))
            if load:
                for lane, reg in enumerate((rd, rt2)):
                    put(reg, {'kind': 'memory_read', 'origin_va': row['addr'], 'lane': lane})
            if writeback:
                sp = next_sp
        elif word & 0x7c000000 == 0x14000000:  # B / BL immediate
            target = (va + signed(word & 0x3ffffff, 26) * 4) & MASK
            kind = 'direct_call' if word & 0x80000000 else 'direct_branch'
            transfer = dict(site, kind=kind, target_va=hex(target))
            if tracing:
                transfer['register_inputs'] = {f'x{reg}': get(reg) for reg in (*range(8), *range(19, 30))}
            report['sites'].append(transfer)
            if abi and kind == 'direct_call':
                if len(conditions) >= 32:
                    report['gaps'].append(dict(site, reason='call_condition_budget'))
                    report['stop_reason'] = 'call_condition_budget'
                    break
                conditions.append(row['addr'])
                report['gaps'].append(dict(site, reason='unknown_call_effects', target_va=hex(target)))
                for reg in (*range(19), 30):
                    regs[reg] = {'kind': 'call_clobbered', 'register': f'x{reg}', 'call_va': row['addr']}
            else:
                report['stop_reason'] = 'direct_transfer_boundary'
                report['gaps'].append(dict(site, reason='direct_transfer_boundary'))
                break
        elif word & 0xfffffc1f == 0xd63f0000:  # BLR
            invocation = dict(site, kind='indirect_invocation', operand=get(rn), register=f'x{rn}')
            if tracing:
                invocation['register_inputs'] = {f'x{reg}': get(reg) for reg in (*range(8), *range(19, 30))}
            report['sites'].append(invocation)
            report['gaps'].append(dict(site, reason='invocation_boundary'))
            report['stop_reason'] = 'invocation_boundary'
            break
        elif word & 0xfffffc1f == 0xd65f0000:  # RET
            report['stop_reason'] = 'return_boundary'
            break
        elif word == 0xd503201f:  # NOP
            continue
        else:
            report['gaps'].append(dict(site, reason='unsupported_instruction_boundary'))
            report['interpreted_end_va'] = hex(va)
            report['stop_reason'] = 'unsupported_instruction_boundary'
            break
    if data.get('gaps'):
        report['gaps'].append({'reason': 'disassembly_incomplete'})
    return result
