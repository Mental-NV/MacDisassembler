"""Bounded byte facts, deliberately not a Swift closure/alias analysis."""
import copy
import hashlib
import json
import re

POLICY = 'macscope-callback-sites/1'
MAX_INSTRUCTIONS = 1024
MASK = (1 << 64) - 1


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits-1)) else value


def project(response):
    """Annotate a validated import disassembly without mutating its receipt."""
    result = copy.deepcopy(response)
    data = result['data']
    proof = data['selection']
    report = {'policy': POLICY,
              'source_envelope_sha256': hashlib.sha256(json.dumps(response, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest(),
              'selection': copy.deepcopy(proof),
              'status': 'inconclusive', 'sites': [], 'gaps': [],
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
    regs = {}
    report['stop_reason'] = 'selected_prefix_end'
    for row in rows:
        va = int(row['addr'], 16)
        word = int.from_bytes(bytes.fromhex(row['bytes']), 'little')
        rd, rn = word & 31, (word >> 5) & 31
        site = {'instruction_va': row['addr'], 'instruction_bytes': row['bytes']}
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
        elif word & 0xff800000 == 0x91000000 and rn != 31 and rd != 31:
            base = get(rn)
            imm = ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)
            put(rd, {'kind': 'address', 'value': hex((int(base['value'], 16)+imm) & MASK),
                     'origin_va': base['origin_va']} if base['kind'] == 'address' else
                    {'kind': 'unknown', 'register': f'x{rd}'})
        elif word & 0xffe0ffe0 == 0xaa0003e0 and ((word >> 16) & 31) != 31 and rd != 31:  # unshifted MOV Xd,Xm
            put(rd, get((word >> 16) & 31))
        elif word & 0xffc00000 in (0xf9000000, 0xf9400000) and rd != 31:
            location = {'base': get(rn) if rn != 31 else {'kind': 'unknown_stack_pointer'},
                        'base_register': f'x{rn}' if rn != 31 else 'sp',
                        'offset': ((word >> 10) & 0xfff)*8}
            if word & 0xffc00000 == 0xf9400000:
                value = {'kind': 'memory_read', 'origin_va': row['addr'], 'location': location}
                # A compact reference avoids nesting a long chain of loads.
                report['sites'].append(dict(site, kind='memory_load', register=f'x{rd}', location=location))
                put(rd, {'kind': 'memory_read', 'origin_va': value['origin_va']})
            else:
                report['sites'].append(dict(site, kind='memory_store', location=location, value=get(rd)))
        elif word & 0xfffffc1f == 0xd63f0000:  # BLR
            report['sites'].append(dict(site, kind='indirect_invocation', operand=get(rn), register=f'x{rn}'))
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
