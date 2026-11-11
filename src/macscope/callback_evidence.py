"""Bounded byte facts, deliberately not a Swift closure/alias analysis."""
import copy
import hashlib
import json
import re

POLICY = 'macscope-callback-sites/7'
BIT_TEST_POLICY = 'macscope-callback-sites/8'
MAX_INSTRUCTIONS = 1024
MASK = (1 << 64) - 1


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits-1)) else value


def project(response, *, abi=None, provenance=False, fallthrough=False, checked_add=False, bit_test_fallthrough=False):
    """Annotate a validated import disassembly without mutating its receipt."""
    if abi not in (None, 'aapcs64'):
        raise ValueError('Unsupported callback ABI hypothesis')
    tracing = provenance or abi is not None
    if fallthrough and not tracing:
        raise ValueError('Fallthrough obligations require register provenance')
    if checked_add and not tracing:
        raise ValueError('Checked-add guards require register provenance')
    if bit_test_fallthrough and (not tracing or fallthrough or checked_add):
        raise ValueError('Bit-test fallthrough requires tracing and cannot mix path modes')
    result = copy.deepcopy(response)
    data = result['data']
    proof = data['selection']
    report = {'policy': BIT_TEST_POLICY if bit_test_fallthrough else POLICY,
              'source_envelope_sha256': hashlib.sha256(json.dumps(response, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest(),
              'selection': copy.deepcopy(proof),
              'status': 'inconclusive', 'sites': [], 'gaps': [],
              'path_mode': ('explicit_bit_test_fallthrough' if bit_test_fallthrough else
                            'explicit_fallthrough_and_checked_add' if fallthrough and checked_add else
                            'explicit_fallthrough' if fallthrough else
                            'explicit_checked_add_guards' if checked_add else 'no_conditional_paths'),
              'checked_add_mode': 'explicit_adjacent_overflow_guard' if checked_add else 'disabled',
              'path_obligations': [],
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
    branch_conditions = []
    report['stop_reason'] = 'selected_prefix_end'
    skipped_guard = None
    for index, row in enumerate(rows):
        if index == skipped_guard:
            continue
        va = int(row['addr'], 16)
        word = int.from_bytes(bytes.fromhex(row['bytes']), 'little')
        rd, rn = word & 31, (word >> 5) & 31
        site = {'instruction_va': row['addr'], 'instruction_bytes': row['bytes']}
        if conditions:
            site['conditional_on_calls'] = list(conditions)
        if branch_conditions:
            site['conditional_on_branches'] = list(branch_conditions)
        report['interpreted_end_va'] = hex(va + 4)
        def get(reg):
            return copy.deepcopy(regs.get(reg, {'kind': 'unknown', 'register': f'x{reg}'}))
        def put(reg, value):
            if reg != 31:
                if tracing and value.get('kind') == 'unknown' and 'value_identity' not in value:
                    value = dict(value, value_identity={'origin_va': row['addr'],
                        'source_envelope_sha256': report['source_envelope_sha256']})
                regs[reg] = value
        if word & 0x1f000000 == 0x10000000:  # ADR/ADRP
            imm = signed(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3), 21)
            address = ((va & ~0xfff) + (imm << 12)) if word >> 31 else va + imm
            put(rd, {'kind': 'address', 'value': hex(address & MASK), 'origin_va': row['addr']})
        elif checked_add and word & 0xff800000 == 0xb1000000:
            following = rows[index+1] if index+1 < len(rows) else None
            branch_word = int.from_bytes(bytes.fromhex(following['bytes']), 'little') if following else 0
            condition = branch_word & 0xff00001f
            if rn == 31 or condition not in (0x54000006, 0x54000007):
                report['gaps'].append(dict(site, reason='unsupported_checked_add_guard'))
                report['interpreted_end_va'] = hex(va)
                report['stop_reason'] = 'unsupported_instruction_boundary'
                break
            left = get(rn)
            immediate = ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)
            overflow = None
            if left['kind'] in ('address', 'integer_constant'):
                operand = int(left['value'], 16) & MASK
                value = {'kind': 'integer_constant', 'value': hex((operand+immediate) & MASK), 'origin_va': row['addr']}
                overflow = not (-(1 << 63) <= signed(operand,64)+immediate < (1 << 63))
            else:
                value = {'kind': 'checked_add_result', 'origin_va': row['addr'], 'width': 64,
                         'selection_start_va': proof['start_va'], 'source_envelope_sha256': report['source_envelope_sha256']}
            # Zero cannot overflow; W shifted-ADD results are zero-extended and
            # remain below signed64 maximum even with the largest immediate.
            if immediate == 0 or (left['kind'] == 'register_add_result' and left.get('width') == 32):
                overflow = False
            flag = {'kind': 'signed_overflow_flag', 'origin_va': row['addr'],
                    'selection_start_va': proof['start_va'], 'source_envelope_sha256': report['source_envelope_sha256'],
                    'value': overflow}
            report['sites'].append(dict(site, kind='checked_add', width=64, left=left,
                immediate=immediate, result=copy.deepcopy(value), overflow_flag=copy.deepcopy(flag),
                destination_register=f'x{rd}' if rd != 31 else 'zr', discarded_write=rd == 31))
            put(rd,value)
            branch_va = va+4
            target = (branch_va + signed((branch_word >> 5) & 0x7ffff,19)*4) & MASK
            requires_overflow = condition == 0x54000007
            branch = dict(site, instruction_va=following['addr'], instruction_bytes=following['bytes'],
                kind='conditional_branch', branch='b.vc' if requires_overflow else 'b.vs',
                target_va=hex(target), fallthrough_va=hex(va+8), width=64, tested_value=flag,
                checked_add_operand=copy.deepcopy(left), checked_add_immediate=immediate,
                fallthrough_predicate='signed_overflow' if requires_overflow else 'no_signed_overflow',
                predicate_status='unverified', taken_path='not_analyzed')
            report['sites'].append(branch)
            report['interpreted_end_va'] = hex(va+8)
            identity_bearing = left['kind'] in ('range_input_register','memory_read','register_add_result',
                'checked_add_result','call_clobbered','unknown_arithmetic','stack_pointer_relative') or 'value_identity' in left
            conflicts = [prior['instruction_va'] for prior in report['path_obligations']
                         if identity_bearing and prior.get('checked_add_operand') == left
                         and prior.get('checked_add_immediate') == immediate
                         and prior['fallthrough_predicate'] != branch['fallthrough_predicate']]
            if conflicts:
                branch['contradictory_with'] = conflicts
            reason = ('conditional_backedge_or_cycle' if target <= branch_va else
                      'branch_condition_budget' if len(branch_conditions) >= 16 else
                      'impossible_fallthrough_predicate' if overflow is not None and overflow != requires_overflow else
                      'contradictory_fallthrough_predicates' if conflicts else None)
            if reason:
                report['gaps'].append({'instruction_va': following['addr'], 'reason': reason})
                report['stop_reason'] = reason
                break
            if overflow is not None:
                branch['predicate_status'] = 'statically_satisfied'
            report['path_obligations'].append(copy.deepcopy(branch))
            branch_conditions.append(following['addr'])
            if 'alternate_branch_paths_not_analyzed' not in report['missing_evidence']:
                report['missing_evidence'].append('alternate_branch_paths_not_analyzed')
            skipped_guard = index+1
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
            if (left['kind'] in concrete and right['kind'] in concrete
                    and (not bit_test_fallthrough or 'address' not in (left['kind'], right['kind']))):
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
        elif bit_test_fallthrough and word & 0x7e000000 == 0x36000000:  # TBZ / TBNZ
            bit = ((word >> 26) & 32) | ((word >> 19) & 31)
            width = 32 if bit < 32 else 64
            nonzero_branch = bool(word & (1 << 24))
            displacement = signed((word >> 5) & 0x3fff, 14) * 4
            target = (va + displacement) & MASK
            value = get(rd) if rd != 31 else {'kind': 'integer_constant', 'value': '0x0', 'basis': 'zero_register'}
            expected_set = not nonzero_branch
            branch = dict(site, kind='conditional_branch', branch='tbnz' if nonzero_branch else 'tbz',
                          target_va=hex(target), fallthrough_va=hex(va+4), width=width, bit_index=bit,
                          register=(f'w{rd}' if width == 32 else f'x{rd}') if rd != 31 else 'zr',
                          tested_value=value, fallthrough_predicate='bit_set' if expected_set else 'bit_clear',
                          predicate_status='unverified', taken_path='not_analyzed')
            report['sites'].append(branch)
            known_set = None
            if value['kind'] == 'integer_constant':
                known_set = bool((int(value['value'],16) >> bit) & 1)
            elif value['kind'] == 'register_add_result' and value.get('width') == 32 and bit >= 32:
                known_set = False
            identity_bearing = value['kind'] in ('address','range_input_register','memory_read',
                'register_add_result','call_clobbered','unknown_arithmetic','stack_pointer_relative') or 'value_identity' in value
            conflicts = [prior['instruction_va'] for prior in report['path_obligations']
                         if identity_bearing and prior.get('bit_index') == bit
                         and prior['tested_value'] == value
                         and prior['fallthrough_predicate'] != branch['fallthrough_predicate']]
            reason = ('conditional_backedge_or_cycle' if displacement <= 0 or target <= va else
                      'branch_condition_budget' if len(branch_conditions) >= 16 else
                      'impossible_fallthrough_predicate' if known_set is not None and known_set != expected_set else
                      'contradictory_fallthrough_predicates' if conflicts else None)
            if reason:
                if conflicts:branch['contradictory_with'] = conflicts
                report['gaps'].append(dict(site, reason=reason, prior_sites=conflicts))
                report['stop_reason'] = reason
                break
            if known_set is not None:branch['predicate_status'] = 'statically_satisfied'
            report['path_obligations'].append(copy.deepcopy(branch))
            branch_conditions.append(row['addr'])
            if 'alternate_branch_paths_not_analyzed' not in report['missing_evidence']:
                report['missing_evidence'].append('alternate_branch_paths_not_analyzed')
        elif fallthrough and word & 0x7e000000 == 0x34000000:  # CBZ / CBNZ W/X
            width = 64 if word & (1 << 31) else 32
            nonzero_branch = bool(word & (1 << 24))
            target = (va + signed((word >> 5) & 0x7ffff, 19)*4) & MASK
            value = get(rd) if rd != 31 else {'kind': 'integer_constant', 'value': '0x0', 'basis': 'zero_register'}
            branch = dict(site, kind='conditional_branch', branch='cbnz' if nonzero_branch else 'cbz',
                          target_va=hex(target), fallthrough_va=hex(va+4), width=width,
                          register=f'x{rd}' if rd != 31 else 'zr', tested_value=value,
                          fallthrough_predicate='zero' if nonzero_branch else 'nonzero',
                          predicate_status='unverified', taken_path='not_analyzed')
            report['sites'].append(branch)
            if target <= va:
                report['gaps'].append(dict(site, reason='conditional_backedge_or_cycle'))
                report['stop_reason'] = 'conditional_backedge_or_cycle'
                break
            if len(branch_conditions) >= 16:
                report['gaps'].append(dict(site, reason='branch_condition_budget'))
                report['stop_reason'] = 'branch_condition_budget'
                break
            if value['kind'] in ('integer_constant', 'address'):
                is_zero = not (int(value['value'],16) & ((1 << width)-1))
                if is_zero != nonzero_branch:
                    report['gaps'].append(dict(site, reason='impossible_fallthrough_predicate'))
                    report['stop_reason'] = 'impossible_fallthrough_predicate'
                    break
                branch['predicate_status'] = 'statically_satisfied'
            conflicts = []
            identity_bearing = value['kind'] in ('range_input_register', 'memory_read',
                'register_add_result', 'call_clobbered', 'unknown_arithmetic', 'stack_pointer_relative') or 'value_identity' in value
            for prior in report['path_obligations']:
                if not identity_bearing or prior['tested_value'] != value or prior['fallthrough_predicate'] == branch['fallthrough_predicate']:
                    continue
                zero_width = prior['width'] if prior['fallthrough_predicate'] == 'zero' else width
                nonzero_width = prior['width'] if prior['fallthrough_predicate'] == 'nonzero' else width
                # X==0 implies W==0, but W==0 alone does not imply X==0.
                # A symbolic W ADD result is independently zero-extended.
                if zero_width >= nonzero_width or (value['kind'] == 'register_add_result' and value['width'] == 32):
                    conflicts.append(prior['instruction_va'])
            if conflicts:
                branch['contradictory_with'] = conflicts
                report['gaps'].append(dict(site, reason='contradictory_fallthrough_predicates', prior_sites=conflicts))
                report['stop_reason'] = 'contradictory_fallthrough_predicates'
                break
            report['path_obligations'].append(copy.deepcopy(branch))
            branch_conditions.append(row['addr'])
            if 'alternate_branch_paths_not_analyzed' not in report['missing_evidence']:
                report['missing_evidence'].append('alternate_branch_paths_not_analyzed')
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
