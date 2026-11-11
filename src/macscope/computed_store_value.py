"""One scoped checked-add definition, not a general expression or alias solver."""
import copy


def project(report,store):
    value=store['value'];scope=report['source_envelope_sha256'];start=report['selection']['start_va']
    if (value.get('kind')!='checked_add_result' or value.get('width')!=64
            or value.get('source_envelope_sha256')!=scope or value.get('selection_start_va')!=start):
        return None
    definitions=[s for s in report['sites'] if s['kind']=='checked_add' and s['instruction_va']==value.get('origin_va')]
    if len(definitions)!=1:return None
    definition=definitions[0]
    try:
        word=int.from_bytes(bytes.fromhex(definition['instruction_bytes']),'little')
        origin=int(definition['instruction_va'],16);store_va=int(store['instruction_va'],16)
    except (ValueError,TypeError,KeyError):return None
    if (len(definition['instruction_bytes'])!=8 or word & 0xff800000!=0xb1000000
            or ((word>>5)&31)==31 or (word&31)==31 or definition.get('width')!=64 or definition.get('result')!=value
            or definition.get('immediate')!=((word>>10)&4095) << (12 if word&(1<<22) else 0)
            or definition.get('destination_register')!=('zr' if word&31==31 else f'x{word&31}')
            or definition.get('discarded_write') or not int(start,16)<=origin<store_va<int(report['selection']['end_va'],16)):
        return None
    root=definition.get('left',{})
    if root.get('kind')=='range_input_register':
        if (root.get('source_envelope_sha256')!=scope or root.get('selection_start_va')!=start
                or root.get('register') not in {f'x{i}' for i in range(31)}):return None
    else:
        # Concrete arithmetic is handled by the existing byte-defined basis.
        return None
    flag=definition.get('overflow_flag',{})
    if (flag.get('kind')!='signed_overflow_flag' or flag.get('origin_va')!=hex(origin)
            or flag.get('source_envelope_sha256')!=scope or flag.get('selection_start_va')!=start):return None
    guards=[g for g in report.get('path_obligations',[]) if g.get('instruction_va')==hex(origin+4)]
    if len(guards)!=1:return None
    guard=guards[0]
    if (guard not in report['sites'] or guard.get('tested_value')!=flag
            or guard.get('checked_add_operand')!=root or guard.get('checked_add_immediate')!=definition['immediate']
            or guard.get('predicate_status') not in ('unverified','statically_satisfied')
            or origin+4>=store_va or hex(origin+4) not in store.get('conditional_on_branches',[])):
        return None
    try:branch_word=int.from_bytes(bytes.fromhex(guard['instruction_bytes']),'little')
    except (ValueError,TypeError,KeyError):return None
    cond=branch_word & 0xff00001f
    if len(guard['instruction_bytes'])!=8 or cond not in (0x54000006,0x54000007):return None
    immediate19=(branch_word>>5)&0x7ffff
    if immediate19&(1<<18):immediate19-=1<<19
    target=(origin+4+immediate19*4)&((1<<64)-1)
    if (guard.get('fallthrough_predicate')!=('no_signed_overflow' if cond==0x54000006 else 'signed_overflow')
            or guard.get('kind')!='conditional_branch' or guard.get('branch')!=('b.vs' if cond==0x54000006 else 'b.vc')
            or guard.get('target_va')!=hex(target) or target<=origin+4 or guard.get('fallthrough_va')!=hex(origin+8)
            or guard.get('width')!=64):return None
    prior_calls={s['instruction_va'] for s in report['sites'] if s['kind']=='direct_call' and int(s['instruction_va'],16)<store_va}
    prior_guards={g['instruction_va'] for g in report.get('path_obligations',[]) if int(g['instruction_va'],16)<store_va}
    if not prior_calls.issubset(store.get('conditional_on_calls',[])) or not prior_guards.issubset(store.get('conditional_on_branches',[])):
        return None
    expected_overflow = False if definition['immediate']==0 else None
    if 'value' not in flag or flag['value'] is not expected_overflow:
        return None
    expected_status = 'unverified' if expected_overflow is None else 'statically_satisfied'
    if guard.get('predicate_status') != expected_status or (expected_overflow is False and cond==0x54000007):
        return None
    for key in ('conditional_on_calls','conditional_on_branches'):
        if not set(definition.get(key,[])+guard.get(key,[])).issubset(store.get(key,[])):return None
    return {'basis':'scoped_checked_add_computation','source_envelope_sha256':scope,
            'selection':copy.deepcopy(report['selection']), 'definition':copy.deepcopy(definition),
            'guard':copy.deepcopy(guard),'symbolic_input':copy.deepcopy(root),
            'runtime_value':'unknown','application_meaning':'unknown'}
