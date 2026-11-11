"""Bounded reading view of existing evidence, not a semantic analyzer."""
from . import objc_type_evidence, terminal, token_preview

MAX_LEADS = 4
MAX_BYTES = 65536
MAX_LINES = 512
LEAD_BYTES = 12288
LEAD_LINES = 96
FIELD_CHARS = 160
RESERVE = 768


class LeadView:
    def __init__(self):
        self.lines = []
        self.bytes = 0
        self.clipped = 0
        self.omitted = {}
        self.skipped_lines = 0

    def field(self, value):
        value = 'unavailable' if value is None else str(value)
        if len(value) > FIELD_CHARS:
            self.clipped += 1
        return terminal.safe(value[:FIELD_CHARS]) + (' [clipped]' if len(value) > FIELD_CHARS else '')

    def line(self, text):
        size = len((text + '\n').encode('utf-8'))
        if self.bytes + size > LEAD_BYTES - RESERVE or len(self.lines) >= LEAD_LINES - 2:
            self.skipped_lines += 1
            return False
        self.lines.append(text)
        self.bytes += size
        return True

    def items(self, title, rows, cap, format_row):
        self.line(title + ' (sample):')
        shown = 0
        for i, row in enumerate(rows[:cap]):
            if not self.line('  ' + format_row(i, row)):
                break
            shown += 1
        self.omitted[title] = len(rows) - shown
        if not rows:
            self.line('  No entries recorded; absence is not a runtime claim.')

    def finish(self):
        footer = 'Omitted items: ' + '; '.join(f'{name}={count}' for name, count in self.omitted.items())
        self.lines.extend([footer, f'Fields clipped: {self.clipped}; budget lines omitted: {self.skipped_lines}. Full evidence: --format json or --format text.'])
        return '\n'.join(self.lines) + '\n'


def focused_function_source(function, query, pin):
    """Recognize recorded focused payload placement; receipt checks belong upstream."""
    origin = function.get('origin')
    return (isinstance(query, dict) and query.get('status') in ('complete', 'partial')
            and isinstance(origin, dict) and origin.get('mode') == 'focused_readonly_import'
            and isinstance(origin.get('job_id'), str) and bool(origin['job_id'])
            and query.get('origin') == origin
            and isinstance(origin.get('extent'), dict)
            and bool(pin.get('import_program_sha256'))
            and origin['extent'].get('program_sha256') == pin['import_program_sha256'])


def lead_view(row, pin, types):
    view = LeadView()
    f = view.field
    lead = row['lead']
    function = row.get('function')
    view.line(f"Lead {f(lead.get('id'))} [{f(row.get('status'))}] {f(lead.get('kind'))}: {f(lead.get('value'))}")
    view.line(f"Image {f(lead.get('image_id'))}; architecture {f(pin.get('arch'))}")
    view.line(f"Artifact {f(pin.get('artifact_sha256'))}; slice {f(pin.get('slice_sha256'))}")
    view.line(f"Source pin: analysis {f(pin.get('analysis_id'))}; import Program {f(pin.get('import_program_sha256'))}")
    blockers = ([row['reason']] if row.get('reason') else []) + (row.get('gaps') or [])
    view.items('Blockers', blockers, 4, lambda i, x: f(x) + ' (site not inferred)')
    if row.get('status') != 'resolved' and not blockers:
        view.line('Missing evidence unspecified; incomplete status is retained.')
    if function is None:
        view.line('Selected function unavailable; no code inferred.')
        return view.finish()
    view.line(f"Function {f(function.get('function_id'))}; entry {f(function.get('entry_va'))}")
    query = row.get('query')
    code = query if isinstance(query, dict) and 'pseudocode' in query else function
    focused_source = code is function and focused_function_source(function, query, pin)
    source = ('selected saved query' if code is query else
              'selected import-focused query (function payload)' if focused_source else
              'saved function' if pin.get('analysis_id') else 'recorded function payload (query relationship unestablished)')
    view.line(f"Pseudocode source: {source}; decompile status: {f(code.get('decompile_status'))}")
    view.line("Recorded function signature metadata: " + f(function.get('signature')))
    view.line('Signature metadata may differ from pseudocode-inferred arguments; neither is reconciled or a verified source declaration.')
    view.line("Recorded pseudocode truncation: " + f(code.get('pseudocode_truncated')))
    view.line(f"Source job: {f((code.get('origin') or {}).get('job_id'))}; query status: {f((query or {}).get('status'))}")
    if isinstance(query, dict) and code is function and not focused_source:
        view.line('No inline query pseudocode or matching focused-query provenance; function payload is not established as this query output.')
    if types is None:
        view.line('Declaration context not requested/available.' +
                  (' Add --objc-types for exact metadata binding.' if lead.get('kind') == 'objc_selector' else ''))
    else:
        view.line(f"Declaration context: {f(types['status'])}; reason {f(types['reason'])}")
        view.line('Recorded type encoding: ' + f((types.get('declaration') or {}).get('type_encoding')))
        decoded = types.get('decoded_types') or {}
        view.line('Decoded declaration (generated): ' + f(decoded.get('declaration')))
        abi = types.get('abi_projection') or {}
        view.line(f"ABI roles: {f(abi.get('status'))}; conditional on conforming IMP, not implementation verification.")
        view.line('ABI argument labels are generated; declarations do not verify implementation types.')
        view.line('ABI widths describe values inside register containers, not upper-bit validity or extension.')
        view.items('ABI arguments', abi.get('arguments') or [], 8,
                   lambda i, x: f(x.get('label')) + ' [' + f(x.get('role')) + '] -> ' + f(x.get('register')) + ' (' + f(x.get('width_bits')) + '-bit ' + f(x.get('representation')) + ')')
        if abi.get('reasons'):
            view.line('ABI unsupported: ' + f(', '.join(abi['reasons'])))
        if abi.get('return_value'):
            returned = abi['return_value']
            if returned.get('kind') == 'void':
                view.line('Conditional return: void (no value register).')
            else:
                view.line('Conditional return register: ' + f(returned.get('register')) +
                          ' (' + f(returned.get('width_bits')) + '-bit ' + f(returned.get('representation')) + ')')
    view.items('Flow gaps', code.get('control_flow_gaps') or [], 4,
               lambda i, x: f(x.get('reason')))
    tokens = token_preview.preview(code)
    view.line(f"Recorded token/address coverage: {f(tokens['status'])}; reason {f(tokens['reason'])}")
    view.line('UTF-16 token offsets are half-open; address ranges are inclusive. Not source lines or whole-line mappings.')
    view.line('Tokens may be outside the clipped snippet.')
    view.items('Token addresses', tokens['records'], 4,
               lambda i, x: f"{x['text_start']}:{x['text_end']} " + f(x['token'])
               + (' [token clipped]' if x['token_clipped'] else '') + ' => '
               + ', '.join(lo + '..' + hi for lo, hi in x['ranges'])
               + f"; ranges omitted={x['omitted_ranges']}")
    if tokens['omitted_spans'] is None:
        view.omitted['Token addresses'] = 'unknown'
    else:
        view.omitted['Token addresses'] += tokens['omitted_spans']

    pseudocode = code.get('pseudocode')
    lines = pseudocode.splitlines() if isinstance(pseudocode, str) else []
    view.line('Raw pseudocode; numbers are display indices, not recovered source lines or address mappings.')
    view.items('Code lines', lines, 40, lambda i, x: f'{i + 1}: ' + f(x))
    if not lines:
        view.line('Pseudocode unavailable: ' + f(code.get('decompile_error')))
    view.line('Instruction/reference samples below come from the selected import-focused function payload.' if focused_source else
              'Instruction/reference samples below come from the saved function, not the query pseudocode.')
    view.items('Instructions', function.get('instructions') or [], 8,
               lambda i, x: f(x.get('addr')) + ' ' + f(x.get('bytes')) + ' ' + f(x.get('text') or x.get('mnemonic')))
    for direction in ('to', 'from'):
        refs = (function.get('references') or {}).get(direction) or {}
        limit_note = ("; limited: " + f(refs["limited"])) if "limited" in refs else ""
        view.line(f"References {direction} recorded coverage: {f(refs.get('status'))}{limit_note}")
        view.items('References ' + direction, refs.get('records') or [], 4,
                   lambda i, x: f(x.get('from')) + ' -> ' + f(x.get('to')) + ' ' + f(x.get('type')))
    return view.finish()


def render(result):
    data = result['data']
    types = objc_type_evidence.validate(data)
    pins = {pin['image_id']: pin for pin in data['images']}
    leads = data['leads']
    status = terminal.safe(str(result['status'])[:FIELD_CHARS])
    header = f'macscope selected-method dossier [{status}]\n'
    header += 'Static evidence only: runtime dispatch, behavior and persistence are not established.\n'
    if result['status'] == 'partial':
        header += 'Partial evidence (exit6): retained useful artifacts, not an engine crash.\n'
    parts = [header]
    size, lines, shown = len(header.encode('utf-8')), header.count('\n'), 0
    for row in leads[:MAX_LEADS]:
        block = lead_view(row, pins[row['lead']['image_id']], types.get(row['lead']['id']))
        length = len(block.encode('utf-8'))
        count = block.count('\n')
        if size + length > MAX_BYTES - RESERVE or lines + count > MAX_LINES - 2:
            break
        parts.append(block)
        size += length
        lines += count
        shown += 1
    parts.append(f'Leads displayed: {shown}; omitted: {len(leads) - shown}. Nested details are intentionally omitted.\n')
    parts.append('Full evidence: rerun the same invocation with --format json or --format text.\n')
    return ''.join(parts).encode('utf-8')
