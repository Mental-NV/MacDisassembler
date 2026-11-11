"""Bounded reading view of existing evidence, not a semantic analyzer."""
from . import objc_type_evidence, terminal

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
    source = 'selected saved query' if code is query else 'saved function'
    view.line(f"Pseudocode source: {source}; decompile status: {f(code.get('decompile_status'))}")
    view.line("Recorded function signature: " + f(function.get('signature')))
    view.line("Recorded pseudocode truncation: " + f(code.get('pseudocode_truncated')))
    view.line(f"Source job: {f((code.get('origin') or {}).get('job_id'))}; query status: {f((query or {}).get('status'))}")
    if isinstance(query, dict) and code is function:
        view.line('Selected query has no pseudocode; displayed fallback is the saved function, not a successful query.')
    if types is None:
        view.line('Declaration context not requested/available. Add --objc-types for exact metadata binding.')
    else:
        view.line(f"Declaration context: {f(types['status'])}; reason {f(types['reason'])}")
        view.line('Recorded type encoding: ' + f((types.get('declaration') or {}).get('type_encoding')))
        decoded = types.get('decoded_types') or {}
        view.line('Decoded declaration (generated): ' + f(decoded.get('declaration')))
        abi = types.get('abi_projection') or {}
        view.line(f"ABI roles: {f(abi.get('status'))}; conditional on conforming IMP, not implementation verification.")
        view.line('ABI argument labels are generated; declarations do not verify implementation types.')
        view.items('ABI arguments', abi.get('arguments') or [], 8,
                   lambda i, x: f(x.get('label')) + ' [' + f(x.get('role')) + '] -> ' + f(x.get('register')))
        if abi.get('reasons'):
            view.line('ABI unsupported: ' + f(', '.join(abi['reasons'])))
        if abi.get('return_value'):
            view.line('Conditional return register: ' + f(abi['return_value'].get('register')))
    view.items('Flow gaps', code.get('control_flow_gaps') or [], 4,
               lambda i, x: f(x.get('reason')))
    pseudocode = code.get('pseudocode')
    lines = pseudocode.splitlines() if isinstance(pseudocode, str) else []
    view.line('Raw pseudocode; numbers are display indices, not recovered source lines or address mappings.')
    view.items('Code lines', lines, 40, lambda i, x: f'{i + 1}: ' + f(x))
    if not lines:
        view.line('Pseudocode unavailable: ' + f(code.get('decompile_error')))
    view.line('Instruction/reference samples below come from the saved function, not the query pseudocode.')
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
