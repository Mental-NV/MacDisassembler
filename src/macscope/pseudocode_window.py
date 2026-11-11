"""Exact recorded-token navigation. Never infer line ownership or semantics."""
import bisect
from . import pseudocode, terminal

MAX_TEXT = 1024 * 1024
MAX_SPANS = 8192
MAX_LINES = 40
MAX_BYTES = 16 * 1024


def render(result, *, token_start=None, address=None):
    output = ['Recorded-token pseudocode window (not source lines or whole-line ownership)']
    def field(value):
        value = str(value) if isinstance(value, (str, int, bool)) else 'unavailable'
        return terminal.safe(value[:160]) + (' [clipped]' if len(value) > 160 else '')
    def finish(message):
        output.append(message)
        output.append('Full recorded evidence: --format json. Code, spans and receipts unchanged.')
        return ('\n'.join(output)+'\n').encode('utf-8')
    output.append('Outcome: ' + field(result.get('status')))
    data = result.get('data')
    if not isinstance(data, dict): return finish('Window unavailable: no function payload.')
    if 'functions' in data:
        rows = data['functions']
        if not isinstance(rows, list) or len(rows) != 1:
            return finish('Window unavailable: select exactly one function.')
        data = rows[0]
    if not isinstance(data, dict): return finish('Window unavailable: no function payload.')
    output.append('Function: ' + field(data.get('entry_va') or data.get('engine_entry')) +
                  '; ID: ' + field(data.get('function_id')))
    origin = data.get('origin');origin = origin if isinstance(origin, dict) else {}
    output.append('Recorded source mode: ' + field(origin.get('mode')) + '; job: ' + field(origin.get('job_id')))
    output.append('Decompile: ' + field(data.get('decompile_status')) + '; pseudocode truncated: ' + field(data.get('pseudocode_truncated')))
    code = data.get('pseudocode')
    if not isinstance(code, str) or not code: return finish('Window unavailable: no pseudocode.')
    spans = data.get('address_spans', [])
    if (len(code) > MAX_TEXT or not isinstance(spans, list) or len(spans) > MAX_SPANS
            or any(not isinstance(s, dict) or not isinstance(s.get('ranges'), list) for s in spans)):
        return finish('Window unavailable: invalid or oversized recorded mapping.')
    if sum(len(s['ranges']) for s in spans) > MAX_SPANS:
        return finish('Window unavailable: mapping budget exceeded.')
    if len(code.encode('utf-16-le', errors='surrogatepass')) > MAX_TEXT:
        return finish('Window unavailable: text mapping budget exceeded.')
    # Direct saved-query records may carry the already-validated coverage shape.
    checked = data
    if 'address_span_coverage' in data:
        info = data['address_span_coverage']
        if (not isinstance(info, dict) or info.get('available') is not True
                or info.get('text_offsets') != 'utf16' or info.get('status') not in ('complete', 'partial')):
            return finish('Window unavailable: recorded query mapping unavailable.')
        checked = dict(data, coverage={'address_spans': {'status': info['status'], 'emitted': len(spans)}})
    try:
        spans, info = pseudocode.address_spans(checked, code)
    except (ValueError, TypeError, KeyError, AttributeError):
        return finish('Window unavailable: invalid recorded mapping.')
    output.append('Recorded token mapping coverage: ' + field(info.get('status')))
    if not info.get('available'): return finish('Window unavailable: ' + field(info.get('reason')))
    if (token_start is None) == (address is None): return finish('Window unavailable: exactly one anchor required.')
    if token_start is not None:
        if type(token_start) is not int or token_start < 0: return finish('Window unavailable: invalid UTF-16 start.')
        matches = [s for s in spans if s['text_start'] == token_start]
    else:
        if not isinstance(address, str) or not pseudocode.VA.fullmatch(address):
            return finish('Window unavailable: invalid unslid address.')
        matches = [s for s in spans if any(int(lo,16) <= int(address,16) <= int(hi,16) for lo,hi in s['ranges'])]
    if not matches: return finish('Window unavailable: no exact recorded anchor match.')
    if len(matches) != 1:
        output.append('Matching UTF-16 token starts: ' + ', '.join(str(s['text_start']) for s in matches[:8]))
        utf16 = code.encode('utf-16-le', errors='surrogatepass')
        size = len(('\n'.join(output)+'\n').encode('utf-8'))
        shown = 0
        for candidate in matches[:8]:
            token = utf16[candidate['text_start']*2:candidate['text_end']*2].decode('utf-16-le', errors='surrogatepass')
            preview = terminal.safe(token[:80]) + (' [clipped]' if len(token) > 80 else '')
            line = f"Candidate UTF-16 [{candidate['text_start']}, {candidate['text_end']}): {preview}"
            cost = len((line+'\n').encode('utf-8'))
            if size + cost > MAX_BYTES - 1024: break
            output.append(line); size += cost; shown += 1
        return finish(f'Window ambiguous: {len(matches)} recorded spans match; token starts omitted: {max(0,len(matches)-8)}; previews omitted: {len(matches)-shown}. Select --window-token-start explicitly.')
    anchor = matches[0]
    code_lines = code.split('\n');starts = [];offset = 0
    for line in code_lines:
        starts.append(offset);offset += len(line.encode('utf-16-le', errors='surrogatepass'))//2 + 1
    first = bisect.bisect_right(starts, anchor['text_start'])-1
    last = bisect.bisect_right(starts, anchor['text_end']-1)-1
    output.append(f"Anchor UTF-16 [{anchor['text_start']}, {anchor['text_end']}); token presentation lines {first+1}..{last+1}.")
    token = code.encode('utf-16-le', errors='surrogatepass')[anchor['text_start']*2:anchor['text_end']*2].decode('utf-16-le', errors='surrogatepass')
    output.append('Recorded token text (possibly clipped): ' + field(token))
    output.append('Recorded inclusive token ranges: ' + ', '.join(lo+'..'+hi for lo,hi in anchor['ranges'][:8]) +
                  f"; ranges omitted: {max(0,len(anchor['ranges'])-8)}.")
    output.append('Context lines have no inferred address mapping. Clipped prefixes may omit the anchored token.')
    begin = max(0, first-10);end = min(len(code_lines), begin+MAX_LINES)
    begin = max(0,end-MAX_LINES)
    displayed = 0;clipped = 0
    size = len(('\n'.join(output)+'\n').encode('utf-8'))
    for index in range(begin,end):
        original = code_lines[index];was_clipped = len(original)>256
        line = f'{index+1:4d} | ' + terminal.safe(original[:256]) + (' [clipped]' if was_clipped else '')
        cost = len((line+'\n').encode('utf-8'))
        if size+cost > MAX_BYTES-1024: break
        output.append(line);size += cost;displayed += 1;clipped += was_clipped
    anchor_shown = max(0, min(last+1,begin+displayed)-max(first,begin))
    return finish(f'Omitted code lines: {len(code_lines)-displayed} (before {begin}, after {len(code_lines)-begin-displayed}); '
                  f'anchor lines omitted: {last-first+1-anchor_shown}; clipped lines: {clipped}.')
