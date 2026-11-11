"""Navigation-only projection of recorded spans bound to selected pseudocode."""
from . import pseudocode

MAX_TEXT_CHARS = 524288
MAX_SPANS = 4096
MAX_RANGES_PER_SPAN = 16
MAX_RECORDS = 4
DISPLAY_RANGES = 2
TOKEN_CHARS = 160


def preview(source):
    spans = source.get('address_spans', [])
    total = len(spans) if isinstance(spans, list) else None

    def unavailable(reason):
        return dict(status='unavailable', reason=reason, records=[], omitted_spans=total)

    text = source.get('pseudocode')
    if not isinstance(text, str) or not text:
        return unavailable('pseudocode_unavailable')
    if len(text) > MAX_TEXT_CHARS:
        return unavailable('preview_text_limit')
    if not isinstance(spans, list):
        return unavailable('invalid_recorded_spans')
    if len(spans) > MAX_SPANS:
        return unavailable('preview_span_limit')
    for span in spans:
        if not isinstance(span, dict) or not isinstance(span.get('ranges'), list):
            return unavailable('invalid_recorded_spans')
        if len(span['ranges']) > MAX_RANGES_PER_SPAN:
            return unavailable('preview_range_limit')
    adapted = source
    if 'address_span_coverage' in source:
        coverage = source['address_span_coverage']
        if not isinstance(coverage, dict):
            return unavailable('invalid_span_coverage')
        if coverage.get('available') is not True:
            return unavailable('recorded_span_coverage_unavailable')
        if coverage.get('status') not in ('complete', 'partial') or coverage.get('text_offsets') != 'utf16':
            return unavailable('invalid_span_coverage')
        adapted = dict(source, coverage={'address_spans': dict(status=coverage['status'], emitted=total)})
    try:
        validated, coverage = pseudocode.address_spans(adapted, text)
    except (ValueError, KeyError, TypeError, AttributeError):
        return unavailable('invalid_recorded_spans')
    if not coverage['available']:
        return unavailable('recorded_spans_unavailable')
    utf16 = text.encode('utf-16-le', errors='surrogatepass')
    records = []
    for span in validated[:MAX_RECORDS]:
        token = utf16[span['text_start'] * 2:span['text_end'] * 2].decode('utf-16-le', errors='surrogatepass')
        records.append(dict(text_start=span['text_start'], text_end=span['text_end'],
                            token=token[:TOKEN_CHARS], token_clipped=len(token) > TOKEN_CHARS,
                            ranges=[list(pair) for pair in span['ranges'][:DISPLAY_RANGES]],
                            omitted_ranges=len(span['ranges']) - min(len(span['ranges']), DISPLAY_RANGES)))
    return dict(status=coverage['status'], reason=coverage.get('reason'), records=records,
                omitted_spans=total - len(records))
