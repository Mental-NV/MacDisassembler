"""Bounded review of shared virtual ranges in saved function bodies."""
from .metadata import VA


POLICY = "macscope-function-body-overlap/1"
MAX_RANGES = 100000


def intervals(functions, start, end):
    spans = []
    scanned = 0
    for function in functions:
        entry = function.get("engine_entry", function.get("entry_va"))
        if not isinstance(entry, str) or not VA.fullmatch(entry) or function.get("address_space", "ram") != "ram":
            continue
        for pair in function.get("body_ranges", ()):
            if scanned == MAX_RANGES:
                return spans, True
            scanned += 1
            if (not isinstance(pair, (list, tuple)) or len(pair) != 2
                    or not all(isinstance(value, str) and VA.fullmatch(value) for value in pair)):
                continue
            first, last = int(pair[0], 16), int(pair[1], 16)
            first, last = max(start, first), min(end - 1, last)
            if first <= last:
                spans.append((first, last, entry))
    return spans, False


def find(functions, start=0, end=2**64):
    spans, truncated = intervals(functions, start, end)
    witnesses = {}
    leader = alternate = None
    # Track the farthest ends for two distinct owners. The earliest
    # intersection with another owner suffices to mark each affected function.
    for first, last, entry in sorted(spans):
        previous = leader if leader and leader[2] != entry else alternate
        if previous and previous[1] >= first:
            other = previous[2]
            shared = (first, min(last, previous[1]))
            witnesses.setdefault(entry, (other, *shared))
            witnesses.setdefault(other, (entry, *shared))
        span = (first, last, entry)
        if leader is None or last > leader[1]:
            if leader and leader[2] != entry:
                alternate = leader
            leader = span
        elif leader[2] != entry and (alternate is None or last > alternate[1]):
            alternate = span
    return witnesses, truncated


def report(functions, witnesses, truncated):
    if not witnesses and not truncated:
        return None, {}
    ids = {f["engine_entry"]: f["function_id"] for f in functions}
    by_id = {ids[entry]: {"other_function_id": ids[other], "start_va": hex(first), "last_va": hex(last)}
             for entry, (other, first, last) in witnesses.items()}
    return {"policy": POLICY, "affected_functions": len(by_id), "scan_truncated": truncated}, by_id


def snapshot_view(snapshot, findings=None):
    if "body_ownership" in snapshot:
        return snapshot
    functions = snapshot["functions"]
    summary, by_id = report(functions, *(find(functions) if findings is None else findings))
    if summary is None:
        return snapshot
    rows = [dict(f, body_overlap=by_id[f["function_id"]]) if f["function_id"] in by_id else f for f in functions]
    return dict(snapshot, functions=rows, body_ownership=summary, status="partial")


def range_view(functions, start, end):
    summary, by_id = report(functions, *find(functions, start, end))
    if summary is None:
        return None
    return dict(summary, witnesses=[dict(witness, function_id=fid) for fid, witness in sorted(by_id.items())])


def reasons(summary):
    result = ["function_body_overlap"] if summary.get("affected_functions") else []
    if summary.get("scan_truncated"):
        result.append("function_body_review_limit")
    return result


def query_view(response, selected):
    if "body_overlap" not in selected:
        return response
    cov = response["coverage"]
    reason = ";".join(filter(None, (cov["truncation_reason"], "function_body_overlap")))
    return dict(response, status="partial", data=dict(response["data"], body_overlap=selected["body_overlap"]),
                coverage=dict(cov, status="partial", truncation_reason=reason))
