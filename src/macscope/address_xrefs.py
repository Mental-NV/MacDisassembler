"""Address-scoped views of committed reference and instruction evidence."""
from .metadata import VA
from .storage import canonical


REFERENCES = "address_references"
COMPUTED = "computed_flow_sites"


def complete(engine, key):
    facet = engine.get("coverage", {}).get(key, {})
    return (key in engine and facet.get("status") == "complete" and not facet.get("truncated")
            and not facet.get("error") and facet.get("emitted") == len(engine[key]))


def flow_kind(value):
    if "CALL" in value:
        return "call"
    if "JUMP" in value:
        return "jump"
    return None


def match(snapshot, address, direction):
    engine = snapshot["engine"]
    gaps = []
    indexed = complete(engine, REFERENCES)
    flow_complete = complete(engine, COMPUTED)
    if not indexed:
        gaps.append("image_reference_index_incomplete" if REFERENCES in engine else "image_reference_index_unavailable")
    if not flow_complete:
        gaps.append("computed_flow_coverage_incomplete")
    if engine.get("analysis_timed_out"):
        gaps.append("analysis_timed_out")

    refs = [row for row in engine.get(REFERENCES, ()) if row[direction] == address]
    functions = snapshot["functions"]
    if not indexed:
        seen = {canonical(row) for row in refs}
        for function in functions:
            for key in ("xrefs_to_entry", "xrefs_from_sample"):
                for row in function.get(key, ()):
                    if row[direction] == address and (key_bytes := canonical(row)) not in seen:
                        refs.append(row)
                        seen.add(key_bytes)

    sources = {address} if direction == "from" else {row["from"] for row in refs}
    flows = {row["addr"]: row["flow"] for row in engine.get(COMPUTED, ()) if row["addr"] in sources}
    if not flow_complete:
        for function in functions:
            for row in function.get("instructions", ()):
                flow = row.get("flow") or ""
                if row["addr"] in sources and "COMPUTED" in flow and flow_kind(flow):
                    flows.setdefault(row["addr"], flow)

    rows = []
    for ref in refs:
        kind = ref["type"]
        indirect = "COMPUTED" in kind or kind == "INDIRECTION" or (flow_kind(kind) and ref["from"] in flows)
        status = "unresolved" if ref["to"] is None else "indirect_or_inferred" if indirect else "recorded"
        rows.append(dict(ref, target_status=status, evidence="ghidra_reference"))
    if direction == "from" and address in flows:
        flow = flows[address]
        if not any(row["to"] and flow_kind(row["type"]) == flow_kind(flow) for row in refs):
            rows.append({"from": address, "to": None, "type": flow, "source": None, "operand_index": None,
                         "target_status": "unresolved", "evidence": "ghidra_instruction"})
            gaps.append("unresolved_computed_target")

    other = "from" if direction == "to" else "to"

    def order(row):
        value = row[other]
        if value is not None and VA.fullmatch(value):
            return 0, int(value, 16), canonical(row)
        return 1, 0, canonical(row)

    return sorted(rows, key=order), gaps


def omit_for_snapshot_budget(snapshot):
    engine = snapshot.get("engine", {})
    if REFERENCES not in engine:
        return False
    for key in (REFERENCES, COMPUTED):
        engine[key] = []
        engine["coverage"][key] = {"status": "partial", "emitted": 0, "total": None, "truncated": True,
                                   "error": None, "reason": "normalized_snapshot_budget"}
    engine["status"] = snapshot["status"] = "partial"
    return True
