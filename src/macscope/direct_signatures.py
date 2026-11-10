"""Prove direct call paths that forward an observed x86_64 aggregate result."""
from collections import deque

from .dispatch_returns import direct_target, find_observer, instruction_bytes, observation
from .dispatch_tables import UnverifiedDispatch
from .errors import Error
from .macho import thin


POLICY = "macscope-direct-call-signatures/1"
MAX_FUNCTIONS = 24
MAX_DEPTH = 2
MAX_SITES = 16


def forwarding_return(code, site):
    """Recognize an immediate return, with an optional frame-pointer restore."""
    end = site + len(code[site])
    sequence = [site]
    if code.get(end) == b"\x5d":
        sequence.append(end)
        end += 1
    if code.get(end) != b"\xc3":
        return None
    return sequence + [end]


def arm64_direct_target(address, raw):
    word = int.from_bytes(raw, "little")
    if len(raw) != 4 or word >> 26 != 0b100101:
        return None
    delta = word & 0x3ffffff
    return address + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)


def direct_edges(code, function, entries, decode=direct_target):
    facet = function["coverage"]["xrefs_from"]
    rows = function["xrefs_from_sample"]
    if facet["status"] != "complete" or facet["truncated"] or facet["error"] or facet["emitted"] != len(rows):
        raise UnverifiedDispatch("incomplete_direct_call_references")
    references = {}
    for ref in rows:
        if "CALL" in ref["type"]:
            references.setdefault(ref["from"], set()).add((ref["type"], ref["to"], ref["is_external"]))
    for ins in function["instructions"]:
        if ins["flow"] != "UNCONDITIONAL_CALL":
            continue
        address = int(ins["addr"], 16)
        target = decode(address, code[address])
        if target is None or target < 0:
            continue
        entry = hex(target)
        if entry not in entries or references.get(ins["addr"]) != {("UNCONDITIONAL_CALL", entry, False)}:
            continue
        yield address, entry


def requests(binary, image, root, functions):
    if image["arch"] != "x86_64":
        raise UnverifiedDispatch("unsupported_direct_signature_architecture")
    starts = image["loader"]["function_starts"]
    if not starts or starts["status"] != "complete":
        raise UnverifiedDispatch("unverified_direct_signature_function_starts")
    linker = set(starts["addresses"])
    records = {f["entry_va"]: f for f in functions if f["entry_va"] in linker and not f["is_external"]
               and not f["is_thunk"] and f["decompile_status"] == "complete" and not f["pseudocode_truncated"]}
    entry = root["entry_va"]
    if entry not in records:
        raise UnverifiedDispatch("unverified_direct_signature_selection")

    queue, visited = deque([(entry, [])]), {entry}
    groups, site_count, missing_observer = [], 0, False
    while queue:
        parent, path = queue.popleft()
        function = records[parent]
        try:
            code = instruction_bytes(binary, image, function, 16384)
            edges = list(direct_edges(code, function, records))
        except UnverifiedDispatch:
            continue
        forwarded = []
        for site, target in edges:
            edge = {"owner_va": parent, "call_va": hex(site), "target_va": target,
                    "bytes": code[site].hex()}
            if target not in visited and len(path) < MAX_DEPTH:
                if len(visited) == MAX_FUNCTIONS:
                    raise UnverifiedDispatch("direct_signature_function_limit")
                visited.add(target)
                queue.append((target, [*path, edge]))
            end = forwarding_return(code, site)
            if end and target not in {entry, parent, *(hop["owner_va"] for hop in path)}:
                forwarded.append(dict(edge, sequence=observation("forwarded_return", site, end, code)["sequence"]))
        if not forwarded:
            continue
        try:
            witness = find_observer(binary, image, records, function)
        except UnverifiedDispatch:
            missing_observer = True
            continue
        site_count += len(forwarded)
        if site_count > MAX_SITES:
            raise UnverifiedDispatch("direct_signature_site_limit")
        groups.append({"parent_va": parent, "path": path, "observer": witness, "calls": forwarded})
    if not groups:
        raise UnverifiedDispatch("missing_two_register_observer" if missing_observer
                                 else "no_verified_forwarding_calls")
    return groups


def request(binary, image, root, functions):
    plan = {"policy": POLICY, "image_sha256": image["sha256"], "entry_va": root["entry_va"], "requests": []}
    try:
        plan["requests"] = requests(binary, thin(binary), root, functions)
    except UnverifiedDispatch as error:
        plan["skipped_reason"] = str(error)
    return plan


def decision(plan, report):
    if not plan["requests"] and report is None:
        return {"entry_va": plan["entry_va"], "status": "skipped", "reason": plan["skipped_reason"]}
    if (not plan["requests"] or not isinstance(report, dict) or report.get("policy") != POLICY
            or report.get("entry_va") != plan["entry_va"] or not isinstance(report.get("results"), list)
            or len(report["results"]) != len(plan["requests"])):
        raise Error("direct_signature_result", "Worker did not verify the requested direct signatures", 10)
    applied, skipped = [], []
    for expected, row in zip(plan["requests"], report["results"]):
        sites = [{key: call[key] for key in ("call_va", "target_va")} for call in expected["calls"]]
        if not isinstance(row, dict) or row.get("parent_va") != expected["parent_va"] or row.get("sites") != sites:
            raise Error("direct_signature_result", "Worker reported different direct call sites", 10)
        if row.get("status") == "applied" and row.get("return_storage") == "RDX:8,RAX:8":
            applied.append({"parent_va": row["parent_va"], "sites": sites, "return_storage": row["return_storage"]})
        elif row.get("status") == "skipped" and row.get("reason") in (
                "unsupported_callee_signature", "protected_callee_signature"):
            skipped.append({"parent_va": row["parent_va"], "reason": row["reason"]})
        else:
            raise Error("direct_signature_result", "Worker reported invalid direct signature evidence", 10)
    result = {"entry_va": plan["entry_va"], "status": "applied" if applied else "skipped",
              "applied": applied, "skipped": skipped}
    if not applied:
        result["reason"] = "no_eligible_direct_signatures"
    return result
