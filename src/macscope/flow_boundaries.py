"""Report conflicting function ownership backed by linker and fallthrough evidence."""
from bisect import bisect_right
from collections import defaultdict
import hashlib
import re

from .errors import Error
from .macho import thin
from .storage import canonical


REASONS = frozenset((
    "fallthrough_into_unconfirmed_function",
    "unconfirmed_function_entry_reached_by_fallthrough",
))
POLICY = "macscope-function-boundary-coverage/1"
RECOVERY_POLICY = "macscope-linker-fallthrough-join/1"
MAX_CANDIDATES = 128
VA = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})")


def recovery_request(data, image):
    """Bind opt-in repair to the complete linker table of the verified slice."""
    parsed = thin(data)
    starts = parsed["loader"]["function_starts"]
    text = [segment for segment in parsed["segments"] if segment["name"] == "__TEXT"]
    if not starts or starts["status"] != "complete" or len(text) != 1 or len(starts["addresses"]) < 2:
        raise Error("boundary_recovery_unavailable",
                    "Boundary recovery requires a complete linker function-start table and a unique __TEXT", 3)
    if image.get("loader", {}).get("function_starts", starts) != starts:
        raise Error("input_integrity", "Recorded function starts differ from the verified slice")
    return {
        "policy": RECOVERY_POLICY,
        "input_sha256": image["sha256"],
        "image_base": text[0]["va"],
        "linker_starts": starts["addresses"],
    }


def recovery_identity(request):
    return {
        "policy": RECOVERY_POLICY,
        "request_sha256": hashlib.sha256(canonical(request) + b"\n").hexdigest(),
    }


def verify_recovery(result, request):
    report = result.get("boundary_recovery")
    if request is None:
        if report is not None:
            raise Error("boundary_recovery_result", "Worker applied an unrequested boundary policy", 10)
        return
    identity = recovery_identity(request)
    if (not isinstance(report, dict) or set(report) != {*identity, "status", "candidates", "reason"}
            or any(report.get(key) != value for key, value in identity.items())
            or report["status"] not in ("complete", "partial")
            or not isinstance(report["candidates"], list) or len(report["candidates"]) > MAX_CANDIDATES):
        raise Error("boundary_recovery_result", "Worker returned invalid boundary recovery provenance", 10)
    starts = [int(address, 16) for address in request["linker_starts"]]
    known = set(starts)
    joined = set()
    previous = -1
    partial = report["reason"] is not None
    if report["reason"] not in (None, "analysis_timeout", "function_limit", "candidate_limit"):
        raise Error("boundary_recovery_result", "Worker returned an invalid boundary scan outcome", 10)
    reasons = {
        "joined", "unbounded_linker_extent", "multiple_competing_entries", "named_competing_entry",
        "noncontiguous_or_oversized_body", "unconfirmed_instruction_extent", "outside_reference", "reference_limit",
    }
    for row in report["candidates"]:
        if (not isinstance(row, dict) or set(row) != {"owner", "competing", "outcome"}
                or any(not isinstance(row[key], str) or not VA.fullmatch(row[key]) for key in ("owner", "competing"))
                or not isinstance(row["outcome"], str) or row["outcome"] not in reasons):
            raise Error("boundary_recovery_result", "Worker returned a malformed boundary candidate", 10)
        owner, competing = (int(row[key], 16) for key in ("owner", "competing"))
        i = bisect_right(starts, competing)
        if (owner not in known or competing in known or not i or starts[i - 1] != owner
                or competing <= previous or (i == len(starts) and row["outcome"] == "joined")):
            raise Error("boundary_recovery_result", "Worker reported a candidate outside its linker extent", 10)
        previous = competing
        if row["outcome"] == "joined":
            joined.add(row["competing"])
        partial |= row["outcome"] != "joined"
    if ((report["status"] == "partial") != partial
            or (partial and result["status"] != "partial")
            or (report["reason"] is not None and report["candidates"])
            or any(function.get("entry_va") in joined for function in result.get("functions", ()))):
        raise Error("boundary_recovery_result", "Worker returned inconsistent boundary coverage", 10)


def gaps(snapshot):
    starts = (snapshot.get("image", {}).get("loader", {}).get("function_starts") or {})
    if starts.get("status") != "complete":
        return {}
    linker = sorted(int(address, 16) for address in starts["addresses"])
    known = set(linker)
    entries = {
        int(function["entry_va"], 16): function for function in snapshot["functions"]
        if function.get("entry_va") is not None and not (function.get("is_external") or function.get("is_thunk"))
    }
    discovered = defaultdict(list)
    for entry in linker:
        function = entries.get(entry)
        if function is None:
            continue
        coverage = function.get("coverage", {})
        if any(coverage.get(facet, {}).get("status") != "complete"
               for facet in ("cfg", "body_ranges")):
            continue
        body = [(int(lo, 16), int(hi, 16)) for lo, hi in function["body_ranges"]]
        for block in function["blocks"]:
            if block.get("edges_truncated"):
                continue
            for edge in block["dsts"]:
                if edge.get("flow") != "FALL_THROUGH" or not (edge.get("to") or "").startswith("0x"):
                    continue
                target = int(edge["to"], 16)
                if (target <= entry or target not in entries or target in known
                        or target != int(block["max"], 16) + 1
                        or linker[bisect_right(linker, target) - 1] != entry
                        or any(lo <= target <= hi for lo, hi in body)):
                    continue
                evidence = {
                    "source": "ghidra_cfg_and_linker_starts", "from": edge["from"],
                    "to": edge["to"], "linker_entry_va": function["entry_va"],
                }
                discovered[function["entry_va"]].append(
                    dict(evidence, reason="fallthrough_into_unconfirmed_function"),
                )
                discovered[entries[target]["entry_va"]].append(
                    dict(evidence, reason="unconfirmed_function_entry_reached_by_fallthrough"),
                )
    return discovered
