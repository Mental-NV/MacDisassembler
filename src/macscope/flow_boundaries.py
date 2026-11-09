"""Report conflicting function ownership backed by linker and fallthrough evidence."""
from bisect import bisect_right
from collections import defaultdict


REASONS = frozenset((
    "fallthrough_into_unconfirmed_function",
    "unconfirmed_function_entry_reached_by_fallthrough",
))
POLICY = "macscope-function-boundary-coverage/1"


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
