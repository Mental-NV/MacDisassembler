"""Bounded traversal of recorded call evidence in one image."""
from collections import deque
from . import address_xrefs

DIRECT_CALLS = {"UNCONDITIONAL_CALL", "CONDITIONAL_CALL"}


def graph(snapshot, root, direction, depth, max_edges):
    functions = snapshot["functions"]
    entries = {f["engine_entry"]: f["function_id"] for f in functions}
    by_id = {f["function_id"]: f for f in functions}
    owners = {}
    computed_sites = set()
    for function in functions:
        fid = function["function_id"]
        for ins in function["instructions"]:
            address = ins["addr"]
            if owners.setdefault(address, fid) != fid:
                owners[address] = None
            if "COMPUTED_CALL" in (ins.get("flow") or ""):
                computed_sites.add(address)

    directions = ("callers", "callees") if direction == "both" else (direction,)
    pending = deque([(root["function_id"], 0)])
    discovered = {root["function_id"]: 0}
    expanded = 0
    edges = {}
    gaps = set()
    engine = snapshot["engine"]
    references = address_xrefs.FunctionReferences(engine)
    computed_complete = address_xrefs.complete(engine, address_xrefs.COMPUTED)
    computed_sites.update(row["addr"] for row in engine.get(address_xrefs.COMPUTED, ())
                          if "COMPUTED_CALL" in row["flow"])
    if engine.get("functions_truncated") or engine.get("analysis_timed_out") or engine.get("output_budget_reached"):
        gaps.add("incomplete_analysis")
    if engine.get("coverage", {}).get("functions", {}).get("status", "complete") != "complete":
        gaps.add("function_coverage_incomplete")

    while pending:
        fid, distance = pending.popleft()
        if distance == depth:
            continue
        expanded += 1
        function = by_id[fid]
        for side in directions:
            incoming = side == "callers"
            facet = "xrefs_to_entry" if incoming else "xrefs_from"
            rows, incomplete, recovered = references.records(function, "to" if incoming else "from")
            if incomplete:
                gaps.add(facet + "_incomplete")
            refs = [row for row in rows if "CALL" in row["type"]]
            if not incoming:
                if function.get("control_flow_gaps"):
                    gaps.add("unresolved_control_flow")
                if function.get("instructions_truncated") or function.get("instructions_error"):
                    gaps.add("instructions_incomplete")
                sites = {row["from"] for row in refs}
                refs.extend({"from": ins["addr"], "to": None, "type": ins["flow"]}
                            for ins in function["instructions"]
                            if "CALL" in (ins.get("flow") or "") and ins["addr"] not in sites)
            for ref in refs:
                site, target, ref_type = ref["from"], ref["to"], ref["type"]
                if incoming:
                    caller = owners.get(site)
                else:
                    caller = fid if owners.get(site, None if recovered else fid) == fid else None
                direct = (ref_type in DIRECT_CALLS and site not in computed_sites
                          and (not recovered or site in owners or computed_complete))
                callee = entries.get(target) if direct else None
                if not direct:
                    resolution = "indirect_or_inferred"
                elif callee is None:
                    resolution = "unresolved_target"
                elif caller is None:
                    resolution = "unresolved_caller"
                else:
                    resolution = "direct"
                edge_key = (caller, callee, site, target, ref_type, ref.get("operand_index"))
                if edge_key in edges:
                    continue
                if len(edges) == max_edges:
                    gaps.add("edge_limit")
                    break
                edges[edge_key] = {
                    "caller_function_id": caller, "callee_function_id": callee,
                    "callsite": site, "reported_target": target, "type": ref_type,
                    "resolution": resolution, "evidence": "reference" if target is not None else "instruction",
                    "reference_source": ref.get("source"), "operand_index": ref.get("operand_index"),
                }
                neighbor = caller if incoming else callee
                if resolution == "direct" and neighbor not in discovered:
                    discovered[neighbor] = distance + 1
                    pending.append((neighbor, distance + 1))
            if "edge_limit" in gaps:
                break
        if "edge_limit" in gaps:
            break

    nodes = [{"function_id": fid, "engine_entry": by_id[fid]["engine_entry"],
              "entry_va": by_id[fid]["entry_va"], "names": by_id[fid]["names"],
              "distance": distance}
             for fid, distance in discovered.items()]
    return {
        "root_function_id": root["function_id"],
        "image_id": snapshot["image"]["image_id"], "arch": snapshot["image"]["arch"],
        "direction": direction, "depth": depth, "max_edges": max_edges,
        "expanded_functions": expanded, "nodes": nodes, "edges": list(edges.values()),
    }, sorted(gaps)
