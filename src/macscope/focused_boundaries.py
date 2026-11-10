"""Check focused control-flow boundaries before decompiler optimization.

Native high p-code may fold an outside write into an in-body constant. Its
absence from the optimized result therefore cannot establish body confinement.
Use the separately captured instruction listing and BasicBlockModel edges.
"""
from . import focused_tailcalls
from .metadata import VA

POLICY = "macscope-focused-flow-boundaries/1"
MAX_INSTRUCTIONS = 2000
MAX_BLOCKS = 500
MAX_EDGES = 500
MAX_GAPS = 64
DIRECT_JUMPS = {"UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP"}


def address(value):
    return int(value, 16) if isinstance(value, str) and VA.fullmatch(value) else None


def gaps(function, proof):
    rows = []
    incomplete = False

    def gap(reason, **evidence):
        nonlocal incomplete
        if len(rows) < MAX_GAPS:
            row = {"policy": POLICY, "reason": reason, **evidence}
            if row not in rows:
                rows.append(row)
        else:
            incomplete = True

    try:
        start, end = address(proof["entry_va"]), address(proof["end_va_exclusive"])
        ranges = function["body_ranges"]
        instructions, blocks = function["instructions"], function["blocks"]
        if (start is None or end is None or start >= end or not isinstance(ranges, list)
                or not 1 <= len(ranges) <= MAX_INSTRUCTIONS
                or not isinstance(instructions, list) or not 1 <= len(instructions) <= MAX_INSTRUCTIONS
                or not isinstance(blocks, list) or not 1 <= len(blocks) <= MAX_BLOCKS):
            raise ValueError("Incomplete focused collections")
        body = []
        previous = start - 1
        for lo, hi in ranges:
            lo, hi = address(lo), address(hi)
            if lo is None or hi is None or not previous < lo <= hi < end or lo < start:
                raise ValueError("Invalid focused ranges")
            body.append((lo, hi))
            previous = hi

        def contains(value):
            return value is not None and any(lo <= value <= hi for lo, hi in body)

        def contained(lo, hi):
            return lo is not None and hi is not None and any(a <= lo <= hi <= b for a, b in body)

        for facet, count in (("instructions", len(instructions)), ("body_ranges", len(body)), ("cfg", len(blocks))):
            coverage = function.get("coverage", {}).get(facet, {})
            if not isinstance(coverage, dict):
                raise ValueError("Invalid focused coverage")
            if (coverage.get("status") != "complete" or coverage.get("emitted") != count
                    or coverage.get("truncated") is not False or coverage.get("error") is not None):
                incomplete = True
        if any(function.get(key) for key in ("instructions_truncated", "instructions_error", "blocks_truncated",
                                             "edges_truncated", "cfg_error")):
            incomplete = True
        index = {}
        for instruction in instructions:
            if not isinstance(instruction, dict):
                raise ValueError("Invalid focused instruction")
            site = address(instruction["addr"])
            raw = bytes.fromhex(instruction["bytes"])
            if (site in index or not raw or not contained(site, site + len(raw) - 1)
                    or "fallthrough" not in instruction or not isinstance(instruction.get("flow"), str)):
                raise ValueError("Invalid focused instruction")
            index[site] = instruction
            target = instruction["fallthrough"]
            if target is not None:
                decoded = address(target)
                if decoded is None:
                    gap("focused_flow_destination_unavailable", source="ghidra_instruction", **{"from":instruction["addr"], "flow":"FALL_THROUGH"})
                elif not contains(decoded):
                    gap("focused_flow_outside_body", source="ghidra_instruction", **{"from":instruction["addr"], "to":target, "flow":"FALL_THROUGH"})
            elif instruction["flow"] == "FALL_THROUGH" or instruction["flow"].startswith("CONDITIONAL_"):
                gap("focused_flow_destination_unavailable", source="ghidra_instruction",
                    **{"from":instruction["addr"], "flow":"FALL_THROUGH"})
        for instruction in index.values():
            target = address(instruction["fallthrough"])
            if target is not None and contains(target) and target not in index:
                gap("focused_flow_destination_unavailable", source="ghidra_instruction",
                    **{"from":instruction["addr"], "to":instruction["fallthrough"], "flow":"FALL_THROUGH"})
        # Temporary receipt context permits exactly the already-verified tail proofs.
        receipt = dict(function, origin={"extent":proof})
        jump_sources = set()
        covered = set()
        edge_count = 0
        for block in blocks:
            if not isinstance(block, dict):
                raise ValueError("Invalid focused block")
            lo, hi = address(block["min"]), address(block["max"])
            if not contained(lo, hi) or not isinstance(block.get("dsts"), list):
                raise ValueError("CFG block crosses the selected body")
            covered.update(site for site in index if lo <= site <= hi)
            if block.get("edges_truncated") is not False:
                incomplete = True
            for edge in block["dsts"]:
                if not isinstance(edge, dict):
                    raise ValueError("Invalid focused edge")
                edge_count += 1
                if edge_count > MAX_EDGES:
                    raise ValueError("Focused edge limit")
                site, target = address(edge.get("from")), address(edge.get("to"))
                flow = edge.get("flow")
                if site not in index or not isinstance(flow, str):
                    raise ValueError("Invalid focused edge")
                instruction = index[site]
                # A call has a separate return path. A branch overridden as a tail
                # call is exempt only when its exact target matches the bound proof.
                if "CALL" in flow:
                    if instruction["flow"] == "CALL_TERMINATOR":
                        if target is None or focused_tailcalls.verified_target(receipt, instruction) != target:
                            gap("focused_tail_call_unverified", source="ghidra_cfg", **{"from":edge["from"], "to":edge.get("to"), "flow":flow})
                    elif "CALL" not in instruction["flow"]:
                        incomplete = True
                    continue
                if "JUMP" in flow or flow == "FALL_THROUGH":
                    if "JUMP" in flow:
                        jump_sources.add(site)
                    if target is None:
                        gap("focused_flow_destination_unavailable", source="ghidra_cfg", **{"from":edge["from"], "flow":flow})
                    elif not contains(target):
                        gap("focused_flow_outside_body", source="ghidra_cfg", **{"from":edge["from"], "to":edge["to"], "flow":flow})
                    elif target not in index:
                        gap("focused_flow_destination_unavailable", source="ghidra_cfg", **{"from":edge["from"], "to":edge["to"], "flow":flow})
                else:
                    incomplete = True
        if covered != index.keys():
            incomplete = True
        for site, instruction in index.items():
            if instruction["flow"] in DIRECT_JUMPS and site not in jump_sources:
                gap("focused_flow_destination_unavailable", source="ghidra_instruction", **{"from":instruction["addr"], "flow":instruction["flow"]})
    except (KeyError, TypeError, ValueError, AttributeError):
        incomplete = True
    if incomplete:
        rows.append({"policy": POLICY, "reason":"focused_control_flow_incomplete", "source":"ghidra_instruction_and_cfg"})
    return rows
