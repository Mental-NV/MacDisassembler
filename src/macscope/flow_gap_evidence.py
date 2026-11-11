"""Add independently located evidence to newly captured focused flow gaps.

Policy 1 remains unclassified. Policy 2 uses request-bound source proofs.
Neither parses an address from a printer warning or rewrites a saved receipt.
"""
import re

from . import flow_gap_classification, focused_tailcalls
from .metadata import VA
from .storage import is_digest


LEGACY_POLICY = "macscope-control-flow-gap-evidence/1"
POLICY = "macscope-control-flow-gap-evidence/2"
MAX_INSTRUCTIONS = 2000
MAX_BLOCKS = 500
MAX_EDGES = 500
MAX_RANGES = 512


def address(value):
    return int(value, 16) if isinstance(value, str) and VA.fullmatch(value) else None


def instruction_index(function):
    rows = function.get("instructions")
    ranges = function.get("body_ranges")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_INSTRUCTIONS or not isinstance(ranges, list):
        return {}, "instruction_evidence_unavailable"
    indexed = {}
    previous_end = -1
    try:
        body = [(address(lo), address(hi)) for lo, hi in ranges]
        if any(lo is None or hi is None or lo > hi for lo, hi in body):
            raise ValueError("Invalid body")
        for row in rows:
            site = address(row["addr"])
            raw = row["bytes"]
            if (site is None or not isinstance(raw, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", raw)
                    or not isinstance(row.get("flow"), str)):
                raise ValueError("Invalid instruction")
            size = len(raw) // 2
            if (function["arch"] == "arm64" and (site % 4 or size != 4)
                    or function["arch"] == "x86_64" and not 1 <= size <= 15
                    or site < previous_end or not any(lo <= site <= site + size - 1 <= hi for lo, hi in body)):
                raise ValueError("Ambiguous instruction")
            indexed[site] = row
            previous_end = site + size
    except (KeyError, TypeError, ValueError):
        return {}, "instruction_evidence_ambiguous"
    return indexed, None


def identity(function, policy):
    origin = function.get("origin")
    proof = origin.get("extent") if isinstance(origin, dict) else None
    if not isinstance(proof, dict) or origin.get("mode") != "focused_readonly_import":
        raise ValueError("Invalid focused gap extent")
    keys = ("function_id", "image_id", "arch", "entry_va", "slice_sha256")
    selected = {key: function[key] for key in keys}
    selected.update(extent_sha256=proof["extent_sha256"], program_sha256=proof["program_sha256"])
    if (selected["arch"] not in ("arm64", "x86_64") or address(selected["entry_va"]) is None
            or any(not is_digest(value) for key, value in selected.items() if key not in ("arch", "entry_va"))
            or proof.get("policy") != ("macscope-focused-import/2" if policy == LEGACY_POLICY
                                       else "macscope-focused-import/3")
            or proof.get("entry_va") != selected["entry_va"]):
        raise ValueError("Invalid focused gap identity")
    return selected


def exact(instruction, function):
    original = instruction["flow"]
    if focused_tailcalls.verified_target(function, instruction) is not None:
        original = instruction["original_flow"]
    return {"kind": "instruction", "instruction_va": instruction["addr"],
            "instruction_bytes": instruction["bytes"], "byte_verification": "selected_extent",
            "original_flow": original,
            "effective_flow": instruction["flow"]}


def location(gap, function, indexed, index_reason):
    # Even an address-looking warning is just text. Native p-code operation
    # addresses identify the observed operations, not the transfer causing them.
    reason = gap["reason"]
    if reason == "decompiler_unresolved_jump":
        return {"kind": "unavailable", "reason": "warning_has_no_independent_site"}
    if reason in ("native_operations_outside_body", "native_operation_scope_unavailable"):
        return {"kind": "unavailable", "reason": "native_scope_does_not_identify_transfer"}
    site = address(gap.get("from"))
    if site is not None and site in indexed:
        return exact(indexed[site], function)
    blocks = function.get("blocks", ())
    if not isinstance(blocks, list) or len(blocks) > MAX_BLOCKS:
        blocks = []
    candidates = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        lo, hi = address(block.get("min")), address(block.get("max"))
        if lo is None or hi is None or lo > hi:
            continue
        if ((gap.get("block_min"), gap.get("block_max")) == (block["min"], block["max"])
                or site is not None and lo <= site <= hi):
            candidates.append(block)
    if candidates:
        block = min(candidates, key=lambda row: (int(row["max"], 16) - int(row["min"], 16),
                                                 int(row["min"], 16), int(row["max"], 16)))
        lo, hi = int(block["min"], 16), int(block["max"], 16)
        # x86 instructions are variable-width: never subtract a guessed width.
        terminal = [row for va, row in indexed.items()
                    if lo <= va and va + len(row["bytes"]) // 2 - 1 == hi
                    and row["flow"] == block.get("flow")]
        if site is None and reason == "computed_jump_destination_unavailable" and len(terminal) == 1:
            return exact(terminal[0], function)
        return {"kind": "block_range", "block_min": block["min"], "block_max": block["max"],
                "reason": index_reason or "exact_instruction_not_established"}
    return {"kind": "unavailable", "reason": index_reason or (
        "capture_incomplete" if reason == "focused_control_flow_incomplete" else "source_site_not_captured")}


def annotate(function, *, policy=None):
    """Call only after focused.verify has checked instructions against the slice."""
    gaps = function.get("control_flow_gaps")
    if not gaps:
        return function
    proof = function.get("origin", {}).get("extent", {})
    policy = policy or (POLICY if proof.get("policy") == "macscope-focused-import/3" else LEGACY_POLICY)
    if policy not in (LEGACY_POLICY, POLICY):
        raise ValueError("Unsupported flow gap evidence policy")
    selected = identity(function, policy)
    indexed, unavailable = instruction_index(function)
    enriched = []
    for gap in gaps:
        site = location(gap, function, indexed, unavailable)
        classification = {"kind": "unclassified", "reason": "classification_not_evaluated"}
        if policy == POLICY:
            classification = flow_gap_classification.classification(function, gap, site,
                                                                     proof["flow_gap_classification"])
        evidence = {"policy": policy, "function": selected, "location": site,
                    "classification": classification}
        enriched.append(dict(gap, evidence=evidence))
    return dict(function, control_flow_gaps=enriched)


def validate_sources(function):
    """Bound and type-check saved sources before invoking the raw detectors."""
    instructions, blocks, ranges = (function.get(key) for key in ("instructions", "blocks", "body_ranges"))
    if (not isinstance(instructions, list) or len(instructions) > MAX_INSTRUCTIONS
            or not isinstance(blocks, list) or len(blocks) > MAX_BLOCKS
            or not isinstance(ranges, list) or len(ranges) > MAX_RANGES):
        raise ValueError("Invalid or oversized flow evidence sources")
    for instruction in instructions:
        if not isinstance(instruction, dict) or not isinstance(instruction.get("flow"), str) or not instruction["flow"]:
            raise ValueError("Invalid captured instruction flow")
        original = instruction.get("original_flow", instruction["flow"])
        if not isinstance(original, str) or not original:
            raise ValueError("Invalid original instruction flow")
        if ("flow_override" in instruction or original != instruction["flow"]):
            if (instruction.get("flow_override") != "CALL_RETURN"
                    or focused_tailcalls.verified_target(function, instruction) is None):
                raise ValueError("Original instruction flow lacks a verified override")
    edges = 0
    for block in blocks:
        if not isinstance(block, dict):
            raise ValueError("Invalid captured CFG block")
        lo, hi = address(block.get("min")), address(block.get("max"))
        destinations = block.get("dsts")
        if (lo is None or hi is None or lo > hi or not isinstance(block.get("flow"), str) or not block["flow"]
                or not isinstance(destinations, list) or type(block.get("edges_truncated")) is not bool):
            raise ValueError("Invalid captured CFG block fields")
        edges += len(destinations)
        if edges > MAX_EDGES:
            raise ValueError("Captured CFG edge limit exceeded")
        for edge in destinations:
            if (not isinstance(edge, dict) or not isinstance(edge.get("flow"), str) or not edge["flow"]
                    or any(key not in edge or edge[key] is not None and not isinstance(edge[key], str)
                           for key in ("from", "to"))):
                raise ValueError("Invalid captured CFG edge")


def validate(function, proof):
    """Validate present new fields; leave legacy receipt contents unchanged."""
    gaps = function.get("control_flow_gaps", [])
    if not isinstance(gaps, (list, tuple)):
        raise ValueError("Invalid control-flow gap collection")
    present = [isinstance(gap, dict) and "evidence" in gap for gap in gaps]
    current = proof.get("policy") == "macscope-focused-import/3"
    if not any(present) and not current:
        return
    if not all(present) or gaps and function.get("decompile_status") == "complete":
        raise ValueError("Incomplete or inconsistent flow gap evidence")
    if function.get("origin", {}).get("extent") != proof:
        raise ValueError("Flow gap extent differs from the focused request")
    validate_sources(function)
    policy = POLICY if current else LEGACY_POLICY
    if any(gap["evidence"].get("policy") != policy for gap in gaps):
        raise ValueError("Flow gap evidence policy differs from its capture")
    if current:
        flow_gap_classification.validate_plan(proof["flow_gap_classification"])
        if proof["flow_gap_classification"]["arch"] != function["arch"]:
            raise ValueError("Flow classification architecture differs from its capture")
    from . import flow_evidence

    raw = dict(function, control_flow_gaps=[{key: value for key, value in gap.items() if key != "evidence"}
                                          for gap in gaps])
    # Validate against the actual detectors, not an attacker-selected reason,
    # edge, or block. A recomputed receipt digest is not semantic validation.
    detected = flow_evidence.review({key: value for key, value in raw.items() if key != "control_flow_gaps"},
                                    arch=function["arch"], focused_extent=proof)
    if detected.get("control_flow_gaps", []) != raw["control_flow_gaps"]:
        raise ValueError("Flow gaps differ from captured instruction and CFG evidence")
    expected = annotate(raw, policy=policy)
    if expected["control_flow_gaps"] != gaps:
        raise ValueError("Invalid or unsupported control-flow gap evidence")
