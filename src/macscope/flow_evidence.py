"""CLI coverage review for observable gaps in Ghidra's control-flow evidence."""
import re

from . import body_ownership, flow_boundaries
from .metadata import VA


POLICY = "macscope-computed-jump-coverage/1"
TRAP_POLICY = "macscope-arm64-brk-flow/1"
MAX_TRAP_INSTRUCTIONS = 100000
MAX_TRAP_PROOFS = 256
COMPUTED_JUMPS = {"COMPUTED_JUMP", "CONDITIONAL_COMPUTED_JUMP"}
WARNING = re.compile(
    r"^[ \t]*/\* WARNING: (Treating indirect jump as call|Could not recover jumptable at [^\r\n]*?) \*/[ \t]*$",
    re.MULTILINE,
)


def trap_instructions(instructions, arch):
    """Fail closed on incomplete or ambiguous instruction evidence, never on text."""
    if arch != "arm64" or not isinstance(instructions, (list, tuple)):
        return {}
    if len(instructions) > MAX_TRAP_INSTRUCTIONS:
        return {}
    indexed = {}
    for row in instructions:
        if not isinstance(row, dict):
            return {}
        address, encoded = row.get("addr"), row.get("bytes")
        if (not isinstance(address, str) or not VA.fullmatch(address)
                or not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-fA-F]{8}", encoded)):
            return {}
        address = int(address, 16)
        if address % 4 or address in indexed:
            return {}
        indexed[address] = row
    return indexed


def trap_proof(block, instructions):
    first, last = block.get("min"), block.get("max")
    if not all(isinstance(value, str) and VA.fullmatch(value) for value in (first, last)):
        return None
    address = int(last, 16) - 3
    if int(first, 16) > address:
        return None
    row = instructions.get(address)
    if row is None or row.get("flow") != block.get("flow"):
        return None
    word = int.from_bytes(bytes.fromhex(row["bytes"]), "little")
    if word & 0xffe0001f != 0xd4200000:
        return None
    return {"policy": TRAP_POLICY, "reason": "arm64_brk_exception", "source": "instruction_bytes",
            "arch": "arm64", "instruction_va": hex(address), "instruction_bytes": row["bytes"],
            "immediate": (word >> 5) & 0xffff, "block_min": first, "block_max": last,
            "engine_flow": block["flow"]}


def review(function, *, blocks=None, boundary_gaps=(), arch=None, instructions=None):
    """Preserve original evidence and distinguish unresolved jumps from printer completion."""
    if function.get("is_thunk") or function.get("is_external"):
        return function
    if "control_flow_traps" in function:
        function = {key: value for key, value in function.items() if key != "control_flow_traps"}
    gaps = []
    traps = []
    decoded = trap_instructions(function.get("instructions", ()) if instructions is None else instructions, arch)
    if blocks is None:
        blocks = function.get("blocks", ())
    for block in blocks:
        if block.get("flow") in COMPUTED_JUMPS and not any(
            "JUMP" in (edge.get("flow") or "") and edge.get("to") for edge in block["dsts"]
        ):
            proof = trap_proof(block, decoded) if len(traps) < MAX_TRAP_PROOFS else None
            if proof is not None:
                traps.append(proof)
                continue
            gaps.append({"reason": "computed_jump_destination_unavailable", "source": "ghidra_cfg",
                         "block_min": block["min"], "block_max": block["max"]})
    for warning in dict.fromkeys(WARNING.findall(function.get("pseudocode") or "")):
        gaps.append({"reason": "decompiler_unresolved_jump", "source": "ghidra_pseudocode",
                     "warning": warning})
    scope = function.get("native_scope")
    if scope and scope.get("status") != "complete":
        gaps.append({"reason": "native_operations_outside_body" if scope.get("outside_body_operations")
                     else "native_operation_scope_unavailable", "source": "ghidra_native_pcode",
                     "scope": scope})
    gaps.extend(boundary_gaps)
    if traps:
        function = dict(function, control_flow_traps=traps)
    if not gaps:
        return function
    status = function.get("engine_decompile_status", function["decompile_status"])
    policy = flow_boundaries.POLICY if boundary_gaps else POLICY
    result = dict(function, control_flow_gaps=gaps, control_flow_review=policy, engine_decompile_status=status)
    if function["decompile_status"] == "complete":
        result["decompile_status"] = "partial"
        coverage = function.get("coverage", {})
        result["coverage"] = dict(coverage, pseudocode=dict(coverage.get("pseudocode", {}), status="partial",
                                                            reason="unresolved_control_flow"))
    return result


def snapshot_view(snapshot):
    snapshot = body_ownership.snapshot_view(snapshot)
    boundaries = flow_boundaries.gaps(snapshot)
    functions = [review(function, arch=snapshot.get("image", {}).get("arch"),
                        boundary_gaps=boundaries.get(function.get("entry_va"), ()))
                 for function in snapshot["functions"]]
    affected = sum("control_flow_gaps" in function for function in functions)
    if not affected:
        return dict(snapshot, functions=functions) if functions != snapshot["functions"] else snapshot
    policy = flow_boundaries.POLICY if boundaries else POLICY
    return dict(snapshot, functions=functions, status="partial",
                control_flow_review={"policy": policy, "affected_functions": affected})


def query_view(response, selected):
    """Apply saved ownership evidence to a new or previously published query."""
    boundary_gaps = [gap for gap in selected.get("control_flow_gaps", ())
                     if gap["reason"] in flow_boundaries.REASONS]
    if not boundary_gaps:
        return body_ownership.query_view(response, selected)
    data = response["data"]
    engine_status = data.get("engine_decompile_status", data["decompile_status"])
    displayed = dict(data, control_flow_review=flow_boundaries.POLICY,
                     control_flow_gaps=[*data.get("control_flow_gaps", ()), *boundary_gaps],
                     engine_decompile_status=engine_status)
    if displayed["decompile_status"] == "complete":
        displayed["decompile_status"] = "partial"
    coverage = dict(response["coverage"], status="partial", truncation_reason="unresolved_control_flow")
    return body_ownership.query_view(dict(response, data=displayed, status="partial", coverage=coverage), selected)
