"""CLI coverage review for observable gaps in Ghidra's control-flow evidence."""
import re


POLICY = "macscope-computed-jump-coverage/1"
COMPUTED_JUMPS = {"COMPUTED_JUMP", "CONDITIONAL_COMPUTED_JUMP"}
WARNING = re.compile(
    r"^[ \t]*/\* WARNING: (Treating indirect jump as call|Could not recover jumptable at [^\r\n]*?) \*/[ \t]*$",
    re.MULTILINE,
)


def review(function, *, blocks=None):
    """Preserve original evidence and distinguish unresolved jumps from printer completion."""
    if function.get("is_thunk") or function.get("is_external"):
        return function
    gaps = []
    if blocks is None:
        blocks = function.get("blocks", ())
    for block in blocks:
        if block.get("flow") in COMPUTED_JUMPS and not any(
            "JUMP" in (edge.get("flow") or "") and edge.get("to") for edge in block["dsts"]
        ):
            gaps.append({"reason": "computed_jump_destination_unavailable", "source": "ghidra_cfg",
                         "block_min": block["min"], "block_max": block["max"]})
    for warning in dict.fromkeys(WARNING.findall(function.get("pseudocode") or "")):
        gaps.append({"reason": "decompiler_unresolved_jump", "source": "ghidra_pseudocode",
                     "warning": warning})
    if not gaps:
        return function
    status = function["decompile_status"]
    result = dict(function, control_flow_gaps=gaps, control_flow_review=POLICY, engine_decompile_status=status)
    if status == "complete":
        result["decompile_status"] = "partial"
        coverage = function.get("coverage", {})
        result["coverage"] = dict(coverage, pseudocode=dict(coverage.get("pseudocode", {}), status="partial",
                                                            reason="unresolved_control_flow"))
    return result


def snapshot_view(snapshot):
    functions = [review(function) for function in snapshot["functions"]]
    affected = sum("control_flow_gaps" in function for function in functions)
    if not affected:
        return snapshot
    return dict(snapshot, functions=functions, status="partial",
                control_flow_review={"policy": POLICY, "affected_functions": affected})
