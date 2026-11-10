"""CLI coverage review for observable gaps in Ghidra's control-flow evidence."""
import re

from . import body_ownership, flow_boundaries


POLICY = "macscope-computed-jump-coverage/1"
COMPUTED_JUMPS = {"COMPUTED_JUMP", "CONDITIONAL_COMPUTED_JUMP"}
WARNING = re.compile(
    r"^[ \t]*/\* WARNING: (Treating indirect jump as call|Could not recover jumptable at [^\r\n]*?) \*/[ \t]*$",
    re.MULTILINE,
)


def review(function, *, blocks=None, boundary_gaps=()):
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
    gaps.extend(boundary_gaps)
    if not gaps:
        return function
    status = function["decompile_status"]
    policy = flow_boundaries.POLICY if boundary_gaps else POLICY
    result = dict(function, control_flow_gaps=gaps, control_flow_review=policy, engine_decompile_status=status)
    if status == "complete":
        result["decompile_status"] = "partial"
        coverage = function.get("coverage", {})
        result["coverage"] = dict(coverage, pseudocode=dict(coverage.get("pseudocode", {}), status="partial",
                                                            reason="unresolved_control_flow"))
    return result


def snapshot_view(snapshot):
    snapshot = body_ownership.snapshot_view(snapshot)
    boundaries = flow_boundaries.gaps(snapshot)
    functions = [review(function, boundary_gaps=boundaries.get(function.get("entry_va"), ()))
                 for function in snapshot["functions"]]
    affected = sum("control_flow_gaps" in function for function in functions)
    if not affected:
        return snapshot
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
