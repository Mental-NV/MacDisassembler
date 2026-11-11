"""Deliberate, byte-verified gap derivation from a pinned analyzed snapshot.

Receipt replay never backfills this extension. Source references resolve only
inside the committed project; no engine or original application is required.
"""
from . import flow_evidence, flow_gap_evidence as sites, metadata
from .errors import Error
from .macho import thin
from .storage import is_digest

POLICY = "macscope-analyzed-flow-gap-evidence/1"
MAX_BYTES = 8192
SOURCE_FIELD = "flow_gap_sources"


def _raw(gaps):
    if not isinstance(gaps, list) or any(not isinstance(gap, dict) for gap in gaps):
        raise ValueError("Invalid analyzed gap collection")
    return [{key: value for key, value in gap.items() if key != "evidence"} for gap in gaps]


def _selected(snapshot, function):
    rows = [row for row in snapshot["functions"] if row.get("function_id") == function.get("function_id")]
    if len(rows) != 1 or rows[0].get("entry_va") != function.get("entry_va"):
        raise ValueError("Analyzed gap source is missing or ambiguous")
    if sum(row.get("entry_va") == function["entry_va"] for row in snapshot["functions"]) != 1:
        raise ValueError("Analyzed gap entry is ambiguous")
    return rows[0]


def _verify(project, image, function):
    """Verify at most 2,000 instructions / 8 KiB, without decoding the image."""
    binary = metadata.verified_slice(project, image)
    ranges = function.get("body_ranges")
    if ranges is None and "body_ranges" not in function:
        return {}, "instruction_evidence_unavailable"
    if not isinstance(ranges, list):
        raise ValueError("Invalid saved instruction body ranges")
    if len(ranges) > sites.MAX_RANGES:
        return {}, "instruction_evidence_limit"
    indexed, reason = sites.instruction_index(function)
    if not indexed:
        return {}, reason
    if sum(len(row["bytes"]) // 2 for row in indexed.values()) > MAX_BYTES:
        return {}, "instruction_evidence_limit"
    parsed = thin(binary, include_section_linkage=True)
    if parsed["arch"] != image["arch"]:
        raise ValueError("Saved slice architecture differs")
    for address, row in indexed.items():
        raw = bytes.fromhex(row["bytes"])
        offset = metadata.mapped_location(parsed, address, len(raw), from_file=False)
        sections = [section for section in parsed["sections"] if section.get("file_offset") is not None
                    and int(section["va"], 16) <= address
                    and address + len(raw) <= int(section["va"], 16) + int(section["size"], 16)]
        if (offset is None or len(sections) != 1 or not sections[0]["protections"] & 4
                or not int(sections[0]["flags"], 16) & 0x80000400):
            return {}, "instruction_mapping_unavailable"
        table = parsed["loader"].get("data_in_code")
        if table and (table["status"] != "complete" or any(
                offset < int(item["slice_file_offset"], 16) + item["length"]
                and int(item["slice_file_offset"], 16) < offset + len(raw) for item in table["records"])):
            return {}, "instruction_data_in_code"
        encryption = parsed["loader"].get("encryption")
        if encryption and encryption["cryptid"] and (
                offset < int(encryption["slice_file_offset"], 16) + int(encryption["size"], 16)
                and int(encryption["slice_file_offset"], 16) < offset + len(raw)):
            return {}, "instruction_encrypted"
        if binary[offset:offset + len(raw)] != raw:
            raise ValueError("Saved instruction bytes differ from the selected slice")
    return indexed, None


def _derive(project, image, snapshot, source, function, *, fresh=False, program=None):
    selected = _selected(snapshot, function)
    identity = {key: selected[key] for key in ("function_id", "image_id", "arch", "entry_va")}
    identity.update(slice_sha256=image["sha256"], analysis_id=snapshot["analysis_id"],
                    snapshot_sha256=source["snapshot_sha256"],
                    program_sha256=program or source["analysis_program_sha256"])
    if (identity["arch"] != image["arch"] or identity["image_id"] != image["image_id"]
            or sites.address(identity["entry_va"]) is None
            or any(not is_digest(value) for key, value in identity.items() if key not in ("arch", "entry_va"))):
        raise ValueError("Invalid analyzed gap identity")
    indexed, reason = _verify(project, image, selected)
    # These raw gaps come from the pinned snapshot, including cross-function
    # fallthrough proofs. No predecessor bytes are attributed to the selection.
    clean = dict(snapshot, functions=[{key: value for key, value in row.items()
                                        if key != "control_flow_gaps"} for row in snapshot["functions"]])
    viewed = flow_evidence.snapshot_view(clean)
    saved = _selected(viewed, function)
    if fresh:
        base = dict(selected, pseudocode=function.get("pseudocode"),
                    decompile_status=function["decompile_status"])
        base.pop("control_flow_gaps", None)
        base.pop("native_scope", None)
        base.pop("engine_decompile_status", None)
        if "native_scope" in function:
            base["native_scope"] = function["native_scope"]
            from .focused import verify_native_scope
            verify_native_scope(base)
        from .flow_boundaries import REASONS
        boundaries = [gap for gap in saved.get("control_flow_gaps", ()) if gap["reason"] in REASONS]
        detected = flow_evidence.review(base, arch=image["arch"], boundary_gaps=boundaries)
    else:
        detected = saved
    gaps = _raw(detected.get("control_flow_gaps", []))
    result = []
    for gap in gaps:
        if gap["reason"] == "unconfirmed_function_entry_reached_by_fallthrough":
            location = {"kind": "unavailable", "reason": "source_belongs_to_related_function"}
        else:
            location = sites.location(gap, selected, indexed, reason)
        if location["kind"] == "instruction":
            location = dict(location, byte_verification="saved_slice")
        result.append(dict(gap, evidence={"policy": POLICY, "function": identity,
                           "derivation": "fresh_query_with_saved_flow" if fresh else "saved_snapshot",
                           "location": location, "classification": {
                               "kind": "unclassified", "reason": "classification_not_evaluated"}}))
    return result


def annotate_selected(project, image, snapshot, source, function):
    """Return a derived view; do not mutate the committed snapshot or annotations."""
    if not function.get("control_flow_gaps"):
        return function
    try:
        # Older cached snapshots did not persist both durable source pins. They
        # remain readable, but cannot acquire a new byte/provenance claim.
        pins = ("snapshot_sha256", "analysis_program_sha256")
        if not isinstance(source, dict):
            raise ValueError("Invalid saved analysis source")
        if any(key in source and not is_digest(source[key]) for key in pins):
            raise ValueError("Invalid supplied saved analysis pin")
        if any(key not in source for key in pins):
            if SOURCE_FIELD in function or any("evidence" in gap for gap in function["control_flow_gaps"]):
                raise ValueError("Existing analyzed evidence is missing its source pins")
            return function
        gaps = _derive(project, image, snapshot, source, function)
        if _raw(gaps) != _raw(function["control_flow_gaps"]):
            raise ValueError("Selected gaps differ from the saved sources")
        return dict(function, control_flow_gaps=gaps)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        raise Error("query_receipt", "Invalid saved analyzed flow evidence") from error


def annotate_query(project, image, snapshot, source, response, request):
    """Enrich a NEW result before publishing, after query_view adds boundaries.

    Fresh native_scope must be copied into response.data by the producer. Other
    raw flow sources are durable snapshot references, not claimed worker capture.
    Switch-assisted CFG changes remain on their existing contract for now.
    """
    data = response["data"]
    if not data.get("control_flow_gaps") or "switch_table_recovery" in data.get("origin", {}):
        return response
    try:
        gaps = _derive(project, image, snapshot, source, data, fresh=True,
                       program=request["source_program_sha256"])
        if _raw(gaps) != _raw(data["control_flow_gaps"]):
            raise ValueError("Fresh gaps differ from their durable raw sources")
        data = dict(data, control_flow_gaps=gaps, **{SOURCE_FIELD: {"policy": POLICY}})
        return dict(response, data=data)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        raise Error("query_receipt", "Invalid fresh analyzed flow evidence") from error


def validate_result(project, result, request):
    """Production writer/reader hook. Old receipts are returned untouched."""
    try:
        required = "flow_gap_policy" in request
        if required and request["flow_gap_policy"] != POLICY:
            raise ValueError("Unsupported analyzed flow evidence request policy")
        data = result.get("data")
        if not isinstance(data, dict):
            if required:
                raise ValueError("Missing required analyzed flow result")
            return
        if required and ("switch_table_recovery" in request
                         or "switch_table_recovery" in data.get("origin", {})):
            raise ValueError("Analyzed flow evidence policy excludes switch-assisted results")
        gaps = data.get("control_flow_gaps", [])
        if not isinstance(gaps, list):
            raise ValueError("Invalid analyzed gap collection")
        present = SOURCE_FIELD in data or isinstance(gaps, list) and any(
            isinstance(gap, dict) and "evidence" in gap for gap in gaps)
        if not present and not required:
            return
        image = project.select(image=request["image_id"])
        image = dict(image, active_analysis=request["source_analysis_id"])
        snapshot, source = project.snapshot(image)
        from .jobs import matches_program
        if (request.get("source_snapshot_sha256") != source["snapshot_sha256"]
                or not matches_program(source, request.get("source_program_sha256"), "analysis_program_sha256")
                or any(data.get(key) != request.get(key) for key in ("function_id", "image_id", "entry_va"))
                or request.get("slice_sha256") != image["sha256"]
                or request.get("artifact_sha256") != image["artifact_sha256"]
                or result.get("analysis_id") != snapshot["analysis_id"]
                or data.get("arch") != image["arch"]
                or data.get("origin", {}).get("mode") != "fresh_readonly"):
            raise ValueError("Analyzed source reference differs from request")
        expected = _derive(project, image, snapshot, source, data, fresh=True,
                           program=request["source_program_sha256"])
        if expected:
            if (data.get(SOURCE_FIELD) != {"policy": POLICY} or result.get("status") != "partial"
                    or data.get("decompile_status") == "complete"
                    or any(not isinstance(gap, dict) or "evidence" not in gap for gap in gaps)):
                raise ValueError("Required analyzed evidence extension is missing or inconsistent")
        elif present:
            raise ValueError("Analyzed evidence extension has no source gaps")
        if gaps != expected:
            raise ValueError("Analyzed evidence differs from durable sources")
    except Error as error:
        if error.code == "query_receipt":
            raise
        raise Error("query_receipt", "Saved analyzed flow source cannot be verified") from error
    except (KeyError, TypeError, ValueError, IndexError, AttributeError, RecursionError) as error:
        raise Error("query_receipt", "Invalid saved analyzed flow evidence") from error
