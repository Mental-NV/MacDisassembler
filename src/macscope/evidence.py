"""Bounded handoffs from pinned, committed analyses and optional query receipts."""
from collections import defaultdict
import json
import re

from . import address_xrefs, body_ownership, calls, flow_evidence, jobs, metadata, objc, search
from .errors import Error
from .macho import read_regular
from .storage import canonical, identity, is_digest


LEADS_SCHEMA = "macscope-evidence-leads/1"
REPORT_SCHEMA = "macscope-evidence/1"
MAX_LEADS = 16
MAX_IMAGES = 4
MAX_MANIFEST_BYTES = 65536
MAX_LEAD_BYTES = 512 * 1024
MAX_MATCHES = 16
MAX_REFERENCES = 64
MAX_EDGES = 32
IMAGE_FIELDS = {"image_id", "arch", "artifact_sha256", "slice_sha256", "analysis_id"}
LEAD_FIELDS = {"id", "image_id", "kind", "value"}
KINDS = {"address", "function_id", "name", "objc_selector", "string"}
FUNCTION_FIELDS = (
    "function_id", "entry_va", "engine_entry", "address_space", "names", "signature", "body_ranges",
    "is_external", "is_thunk", "thunk_target", "instructions", "instruction_bytes_sha256",
    "pseudocode", "decompile_status", "decompile_error", "pseudocode_truncated", "address_spans",
    "facets", "coverage", "origin", "control_flow_review", "control_flow_gaps", "body_overlap",
)


def unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("Duplicate evidence field")
    return value


def lead_text(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and value.isprintable() and bool(value.strip())


def load(path):
    try:
        manifest = json.loads(read_regular(path, MAX_MANIFEST_BYTES), object_pairs_hook=unique_object)
    except (ValueError, RecursionError) as error:
        raise Error("evidence_manifest", "Invalid lead manifest JSON", 2) from error
    if (not isinstance(manifest, dict) or manifest.keys() != {"schema", "images", "leads"}
            or manifest["schema"] != LEADS_SCHEMA or not isinstance(manifest["images"], list)
            or not isinstance(manifest["leads"], list)):
        raise Error("evidence_manifest", "Expected a versioned evidence lead manifest", 2)
    images, leads = manifest["images"], manifest["leads"]
    if not 1 <= len(images) <= MAX_IMAGES or not 1 <= len(leads) <= MAX_LEADS:
        raise Error("evidence_manifest_limit", "Select up to four images and 16 leads", 2)
    pins, lead_ids = set(), set()
    for image in images:
        if (not isinstance(image, dict) or image.keys() != IMAGE_FIELDS
                or image["arch"] not in ("arm64", "x86_64")
                or any(not is_digest(image[key]) for key in IMAGE_FIELDS - {"arch"})
                or image["image_id"] in pins):
            raise Error("evidence_image_pin", "Each image needs a unique ID, architecture and exact digests", 2)
        pins.add(image["image_id"])
    used = set()
    for lead in leads:
        if (not isinstance(lead, dict) or not LEAD_FIELDS <= lead.keys()
                or lead.keys() - LEAD_FIELDS - {"class_name", "query_job"}
                or not isinstance(lead["id"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", lead["id"])
                or lead["id"] in lead_ids or not is_digest(lead["image_id"]) or lead["image_id"] not in pins
                or not isinstance(lead["kind"], str) or lead["kind"] not in KINDS or not lead_text(lead["value"])):
            raise Error("evidence_lead", "Invalid lead ID, image or selector", 2)
        kind, value = lead["kind"], lead["value"]
        if (kind == "address" and not metadata.VA.fullmatch(value)
                or kind == "function_id" and not is_digest(value)
                or "class_name" in lead and (kind != "objc_selector" or not lead_text(lead["class_name"]))
                or "query_job" in lead and (not isinstance(lead["query_job"], str)
                                           or not jobs.JOB_ID.fullmatch(lead["query_job"]))):
            raise Error("evidence_lead", "Invalid unslid address, function ID, class or query job", 2)
        if kind == "address":
            lead["value"] = hex(int(value, 16))
        lead_ids.add(lead["id"])
        used.add(lead["image_id"])
    if used != pins:
        raise Error("evidence_image_pin", "Each pinned image must have a lead", 2)
    return manifest


def open_image(project, image, pin):
    if image is None or not image["imported"]:
        raise Error("evidence_image_missing", "Pinned image is absent from the workspace", 3)
    if (image["arch"], image["sha256"], image["artifact_sha256"]) != (
            pin["arch"], pin["slice_sha256"], pin["artifact_sha256"]):
        raise Error("evidence_image_mismatch", "Pinned architecture or input digest differs from the workspace")
    snapshot, source = project.snapshot(dict(image, active_analysis=pin["analysis_id"]))
    return flow_evidence.snapshot_view(snapshot), source


def selection_gaps(snapshot):
    engine = snapshot["engine"]
    if (any(engine.get(key) for key in ("functions_truncated", "analysis_timed_out", "output_budget_reached"))
            or engine.get("coverage", {}).get("functions", {}).get("status", "complete") != "complete"):
        return ["function_coverage_incomplete"]
    return []


def string_selection(snapshot, value):
    hits, gaps = search.snapshot_matches(snapshot, search.pattern(value), "strings")
    if len(hits) > MAX_MATCHES:
        return [], hits[:MAX_MATCHES], [], [*gaps, "string_match_limit"]
    refs = []
    for address in dict.fromkeys(hit["va"] for hit in hits if hit["va"] is not None):
        rows, ref_gaps = address_xrefs.match(snapshot, address, "to")
        refs.extend(rows)
        gaps.extend(ref_gaps)
        if len(refs) > MAX_REFERENCES:
            return [], hits, refs[:MAX_REFERENCES], [*gaps, "string_reference_limit"]
    sites = {row["from"] for row in refs if row["target_status"] == "recorded"}
    if not sites:
        return [], hits, refs, gaps
    functions = snapshot["functions"]
    shared, limited = body_ownership.shared_ranges(functions)
    if limited:
        return [], hits, refs, [*gaps, "function_body_review_limit"]
    owners = defaultdict(list)
    for function in functions:
        if function["entry_va"] is None:
            continue
        for site in sites.intersection(ins["addr"] for ins in function["instructions"]):
            owners[site].append(function)
    candidates = {}
    for row in refs:
        site = row["from"]
        if row["target_status"] != "recorded":
            continue
        if body_ownership.contains(shared, site) or len(owners[site]) > 1:
            gaps.append("ambiguous_reference_owner")
            continue
        if owners[site]:
            owner = owners[site][0]
            row["owner_function_id"] = owner["function_id"]
            candidates[owner["function_id"]] = owner
    return list(candidates.values()), hits, refs, [*gaps, *selection_gaps(snapshot)]


def resolve(snapshot, lead, selector_rows):
    functions = snapshot["functions"]
    kind, value = lead["kind"], lead["value"]
    gaps, matches, references = [], [], []
    if kind == "string":
        candidates, matches, references, gaps = string_selection(snapshot, value)
    elif kind == "objc_selector":
        methods, gaps = selector_rows
        matches = [row for row in methods if row["name"] == value
                   and ("class_name" not in lead or row["class_name"] == lead["class_name"])]
        if len(matches) > MAX_MATCHES:
            return [], matches[:MAX_MATCHES], [], [*gaps, "selector_match_limit"]
        addresses = {row["implementation_va"] for row in matches}
        candidates = [f for f in functions if f["entry_va"] is not None and f["entry_va"] in addresses]
        if addresses - {f["entry_va"] for f in candidates}:
            gaps = [*gaps, "selector_implementation_unavailable"]
    elif kind == "name":
        candidates = [f for f in functions if any(row["name"] == value for row in f["names"])]
        if search.entry_labels_incomplete(functions):
            gaps.append("function_entry_label_coverage_incomplete")
        gaps.extend(selection_gaps(snapshot))
    else:
        key = "entry_va" if kind == "address" else "function_id"
        candidates = [f for f in functions if f[key] == value]
    if not candidates:
        gaps = [*gaps, *selection_gaps(snapshot)]
    return candidates, matches, references, gaps


def function_view(snapshot, function):
    refs = address_xrefs.FunctionReferences(snapshot["engine"])
    view = {key: function[key] for key in FUNCTION_FIELDS if key in function}
    view["references"] = {}
    gaps = []
    for direction in ("to", "from"):
        rows, incomplete, recovered = refs.records(function, direction)
        capped = len(rows) > MAX_REFERENCES
        view["references"][direction] = {"records": rows[:MAX_REFERENCES], "limited": capped,
                                         "status": "partial" if capped or incomplete else "complete",
                                         "source": "image_index" if recovered else "function"}
        if capped or incomplete:
            gaps.append(f"references_{direction}_incomplete")
    trace, trace_gaps = calls.graph(snapshot, function, "both", 1, MAX_EDGES)
    view["call_trace"] = dict(trace, gaps=trace_gaps)
    if function["decompile_status"] != "complete":
        gaps.append("pseudocode_" + function["decompile_status"])
    elif not function.get("pseudocode"):
        gaps.append("pseudocode_unavailable")
    elif not function.get("address_spans"):
        gaps.append("address_spans_unavailable")
    if function.get("pseudocode_truncated"):
        gaps.append("pseudocode_limit")
    if function.get("instructions_error") or function.get("instructions_truncated"):
        gaps.append("instructions_incomplete")
    elif not function.get("instructions"):
        gaps.append("instructions_unavailable")
    if function.get("body_overlap"):
        gaps.append("function_body_overlap")
    return view, [*gaps, *trace_gaps]


def query_view(project, job_id, pin, source, function):
    _, record = jobs.get(project, job_id)
    request = jobs.restart_request(record)
    expected = {"project_id": project.project_id, "image_id": pin["image_id"],
                "source_analysis_id": pin["analysis_id"], "source_snapshot_sha256": source["snapshot_sha256"],
                "source_program_sha256": source.get("analysis_program_sha256"), "slice_sha256": pin["slice_sha256"],
                "artifact_sha256": pin["artifact_sha256"], "function_id": function["function_id"],
                "entry_va": function["entry_va"]}
    if (record.get("mode") != "query" or request is None or not is_digest(expected["source_program_sha256"])
            or any(request.get(key) != value for key, value in expected.items())):
        raise Error("evidence_query_mismatch", "Recorded query does not belong to the selected function and analysis", 3)
    result = jobs.query_receipt(project, job_id, request)
    if result is None:
        raise Error("evidence_query_unpublished", "The selected query has no published result", 3)
    return {"status": result["status"], "coverage": result["coverage"],
            **{key: result["data"][key] for key in ("origin", "pseudocode", "decompile_status",
                                                    "address_spans", "address_span_coverage")}}


def lead_view(project, pin, source, snapshot, lead, selector_rows):
    candidates, matches, references, gaps = resolve(snapshot, lead, selector_rows)
    row = {"lead": lead, "matches": matches, "match_references": references,
           "candidates": [{"function_id": f["function_id"], "entry_va": f["entry_va"]}
                          for f in candidates[:MAX_MATCHES]], "function": None, "query": None}
    if len(candidates) != 1:
        if len(candidates) > MAX_MATCHES:
            gaps = [*gaps, "candidate_limit"]
        reason = ("lead_ambiguous" if candidates else "lead_resolution_incomplete" if gaps
                  else "lead_no_function" if matches else "lead_not_found")
        return dict(row, status="unresolved", reason=reason, gaps=sorted(set(gaps)))
    function = candidates[0]
    row["function"], function_gaps = function_view(snapshot, function)
    gaps = [*gaps, *function_gaps]
    if "query_job" in lead:
        try:
            row["query"] = query_view(project, lead["query_job"], pin, source, function)
            if row["query"]["status"] != "complete":
                gaps.append("query_result_partial")
        except Error as error:
            row["query"] = {"status": "unavailable", "reason": error.code}
            gaps.append(error.code)
    return dict(row, status="partial" if gaps else "resolved", reason=None, gaps=sorted(set(gaps)))


def unresolved(lead, reason):
    return {"lead": lead, "status": "unresolved", "reason": reason, "gaps": [], "candidates": [],
            "matches": [], "match_references": [], "function": None, "query": None}


def export(project, manifest):
    images = {image["image_id"]: image for image in project.images()}
    records, pins = {}, []
    for pin in manifest["images"]:
        image = images.get(pin["image_id"])
        leads = [lead for lead in manifest["leads"] if lead["image_id"] == pin["image_id"]]
        try:
            snapshot, source = open_image(project, image, pin)
        except Error as error:
            pins.append(dict(pin, status="unavailable", reason=error.code))
            records.update((lead["id"], unresolved(lead, error.code)) for lead in leads)
            continue
        engine_identity = snapshot.get("identity", {}).get("engine", {})
        engine = {key: engine_identity.get(key) for key in ("bridge_sha256", "ghidra_tree_sha256")}
        engine.update({key: snapshot["engine"].get(key) for key in ("bridge_version", "ghidra_version")})
        pins.append(dict(pin, status="available", snapshot_sha256=source["snapshot_sha256"], engine=engine,
                         bundle_image=snapshot["image"].get("bundle_image"), profile=snapshot.get("analysis_profile")))
        selector_rows, selector_error = ([], []), None
        if any(lead["kind"] == "objc_selector" for lead in leads):
            try:
                selector_rows = objc.inventory(metadata.verified_slice(project, image), image, "methods")
            except Error as error:
                selector_error = error.code
        for lead in leads:
            if lead["kind"] == "objc_selector" and selector_error:
                row = unresolved(lead, selector_error)
            else:
                row = lead_view(project, pin, source, snapshot, lead, selector_rows)
            records[lead["id"]] = (row if len(canonical(row)) <= MAX_LEAD_BYTES
                                   else unresolved(lead, "lead_output_limit"))
    return {"schema": REPORT_SCHEMA, "authority": "committed_static_evidence",
            "manifest_sha256": identity(manifest), "images": pins,
            "leads": [records[lead["id"]] for lead in manifest["leads"]]}
