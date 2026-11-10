"""Bounded handoffs from pinned analyses or committed import query receipts."""
from collections import defaultdict
import re

from . import address_xrefs, body_ownership, calls, flow_evidence, focused, import_links, jobs, metadata, objc, search
from .errors import Error
from .macho import read_regular
from .schema import validate_envelope
from .storage import canonical, identity, is_digest, strict_json


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
IMPORT_PIN = "import_program_sha256"
IMPORT_FIELDS = (IMAGE_FIELDS - {"analysis_id"}) | {IMPORT_PIN}
LEAD_FIELDS = {"id", "image_id", "kind", "value"}
KINDS = {"address", "function_id", "name", "objc_selector", "string"}
FUNCTION_FIELDS = (
    "function_id", "entry_va", "engine_entry", "address_space", "names", "signature", "body_ranges",
    "is_external", "is_thunk", "thunk_target", "instructions", "instruction_bytes_sha256",
    "pseudocode", "decompile_status", "decompile_error", "pseudocode_truncated", "address_spans",
    "facets", "coverage", "origin", "control_flow_review", "control_flow_gaps", "body_overlap",
)


def lead_text(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and value.isprintable() and bool(value.strip())


def load(path):
    try:
        manifest = strict_json(read_regular(path, MAX_MANIFEST_BYTES))
    except (ValueError, RecursionError) as error:
        raise Error("evidence_manifest", "Invalid lead manifest JSON", 2) from error
    if (not isinstance(manifest, dict) or manifest.keys() != {"schema", "images", "leads"}
            or manifest["schema"] != LEADS_SCHEMA or not isinstance(manifest["images"], list)
            or not isinstance(manifest["leads"], list)):
        raise Error("evidence_manifest", "Expected a versioned evidence lead manifest", 2)
    images, leads = manifest["images"], manifest["leads"]
    if not 1 <= len(images) <= MAX_IMAGES or not 1 <= len(leads) <= MAX_LEADS:
        raise Error("evidence_manifest_limit", "Select up to four images and 16 leads", 2)
    pins, lead_ids = {}, set()
    for image in images:
        if (not isinstance(image, dict) or image.keys() not in (IMAGE_FIELDS, IMPORT_FIELDS)
                or image["arch"] not in ("arm64", "x86_64")
                or any(not is_digest(image[key]) for key in image.keys() - {"arch"})
                or image["image_id"] in pins):
            raise Error("evidence_image_pin", "Each image needs a unique ID, architecture and exact digests", 2)
        pins[image["image_id"]] = image
    used = set()
    for lead in leads:
        if (not isinstance(lead, dict) or not LEAD_FIELDS <= lead.keys()
                or lead.keys() - LEAD_FIELDS - {"class_name", "class_slot", "query_job"}
                or not isinstance(lead["id"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", lead["id"])
                or lead["id"] in lead_ids or not is_digest(lead["image_id"]) or lead["image_id"] not in pins
                or not isinstance(lead["kind"], str) or lead["kind"] not in KINDS or not lead_text(lead["value"])):
            raise Error("evidence_lead", "Invalid lead ID, image or selector", 2)
        kind, value = lead["kind"], lead["value"]
        if (kind == "address" and not metadata.VA.fullmatch(value)
                or kind == "function_id" and not is_digest(value)
                or "class_name" in lead and (kind != "objc_selector" or not lead_text(lead["class_name"]))
                or "class_slot" in lead and (kind != "objc_selector" or not isinstance(lead["class_slot"], str)
                                              or not metadata.VA.fullmatch(lead["class_slot"]))
                or "query_job" in lead and (not isinstance(lead["query_job"], str)
                                           or not jobs.JOB_ID.fullmatch(lead["query_job"]))):
            raise Error("evidence_lead", "Invalid unslid address, function ID, class or query job", 2)
        if kind == "address":
            lead["value"] = hex(int(value, 16))
        if IMPORT_PIN in pins[lead["image_id"]] and (kind not in ("address", "objc_selector") or "query_job" not in lead):
            raise Error("evidence_import_lead", "Import pins require an exact address or Objective-C selector and a focused query job", 2)
        if "class_slot" in lead:
            lead["class_slot"] = hex(int(lead["class_slot"], 16))
        lead_ids.add(lead["id"])
        used.add(lead["image_id"])
    if used != pins.keys():
        raise Error("evidence_image_pin", "Each pinned image must have a lead", 2)
    return manifest


def open_image(project, image, pin):
    if image is None or not image["imported"]:
        raise Error("evidence_image_missing", "Pinned image is absent from the workspace", 3)
    if (image["arch"], image["sha256"], image["artifact_sha256"]) != (
            pin["arch"], pin["slice_sha256"], pin["artifact_sha256"]):
        raise Error("evidence_image_mismatch", "Pinned architecture or input digest differs from the workspace")
    if IMPORT_PIN in pin:
        if image.get("engine_baseline_sha256") != pin[IMPORT_PIN]:
            raise Error("evidence_import_mismatch", "Pinned Program digest differs from the committed import", 3)
        return {"image":image, "functions":[], "engine":{"coverage":{"functions":{"status":"partial"}}}}, None
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


def selector_matches(lead, selector_rows):
    methods, gaps = selector_rows
    return [row for row in methods if row["name"] == lead["value"]
            and ("class_name" not in lead or row["class_name"] == lead["class_name"])], gaps


def resolve(snapshot, lead, selector_rows):
    functions = snapshot["functions"]
    kind, value = lead["kind"], lead["value"]
    gaps, matches, references = [], [], []
    if kind == "string":
        candidates, matches, references, gaps = string_selection(snapshot, value)
    elif kind == "objc_selector":
        matches, gaps = selector_matches(lead, selector_rows)
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


def function_view(snapshot, function, *, from_import=False):
    refs = address_xrefs.FunctionReferences(snapshot["engine"])
    view = {key: function[key] for key in FUNCTION_FIELDS if key in function}
    view["references"] = {}
    gaps = []
    for direction in ("to", "from"):
        rows, incomplete, recovered = refs.records(function, direction)
        incomplete = incomplete or (from_import and direction == "to")
        capped = len(rows) > MAX_REFERENCES
        view["references"][direction] = {"records": rows[:MAX_REFERENCES], "limited": capped,
                                         "status": "partial" if capped or incomplete else "complete",
                                         "source": "focused_program" if from_import else "image_index" if recovered else "function"}
        if capped or incomplete:
            gaps.append(f"references_{direction}_incomplete")
    trace, trace_gaps = calls.graph(snapshot, function, "callees" if from_import else "both", 1, MAX_EDGES)
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
    try:
        validate_envelope(result)
        return {"status": result["status"], "coverage": result["coverage"],
                **{key: result["data"][key] for key in ("origin", "pseudocode", "decompile_status",
                                                        "address_spans", "address_span_coverage")}}
    except (KeyError, ValueError) as error:
        raise Error("query_receipt", "Invalid saved query evidence", 3) from error


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


def focused_query(project, image, binary, entry, job_id):
    _, record = jobs.get(project, job_id)
    if jobs.focused_record(record) is None:
        raise Error("evidence_query_mismatch", "The job did not decompile from a committed import", 3)
    proof, payload = focused.extent(binary, image, entry)
    request = jobs.focused_request(project, image, dict(proof, program_sha256=image["engine_baseline_sha256"]))
    if jobs.focused_record(record) != request:
        raise Error("evidence_query_mismatch", "Focused receipt does not match the selected image and entry", 3)
    original = record.get("resumed_from", job_id)
    result = jobs.query_receipt(project, original, request)
    if result is None:
        raise Error("evidence_query_unpublished", "The focused job has no published result", 3)
    if original != job_id and result["data"]["origin"]["job_id"] != job_id:
        raise Error("evidence_query_mismatch", "The focused result was published by a different retry", 3)
    focused.verify_instructions(proof, payload, result["data"])
    return result


def focused_lead(project, snapshot, binary, lead, selector_rows):
    row = unresolved(lead, None)
    entry = lead["value"]
    gaps = []
    if lead["kind"] == "objc_selector":
        matches, gaps = selector_matches(lead, selector_rows)
        row["matches"] = matches[:MAX_MATCHES]
        entries = {match["implementation_va"] for match in matches}
        if len(matches) > MAX_MATCHES:
            return dict(row, reason="lead_resolution_incomplete", gaps=sorted(set(gaps) | {"selector_match_limit"}))
        if len(entries) > 1:
            return dict(row, reason="lead_ambiguous", gaps=sorted(set(gaps)))
        entry = next(iter(entries), None)
        if entry is None:
            reason = "lead_resolution_incomplete" if gaps else "lead_no_function" if matches else "lead_not_found"
            return dict(row, reason=reason, gaps=sorted(set(gaps)))
    try:
        result = focused_query(project, snapshot["image"], binary, entry, lead["query_job"])
    except Error as error:
        return dict(row, reason=error.code, gaps=sorted(set(gaps)),
                    query={"status":"unavailable", "reason":error.code})
    function = result["data"]
    view, function_gaps = function_view(dict(snapshot, functions=[function]), function, from_import=True)
    query = {"status":result["status"], "coverage":result["coverage"], "origin":function["origin"]}
    if result["status"] != "complete":
        gaps = [*gaps, "query_result_partial"]
    gaps = sorted(set(gaps) | set(function_gaps))
    return dict(row, function=view, query=query, status="partial" if gaps else "resolved", gaps=gaps,
                candidates=[{"function_id":function["function_id"], "entry_va":entry}])


def export(project, manifest, *, link_imports=False):
    images = {image["image_id"]: image for image in project.images()}
    records, pins = {}, []
    providers, pending = [], {}
    for pin in manifest["images"]:
        from_import = IMPORT_PIN in pin
        linkage, linkage_error = None, None
        image = images.get(pin["image_id"])
        leads = [lead for lead in manifest["leads"] if lead["image_id"] == pin["image_id"]]
        try:
            snapshot, source = open_image(project, image, pin)
        except Error as error:
            pins.append(dict(pin, status="unavailable", reason=error.code))
            records.update((lead["id"], unresolved(lead, error.code)) for lead in leads)
            continue
        if from_import:
            pins.append(dict(pin, status="available", source="committed_import", bundle_image=image.get("bundle_image")))
        else:
            engine_identity = snapshot.get("identity", {}).get("engine", {})
            engine = {key: engine_identity.get(key) for key in ("bridge_sha256", "ghidra_tree_sha256")}
            engine.update({key: snapshot["engine"].get(key) for key in ("bridge_version", "ghidra_version")})
            pins.append(dict(pin, status="available", snapshot_sha256=source["snapshot_sha256"], engine=engine,
                             bundle_image=snapshot["image"].get("bundle_image"), profile=snapshot.get("analysis_profile")))
        selector_rows, selector_error = ([], []), None
        selectors = [lead for lead in leads if lead["kind"] == "objc_selector"]
        scoped_selectors = {}
        binary = None
        if selectors or link_imports or from_import:
            try:
                binary = metadata.verified_slice(project, image)
            except Error as error:
                selector_error = linkage_error = error.code
        if binary is not None and any("class_slot" not in lead for lead in selectors):
            try:
                selector_rows = objc.inventory(binary, image, "methods")
            except Error as error:
                selector_error = error.code
        if binary is not None:
            for slot in dict.fromkeys(lead["class_slot"] for lead in selectors if "class_slot" in lead):
                try:
                    scoped_selectors[slot] = (objc.selected_methods(binary, image, int(slot, 16)), None)
                except Error as error:
                    scoped_selectors[slot] = (None, error.code)
        if binary is not None and link_imports:
            try:
                linkage = import_links.ImageLinkage(binary, image, snapshot)
                if not from_import and (provider := linkage.provider(pin)):
                    providers.append(provider)
            except Error as error:
                linkage_error = error.code
        focused_functions = {}
        for lead in leads:
            methods, error = scoped_selectors.get(lead.get("class_slot"), (selector_rows, selector_error))
            if lead["kind"] == "objc_selector" and error:
                row = unresolved(lead, error)
            elif from_import:
                row = (focused_lead(project, snapshot, binary, lead, methods) if binary is not None
                       else unresolved(lead, selector_error))
            else:
                row = lead_view(project, pin, source, snapshot, lead, methods)
            if len(canonical(row)) > MAX_LEAD_BYTES:
                row = unresolved(lead, "lead_output_limit")
            records[lead["id"]] = row
            if link_imports and row["function"] is not None:
                function = row["function"]
                if from_import:
                    focused_functions[function["function_id"]] = function
                links, gaps = (linkage.calls(function, from_import=from_import) if linkage_error is None
                               else ([], [linkage_error]))
                pending[lead["id"]] = (pin, links, gaps)
        if from_import and linkage is not None and linkage_error is None:
            snapshot["functions"] = list(focused_functions.values())
            if provider := linkage.provider(pin):
                providers.append(provider)
    for lead_id, (pin, links, gaps) in pending.items():
        row = records[lead_id]
        matches = [import_links.destination(link, pin, providers) for link in links]
        gaps = sorted(set(gaps) | {match["reason"] for match in matches if match["reason"]})
        row["declared_imports"] = {"status": "partial" if gaps else "complete", "links": matches, "gaps": gaps}
        if gaps:
            row.update(status="partial", gaps=sorted(set(row["gaps"]) | set(gaps)))
        if len(canonical(row)) > MAX_LEAD_BYTES:
            records[lead_id] = unresolved(row["lead"], "lead_output_limit")
    report = {"schema": REPORT_SCHEMA, "authority": "committed_static_evidence",
              "manifest_sha256": identity(manifest), "images": pins,
              "leads": [records[lead["id"]] for lead in manifest["leads"]]}
    if link_imports:
        report["import_linkage_policy"] = import_links.POLICY
    return report
