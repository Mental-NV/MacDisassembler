"""Compare observations selected by the same reviewer across saved handoffs."""
from collections import Counter
import hashlib

from . import binary_diff, evidence
from .errors import Error
from .macho import read_regular
from .metadata import VA
from .schema import validate_envelope
from .storage import canonical, identity, is_digest, strict_json


POLICY = "macscope-handoff-diff/1"
MAX_INPUT = evidence.MAX_LEADS * evidence.MAX_LEAD_BYTES + evidence.MAX_MANIFEST_BYTES


def role(pin):
    bundle = pin.get("bundle_image")
    if bundle is None:
        return None
    path = bundle["relative_path"]
    if (not isinstance(path, str) or not path.startswith("Contents/") or ".." in path.split("/")
            or type(bundle["main_executable"]) is not bool):
        raise ValueError("Invalid bundle role")
    return {"relative_path": path, "main_executable": bundle["main_executable"]}


def projection(record, keys):
    if not isinstance(record, dict):
        raise ValueError("Expected an evidence record")
    return {key: record[key] for key in keys if key in record}


def measured(value, complete):
    result = {"sha256": identity(value), "coverage": "complete" if complete else "partial"}
    if isinstance(value, (list, dict)):
        result["records"] = len(value)
    elif isinstance(value, str):
        result["characters"] = len(value)
    return result


def complete(section):
    if section["status"] not in ("complete", "partial"):
        raise ValueError("Invalid handoff facet coverage")
    return section["status"] == "complete"


def code(record):
    text = record.get("pseudocode") if record else None
    if text is None:
        return None
    if not isinstance(text, str):
        raise ValueError("Invalid pseudocode")
    return measured(text, bool(text) and record.get("decompile_status") == "complete"
                    and not record.get("pseudocode_truncated") and not record.get("decompile_error"))


def location(address, entry, ranges, *, keep_absolute=False):
    if address is None:
        return None
    if not isinstance(address, str):
        raise ValueError("Invalid evidence address")
    if not VA.fullmatch(address):
        return address
    value = int(address, 16)
    if any(lo <= value <= hi for lo, hi in ranges):
        return {"entry_offset": hex(value - entry)}
    return hex(value) if keep_absolute else {"outside_selected_body": True}


def relation_facts(rows, entry, ranges, *, fields, addresses):
    if not isinstance(rows, list):
        raise ValueError("Invalid evidence records")
    logical, locations = [], []
    for row in rows:
        fact = projection(row, fields)
        coords = {key: location(row.get(key), entry, ranges) for key in addresses}
        logical.append(dict(fact, **coords))
        locations.append({key: location(row.get(key), entry, ranges, keep_absolute=True) for key in addresses})
    return sorted(logical, key=canonical), sorted(locations, key=canonical)


def declared_imports(section, images, entry, ranges):
    logical, locations = [], []
    if not isinstance(section["links"], list):
        raise ValueError("Invalid declared import records")
    for row in section["links"]:
        fact = projection(row, ("status", "reason", "bundle_paths"))
        fact["callsite"] = location(row["callsite"], entry, ranges)
        fact["binding"] = projection(row.get("binding", {}),
                                     ("symbol", "library", "weak_import", "import_addend", "inline_addend"))
        export = projection(row.get("export", {}), ("name", "kind", "weak_definition"))
        fact["export"] = export
        target = row.get("target")
        if target is not None:
            provider = images[target["image_id"]]
            fact["provider"] = {"arch": provider["arch"], "role": role(provider)}
        logical.append(fact)
        locations.append({"callsite": fact["callsite"], "symbol": fact["binding"].get("symbol"),
                          "stub_va": row.get("stub_va"), "bind_va": row.get("bind_va"),
                          "target_entry_va": target.get("entry_va") if target else None})
    return measured(sorted(logical, key=canonical), complete(section)), identity(sorted(locations, key=canonical))


def lead_facts(row, images):
    lead, function = row["lead"], row["function"]
    pin = images[lead["image_id"]]
    descriptor = {"lead": lead, "arch": pin["arch"], "bundle_role": role(pin), "status": row["status"],
                  "reason": row["reason"], "gaps": row["gaps"]}
    provenance = projection(pin, ("image_id", "artifact_sha256", "slice_sha256", "analysis_id",
                                  "import_program_sha256"))
    if "engine" in pin:
        provenance["engine"] = projection(pin["engine"], ("bridge_version", "ghidra_version",
                                                          "bridge_sha256", "ghidra_tree_sha256"))
    provenance.update(projection(lead, ("class_slot", "query_job")))
    if lead["kind"] in ("address", "function_id"):
        provenance["selector_value"] = lead["value"]
    facets = {}
    if function is not None:
        va = function["entry_va"]
        if (pin["status"] != "available" or not is_digest(function["function_id"])
                or (va is not None and not VA.fullmatch(va))
                or lead["kind"] == "address" and va != lead["value"]
                or lead["kind"] == "function_id" and function["function_id"] != lead["value"]
                or lead["kind"] == "objc_selector" and not any(
                    match["implementation_va"] == va for match in row["matches"])):
            raise ValueError("Function does not match the reported lead")
        entry = int(va, 16) if va is not None else None
        ranges = [(int(lo, 16), int(hi, 16)) for lo, hi in function["body_ranges"]] if va is not None else []
        fingerprint, decoded = binary_diff.instruction_evidence(function)
        facets["instruction_bytes"] = measured([[offset, ins["bytes"]] for offset, ins in sorted(decoded.items())],
                                               fingerprint is not None) if decoded else None
        facets["pseudocode"] = code(function)
        facets["signature"] = measured(function["signature"], True) if function.get("signature") else None
        names = [name for name in function["names"] if not binary_diff.AUTO_NAME.fullmatch(name["name"])]
        facets["names"] = measured(sorted(names, key=canonical), True)
        provenance.update(projection(function, ("entry_va", "function_id")))
        provenance["function_origin"] = projection(function["origin"], ("mode", "job_id", "bridge_version",
                                                                         "bridge_sha256", "ghidra_tree_sha256"))
        for direction in ("to", "from"):
            refs = function["references"][direction]
            logical, coords = relation_facts(refs["records"], entry, ranges, addresses=("from", "to"),
                                             fields=("type", "source", "operand_index", "is_external", "from_external"))
            facets["references_" + direction] = measured(logical, complete(refs))
            provenance["reference_locations_" + direction] = identity(coords)
        trace = function["call_trace"]
        if not isinstance(trace["gaps"], list):
            raise ValueError("Invalid call trace coverage")
        logical, coords = relation_facts(trace["edges"], entry, ranges, addresses=("callsite", "reported_target"),
                                         fields=("type", "resolution", "evidence", "reference_source", "operand_index"))
        facets["call_trace"] = measured(logical, not trace["gaps"])
        provenance["call_locations"] = identity(coords)
        if "declared_imports" in row:
            facets["declared_imports"], provenance["import_locations"] = declared_imports(
                row["declared_imports"], images, entry, ranges)
        if "selected_calls" in row:
            selected = row["selected_calls"]
            logical, coords = relation_facts(selected["links"], entry, ranges, fields=("target_leads",),
                                             addresses=("callsite", "target_entry_va"))
            facets["selected_calls"] = measured(logical, complete(selected))
            provenance["selected_call_locations"] = identity(coords)
    if query := row["query"]:
        if "pseudocode" in query:
            facets["query_pseudocode"] = code(query)
        provenance["query_origin"] = projection(query.get("origin", {}), ("mode", "job_id", "bridge_version",
                                                                             "bridge_sha256", "ghidra_tree_sha256"))
    return {"selection": descriptor, "provenance": provenance, "facets": facets, "has_function": function is not None}


def read_handoff(path, side):
    raw = read_regular(path, MAX_INPUT)
    try:
        envelope = strict_json(raw)
        validate_envelope(envelope)
        data = envelope["data"]
        if (envelope["command"] != "evidence" or envelope["analysis_id"] is not None
                or envelope["status"] not in ("complete", "partial") or data["schema"] != evidence.REPORT_SCHEMA
                or data["authority"] != "committed_static_evidence" or not is_digest(data["manifest_sha256"])
                or not isinstance(data["images"], list) or not 1 <= len(data["images"]) <= evidence.MAX_IMAGES
                or not isinstance(data["leads"], list) or not 1 <= len(data["leads"]) <= evidence.MAX_LEADS):
            raise ValueError("Invalid handoff envelope")
        evidence.validate_manifest({"schema": evidence.LEADS_SCHEMA,
            "images": [projection(pin, evidence.IMAGE_FIELDS | {evidence.IMPORT_PIN}) for pin in data["images"]],
            "leads": [dict(row["lead"]) for row in data["leads"]]})
        if envelope["coverage"]["returned_count"] != len(data["leads"]):
            raise ValueError("Handoff lead count does not match its records")
        images = {}
        for image in data["images"]:
            if image["status"] not in ("available", "unavailable"):
                raise ValueError("Invalid handoff image pin")
            images[image["image_id"]] = image
        facts = {}
        for row in data["leads"]:
            lead = row["lead"]
            if (row["status"] not in ("resolved", "partial", "unresolved")
                    or (row["status"] == "unresolved") != (row["function"] is None)
                    or not isinstance(row["gaps"], list) or any(not isinstance(gap, str) for gap in row["gaps"])):
                raise ValueError("Invalid handoff lead")
            facts[lead["id"]] = lead_facts(row, images)
        descriptor = {"export_sha256": hashlib.sha256(raw).hexdigest(), "manifest_sha256": data["manifest_sha256"],
                      "status": envelope["status"], "lead_count": len(facts)}
    except (Error, AttributeError, ValueError, KeyError, TypeError, RecursionError) as error:
        raise Error("diff_evidence", f"{side} must be a valid MacDisassembler evidence handoff", 2) from error
    return descriptor, facts


def selector(lead):
    value = lead["value"] if lead["kind"] not in ("address", "function_id") else None
    return lead["kind"], value, lead.get("class_name")


def compare_lead(key, left, right):
    row = {"lead_id": key, "left": left, "right": right}
    if left is None or right is None:
        return dict(row, status="lead_added" if left is None else "lead_removed")
    a, b = left["selection"], right["selection"]
    if not left["has_function"] or not right["has_function"]:
        return dict(row, status="unresolved")
    for reason, x, y in (("architecture_changed", a["arch"], b["arch"]),
                         ("bundle_role_changed", a["bundle_role"], b["bundle_role"]),
                         ("selector_changed", selector(a["lead"]), selector(b["lead"]))):
        if x != y:
            return dict(row, status="incomparable", reason=reason)
    x, y = left["facets"], right["facets"]
    shared = sorted(key for key in x.keys() & y.keys() if x[key] is not None and y[key] is not None)
    changed = [key for key in shared if x[key]["sha256"] != y[key]["sha256"]]
    coverage = [key for key in sorted(x.keys() | y.keys())
                if (x.get(key) or {}).get("coverage") != (y.get(key) or {}).get("coverage")]
    if projection(a, ("status", "reason", "gaps")) != projection(b, ("status", "reason", "gaps")):
        coverage.append("lead")
    p, q = left["provenance"], right["provenance"]
    provenance = [key for key in sorted(p.keys() | q.keys()) if p.get(key) != q.get(key)]
    return dict(row, status="changed" if changed else "unchanged_observations", match="reviewer_lead_id",
                changed_observations=changed, changed_coverage=coverage, changed_provenance=provenance)


def compare(left_path, right_path):
    left, a = read_handoff(left_path, "LEFT")
    right, b = read_handoff(right_path, "RIGHT")
    rows = [compare_lead(key, a.get(key), b.get(key)) for key in sorted(a.keys() | b.keys())]
    summary = dict(Counter(row["status"] for row in rows))
    gaps = [side + "_handoff_partial" for side, report in (("left", left), ("right", right))
            if report["status"] == "partial"]
    if summary.get("incomparable") or summary.get("unresolved"):
        gaps.append("lead_comparison_incomplete")
    if any(row.get("changed_coverage") for row in rows):
        gaps.append("lead_coverage_changed")
    data = {"policy": POLICY, "scope": "evidence", "left": left, "right": right, "summary": summary, "gaps": gaps}
    return data, rows, identity([left["export_sha256"], right["export_sha256"], POLICY])
