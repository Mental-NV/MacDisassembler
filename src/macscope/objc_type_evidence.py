"""Declaration-bound type sidecars; conditional ABI roles, never engine hints."""
from . import objc_types
from .storage import canonical, check_json_nesting, identity, is_digest
from .metadata import VA


POLICY = "macscope-objc-function-types/1"
LEGACY_ABI_POLICY = "darwin-objc-word-registers/1"
ABI_POLICY = "darwin-objc-word-registers/2"
ABI_POLICIES = (LEGACY_ABI_POLICY, ABI_POLICY)
FIELD = "objc_type_evidence"
MAX_SIDECAR_BYTES = 96 * 1024
GP = {"arm64": [f"x{n}" for n in range(8)],
      "x86_64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]}
LIMITATIONS = [
    "Recorded declarations do not prove implementation types or runtime dispatch.",
    "Register roles are conditional on a conforming Darwin Objective-C IMP.",
    "Variadic tails are not encoded or modeled; source argument names are unavailable.",
    "Encoded offsets are not used to infer registers, stack slots or object layout.",
    "No engine signature, pseudocode, annotation or saved receipt is changed.",
]
SCALAR_LIMITATIONS = [
    "width_bits describes the declared value inside a GP register container, not upper-bit validity or extension.",
    "B has an 8-bit Boolean storage representation; c does not identify a source Boolean typedef or plain-char signedness.",
]


def limitations(abi_policy):
    return LIMITATIONS + (SCALAR_LIMITATIONS if abi_policy == ABI_POLICY else [])


PIN_FIELDS = ("image_id", "arch", "artifact_sha256", "slice_sha256", "analysis_id", "import_program_sha256")
METHOD_FIELDS = ("name", "class_name", "class_slot", "category", "method_kind", "type_encoding", "record_va",
                 "selector_va", "selector_reference_va", "implementation_va", "origin", "encoding")


def word_type(value, policy=ABI_POLICY):
    if any(q != "const" for q in value["qualifiers"]):
        return None
    kind, code = value["kind"], value["code"]
    if policy == ABI_POLICY and kind == "scalar" and code in "cCsSiIB":
        return {"width_bits": {"c": 8, "C": 8, "s": 16, "S": 16,
                               "i": 32, "I": 32, "B": 8}[code],
                "representation": "boolean" if code == "B" else "integer",
                "signed": None if code in ("B", "c") else code.islower()}
    if kind == "scalar" and code in ("q", "Q"):
        return {"width_bits": 64, "representation": "integer", "signed": code == "q"}
    if kind in ("pointer", "object", "class", "selector", "cstring"):
        return {"width_bits": 64, "representation": "pointer", "signed": None}
    return None


def project_abi(decoded, arch, policy=ABI_POLICY):
    if policy not in ABI_POLICIES:
        raise ValueError("Unsupported Objective-C ABI policy")
    result = {"policy": policy, "status": "unsupported", "reasons": [],
              "claim": "conditional_register_roles", "implementation_signature_verified": False}
    if arch not in GP:
        return dict(result, reasons=["unsupported_architecture"])
    if decoded["status"] != "decoded":
        return dict(result, reasons=["type_encoding_incomplete"])
    arguments, ret = decoded["arguments"], decoded["return_type"]
    reasons = []
    if len(arguments) > len(GP[arch]):
        reasons.append("stack_arguments_unsupported")
    values = [word_type(arg["type"], policy) for arg in arguments]
    reasons.extend(f"argument_{index}_type_unsupported" for index, value in enumerate(values) if value is None)
    returns_void = ret["code"] == "v" and not ret["qualifiers"]
    returned = None if returns_void else word_type(ret, policy)
    if not returns_void and returned is None:
        reasons.append("return_type_unsupported")
    if reasons:
        return dict(result, reasons=reasons)
    rows = [{"argument_index": index, "role": arg["role"], "label": arg["name"],
             "register": GP[arch][index], **value}
            for index, (arg, value) in enumerate(zip(arguments, values))]
    returned = {"kind": "void", "register": None} if returns_void else dict(
        returned, kind="value", register="x0" if arch == "arm64" else "rax")
    return dict(result, status="projected", arguments=rows, return_value=returned,
                variadic_tail="not_encoded_or_modeled")


def seal(row):
    return dict(row, sha256=identity(row))


def sidecar(row, pin, metadata_gaps, *, redacted=False, abi_policy=ABI_POLICY):
    lead, function = row["lead"], row["function"]
    if (not isinstance(metadata_gaps, list) or len(metadata_gaps) > 64
            or any(not isinstance(g, str) or not 0 < len(g) <= 128 for g in metadata_gaps)
            or metadata_gaps != sorted(set(metadata_gaps))):
        raise ValueError("Invalid Objective-C metadata-selection gaps")
    result = {"lead_id": lead["id"], "status": "unavailable", "reason": None,
              "metadata_gaps": metadata_gaps, "binding": None, "declaration": None,
              "decoded_types": None, "abi_projection": None}
    def unavailable(reason):
        return seal(dict(result, reason=reason))
    if lead["kind"] != "objc_selector":
        return seal(dict(result, status="not_applicable", reason="not_objc_selector"))
    if redacted:
        return unavailable("declaration_redacted")
    if "class_slot" not in lead:
        return unavailable("exact_class_slot_required")
    if row.get("reason") == "lead_output_limit":
        return unavailable("lead_output_limit")
    if pin["status"] != "available":
        return unavailable("image_unavailable")
    if metadata_gaps:
        return unavailable("method_selection_incomplete")
    if function is None:
        return unavailable("selected_function_unavailable")
    if "query_job" in lead and (not isinstance(row.get("query"), dict)
                               or row["query"].get("status") not in ("complete", "partial")):
        return unavailable("selected_query_unavailable")
    matches = row["matches"]
    if len(matches) != 1:
        return unavailable("method_declaration_ambiguous" if matches else "method_declaration_unavailable")
    method = matches[0]
    if method.get("class_slot") != lead["class_slot"]:
        return unavailable("method_class_slot_mismatch")
    if (method.get("implementation_va") != function["entry_va"] or function["entry_va"] is None
            or method.get("name") != lead["value"]
            or "class_name" in lead and method.get("class_name") != lead["class_name"]):
        return unavailable("method_entry_mismatch")
    if (method.get("origin") != "objc_method_list" or method.get("method_kind") not in ("instance", "class")
            or method.get("category") is not None or method.get("encoding") not in ("relative", "absolute")
            or not isinstance(method.get("record_va"), str) or not VA.fullmatch(method["record_va"])
            or not is_digest(function["function_id"])
            or any(not is_digest(pin.get(k)) for k in ("image_id", "artifact_sha256", "slice_sha256"))
            or not any(is_digest(pin.get(k)) for k in ("analysis_id", "import_program_sha256"))):
        return unavailable("declaration_identity_unavailable")
    decoded = objc_types.decode_method(method.get("type_encoding"), method["name"], method["method_kind"])
    binding = {key: pin[key] for key in PIN_FIELDS if key in pin}
    binding.update(function_id=function["function_id"], entry_va=function["entry_va"],
                   class_slot=lead["class_slot"], method_record_va=method["record_va"])
    if "query_job" in lead:
        binding["query_job"] = lead["query_job"]
    result.update(status="associated", binding=binding,
                  declaration={key: method[key] for key in METHOD_FIELDS if key in method},
                  decoded_types=decoded, abi_projection=project_abi(decoded, pin["arch"], abi_policy))
    reason = None
    if len(canonical(result)) > MAX_SIDECAR_BYTES - 100:
        reason = "sidecar_output_limit"
    try:
        # Reserve room for envelope/report/section/records nesting on replay.
        check_json_nesting(b'[' * 8 + canonical(result) + b']' * 8)
    except ValueError:
        reason = "sidecar_nesting_limit"
    if reason:
        return seal(dict(result, status="unavailable", reason=reason, binding=None,
                         declaration=None, decoded_types=None, abi_projection=None))
    return seal(result)


def build(report, metadata_gaps, *, redacted_leads=(), abi_policy=ABI_POLICY):
    if abi_policy not in ABI_POLICIES:
        raise ValueError("Unsupported Objective-C ABI policy")
    pins = {pin["image_id"]: pin for pin in report["images"]}
    records = [sidecar(row, pins[row["lead"]["image_id"]],
                       [] if row.get("reason") == "lead_output_limit" else metadata_gaps.get(row["lead"]["id"], []),
                       redacted=row["lead"]["id"] in redacted_leads, abi_policy=abi_policy)
               for row in report["leads"]]
    return {"policy": POLICY, "decoder_policy": objc_types.POLICY, "abi_policy": abi_policy,
            "limitations": limitations(abi_policy), "records": records}


def validate(report):
    if FIELD not in report:
        return {}
    section = report[FIELD]
    if (not isinstance(section, dict) or set(section) != {"policy", "decoder_policy", "abi_policy", "limitations", "records"}
            or section["policy"] != POLICY or section["decoder_policy"] != objc_types.POLICY
            or section["abi_policy"] not in ABI_POLICIES or section["limitations"] != limitations(section["abi_policy"])
            or not isinstance(section["records"], list) or len(section["records"]) != len(report["leads"])):
        raise ValueError("Unsupported or malformed Objective-C type sidecar policy")
    gaps = {}
    for record, row in zip(section["records"], report["leads"]):
        if not isinstance(record, dict) or record.get("lead_id") != row["lead"]["id"]:
            raise ValueError("Objective-C sidecar lead identity differs")
        gaps[record["lead_id"]] = record["metadata_gaps"]
        if any(gap not in row["gaps"] and gap != row.get("reason") for gap in record["metadata_gaps"]):
            raise ValueError("Sidecar metadata gaps differ from the lead")
    redacted = [record["lead_id"] for record in section["records"] if record.get("reason") == "declaration_redacted"]
    if section != build(report, gaps, redacted_leads=redacted, abi_policy=section["abi_policy"]):
        raise ValueError("Objective-C sidecar differs from its declaration and pins")
    return {row["lead_id"]: row for row in section["records"]}


def redact_report(report, sanitizer):
    clean = sanitizer(report)
    if FIELD not in report:
        return clean
    changed = [row["lead"]["id"] for row, sanitized in zip(report["leads"], clean["leads"])
               if row["lead"] != sanitized["lead"] or row["matches"] != sanitized["matches"]]
    gaps = {row["lead_id"]: row["metadata_gaps"] for row in clean[FIELD]["records"]}
    clean[FIELD] = build(clean, gaps, redacted_leads=changed, abi_policy=report[FIELD]["abi_policy"])
    return clean


def observations(record, abi_policy=ABI_POLICY):
    declaration = record["declaration"]
    if declaration:
        declaration = {key: declaration[key] for key in ("name", "class_name", "category", "method_kind", "type_encoding")
                       if key in declaration}
    return {"policy": POLICY, "decoder_policy": objc_types.POLICY, "abi_policy": abi_policy,
            **{key: record[key] for key in ("status", "reason", "metadata_gaps", "decoded_types", "abi_projection")},
            "declaration": declaration}
