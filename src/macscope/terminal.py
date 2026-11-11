"""Deterministic, terminal-safe views of CLI evidence envelopes."""
import io

from . import evidence_summary


def safe(value):
    if value is None:
        return "unavailable"
    text = str(value)
    if text.isprintable():
        return text
    named = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}
    return "".join(char if char.isprintable() else named.get(char) or f"\\u{{{ord(char):x}}}"
                   for char in text)


class Report:
    def __init__(self):
        self.output = io.StringIO()

    def line(self, value=""):
        self.output.write(value + "\n")

    def field(self, label, value):
        self.line(f"{label}  {safe(value)}")

    def code(self, value):
        for line in value.split("\n"):
            self.line("    " + safe(line.expandtabs(4)))

    def tree(self, value, depth=0):
        indent = "  " * depth
        if isinstance(value, dict) and value:
            entries = sorted(value.items())
        elif isinstance(value, list) and value:
            entries = ((f"[{index}]", row) for index, row in enumerate(value, 1))
        else:
            self.line(indent + safe(value))
            return
        for key, item in entries:
            if isinstance(item, (dict, list)) and item:
                self.line(indent + safe(key))
                self.tree(item, depth + 1)
            else:
                self.line(f"{indent}{safe(key)}  {safe(item)}")


def function_name(row):
    names = row.get("names") or []
    return names[0]["name"] if names else row.get("name") or "unnamed"


def function(report, row):
    entry = row.get("entry_va") or row.get("engine_entry")
    status = row.get("decompile_status", "unknown")
    report.line(f"{safe(entry)}  {safe(function_name(row))}  [{safe(status)}]")
    report.field("  Function ID", row.get("function_id"))
    for name in (row.get("names") or [])[1:]:
        report.field(f"  Name ({safe(name.get('origin'))})", name.get("name"))
    if row.get("signature"):
        report.field("  Signature", row["signature"])
    if target := row.get("thunk_target"):
        report.field("  Thunk target", f"{target['name']} ({target['engine_entry']})")
    if overlap := row.get("body_overlap"):
        report.field("  Body overlap", f"{overlap['start_va']}–{overlap['last_va']} with {overlap['other_function_id']}")


def functions(report, data):
    if isinstance(data, list):
        for row in data:
            function(report, row)
        return
    function(report, data)
    for key in ("body_ranges", "entry_address", "origin", "coverage", "annotations", "control_flow_gaps"):
        if data.get(key):
            report.line("  " + key.replace("_", " ").capitalize())
            report.tree(data[key], 2)


def decompile(report, data):
    if isinstance(data, dict) and data.get('policy') == 'macscope-focused-selection-preflight/1':
        report.line('Static selection preflight only; no decompilation or native readiness check.')
        report.tree(data)
        return
    if batch := data.get("batch_summary"):
        report.line("Captured batch outcomes")
        report.tree(batch, 1)
        report.line()
    if summary := data.get("summary"):
        report.line("Page outcomes")
        report.tree(summary, 1)
        report.line()
    rows = data.get("functions", [data])
    if not rows:
        report.line("No matching functions.")
    for row in rows:
        function(report, row)
        code = row.get("pseudocode")
        if code:
            report.code(code.strip("\n"))
        else:
            report.field("  Pseudocode", row.get("decompile_error") or "unavailable")
        if row.get("origin"):
            report.line("  Provenance")
            report.tree(row["origin"], 2)
        if row.get("control_flow_gaps"):
            report.line("  Control-flow gaps")
            report.tree(row["control_flow_gaps"], 2)
        report.line()


def disasm(report, data):
    if data.get("function_id"):
        report.field("Function ID", data["function_id"])
    if "start_va" in data:
        report.line(f"Range  {safe(data['start_va'])}–{safe(data['end_va'])} (end excluded)")
        report.line(f"Bytes covered  {safe(data['covered_bytes'])} of {safe(data['requested_bytes'])}")
    report.line("Address             Bytes                            Instruction")
    for ins in data["instructions"]:
        asm = ins.get("text") or ins.get("mnemonic")
        report.line(f"{safe(ins.get('addr')):<18}  {safe(ins.get('bytes')):<30}  {safe(asm)}")
    for key in ("gaps", "control_flow_gaps"):
        if data.get(key):
            report.line("Instruction gaps" if key == "gaps" else "Control-flow gaps")
            report.tree(data[key], 1)
    if isinstance(data.get("callback_evidence"), dict):
        callback_summary(report, data["callback_evidence"])
    if ownership := data.get("body_ownership"):
        report.line("Function body ownership")
        report.tree(ownership, 1)



def callback_summary(report, evidence):
    """Bounded display only: never modifies evidence or upgrades its claims."""
    marker = "...[truncated]"

    def clipped(text, limit):
        raw = text.encode('utf-8')
        return text if len(raw) <= limit else raw[:limit-len(marker)].decode('utf-8', 'ignore') + marker

    def field(value):
        if isinstance(value, (dict, list, tuple)):
            return '[structured; see JSON]'
        value = 'unavailable' if value is None else str(value)
        shortened = value[:120]
        if len(value) > 120:
            shortened += marker
        return clipped(safe(shortened), 240)

    def row(value):
        return value if isinstance(value, dict) else {}

    def sequence(value):
        return value if isinstance(value, list) else []

    lines = []
    def line(value):
        lines.append(clipped(value, 320))

    composition = row(evidence.get('composition'))
    chain = row(evidence.get('two_hop_chain'))
    source = composition or chain or evidence
    link = row(evidence.get('destination_link'))
    effects = row(source.get('destination_effects')) or row(link.get('destination_effects'))
    selection = row(evidence.get('selection'))
    line('Callback evidence (bounded summary; independent of byte-decoding completion)')
    line('  Analysis status: ' + field(source.get('status')))
    if chain:
        line('  Two-hop links: ' + field(chain.get('link_status')) + ' (independent edges; not runtime proof)')
        line('  Outer extent: ' + field(chain.get('source_extent')))
        if boundary := row(chain.get('source_extent_evidence')):
            line('  Outer boundary basis: ' + field(boundary.get('basis', boundary.get('reason'))))
        if forwarding := row(chain.get('register_forwarding')):
            line('  Static register forwarding: ' + field(forwarding.get('status'))
                 + '; destination entry: ' + field(forwarding.get('destination_entry_va')))
        line('  Destination prefix stop: ' + field(chain.get('destination_stop_reason')))
        if writer_proof := row(chain.get('writer_call_evidence')):
            line('  Conditional writer proof: ' + field(writer_proof.get('status')) + ' (runtime values unknown)')
    if composition:
        if composition.get('route_kind'):
            line('  Composition route: ' + field(composition.get('route_kind'))
                 + '; conditional writer-entry bindings: ' + field(len(composition.get('conditional_writer_entry_bindings', []))))
        line('  Composition candidate: ' + field(composition.get('candidate_status')) + ' (not runtime proof)')
    line('  Selected source: ' + field(selection.get('start_va')) + ':' + field(selection.get('end_va')))
    line('  Source envelope: ' + field(evidence.get('source_envelope_sha256')))
    line('  Application writer attribution: ' + field(effects.get('application_writer_attribution', 'unknown'))
         + '; runtime execution: ' + field(effects.get('runtime_execution', 'unknown'))
         + '; persistence: ' + field(effects.get('persistence', 'unknown')))
    if effects:
        counts = row(effects.get('counts'))
        line('  Observed destination stores: stack/frame=' + field(counts.get('stack_or_frame'))
             + '; mapped nonstack=' + field(counts.get('mapped_image_nonstack'))
             + '; unresolved=' + field(counts.get('unresolved_destination')))
    if link:
        line('  Destination link: ' + field(link.get('status')) + '; reason=' + field(link.get('reason')))
        line('  Destination prefix stop: ' + field(row(link.get('destination_evidence')).get('stop_reason')))
    line('  Selected-prefix stop: ' + field(evidence.get('stop_reason')))

    def details(label, values, render):
        values = sequence(values)
        line('  ' + label + ': ' + str(len(values)))
        for item in values[:4]:
            line('    ' + render(item))
        if len(values) > 4:
            line('    Omitted ' + str(len(values)-4) + ' entries; see JSON')

    def scoped(item):
        item = row(item)
        detail = row(item.get('evidence')) or item
        return ('role=' + field(item.get('role', 'selected_source')) + '; '
                + field(detail.get('reason') or detail.get('kind'))
                + '; site=' + field(detail.get('instruction_va'))
                + ('; fallthrough=' + field(detail.get('fallthrough_predicate')) if 'fallthrough_predicate' in detail else ''))

    def assumption(item):
        if not isinstance(item, dict):
            return field(item)
        return 'role=' + field(item.get('role')) + '; ' + field(item.get('condition'))

    # Composition decisions follow collected role-local boundaries in JSON.
    # Surface explicit decision reasons first without changing evidence ordering.
    gaps = sequence(source.get('gaps'))
    if chain:
        gaps = gaps + [{'role':'writer_proof','evidence':g} for g in sequence(row(chain.get('writer_call_evidence')).get('gaps'))]
        gaps = gaps + [{'role':'destination','evidence':g} for g in sequence(chain.get('destination_gaps'))]
    if composition:
        gaps = sorted(gaps, key=lambda item: 'reason' not in row(item))
    details('Gaps (explicit decisions first; may include role-local boundaries)', gaps, scoped)
    details('Assumptions', source.get('assumptions'), assumption)
    details('Path obligations (not executed paths)', source.get('path_obligations'), scoped)
    details('Call obligations (normal return / ABI hypotheses; side effects unknown)', source.get('call_obligations'), scoped)
    details('Unknowns / missing evidence', source.get('unknowns', source.get('missing_evidence')), field)
    if composition:
        if diagnostic := row(composition.get('assignment_diagnostic')):
            line('  Assignment diagnostic: ' + field(diagnostic.get('reason')))
        assignment = row(row(composition.get('independent_evidence')).get('assignment'))
        line('  Assignment selection: ' + field(row(assignment.get('selection')).get('start_va'))
             + ':' + field(row(assignment.get('selection')).get('end_va'))
             + '; stop=' + field(assignment.get('stop_reason')))
        line('  Assignment envelope: ' + field(assignment.get('source_envelope_sha256')))
        line('  Expected selected thunk entry: ' + field(selection.get('start_va')))
        stores = [s for s in sequence(assignment.get('sites')) if row(s).get('kind') == 'memory_store']
        def store(item):
            value = row(item.get('value'))
            return ('site=' + field(item.get('instruction_va')) + '; lane=' + field(item.get('lane'))
                    + '; value=' + field(value.get('kind')) + ':'
                    + field(value.get('value') if value.get('kind') == 'address' else value.get('register')))
        details('Assignment stores (not inferred callback targets)', stores, store)
    # Fixed list caps produce <= 53 lines / 16 KiB; retain a final full-evidence route.
    for value in lines:
        report.line(value)
    report.line('  Full evidence: repeat with --format json; summary omissions do not imply complete analysis.')


def references(report, data):
    if data.get("policy") == "macscope-focused-receipt-xrefs/1":
        report.field("Scope", data.get("scope"))
        report.field("Saved query job", data.get("publication_job_id"))
        report.field("Source envelope", data.get("source_envelope_sha256"))
        report.field("Recorded query status", data.get("source_query_status"))
        report.field("Reference gaps", "; ".join(data.get("gaps", [])) or "none within recorded scope")
    if data.get("function_id"):
        report.field("Function ID", data["function_id"])
    for key, label in (("references", "References"), ("to_entry", "Incoming to entry"), ("from_body", "Outgoing from body")):
        if key not in data:
            continue
        report.field(label, len(data[key]))
        for ref in data[key]:
            target = safe(ref["to"]) if ref["to"] is not None else "unresolved"
            status = ref.get("target_status")
            detail = f" [{safe(status)}]" if status else ""
            report.line(f"  {safe(ref['from'])} -> {target}  {safe(ref['type'])}{detail}")
    if data.get("control_flow_gaps"):
        report.line("Control-flow gaps")
        report.tree(data["control_flow_gaps"], 1)


def cfg(report, data):
    report.field("Function ID", data["function_id"])
    for block in data["blocks"]:
        report.line(f"{safe(block['min'])}–{safe(block['max'])}  {safe(block.get('flow'))}")
        for edge in block["dsts"]:
            report.line(f"  -> {safe(edge['to'])}  {safe(edge.get('flow'))}")
    if data.get("control_flow_gaps"):
        report.line("Control-flow gaps")
        report.tree(data["control_flow_gaps"], 1)


def calls(report, data):
    report.field("Root function ID", data["root_function_id"])
    report.line(f"Direction  {safe(data['direction'])}    Depth  {safe(data['depth'])}")
    names = {row["function_id"]: f"{safe(function_name(row))} ({safe(row['engine_entry'])})"
             for row in data["nodes"]}
    for edge in data["edges"]:
        caller = names.get(edge["caller_function_id"], edge["caller_function_id"])
        callee = names.get(edge["callee_function_id"], edge["reported_target"])
        report.line(f"{safe(edge['callsite'])}  {safe(caller)} -> {safe(callee)}  "
                    f"{safe(edge['type'])} [{safe(edge['resolution'])}]")


def search(report, data):
    for hit in data:
        address = hit.get("va") or hit.get("engine_address")
        detail = " (context clipped)" if hit.get("context_truncated") else ""
        report.line(f"{safe(address)}  {safe(hit['kind'])} ({safe(hit.get('source'))}){detail}")
        report.line("  " + safe(hit["context"]))
        if hit.get("function_id"):
            report.field("  Function ID", hit["function_id"])


def byte_dump(report, data):
    report.field("Slice file offset", data["slice_file_offset"])
    report.field("Container file offset", data["container_file_offset"])
    start = int(data.get("va") or data["slice_file_offset"], 16)
    report.line("VA" if data.get("va") else "Slice offset")
    payload = bytes.fromhex(data["bytes"])
    for offset in range(0, len(payload), 16):
        row = payload[offset:offset + 16]
        ascii_view = "".join(chr(byte) if 0x20 <= byte <= 0x7e else "." for byte in row)
        report.line(f"{start + offset:#018x}  {row.hex(' '):<47}  |{ascii_view}|")


def project_status_summary(report, data):
    """Explain recorded lifecycle separately; preserve the full raw status below."""
    def field(value):
        text = safe(value)
        return text[:160] + (' [clipped]' if len(text) > 160 else '')
    rows = data.get('images', [])
    rows = rows if isinstance(rows, list) else []
    report.line('Import and whole-image analysis are independent of query outcomes and graph coverage.')
    for image in rows[:8]:
        if not isinstance(image, dict):
            report.line('Image status unavailable: invalid recorded row.')
            continue
        analysis = image.get('analysis');analysis = analysis if isinstance(analysis, dict) else {}
        programs = image.get('programs');programs = programs if isinstance(programs, dict) else {}
        imported = programs.get('import');imported = imported if isinstance(imported, dict) else {}
        analyzed = programs.get('analysis');analyzed = analyzed if isinstance(analyzed, dict) else {}
        import_status = imported.get('status') or ('recorded, not verified in this view' if image.get('imported') else 'not recorded')
        report.line('Image ' + field(image.get('image_id')) + ': import ' + field(import_status))
        if imported.get('error') or imported.get('reason'):
            report.line('  Import diagnostic: ' + field(imported.get('error') or imported.get('reason')))
        no_analysis = (analysis.get('status') == 'not_analyzed' and 'analysis_id' in analysis
                       and analysis['analysis_id'] is None and 'active_analysis' in image
                       and image['active_analysis'] is None and image.get('imported')
                       and imported.get('status') in (None, 'verified')
                       and analyzed.get('status') in (None, 'not_analyzed')
                       and not any(row.get(key) for row in (analysis, imported, analyzed) for key in ('error','reason')))
        if no_analysis:
            report.line('  No whole-image analysis recorded (no committed snapshot).')
        else:
            report.line('  Whole-image analysis: ' + field(analysis.get('status')) +
                        '; ID: ' + field(analysis.get('analysis_id')))
        if analysis.get('error') or analysis.get('reason'):
            report.line('  Analysis diagnostic: ' + field(analysis.get('error') or analysis.get('reason')))
        if analyzed:
            report.line('  Analysis Program verification: ' + field(analyzed.get('status')) +
                        '; diagnostic: ' + field(analyzed.get('error') or analyzed.get('reason')))
    report.line(f'Summary images omitted: {max(0,len(rows)-8)}. Full status and job outcomes follow unchanged.')
    report.line('A missing committed snapshot does not mean no analysis was attempted; failed jobs remain below.')


LAYOUTS = {
    "functions list": functions, "functions show": functions, "decompile": decompile,
    "disasm": disasm, "xrefs": references, "cfg": cfg, "calls": calls, "search": search,
    "bytes": byte_dump,
}


def render(result):
    report = Report()
    command = result["command"]
    report.line(f"macscope {safe(command)}  [{safe(result['status'])}]")
    if result.get("analysis_id"):
        report.field("Analysis", result["analysis_id"])
    if selection := result.get("address_selection"):
        report.field("Runtime VA", selection["runtime_va"])
        report.field("Load slide", selection["load_slide"])
        report.field("Unslid VA", selection["va"])
    cov = result["coverage"]
    total = cov["known_total"] if cov["known_total"] is not None else "unknown"
    report.line(f"Coverage  {safe(cov['scope'])}  ({safe(cov['status'])})")
    report.line(f"Returned  {safe(cov['returned_count'])} of {safe(total)}")
    if cov["truncation_reason"]:
        report.field("Coverage gap", cov["truncation_reason"])
    if cov["next_cursor"]:
        report.field("Next cursor", cov["next_cursor"])
    for diagnostic in result["diagnostics"]:
        report.field("Diagnostic", diagnostic)
    report.line()
    data = result["data"]
    if command == "evidence" and isinstance(data, dict):
        evidence_summary.render(report, data)
    if command == "status" and isinstance(data, dict):
        project_status_summary(report, data)
    layout = LAYOUTS.get(command)
    if data == []:
        report.line("No matching records.")
    elif layout:
        layout(report, data)
    else:
        report.tree(data)
    return report.output.getvalue().encode("utf-8")
