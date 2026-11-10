"""Deterministic, terminal-safe views of CLI evidence envelopes."""
import io


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
    if summary := data.get("summary"):
        report.line("Decompilation outcomes")
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


def references(report, data):
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
    layout = LAYOUTS.get(command)
    if data == []:
        report.line("No matching records.")
    elif layout:
        layout(report, data)
    else:
        report.tree(data)
    return report.output.getvalue().encode("utf-8")
