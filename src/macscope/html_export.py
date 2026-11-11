"""Render private, standalone views of committed evidence."""
import base64
import hashlib
from html import escape
import io
import json
import re

from .errors import Error
from . import objc_type_evidence


MAX_HTML_BYTES = 64 * 1024 * 1024
CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ud800-\udfff]")
STYLE = """body { font: 1rem/1.5 system-ui, sans-serif; margin: 2rem auto; padding: 0 1rem; max-width: 80rem; }
:root { color-scheme: light dark; }
dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: .25rem 1rem; }
dd { margin: 0; overflow-wrap: anywhere; }
details { margin: .75rem 0; padding: .5rem; border: 1px solid GrayText; }
summary { cursor: pointer; overflow-wrap: anywhere; }
pre { overflow: auto; padding: .75rem; border: 1px solid GrayText; }
.record { white-space: pre-wrap; overflow-wrap: anywhere; }
.status { font-size: .9em; font-weight: 600; }
"""
STYLE_HASH = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode("ascii")
JSON = json.JSONEncoder(ensure_ascii=True, indent=2, sort_keys=True)


def text(value):
    value = "Unavailable" if value is None else str(value)
    return escape(CONTROLS.sub(lambda match: f"\\u{ord(match[0]):04x}", value))


def function_label(function):
    names = function.get("names", ())
    name = function.get("name") or (names[0]["name"] if names else "Unnamed function")
    address = function.get("entry_va") or function.get("engine_entry")
    return f"<code>{text(address)}</code> {text(name)}"


class Report:
    def __init__(self, title, heading, fields, coverage):
        self.buffer = io.BytesIO()
        self.add(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{STYLE_HASH}'; base-uri 'none'; form-action 'none'">
<title>{text(title)}</title>
<style>{STYLE}</style>
</head>
<body>
<main>
<header>
<p>{text(title)}</p>
<h1>{text(heading)}</h1>
<p>Private analysis data. The report may contain recovered code and strings.</p>
<dl>
""")
        for label, value in (*fields, ("Coverage", coverage["status"])):
            self.add(f"<dt>{label}</dt><dd>{text(value)}</dd>\n")
        if reason := coverage.get("truncation_reason"):
            self.add(f"<dt>Coverage gap</dt><dd>{text(reason)}</dd>\n")
        self.add("</dl>\n</header>\n")

    def add(self, markup):
        encoded = markup.encode("utf-8")
        if self.buffer.tell() + len(encoded) > MAX_HTML_BYTES:
            raise Error("html_output_limit", "HTML export exceeds its output byte limit", 7)
        self.buffer.write(encoded)

    def evidence(self, title, value):
        self.add(f'<details><summary>{escape(title)}</summary><pre class="record">')
        for chunk in JSON.iterencode(value):
            self.add(escape(chunk))
        self.add("</pre></details>\n")

    def finish(self):
        self.add("</main>\n</body>\n</html>\n")
        return self.buffer.getvalue()

    def function(self, index, function):
        status = text(function.get("decompile_status"))
        self.add(f'<details id="function-{index}"><summary>{function_label(function)} '
                 f'<span class="status">({status})</span></summary>\n')
        self.add(f'<p><strong>Function ID</strong> <code>{text(function["function_id"])}</code></p>\n')
        self.add(f'<p><strong>Signature</strong> <code>{text(function.get("signature"))}</code></p>\n')
        self.add("<h3>Pseudocode</h3>\n")
        pseudocode = function.get("pseudocode")
        if pseudocode:
            # The initial newline is discarded by HTML's pre parsing rule.
            self.add(f"<pre>\n{text(pseudocode)}</pre>\n")
        else:
            self.add(f'<p>{text(function.get("decompile_error") or "Pseudocode unavailable.")}</p>\n')
        instructions = function.get("instructions", ())
        if instructions:
            self.add(f"<details><summary>Assembly ({len(instructions)} instructions)</summary><pre>\n")
            for instruction in instructions:
                fields = (instruction.get("addr"), instruction.get("bytes"),
                          instruction.get("text") or instruction.get("mnemonic"))
                self.add("  ".join(map(text, fields)) + "\n")
            self.add("</pre></details>\n")
        self.evidence("Control flow, references and function coverage",
                      {key: value for key, value in function.items() if key != "pseudocode"})
        self.add("</details>\n")


def render(result):
    snapshot = result["data"]
    image, engine, functions = (snapshot[key] for key in ("image", "engine", "functions"))
    fields = (
        ("Analysis ID", result["analysis_id"]), ("Image ID", image["image_id"]),
        ("Architecture", image["arch"]), ("Slice SHA-256", image.get("sha256")),
        ("Ghidra version", engine.get("ghidra_version")),
        ("Profile", snapshot.get("identity", {}).get("profile")), ("Status", result["status"]),
        ("Functions shown", len(functions)),
    )
    report = Report("Macscope analysis report", image.get("input_name") or "Committed image",
                    fields, result["coverage"])
    report.add("<h2>Analysis evidence</h2>\n")
    report.evidence("Manifest, coverage and diagnostics",
                    dict(result, data={key: value for key, value in snapshot.items()
                                       if key not in ("image", "engine", "functions", "annotations")}))
    report.evidence("Mach-O image metadata", image)
    report.evidence("Ghidra evidence and effective options", engine)
    if "annotations" in snapshot:
        report.evidence("Annotation history", snapshot["annotations"])
    report.add("<h2>Functions</h2>\n")
    if functions:
        report.add('<nav aria-label="Function index"><ol>\n')
        for index, function in enumerate(functions, 1):
            report.add(f'<li><a href="#function-{index}">{function_label(function)}</a></li>\n')
        report.add("</ol></nav>\n")
        for index, function in enumerate(functions, 1):
            report.function(index, function)
    else:
        report.add("<p>The snapshot contains zero function records.</p>\n")
    return report.finish()


def render_handoff(result):
    data = result["data"]
    leads = data["leads"]
    type_sidecars = objc_type_evidence.validate(data)
    fields = (("Manifest SHA-256", data["manifest_sha256"]), ("Authority", data["authority"]),
              ("Status", result["status"]), ("Leads shown", len(leads)))
    report = Report("Macscope evidence handoff", "Pinned evidence leads", fields, result["coverage"])
    report.evidence("Handoff metadata", dict(result, data={key: value for key, value in data.items()
                                                          if key not in ("images", "leads", objc_type_evidence.FIELD)}))
    if type_sidecars:
        report.evidence("Objective-C declaration type policy", {key: value for key, value in data[objc_type_evidence.FIELD].items()
                                                              if key != "records"})
    report.evidence("Pinned images", data["images"])
    report.add('<nav aria-label="Lead index"><ol>\n')
    for index, row in enumerate(leads, 1):
        report.add(f'<li><a href="#lead-{index}">{text(row["lead"]["id"])}</a> '
                   f'({text(row["status"])})</li>\n')
    report.add("</ol></nav>\n")
    for index, row in enumerate(leads, 1):
        lead = row["lead"]
        report.add(f'<section id="lead-{index}">\n<h2>{text(lead["id"])}</h2>\n'
                   f'<p><code>{text(lead["kind"])}</code> <code>{text(lead["value"])}</code> '
                   f'<span class="status">({text(row["status"])})</span></p>\n')
        if row["reason"]:
            report.add(f'<p><strong>Reason</strong> <code>{text(row["reason"])}</code></p>\n')
        if row["gaps"]:
            report.add("<p>Coverage gaps</p>\n<ul>\n")
            for gap in row["gaps"]:
                report.add(f"<li><code>{text(gap)}</code></li>\n")
            report.add("</ul>\n")
        report.evidence("Selection and match evidence", {key: row[key] for key in
                        ("lead", "matches", "match_references", "candidates")})
        if lead["id"] in type_sidecars:
            report.evidence("Declared Objective-C types and conditional ABI roles", type_sidecars[lead["id"]])
        if row["function"] is not None:
            report.function(index, row["function"])
        if "fixup" in row:
            report.evidence("Exact dyld fixup", row["fixup"])
        if "declared_imports" in row:
            report.evidence("Declared imports", row["declared_imports"])
        if "selected_calls" in row:
            report.evidence("Direct calls to selected focused functions", row["selected_calls"])
        if query := row["query"]:
            if pseudocode := query.get("pseudocode"):
                report.add(f"<details><summary>Saved query pseudocode</summary><pre>\n{text(pseudocode)}</pre></details>\n")
            report.evidence("Saved query evidence", {key: value for key, value in query.items() if key != "pseudocode"})
        report.add("</section>\n")
    return report.finish()
