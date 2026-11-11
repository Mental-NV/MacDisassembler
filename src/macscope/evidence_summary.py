"""Bounded presentation of existing lead evidence; never resolves evidence."""
MAX_LEADS = 32
MAX_GAPS = 8
MAX_LABEL = 160


def label(value):
    text = str(value)
    return text[:MAX_LABEL] + ("…" if len(text) > MAX_LABEL else "")


def next_action(codes):
    if "lead_ambiguous" in codes:
        return "Disambiguate the selected lead using its recorded candidates."
    if any("limit" in code or "budget" in code for code in codes):
        return "Review the recorded limit and narrow the selected scope; completeness is not guaranteed."
    if any("receipt" in code or "query" in code for code in codes):
        return "Inspect the selected saved receipt and its identity; restore matching evidence if available."
    if any("instruction" in code or "pseudocode" in code or "flow" in code for code in codes):
        return "Inspect recorded instructions and flow gaps; unsupported or unresolved paths remain unknown."
    return "Inspect this lead's detailed evidence and source identity before selecting further analysis."


def render(report, data):
    leads = data.get("leads", [])
    report.line("Selected lead summary")
    report.line("  Worker success and complete individual links do not establish complete graph coverage.")
    for row in leads[:MAX_LEADS]:
        report.field("  Lead", label(row.get("lead", {}).get("id", "ID unavailable")) + " [" + label(row["status"]) + "]")
        if row["status"] == "resolved":
            report.line("    Selected static requirements met; runtime behavior and exhaustive coverage not established.")
            continue
        reason = row.get("reason")
        gaps = row.get("gaps") or []
        count = len(gaps) + bool(reason)
        codes = ([reason] if reason else []) + gaps[:MAX_GAPS]
        shown = codes[:MAX_GAPS]
        for code in shown:
            report.field("    Gap (site not specified by this code)", label(code))
        if not count:
            report.line("    Missing evidence not specified; no gap site inferred.")
        if count > MAX_GAPS:
            report.field("    Additional reason/gap entries omitted from summary", count - MAX_GAPS)
        report.field("    Next", next_action(shown))
    if len(leads) > MAX_LEADS:
        report.field("  Additional leads omitted from summary", len(leads) - MAX_LEADS)
    report.line("  Full recorded reasons, gaps and any locations remain in the detailed evidence below.")
    report.line()
