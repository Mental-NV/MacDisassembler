"""Literal search over a committed analysis snapshot."""
import re

from .errors import Error


SCOPES = ("names", "strings", "pseudocode", "comments")


def pattern(query):
    if not 1 <= len(query) <= 256 or not query.strip() or not query.isprintable():
        raise Error("search_query", "Search requires 1..256 printable characters", 2)
    return re.compile(re.escape(query), re.IGNORECASE)


def snapshot_matches(snapshot, term, scope, *, comments=()):
    fields = SCOPES if scope == "all" else (scope,)
    image = snapshot["image"]
    engine = snapshot["engine"]
    functions = snapshot["functions"]
    engine_coverage = engine.get("coverage", {})
    hits = []
    gaps = []

    def add(kind, value, address, function_id=None, *, source, namespace=None, origin="ghidra"):
        if not isinstance(value, str):
            return
        match = term.search(value)
        if match is None:
            return
        va = address if address and re.fullmatch(r"0x[0-9a-fA-F]{1,16}", address) else None
        start = max(0, match.start() - 60)
        end = min(len(value), match.end() + 60)
        hits.append({
            "kind": kind, "source": source, "namespace": namespace, "origin": origin,
            "function_id": function_id, "image_id": image["image_id"], "arch": image["arch"],
            "engine_address": address, "va": va,
            "context": value[start:end], "context_start": start,
            "context_truncated": start > 0 or end < len(value),
        })

    entries = {f["engine_entry"]: f["function_id"] for f in functions}
    if "names" in fields:
        for function in functions:
            for name in function["names"]:
                add("name", name["name"], function["engine_entry"], function["function_id"],
                    source="function", namespace=function.get("namespace"), origin=name["origin"])
        for symbol in engine.get("symbols", []):
            address = symbol.get("address")
            add("name", symbol.get("name"), address, entries.get(address),
                source="symbol", namespace=symbol.get("namespace"))
        if engine_coverage.get("symbols", {}).get("status") != "complete":
            gaps.append("symbol_coverage_incomplete")

    if "strings" in fields:
        strings = engine.get("strings", [])
        for item in strings:
            add("string", item.get("value"), item.get("address"), source="defined_string")
        if (engine_coverage.get("strings", {}).get("status") != "complete"
                or any(item.get("value_truncated") or item.get("value") is None for item in strings)):
            gaps.append("string_coverage_incomplete")

    if "pseudocode" in fields:
        for function in functions:
            add("pseudocode", function.get("pseudocode"), function["engine_entry"],
                function["function_id"], source="decompiler")
        if any(f.get("pseudocode_truncated")
               or not ((f["decompile_status"] == "complete" and f.get("pseudocode"))
                       or (f["decompile_status"] == "not_requested"
                           and (f["is_external"] or f["is_thunk"])))
               for f in functions):
            gaps.append("pseudocode_coverage_incomplete")

    if "comments" in fields:
        for comment in comments:
            if comment["kind"] == "comment":
                entry = comment["engine_entry"]
                add("comment", comment["value"], comment["instruction"] or entry, entries.get(entry),
                    source="annotation", origin="user_supplied")

    if "names" in fields or "pseudocode" in fields:
        if (engine.get("functions_truncated")
                or engine_coverage.get("functions", {}).get("status", "complete") != "complete"):
            gaps.append("function_coverage_incomplete")
    if scope != "comments":
        if engine.get("analysis_timed_out"):
            gaps.append("analysis_timeout")
        if engine.get("output_budget_reached"):
            gaps.append("engine_output_limit")
    if engine.get("strings_or_names_truncated") and ("names" in fields or "strings" in fields):
        gaps.append("engine_text_limit")

    hits.sort(key=lambda hit: (
        hit["kind"], hit["va"] is None, int(hit["va"], 16) if hit["va"] else 0,
        hit["engine_address"] or "", hit["source"], hit["namespace"] or "", hit["context"],
        hit["function_id"] or "", hit["context_start"], hit["context_truncated"], hit["origin"],
    ))
    return hits, gaps
