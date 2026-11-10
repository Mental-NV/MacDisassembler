"""Literal and bounded regex search over a committed analysis snapshot."""
import json
import re
import subprocess
import sys

from .errors import Error


SCOPES = ("names", "strings", "pseudocode", "comments")
REGEX_TIMEOUT_SECONDS = 3
MAX_REGEX_BYTES = 64 * 1024 * 1024
MAX_REGEX_RECORDS = 100000
CONTEXT_MARGIN = 60
MAX_CONTEXT = 376

# JSON lines on stdin preserve text boundaries. Return only character offsets.
REGEX_WORKER = """
import json, re, sys
lines = sys.stdin.buffer
try:
    term = re.compile(json.loads(next(lines)), re.IGNORECASE)
except (re.error, OverflowError, RecursionError) as error:
    json.dump({"error": str(error)}, sys.stdout)
    raise SystemExit
matches = []
for index, line in enumerate(lines):
    match = term.search(json.loads(line))
    if match is not None:
        matches.append((index, *match.span()))
json.dump(matches, sys.stdout)
"""


def pattern(query, *, regex=False):
    if not 1 <= len(query) <= 256 or not query.strip() or not query.isprintable():
        raise Error("search_query", "Search requires 1..256 printable characters", 2)
    return query if regex else re.compile(re.escape(query), re.IGNORECASE)


def regex_matches(expression, values):
    payload = bytearray(json.dumps(expression).encode("ascii") + b"\n")
    for value in values:
        if len(value) >= MAX_REGEX_BYTES - len(payload):
            raise Error("search_regex_limit", "Regex search exceeds its text budget; narrow --in", 7)
        line = json.dumps(value).encode("ascii")
        if len(payload) + len(line) + 1 > MAX_REGEX_BYTES:
            raise Error("search_regex_limit", "Regex search exceeds its text budget; narrow --in", 7)
        payload.extend(line)
        payload.append(10)
    try:
        worker = subprocess.run([sys.executable, "-I", "-S", "-c", REGEX_WORKER], input=payload,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/", env={},
                                timeout=REGEX_TIMEOUT_SECONDS, check=True)
        result = json.loads(worker.stdout)
    except subprocess.TimeoutExpired as error:
        raise Error("search_regex_timeout", f"Regex search exceeded its {REGEX_TIMEOUT_SECONDS}-second matching deadline",
                    7) from error
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise Error("search_regex_worker", "Could not complete the regex search worker", 10) from error
    if isinstance(result, dict):
        raise Error("search_regex", f"Invalid regular expression: {result['error']}", 2)
    return result


def entry_labels_incomplete(functions):
    return any(function.get("coverage", {}).get("entry_labels", {}).get("status", "complete") != "complete"
               for function in functions)


def snapshot_matches(snapshot, term, scope, *, comments=(), regex=False):
    fields = SCOPES if scope == "all" else (scope,)
    image = snapshot["image"]
    engine = snapshot["engine"]
    functions = snapshot["functions"]
    engine_coverage = engine.get("coverage", {})
    hits = []
    gaps = []
    candidates = []

    def emit(kind, value, address, function_id, source, namespace, origin, *, span):
        va = address if address and re.fullmatch(r"0x[0-9a-fA-F]{1,16}", address) else None
        start = max(0, span[0] - CONTEXT_MARGIN)
        end = min(len(value), span[1] + CONTEXT_MARGIN, start + MAX_CONTEXT)
        hits.append({
            "kind": kind, "source": source, "namespace": namespace, "origin": origin,
            "function_id": function_id, "image_id": image["image_id"], "arch": image["arch"],
            "engine_address": address, "va": va,
            "context": value[start:end], "context_start": start,
            "context_truncated": start > 0 or end < len(value),
        })

    def add(kind, value, address, function_id=None, *, source, namespace=None, origin="ghidra"):
        if not isinstance(value, str):
            return
        record = (kind, value, address, function_id, source, namespace, origin)
        if regex:
            if len(candidates) == MAX_REGEX_RECORDS:
                raise Error("search_regex_limit", "Regex search exceeds its record budget; narrow --in", 7)
            candidates.append(record)
        elif match := term.search(value):
            emit(*record, span=match.span())

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
        if entry_labels_incomplete(functions):
            gaps.append("function_entry_label_coverage_incomplete")

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

    if regex:
        for index, start, end in regex_matches(term, (record[1] for record in candidates)):
            emit(*candidates[index], span=(start, end))

    hits.sort(key=lambda hit: (
        hit["kind"], hit["va"] is None, int(hit["va"], 16) if hit["va"] else 0,
        hit["engine_address"] or "", hit["source"], hit["namespace"] or "", hit["context"],
        hit["function_id"] or "", hit["context_start"], hit["context_truncated"], hit["origin"],
    ))
    return hits, gaps
