#!/usr/bin/env python3
"""Measure behavior and blockers for the entire owned calculator core."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess

from aggregate_compat import MEMORY_STORES, POLICY
from evaluate import CORE_ROUTINES
from prototype_experiment import ROOT, fixture_input
from recovered_compare import HARNESS, LOCALS, ROUTINES, SOURCE_FILES, evaluate, run_candidate
from reference_coverage import xcrun
from score_discovery import text_bytes, verified_captures
from validate_decompiler_evidence import read_bytes, require_complete_function_inventory, sha, write_new_json
from macscope import engine
from macscope.macho import thin


SCALARS = {name[1:]: argument for name, argument in ROUTINES}
HISTORY = {name: index for index, name in enumerate(
    ("calc_history_init", "calc_history_push", "calc_history_len", "calc_history_get"), 1)}
STATE = {"calc_state_init": 1, "calc_engine_clear": 2, "calc_engine_sign_toggle": 3}
AGGREGATES = frozenset("""
calc_add calc_sub calc_mul calc_div calc_negate calc_abs_checked calc_pow_checked
calc_apply_op calc_dispatch_table calc_parse_digits calc_digit_append calc_sign_toggle calc_history_sum
""".split())
HISTORY_HARNESS = ROOT / "analysis/compare_history_harness.c"
STATE_HARNESS = ROOT / "analysis/compare_state_harness.c"
STATE_COMPAT = ROOT / "analysis/aggregate_compat.h"
HISTORY_PARAMETERS = (
    (r"void", (r"long|void\s*\*",)),
    (r"void", (r"long", r"undefined8", r"undefined1", r"undefined8", r"undefined8")),
    (r"undefined8|ulong", (r"long",)),
    (r"long", (r"long", r"ulong")),
)
TYPES = frozenset("void long int ulong uint undefined1 undefined4 undefined8".split())
ZERO_ROUTINES = frozenset(("_bzero", "___bzero", "___memset_chk"))
TOKEN = re.compile(r"\s+|(?:0[xX][0-9a-fA-F]+|[0-9]+)[UL]*|'\\0'|[A-Za-z_]\w*|[{}\[\]();=<>!+,:&|^~*/%\-]",
                   re.ASCII)
DECODER_LINE = re.compile(r"^\s*([0-9a-f]+): ([0-9a-f]{8}|[0-9a-f]{2}(?: [0-9a-f]{2})*)\s+(\S+)(.*)$")


def recovered_name(record, routine):
    name = record["name"]
    if name == "_" + routine or re.fullmatch(r"FUN_[a-f0-9]+", name):
        return name
    raise ValueError("Unexpected recovered candidate name")


def history_declaration(text, name, kind, dependency_names):
    result_type, argument_types = HISTORY_PARAMETERS[kind - 1]
    allowed = set(dependency_names)
    if kind == 1:
        allowed |= ZERO_ROUTINES
    return bounded_declaration(text, name, result_type, argument_types, allowed)


def bounded_declaration(text, name, result_type, argument_types, extras):
    if not 0 < len(text) <= 16384:
        return None
    parameters = r"\s*,\s*".join(rf"(?:{p})\s*(param_[0-9]+)" for p in argument_types)
    declaration = re.fullmatch(
        rf"\s*(?:{result_type})\s+{re.escape(name)}\(\s*({parameters})\s*\)\s*\{{(.*)\}}\s*",
        text, re.ASCII | re.S,
    )
    if declaration is None:
        return None
    allowed = TYPES | {"if", "else", "return", "char"} | extras
    body = declaration.groups()[-1]
    cursor = depth = 0
    for token in TOKEN.finditer(body):
        word = token[0]
        if token.start() != cursor:
            return None
        if ((word[0].isalpha() or word[0] == "_") and word not in allowed
                and not LOCALS.fullmatch(word) and not re.fullmatch(r"puVar[0-9]+", word)):
            return None
        depth += (word == "{") - (word == "}")
        if depth < 0:
            return None
        cursor = token.end()
    if cursor != len(body) or depth:
        return None
    return "pointer" if "*" in declaration[1] else "integer"


def complete(record):
    return (record is not None and record["decompile_status"] == "complete"
            and record["pseudocode_truncated"] is False and not record["decompile_error"]
            and bool(record["pseudocode"]))


def count_status(counts, directed, seeded):
    if (counts["directed"] != directed or counts["seeded"] != seeded
            or not 0 <= counts["mismatches"] <= directed + seeded):
        raise ValueError("History evaluator did not complete its declared domain")
    return "mismatch" if counts["mismatches"] else "passed"


def compare_history(directory, routine, record, records, compiler, sdk, harness, references):
    kind = HISTORY[routine]
    name = recovered_name(record, routine)
    text = record["pseudocode"]
    dependencies = {}
    if kind == HISTORY["calc_history_get"]:
        length = records.get("calc_history_len")
        if complete(length):
            length_name = recovered_name(length, "calc_history_len")
            if re.search(rf"\b{re.escape(length_name)}\s*\(", text):
                body = length["pseudocode"]
                if not history_declaration(body, length_name, HISTORY["calc_history_len"], ()):
                    return {"status": "unsupported_recovered_dependency"}
                dependencies[length_name] = body
    declaration = history_declaration(text, name, kind, dependencies)
    if declaration is None:
        return {"status": "unsupported_history_declaration_or_body"}
    directory.mkdir(mode=0o700)
    (directory / "candidate.c").write_bytes("\n".join([*dependencies.values(), text]).encode())
    flags = [
        "-fsanitize=address", "-fno-strict-aliasing", f"-DRECOVERED={name}",
        f"-DHISTORY_KIND={kind}", f"-DPOINTER_INIT={int(declaration == 'pointer')}",
    ]
    measured = run_candidate(directory, compiler, sdk, harness, references, flags, wide_counter=True)
    measured["dependency_sha256"] = {name: sha(body.encode()) for name, body in dependencies.items()}
    if "results" not in measured:
        return measured
    measured["status"] = count_status(measured["results"], 111, 10000)
    wide = measured["wide_counter"]
    if "results" in wide:
        wide["status"] = count_status(wide["results"], 110, 0)
    return measured


def compare_state(directory, routine, record, records, compiler, sdk, harness, references):
    kind = STATE[routine]
    name = recovered_name(record, routine)
    text = record["pseudocode"]
    if re.search(r"\._[0-9]+_[0-9]+_", text):
        return {"status": "unsupported_aggregate_subfields"}
    argument = (r"long|undefined8|(?:long|undefined8)\s*\*",)
    dependencies = {}
    if kind == STATE["calc_engine_clear"]:
        init = records.get("calc_state_init")
        if complete(init):
            init_name = recovered_name(init, "calc_state_init")
            if re.search(rf"\b{re.escape(init_name)}\s*\(", text):
                body = init["pseudocode"]
                if not bounded_declaration(body, init_name, "void", argument, ZERO_ROUTINES):
                    return {"status": "unsupported_recovered_dependency"}
                dependencies[init_name] = body
    allowed = ZERO_ROUTINES | {"SBORROW8"} | MEMORY_STORES | dependencies.keys()
    declaration = bounded_declaration(text, name, "void", argument, allowed)
    if declaration is None:
        return {"status": "unsupported_state_declaration_or_body"}
    directory.mkdir(mode=0o700)
    (directory / "candidate.c").write_bytes("\n".join([*dependencies.values(), text]).encode())
    flags = [
        "-fsanitize=address", "-fno-strict-aliasing", f"-DRECOVERED={name}",
        f"-DSTATE_KIND={kind}", f"-DPOINTER_STATE={int(declaration == 'pointer')}",
    ]
    measured = run_candidate(directory, compiler, sdk, harness, references, flags)
    measured["dependency_sha256"] = {name: sha(body.encode()) for name, body in dependencies.items()}
    if "results" in measured:
        measured["status"] = count_status(measured["results"], 145, 10000)
    return measured


def core_extents(truth):
    extents = {}
    for entry, (end, names) in truth.items():
        for routine in names.intersection(CORE_ROUTINES):
            if routine in extents:
                raise ValueError("Ambiguous evaluator body for " + routine)
            extents[routine] = entry, end
    return extents


def llvm_instructions(build, case, decoder, extents, *, kind="tool"):
    path, binary, _ = fixture_input(build, case, kind=kind)
    metadata = thin(binary)
    (text_start, _), code = text_bytes(binary, metadata)
    section, = [s for s in metadata["sections"] if (s["segment"], s["name"]) == ("__TEXT", "__text")]
    text_offset = int(section["file_offset"], 16)
    data = metadata["loader"]["data_in_code"]
    if data["status"] != "complete":
        raise ValueError("Incomplete linker data-in-code table")
    data_ranges = [(text_start + int(row["slice_file_offset"], 16) - text_offset, row["length"])
                   for row in data["records"]]
    routines = {}
    for routine, (lo, hi) in extents.items():
        output = subprocess.check_output(
            [decoder, "--disassemble", "--section=__text",
             f"--start-address={lo:#x}", f"--stop-address={hi:#x}", str(path)], timeout=30,
        )
        if len(output) > 16 << 20:
            raise ValueError("Oversized LLVM instruction evidence")
        data_bytes = {va for start, size in data_ranges for va in range(max(lo, start), min(hi, start + size))}
        decoded = set()
        instructions = {}
        for line in output.decode(errors="replace").splitlines():
            match = DECODER_LINE.match(line)
            if not match:
                continue
            entry, raw, mnemonic = int(match[1], 16), bytes.fromhex(match[2]), match[3]
            if case.endswith("-arm64"):
                raw = raw[::-1]
            addresses = set(range(entry, entry + len(raw)))
            if addresses <= data_bytes:
                continue
            offset = entry - text_start
            if (entry < lo or entry + len(raw) > hi or raw != code[offset:offset + len(raw)]
                    or addresses.intersection(decoded | data_bytes) or mnemonic.startswith((".", "<"))):
                raise ValueError("LLVM could not independently decode the exact extent for " + routine)
            decoded.update(addresses)
            instructions[entry] = (raw, mnemonic, match[4].strip())
        if lo not in decoded or len(decoded) + len(data_bytes) != hi - lo:
            raise ValueError("Incomplete independent decode for " + routine)
        routines[routine] = instructions
    return routines


def inventory(snapshot, extents, decoded):
    require_complete_function_inventory(dict(snapshot["engine"], functions=snapshot["functions"]))
    functions = {}
    for record in snapshot["functions"]:
        if record["is_external"] or record["is_thunk"]:
            continue
        entry = int(record["entry_va"], 16)
        if entry in functions:
            raise ValueError("Duplicate recovered entry")
        functions[entry] = record
    rows, records = {}, {}
    for routine in CORE_ROUTINES:
        if routine not in extents:
            rows[routine] = {"status": "missing_evaluator_body"}
            continue
        entry, end = extents[routine]
        record = functions.get(entry)
        records[routine] = record
        row = rows[routine] = {
            "entry_va": hex(entry), "dwarf_end_exclusive": hex(end),
            "llvm_instruction_bytes": sum(len(raw) for raw, _, _ in decoded[routine].values()),
        }
        if record is None:
            row["status"] = "missing_recovered_entry"
        elif not complete(record):
            row["status"] = "incomplete_pseudocode"
        else:
            code = record["pseudocode"]
            row.update(recovered_name=record["name"], signature=record["signature"],
                       pseudocode_sha256=sha(code.encode()))
            if routine in AGGREGATES:
                array_return = re.match(r"\s*(?:/\*.*?\*/\s*)*undefined1\s*\[16\]", code, re.S)
                row["status"] = "aggregate_array_syntax" if array_return else "aggregate_abi_unverified"
    return rows, records


def summarize(rows):
    present = [row for row in rows if "llvm_instruction_bytes" in row]
    tested = [row for row in present if "results" in row]
    passed = [row for row in tested if row["status"] == "passed"
              and row.get("wide_counter", {}).get("status", "passed") == "passed"]
    return {
        "counts": dict(Counter(row["status"] for row in rows)),
        "wide_counter_counts": dict(Counter(row["wide_counter"]["status"]
                                         for row in tested if "wide_counter" in row)),
        "concrete_routines": len(present), "routine_domains_completed": len(tested),
        "routine_domains_passed": len(passed),
        "llvm_instruction_bytes": sum(row["llvm_instruction_bytes"] for row in present),
        "llvm_bytes_for_completed_domains": sum(row["llvm_instruction_bytes"] for row in tested),
        "llvm_bytes_for_passed_domains": sum(row["llvm_instruction_bytes"] for row in passed),
    }


def run(args):
    build = args.fixture_build_root.resolve()
    matrix = args.profile_matrix.resolve()
    output = args.output_dir.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        raise ValueError("Choose a new output directory under canonical /tmp")
    references = {name: read_bytes(ROOT / name) for name in SOURCE_FILES}
    source_hashes = {name: sha(data) for name, data in references.items()}
    references[STATE_COMPAT.name] = read_bytes(STATE_COMPAT)
    scalar_harness, history_harness = read_bytes(HARNESS), read_bytes(HISTORY_HARNESS)
    state_harness = read_bytes(STATE_HARNESS)
    compiler, decoder = xcrun("--find", "clang"), xcrun("--find", "llvm-objdump")
    sdk = xcrun("--sdk", "macosx", "--show-sdk-path")
    output.mkdir(mode=0o700)
    captures, decodes = [], {}
    report = {
        "schema": "macscope-core-behavior/1", "status": "failed", "captures": captures,
        "matrix_report_sha256": sha(read_bytes(matrix / "report.json")), "source_sha256": source_hashes,
        "scalar_harness_sha256": sha(scalar_harness), "history_harness_sha256": sha(history_harness),
        "state_harness_sha256": sha(state_harness),
        "state_compat_sha256": sha(references[STATE_COMPAT.name]), "state_compat_policy": POLICY,
        "compiler_sha256": engine.digest(Path(compiler)), "decoder_sha256": engine.digest(Path(decoder)),
    }
    try:
        for provenance, snapshot, truth, _, manifest in verified_captures(build, matrix):
            if any(manifest["source"]["source_files_sha256"].get(name) != digest
                   for name, digest in source_hashes.items()):
                raise ValueError("Reference source differs from the fixture manifest")
            case, state, profile = (provenance[key] for key in ("case", "symbols", "profile"))
            extents = core_extents(truth)
            if case not in decodes:
                decodes[case] = llvm_instructions(build, case, decoder, extents)
            rows, records = inventory(snapshot, extents, decodes[case])
            for routine, row in rows.items():
                if "status" in row:
                    continue
                record = records[routine]
                directory = output / f"{case}-{state}-{profile.replace('/', '-')}-{routine}"
                if routine in SCALARS:
                    row.update(evaluate(directory, record["pseudocode"], recovered_name(record, routine),
                                        SCALARS[routine], compiler, sdk, scalar_harness, references))
                elif routine in HISTORY:
                    row.update(compare_history(directory, routine, record, records, compiler, sdk,
                                               history_harness, references))
                elif routine in STATE:
                    row.update(compare_state(directory, routine, record, records, compiler, sdk,
                                             state_harness, references))
                else:
                    row["status"] = "harness_unimplemented"
            captures.append(dict(
                provenance, analysis_id=snapshot["analysis_id"],
                native_decompiler_sha256=snapshot["identity"]["engine"]["native_decompiler_sha256"],
                routines=rows, summary=summarize(rows.values()),
            ))
        report["summary"] = summarize([row for capture in captures for row in capture["routines"].values()])
        report["status"] = "passed" if report["summary"]["routine_domains_passed"] == (
            len(captures) * len(CORE_ROUTINES)) else "partial"
    finally:
        write_new_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", type=Path, required=True)
    parser.add_argument("--profile-matrix", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    report = run(args)
    print(json.dumps({"status": report["status"], **report["summary"]}))
    return 0 if report["status"] == "passed" else 6


if __name__ == "__main__":
    raise SystemExit(main())
