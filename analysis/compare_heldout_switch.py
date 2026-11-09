#!/usr/bin/env python3
"""Compare all seven held-out switch routines against their frozen reference."""
import argparse
from collections import Counter
from itertools import product
import json
from pathlib import Path
import re

from prototype_experiment import ROOT
from recovered_compare import LOCALS
from reference_coverage import xcrun
from score_discovery import dwarf_functions, text_bytes, tool_output
from validate_decompiler_evidence import read_bytes, read_json, sha, write_new_json
from macscope import engine
from macscope.errors import Error
from macscope.macho import thin


ROUTINES = ("combine_add", "combine_xor", "combine_mul", "combine_sub", "combine_max",
            "combine_rot", "heldout_dispatch")
CASES = tuple(f"{arch}-{opt}-{state}" for arch, opt, state in
              product(("arm64", "x86_64"), ("O0", "O2"), ("sym", "stripped")))
PROFILES = ("baseline", "parameter-inference")
TYPES = r"(?:int|uint|long|ulong|undefined4|undefined8)"
WORDS = set(("int uint long ulong undefined4 undefined8 if else return switch case default break").split())
TOKEN = re.compile(r"\s+|0[xX][0-9a-fA-F]+|[0-9]+|[A-Za-z_]\w*|[{}();=<>!+,:&|^~*/%\-]", re.ASCII)
FROZEN_SOURCE = "9542120fecb68c6cef1d76b7aa8df5c2dc89bf28c4c6c17337cc372b21d52347"


def eligible(record, arity, dependencies=()):
    if (record["decompile_status"] != "complete" or record["pseudocode_truncated"] is not False
            or record.get("decompile_error")):
        return False
    name, code = record["name"], record["pseudocode"]
    if (not re.fullmatch(r"(?:_combine_[a-z]+|_heldout_dispatch|FUN_[0-9a-f]+)", name)
            or not isinstance(code, str) or not 0 < len(code) <= 16384):
        return False
    declaration = re.fullmatch(rf"\s*{TYPES}\s+{re.escape(name)}\s*\(([^()]*)\)\s*\{{(.*)\}}\s*",
                               code, re.ASCII | re.S)
    if not declaration:
        return False
    parameters = declaration[1].split(",")
    if len(parameters) != arity:
        return False
    for parameter in parameters:
        arg = re.fullmatch(rf"\s*{TYPES}\s+([A-Za-z_]\w*)\s*", parameter, re.ASCII)
        if not arg or not LOCALS.fullmatch(arg[1]):
            return False
    body = declaration[2]
    if re.search(rf"\b{TYPES}\s*\*", body):
        return False
    cursor = depth = 0
    for token in TOKEN.finditer(body):
        value = token[0]
        if token.start() != cursor:
            return False
        if ((value[0].isalpha() or value[0] == "_") and value not in WORDS
                and value not in dependencies and not LOCALS.fullmatch(value)):
            return False
        depth += (value == "{") - (value == "}")
        if depth < 0:
            return False
        cursor = token.end()
    return cursor == len(body) and depth == 0


def truth_for(evaluator, input_dir, variant, routines=ROUTINES, *, include_extents=False):
    binary = read_bytes(evaluator / variant / "Fixture")
    metadata = thin(binary)
    d_sym = evaluator / variant / "Fixture.dSYM/Contents/Resources/DWARF/Fixture"
    uuid = re.search(r"UUID: ([0-9A-Fa-f-]+)", tool_output("--uuid", d_sym))
    if not uuid or uuid[1].replace("-", "").lower() != metadata["uuid"]:
        raise ValueError("Evaluator UUID differs from the linked fixture")
    starts = metadata["loader"]["function_starts"]
    if not starts or starts["status"] != "complete":
        raise ValueError("Incomplete evaluator linker function starts")
    text, code = text_bytes(binary, metadata)
    truth, _ = dwarf_functions(tool_output("--debug-info", d_sym),
                               {int(addr, 16) for addr in starts["addresses"]}, text)
    addresses = {}
    for routine in routines:
        (entry, end), = [(entry, end) for entry, (end, names) in truth.items() if routine in names]
        addresses[routine] = (entry, end) if include_extents else hex(entry)
    digests = {}
    for state in ("sym", "stripped"):
        payload = read_bytes(input_dir / variant / state)
        layout = thin(payload)
        if layout["uuid"] != metadata["uuid"] or text_bytes(payload, layout) != (text, code):
            raise ValueError("Captured slice differs from evaluator text or UUID")
        digests[state] = sha(payload)
    return addresses, digests


def compare(directory, routine, record, dependencies, compiler, sdk, harness, reference):
    directory.mkdir(mode=0o700)
    name = record["name"]
    all_records = [*dependencies, record]
    candidate = "\n".join(f["pseudocode"] for f in all_records).encode()
    (directory / "candidate.c").write_bytes(candidate)
    (directory / "harness.c").write_bytes(harness)
    (directory / "heldout_switch.c").write_bytes(reference)
    result = {"candidate_sha256": sha(candidate)}
    sandbox = directory / "sandbox.sb"
    sandbox.write_text(
        '(version 1) (allow default) (deny network*) (deny file-read-data (subpath "/Users")) '
        '(deny file-write* (require-not (subpath ' + json.dumps(str(directory)) + ')))\n'
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": str(directory), "TMPDIR": str(directory) + "/",
           "LANG": "en_US.UTF-8"}

    def run(phase, argv):
        engine.run_process(
            ["/usr/bin/sandbox-exec", "-f", str(sandbox), *argv], cwd=directory, env=env,
            timeout=30 if phase == "compile" else 10, log_path=directory / (phase + ".log"),
            manifest_path=directory / (phase + ".json"), manifest={"phase": phase},
        )

    dispatch = routine == "heldout_dispatch"
    try:
        run("compile", [compiler, "-std=c11", "-O1", "-fsanitize=undefined",
                        "-fno-sanitize-recover=undefined", "-Werror=implicit-function-declaration",
                        "-isysroot", sdk, f"-DCANDIDATE={name}", f"-DREFERENCE={routine}",
                        f"-DDISPATCH={int(dispatch)}", "harness.c", "-o", "compare"])
    except Error as error:
        diagnostic = failure_line(directory / "compile.log", "error:")
        return dict(result, status="compile_failed", reason=error.code, diagnostic=diagnostic)
    try:
        run("execute", [str(directory / "compare")])
    except Error as error:
        diagnostic = failure_line(directory / "execute.log", "runtime error:")
        return dict(result, status="undefined_behavior" if diagnostic else "execution_failed",
                    reason=error.code, diagnostic=diagnostic)
    counts = read_json(directory / "execute.log")
    if (counts["directed"] != (1452 if dispatch else 121) or counts["seeded"] != 10000
            or not 0 <= counts["mismatches"] <= counts["directed"] + counts["seeded"]):
        raise ValueError("Harness did not evaluate its complete declared domain")
    return dict(result, status="mismatch" if counts["mismatches"] else "passed", counts=counts)


def failure_line(path, pattern):
    if path.exists():
        return next((line for line in read_bytes(path).decode(errors="replace").splitlines()
                     if pattern in line), None)
    return None


def run(args):
    output = args.output_dir.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        raise ValueError("Choose a new output directory under canonical /tmp")
    reference = read_bytes(ROOT / "analysis/heldout_switch.c")
    if sha(reference) != FROZEN_SOURCE or read_bytes(args.evaluator / "heldout_switch.c") != reference:
        raise ValueError("Held-out source differs from the frozen contract")
    harness = read_bytes(ROOT / "analysis/compare_switch_harness.c")
    report_path = args.comparison / "report.json"
    capture_report = read_json(report_path)
    expected = {(worker, case, profile) for case, profile in product(CASES, PROFILES)
                for worker in (("original", "patched") if case.startswith("x86_64-O0-") else ("patched",))}
    rows = capture_report["rows"]
    if len(rows) != len(expected) or {(r["engine"], r["case"], r["profile"]) for r in rows} != expected:
        raise ValueError("Incomplete or duplicate held-out capture matrix")
    truth = {variant: truth_for(args.evaluator, args.inputs, variant)
             for variant in sorted({case.rsplit("-", 1)[0] for case in CASES})}
    compiler = xcrun("--find", "clang")
    sdk = xcrun("--sdk", "macosx", "--show-sdk-path")
    output.mkdir(mode=0o700)
    outcomes = []
    report = {"schema": "macscope-heldout-behavior/1", "status": "failed",
              "comparison_sha256": sha(read_bytes(report_path)), "source_sha256": sha(reference),
              "harness_sha256": sha(harness), "compiler_sha256": engine.digest(Path(compiler)),
              "outcomes": outcomes}
    try:
        for row in rows:
            worker, case, profile = row["engine"], row["case"], row["profile"]
            label = f"{worker}-{case}-{profile}"
            raw = read_bytes(args.comparison / (label + ".json"))
            snapshot = json.loads(raw)["data"]
            variant, state = case.rsplit("-", 1)
            addresses, digests = truth[variant]
            if (sha(raw) != row["export_sha256"] or snapshot["analysis_id"] != row["analysis_id"]
                    or snapshot["identity"]["profile"] != profile + "/1"
                    or snapshot["identity"]["engine"]["native_decompiler_sha256"] != row["native_sha256"]
                    or snapshot["image"]["sha256"] != digests[state]):
                raise ValueError("Held-out capture differs from the verified experiment")
            selected = [f for f in snapshot["functions"] if f["entry_va"] in addresses.values()]
            records = {f["entry_va"]: f for f in selected}
            if len(records) != len(selected):
                raise ValueError("Ambiguous recovered routine entry")
            helpers = [records.get(addresses[name]) for name in ROUTINES[:-1]]
            eligible_helpers = all(f is not None and eligible(f, 2) for f in helpers)
            for routine in ROUTINES:
                record = records.get(addresses[routine])
                dispatch = routine == "heldout_dispatch"
                identity = {"capture": label, "routine": routine, "entry": addresses[routine],
                            "export_sha256": row["export_sha256"]}
                if dispatch and not eligible_helpers:
                    result = {"status": "not_testable", "reason": "Unsupported recovered dependency"}
                else:
                    dependencies = helpers if dispatch else []
                    if record is None or not eligible(record, 3 if dispatch else 2, [f["name"] for f in dependencies]):
                        result = {"status": "not_testable", "reason": "Unsupported unmodified recovered declaration or body"}
                    else:
                        result = compare(output / (label + "-" + routine), routine, record, dependencies,
                                         compiler, sdk, harness, reference)
                outcomes.append(dict(identity, **result))
        report["counts"] = dict(Counter(row["status"] for row in outcomes))
        report["status"] = "passed" if all(row["status"] == "passed" for row in outcomes) else "partial"
    finally:
        write_new_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("comparison", "evaluator", "inputs", "output-dir"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    report = run(args)
    print(json.dumps({key: report[key] for key in ("status", "counts")}))
    return 0 if report["status"] == "passed" else 6


if __name__ == "__main__":
    raise SystemExit(main())
