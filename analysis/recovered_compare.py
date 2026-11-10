#!/usr/bin/env python3
"""Source-aware calibration of two recovered scalar functions on owned fixtures."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import subprocess
import tempfile

from prototype_experiment import CASES, ROOT, fixture_input
from validate_decompiler_evidence import read_bytes, read_json, sha, write_new_json
from macscope import engine
from macscope.errors import Error


PROFILES = ("baseline/1","parameter-inference/1")
ROUTINES = (("_calc_compare_s64","long"),("_calc_compare_u64","ulong"))
SOURCE_FILES = ("fixture/src/calc_core.c","fixture/src/calc_core.h")
HARNESS = ROOT / "analysis/compare_scalar_harness.c"
TOKEN = re.compile(r"\s+|0[xX][0-9a-fA-F]+|[0-9]+|[A-Za-z_]\w*|[{}();=<>!+,:&|^~\-]",re.ASCII)
LOCALS = re.compile(r"(?:[A-Za-z]Var[0-9]+|local_[a-fA-F0-9]+|param_[0-9]+)")
WORDS = {"if","else","return","undefined4","int","uint","long","ulong","char"}
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


def eligible(text, routine, argument):
    if (not isinstance(text,str) or not 0<len(text)<=16384
            or not IDENTIFIER.fullmatch(routine) or argument not in ("long", "ulong")):
        return False
    identifier = r"[A-Za-z_]\w*"
    declaration = rf"\s*(?:int|uint|undefined4)\s+{re.escape(routine)}\s*\(\s*{argument}\s+({identifier})\s*,\s*{argument}\s+({identifier})\s*\)\s*\{{(.*)\}}\s*"
    match = re.fullmatch(declaration,text,re.ASCII|re.S)
    if not match or not LOCALS.fullmatch(match[1]) or not LOCALS.fullmatch(match[2]):
        return False
    allowed = WORDS|{match[1],match[2]}
    body = match[3]
    cursor = depth = 0
    for token in TOKEN.finditer(body):
        value = token[0]
        if token.start()!=cursor:
            return False
        if (value[0].isalpha() or value[0]=="_") and value not in allowed and not LOCALS.fullmatch(value):
            return False
        if value=="{":
            depth += 1
        elif value=="}":
            depth -= 1
            if depth<0:
                return False
        cursor = token.end()
    return cursor==len(body) and depth==0


def matrix_exports(root, *, symbols="sym", kind="tool"):
    report = read_json(root/"report.json")
    if report.get("status")!="passed":
        raise ValueError("Requires a completed owned profile matrix")
    cases = {case["case"]:case for case in report["cases"]}
    exports = defaultdict(list)
    for index,command in enumerate(report["commands"],1):
        argv = command["argv"]
        if argv[0]=="export":
            label = Path(argv[argv.index("--project")+1]).name
            exports[label].append(root/f"{index:03}.stdout")
    for case in CASES:
        label = case+"-"+symbols+"-"+kind
        if label not in cases or len(exports[label])<2:
            raise ValueError("Missing baseline and inference exports for "+label)
        yield case,cases[label],exports[label][:2]


def run_candidate(directory, compiler, sdk, harness, references, candidate_flags, *,
                  wide_counter=False, reference_source="calc_core.c"):
    (directory/"harness.c").write_bytes(harness)
    for name,data in references.items():
        (directory/Path(name).name).write_bytes(data)
    sandbox = directory/"sandbox.sb"
    sandbox.write_text("(version 1)\n(allow default)\n(deny network*)\n"
                       '(deny file-read-data (subpath "/Users"))\n'
                       "(deny file-write* (require-not (subpath "+json.dumps(str(directory))+")))\n")
    env = {"PATH":"/usr/bin:/bin","HOME":str(directory),"TMPDIR":str(directory)+"/","LANG":"en_US.UTF-8"}
    prefix = ["/usr/bin/sandbox-exec","-f",str(sandbox)]
    target = directory/"compare"
    flags = ["-std=c11","-O1","-fsigned-char","-fsanitize=undefined",
             "-fno-sanitize-recover=undefined","-Werror=implicit-function-declaration",
             "-isysroot",sdk,*candidate_flags]
    try:
        engine.run_process([*prefix,compiler,*flags,str(directory/"harness.c"),str(directory/reference_source),
                            "-o",str(target)],
                           cwd=directory,env=env,timeout=30,log_path=directory/"compile.log",
                           manifest_path=directory/"compile-job.json",manifest={"phase":"compile"})
    except Error as error:
        log = directory/"compile.log"
        diagnostic = next((line for line in log.read_text(errors="replace").splitlines()
                           if "error:" in line), None) if log.is_file() else None
        return {"status":"compile_failed","reason":error.code,"diagnostic":diagnostic}
    def execute(phase, argv):
        log = directory/(phase+".log")
        try:
            engine.run_process([*prefix,str(target),*argv],cwd=directory,env=env,timeout=10,
                               log_path=log,manifest_path=directory/(phase+"-job.json"),
                               manifest={"phase":phase})
        except Error as error:
            lines = log.read_text(errors="replace").splitlines() if log.is_file() else ()
            for status, marker in (("undefined_behavior", "runtime error:"),
                                   ("address_sanitizer", "ERROR: AddressSanitizer"),
                                   ("undefined_bits_read", "GHIDRA_UNDEFINED_INPUT")):
                diagnostic = next((line for line in lines if marker in line), None)
                if diagnostic:
                    return {"status":status,"reason":error.code,"diagnostic":diagnostic}
            return {"status":"execution_failed","reason":error.code}
        return {"results":read_json(log)}

    measured = execute("compare", [])
    if wide_counter and "results" in measured:
        measured["wide_counter"] = execute("compare-wide", ["wide"])
    return measured


def evaluate(directory, text, routine, argument, compiler, sdk, harness, references):
    directory.mkdir(mode=0o700)
    payload = text.encode("utf-8")
    (directory/"candidate.c").write_bytes(payload)
    result = {"pseudocode_sha256":sha(payload)}
    if not eligible(text,routine,argument):
        return dict(result,status="not_testable",reason="Unsupported unmodified scalar function")
    flags = ["-DSIGNED_CASE="+str(int(argument=="long")), "-DRECOVERED="+routine]
    measured = run_candidate(directory, compiler, sdk, harness, references, flags)
    counts = measured.get("results")
    if counts is None:
        return dict(result, **measured)
    if (counts["directed"]!=121 or counts["seeded"]!=10000
            or sum(counts[key] for key in ("less","equal","greater"))!=10121
            or not all(counts[key] for key in ("less","equal","greater"))):
        raise ValueError("Evaluator output did not cover its declared input domain")
    return dict(result,status="mismatch" if counts["mismatches"] else "passed",results=counts)


def run(args):
    output = args.output_dir.resolve()
    if not output.is_relative_to(Path("/tmp").resolve()) or output==Path("/tmp").resolve():
        raise ValueError("Choose a new output directory under canonical /tmp")
    plans = list(matrix_exports(args.profile_matrix.resolve()))
    references = {name:read_bytes(ROOT/name) for name in SOURCE_FILES}
    harness = read_bytes(HARNESS)
    compiler = subprocess.check_output(["/usr/bin/xcrun","--find","clang"],text=True,timeout=15).strip()
    sdk = subprocess.check_output(["/usr/bin/xcrun","--sdk","macosx","--show-sdk-path"],text=True,timeout=15).strip()
    compiler_version = subprocess.check_output([compiler,"--version"],text=True,timeout=10).strip()
    output.mkdir(mode=0o700)
    results = []
    report = {"schema":"macscope-recovered-scalar/1","status":"failed",
              "scope":"source-aware; two named scalar comparison functions",
              "matrix_report_sha256":sha(read_bytes(args.profile_matrix/"report.json")),
              "harness_sha256":sha(harness),"results":results,
              "compiler":{"version":compiler_version,"sha256":engine.digest(Path(compiler))},
              "source_sha256":{name:sha(data) for name,data in references.items()}}
    try:
        for case,prior,exports in plans:
            _,binary,manifest = fixture_input(args.fixture_build_root,case)
            binary_sha = sha(binary)
            if prior.get("input_sha256")!=binary_sha:
                raise ValueError("Profile report input does not match the owned fixture: "+case)
            if any(manifest["source"]["source_files_sha256"].get(name)!=sha(data)
                   for name,data in references.items()):
                raise ValueError("Reference source differs from the fixture manifest")
            for profile,export in zip(PROFILES,exports):
                exported = read_bytes(export)
                data = json.loads(exported)["data"]
                expected_id = prior["baseline_analysis_id"] if profile==PROFILES[0] else prior["inference_analysis_id"]
                if (data["identity"]["profile"]!=profile or data["analysis_id"]!=expected_id
                        or data["image"]["sha256"]!=binary_sha or data["image"]["arch"]!=case.split("-",1)[1]):
                    raise ValueError("Profile export does not match its owned fixture: "+case)
                for routine,argument in ROUTINES:
                    functions = [f for f in data["functions"] if f["name"]==routine]
                    identity = {"case":case,"profile":profile,"routine":routine,"export_sha256":sha(exported),
                                "analysis_id":expected_id,"binary_sha256":binary_sha}
                    if (len(functions)!=1 or functions[0]["decompile_status"]!="complete"
                            or functions[0].get("pseudocode_truncated") is not False
                            or not functions[0].get("pseudocode")):
                        results.append(dict(identity,status="not_testable",reason="Missing complete pseudocode"))
                        continue
                    directory = output/(case+"-"+profile.replace("/","-")+"-"+routine[1:])
                    result = evaluate(directory,functions[0]["pseudocode"],routine,argument,
                                      compiler,sdk,harness,references)
                    results.append(dict(identity,**result))
        report["status"] = "passed" if all(r["status"]=="passed" for r in results) else "partial"
        report["tested_pairs"] = sum(r.get("results",{}).get("directed",0)+r.get("results",{}).get("seeded",0)
                                     for r in results)
    except BaseException as error:
        report["error"] = type(error).__name__+": "+str(error)
        raise
    finally:
        write_new_json(output/"report.json",report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root",type=Path,required=True)
    parser.add_argument("--profile-matrix",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    parser.add_argument("--experimental-trusted-input",action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    report = run(args)
    print(json.dumps({"status":report["status"],"candidates":len(report["results"]),
                      "tested_pairs":report["tested_pairs"]}))
    return 0 if report["status"]=="passed" else 6


if __name__=="__main__":
    raise SystemExit(main())
