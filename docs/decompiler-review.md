# Independent decompiler evidence review

This is research tooling, not a change to macscope's production profile or CLI.
It uses only this repository's owned calculator fixtures. A completed decompiler
operation is not proof that the emitted C-like text preserves behavior.

## Findings, 9 November 2026

### Instruction evidence

A read-only check of the historical v1.0 CLI exports from
`build/cli-integration-20261109-095203/` compared all non-external, non-thunk
O0 functions with LLVM and the original input bytes:

| Architecture | Function ranges | Instructions | Direct branch/call targets |
| --- | ---: | ---: | ---: |
| arm64 | 36 | 1,979 | 487 |
| x86_64 | 36 | 1,677 | 326 |
| Total | 72 | 3,656 | 813 |

There were no mismatches or unmeasured direct targets in this population.
The range selection and file offsets come from Ghidra's export. This is not
independent function-body discovery, indirect-target recovery, false-positive
scoring, or pseudocode equivalence. These are **v1.0 inputs**, not measurements
of the current v1.1 source or UI-layout build.

### A concrete pseudocode discrepancy

The arm64 O0 output for `_calc_engine_input_digit` contains:

```c
_calc_latch_error(iVar1,param_1,3);
```

The source and the separately decompiled callee have two parameters. The
historical machine code confirms the actual call:

```text
0x100001020  ldur x0,[x29, #-0x8]
0x100001024  mov w1,#0x3
0x100001028  bl 0x1000010b8
```

The incorrect extra argument also occurs in the frozen v1.1 direct baseline.
The x86_64 O0 output uses two arguments. Raw output is retained; the checker
does not rewrite it or pretend it is compilable C.

### Controlled improvement

Two disposable, binary-derived experiments improve this exact arm64 O0 case:

1. Enable Ghidra's `Decompiler Parameter ID` analyzer for the whole fresh
   Program.
2. Decompile only `_calc_latch_error`, then commit its inferred parameters using
   `HighFunctionDBUtil.commitParamsToDatabase`, with `ReturnCommitOption.NO_COMMIT`
   and `SourceType.ANALYSIS`. Re-decompile the callers.

Both produce the expected two-argument call and the ordinary invalid-digit
guard. No source types, source files, or dSYMs are supplied to Ghidra. Selecting
this known regression for review is still **source-aware**, not a blind study.

The earlier exploratory experiment used 13 disposable runs across historical
v1.0 and v1.1 inputs. The checked-in runner was then validated with a fresh
**10-run v1.1 experiment**:

- Four default/inference pairs: arm64 and x86_64, each at O0 and O2.
- One arm64 O0 callee-only parameter commit in a copy of the default project.
- One fresh repeated arm64 O0 whole-program inference run.

All ten runs completed, with no failed/timed-out/cancelled decompiles. Each O0
run produced 36 complete pseudocode results and eight external/thunk records;
each O2 run produced 31 complete results and eight external/thunk records.
All compared function entries, instruction facets and CFGs remained unchanged.
The repeat had identical measured signatures, pseudocode and machine facets.

The whole-program option changed 15, 6, 13 and 9 pseudocode bodies respectively
for arm64 O0, arm64 O2, x86_64 O0 and x86_64 O2. It also committed many inferred
signatures and calling-convention labels, including `__stdcall` labels on
x86_64. Those changes have **not** been behaviorally validated. The callee-only
experiment changed one saved signature and four caller pseudocode bodies.

The narrower experiment is the demonstrated option for this diagnosed
mismatch. Neither approach is enabled automatically. A future production
option requires an explicit, versioned analysis identity and further review.

## Repeat the read-only instruction check

Run from a checkout. Set paths to an existing normalized CLI export and its
exact original thin binary:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/validate_decompiler_evidence.py \
  --export 'build/cli-integration-20261109-095203/arm thin.json' \
  --binary build/analyst/DebugAnalysis-arm64-sym/CorpusFixture \
  --output /private/tmp/new-arm64-instruction-report.json
```

Use `x86 thin.json` and `DebugAnalysis-x86_64-sym/CorpusFixture` for x86_64.
`--output` refuses an existing file. Omitting it prints JSON. The command runs
`xcrun llvm-objdump --disassemble`; it does not execute the analyzed binary.
For an entirely offline recheck, supply previously captured LLVM text with
`--llvm-text FILE`. The report records the binary, export and LLVM-text hashes.

The validator checks byte order, instruction starts, bytes at the exported
file offsets, and direct target text within the exported function ranges.
Unmeasured direct targets are reported separately. Duplicate engine identities
are rejected; duplicate function names and external functions with null virtual
addresses are handled without collapsing entries.

## Repeat the opt-in inference experiment

Build the owned fixture first using the repository's documented build matrix.
The runner requires its schema-2 `manifest.json` and verifies each selected
input hash. It does not build, install dependencies, launch UI, or execute inputs.

On the pinned macOS arm64/Ghidra 12.2/JDK 25 host:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/prototype_experiment.py run \
  --fixture-build-root build/review-v2 \
  --output-dir /private/tmp/new-macscope-prototype-run \
  --experimental-trusted-input
```

An isolated worktree can use an absolute `--fixture-build-root` pointing at an
existing build in another checkout. The engine receives only copied binaries
and trusted scripts. No existing Program database is edited. The default
command runs the ten-case v1.1 experiment above. To run just the four arm64 O0
stages, add `--case DebugAnalysis-arm64`.

The output must be a new, whitespace/quote/backslash-free directory under the
system temporary directory or canonical `/tmp`. Existing directories are never
reused, even after failure. Default case limits are 120 seconds wall time,
30 seconds per decompile, one engine CPU and a 1-GiB Java heap. The existing
owned-process runner enforces the deadline and bounds logs/sampled storage;
these are not hard process-RSS or filesystem quotas.

Each case records:
- Input identity, copied-script hashes, versioned experiment profile and modes.
- Actual invocation, environment, dependency identity and process outcome.
- Raw bridge output, saved disposable Program, engine/script/launcher logs.
- For callee inference, before/inferred/after signatures and unchanged return type.

The experiment profile identities are separate from the production profile.
The only analyzer-option difference in fresh default/candidate pairs must be
`Decompiler Parameter ID`. The callee path must report a `-noanalysis` query:
on reopening, Ghidra may register dormant options such as External Symbol
Resolver. Their presence is not evidence that those analyzers ran.

Every engine invocation denies network access and reads/writes under `/Users`.
This does not establish comprehensive hostile-input filesystem confinement.
Only trusted, owned fixture inputs are in scope.

Recheck a completed experiment without running Java:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/prototype_experiment.py summarize \
  /private/tmp/new-macscope-prototype-run
```

This verifies the recorded plan, result/script/job/sandbox hashes, inference
evidence and comparisons. Truncated or failed measured instruction/CFG/
pseudocode/signature facets are rejected even if both outputs are identical.
Capped xrefs can still make the raw aggregate result `partial`, because xref
completeness is outside these comparisons.

The first durable trial is retained as failed evidence: its initial validator
incorrectly treated a dormant reopened option as an executed analyzer. The
successful fresh rerun and its recorded results were not rewritten in place.

## Tests and evidence

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s analysis/tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The engine-free research tests cover identity collisions, external null VAs,
byte order, changed bytes/targets, incomplete facets, exact regression
sentinels, input hashes, explicit opt-in, profile drift, output reuse and
recorded-evidence tampering. Existing process-lifecycle tests remain in place.
The compact measured checkpoint is in
[evidence/decompiler-review-20261109.json](evidence/decompiler-review-20261109.json).
Generated binaries, full engine outputs and private workspaces are not tracked.

Remaining limits: no compiled or executed recovered-C comparison, no stripped
inference matrix, no ObjC/Swift or third-party population, no source-equivalence
proof, and no promotion of this research profile into the production default.
