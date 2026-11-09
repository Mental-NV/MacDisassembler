# Phase 1 evidence and review corrections (9 November 2026)

## Historical experiment: semantics v1.0

The original fixture is commit `216f28b`; the first baseline/evaluation is
`1b6e6d7`. Its ignored local evidence remains under `build/workspaces/`,
`build/manifest.json`, and `build/eval-results.json`. These are historical
outputs, not current v1.1 measurements. They have not been replaced.

- 16 direct full-Ghidra headless imports/analyses/exports: 8 thin fixtures ×
  app/tool, both architectures, O0/O2, symbol-preserving/stripped.
- Ghidra 12.2 + JDK 25; 4 CPUs; auto-analysis timeout 600 seconds **per file**;
  decompile timeout 30 seconds/function; enumeration limit 5,000 functions.
  The old runner did **not** enforce a 600-second whole-job limit.
- All 16 headless exits were 0, and reported no failed/timed-out decompiles.
  Elapsed observations were 5–33 seconds app and 5–13 seconds tool.
  The old exporter classified all incomplete results as timeout, so this is
  the old exporter’s report, not validation of error classification.
- Output hashes were recorded in `build/workspaces/freeze.json` before the
  source-aware evaluation. The evaluator now verifies every listed hash
  before consuming a baseline and refuses an unlisted or changed baseline.
- Engine inputs were binary-only. Evaluation and qualitative reading were
  **source-aware by the same developer**, not an independent blind study.
  Absence of source path strings does not demonstrate absence of source access.

## Narrow results, with denominators

Re-evaluation: `build/eval-integrity-review-v4.json` (new file, original report
retained). All 16 historical baseline hashes matched the original freeze.

- Controlled entry recall: 120/120 symbol-bearing and 120/120 stripped
  routines at evaluator-known VAs (26 core + 4 corpus × 4 configurations).
  Pseudocode operation completion: separately 120/120 in each symbol state.
  Entry matches are not function-body correctness or discovery precision.
- All 30 whitelist symbols survived in each configuration. This is an
  observation for this externally linked corpus, not a general O2 guarantee.
- The typed direct-call spot confirms `calc_engine_equals` calls the entry
  of `calc_apply_op` in arm64 O0. There are 2 distinct sampled typed call
  targets; the previous count of 13 included non-call references.
- 8/8 noinline arm64 O0 routines match LLVM instruction starts **and bytes**
  within Ghidra-selected body ranges (also 8/8 instruction-count matches).
  Those ranges are not independent function-boundary truth. Branch targets,
  x86_64 fidelity and optimized fidelity remain unmeasured. The historical
  LLVM text was not included in the original freeze; its current hash is
  recorded by the review, not retroactively called frozen before evaluation.
- One direct universal import selected x86_64 and its name+entry set matched
  one thin x86_64 baseline. This does not establish all-slice result parity.
  Original build checks reported 8/8 unsigned payload matches. Its “text
  hashes” hashed formatted otool text, not raw section bytes; retain that
  provenance and do not reinterpret those digests.
- One case (`DebugAnalysis-arm64-sym-tool`) was run twice with matching JSON
  hashes. The full repeat matrix was not run.
- Raw engine function counts differ by architecture (arm64 app sym 164,
  x86_64 app sym 87). False positives and missed non-whitelist routines are
  unknown.

## Release-gate status (spec §9.1)

| Gate | Status | Actual scope / missing evidence |
|---|---|---|
| Full headless path | PASS (narrow) | 16 historical fixture pipelines returned JSON; old orchestration lacked robust aggregate failure handling |
| Import identity | PARTIAL | hashes/UUIDs/build mapping exist; complete mapping and all import metadata not independently validated |
| Parser safety | UNKNOWN | no hostile/malformed engine corpus |
| O0/O2 discovery | PARTIAL | controlled entry recall/completion only; no full precision or body correctness |
| Instruction fidelity | PARTIAL | 8 arm64 O0 body-range byte/boundary checks; no full architecture/branch adjudication |
| Pseudocode completion | PASS (narrow) | 120/120 controlled routines per symbol state, operation completion only |
| Pseudocode behavior | UNKNOWN / NOT TESTABLE RAW | no validated lowering/recompile harness or executed behavioral comparison |
| Direct calls/xrefs | PARTIAL | one typed direct-call relationship, not complete call recovery |
| Universal parity | PARTIAL | build slice checks and one thin/fat function-set comparison, not all result facets/slices |
| Determinism | PARTIAL | one case twice; not full three-repeat matrix |
| Annotation round trip | NOT RUN | separate CLI validation |
| REA adapter | NOT RUN | optional, outside this milestone |

Raw `calc_add`/`calc_div` pseudocode includes Ghidra constructs such as
`undefined1 [16]`, `auVar1._0_8_`, and uninitialized padding `uStack_4`.
It is inspectable C-like output, **not compilable C**. Arithmetic spot-reading
(e.g. `SCARRY8`) is not semantic equivalence. A generic mechanical lowering
would need its own frozen validation before behavior can be scored.

## Post-review semantics and harness

Semantics **v1.1**, committed separately, fixes controller chain-history
recording, defines sign-preserving decimal entry and pending RHS sign, and
revises the formatter rule to actual rendered length plus NUL. Original v1.0
outputs are neither regenerated in place nor relabeled consistent with v1.1.

- C tests: 59,201 assertions; production-controller tests: 83 assertions
  across 34 journeys. Each passed at O0, O2 and ASan+UBSan. These are headless
  controller tests, not assertions about rendered AppKit windows.
- The tracked `fixture/build/` scripts run from any cwd, refuse a reused
  build directory, capture actual expanded commands, record git revision,
  dirty tracked-diff digest, per-source hashes, tool versions, and raw
  `__TEXT,__text` byte digests. App smoke launch and name-based process
  termination were removed. No user app session is terminated.
- New fixture matrix: `build/review-v2/manifest.json`, 20 artifacts (16 thin,
  4 universal). All four Xcode config/architecture builds passed; strip
  preserved raw text bytes in 8/8 cases; universal extraction matched the
  unsigned thin payload and signed-thin raw text in 8/8 cases.
- New direct baseline evidence: `build/baseline-runs/review-v2-full/`.
  All 16 cases completed in 122.205 seconds total; engine commands took
  4.879–11.034 seconds each. It reported 933 complete decompiles and 340
  thunks/not-requested, with zero failed/timeout/cancelled decompiles.
  `build/review-v2/eval-results.json` verifies the new freeze and separately
  confirms 120/120 sym and stripped controlled entry recall/completion and
  8/8 arm64 O0 byte/boundary comparisons. 12 non-whitelist outgoing-xref
  samples hit the declared 200-reference cap, explicitly marked truncated.
  No instruction/CFG truncation occurred. These are bounded facets, not a
  full-xref gate pass. The historical and new populations remain distinct.
- Negative integration test: `build/baseline-runs/review-timeout/` applies a
  0.01-second whole-command limit; both owned Ghidra processes were stopped,
  results and aggregate status failed, and the completed full run remained
  unchanged. Earlier failed harness bring-up runs `hardening-old-input-*`
  are retained as failed experiments, not included in success counts.
- The direct baseline runner now uses exclusive per-run IDs under
  `build/baseline-runs/`, private input snapshots and Ghidra settings/cache
  dirs, explicit loader flags forbidding library loading/linking, a trusted
  pre-script disabling DWARF/PDB/source/external symbol discovery, and a
  complete effective analysis-option export. The pre-script completion
  marker is verified because headless can exit 0 after a script error.
- Whole experiment budget: 1,800 seconds; each engine command: 600 seconds;
  auto-analysis: 540 seconds/file; decompile: 30 seconds/function. Captured
  logs are capped at 16 MiB, result JSON/partial evidence at 64 MiB, and child
  files at 64 MiB each. Only the exact child’s newly owned process group is
  stopped on cancellation. Completed earlier cases remain available when a
  later case times out. An interrupted in-flight export is partial evidence,
  never published as a completed baseline.
- Java export uses atomic no-replacement publication, records native
  `openProgram` failure, actual timeout/cancel/start/error states, successful
  decompile warnings and facet errors/truncation. Runner validates JSON,
  profile marker, summaries, function/facet counts and aggregate failures.
- Regression suite: 20 tests passed, `python3 -m unittest discover -s analysis/tests -v`.
  Covers evidence tampering/missing/duplicate/unlisted paths, malformed
  JSON, summary/status rejection, output/log limits, owned timeout with an
  unrelated process left alive, and raw section hashing.

## Remaining limitations

Seatbelt denies network, **not filesystem access**. Source and dSYM trees
are on the same readable machine. Disabled analyzers and binary-only input
directories improve hygiene but do not establish enforced source isolation.
Only our own fixtures are authorized for this runner; untrusted binaries
require stronger isolation. User state is isolated in new runner runs, while
old runs used shared Ghidra state. No x86_64 binary has been executed and no
Rosetta use is claimed. Neither this review nor the new runner turns partial
quality gates into a release pass.
