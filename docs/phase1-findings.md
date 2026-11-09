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

## Controlled core instruction audit

The separately selected patched Ghidra 12.2 captures match LLVM across
all 26 public calculator core routines in the owned command-line tool.
The audit covers arm64 and x86_64 at O0 and O2, both symbol states, and
both analysis profiles. The 416 routine instances matched all 13,900
instruction starts and byte sequences, totaling 51,652 instruction bytes.
All 2,732 encoded direct jump and call targets matched.

Eight apparent flow differences are optimized tail calls. LLVM prints the
machine branch and Ghidra classifies it as a terminating call with no
fallthrough. The address matches in every case. LLVM's indirect-symbol
table independently identifies the destination as the `_bzero` stub on
arm64 or `___bzero` stub on x86_64.

The complete outgoing-reference facet contained all 256 direct call
references expected from those instructions, including the eight tail calls.
All 16 encoded indirect calls had no reported target. The evaluator maps
the frozen captures by confirmed DWARF and linker entries, decodes their
exact byte extents, and excludes linker-marked data. Data-reference
completeness, indirect jump tables and other Mach-O images have separate
denominators.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 analysis/audit_core_instructions.py \
  --fixture-build-root /path/to/owned-calculator-build \
  --profile-matrix /private/tmp/owned-patched-profile-matrix \
  --output /private/tmp/new-core-instructions.json
```

The measured report SHA-256 is
`5859c98f8c2be6664f0bddfca4164dbdd9bb3968fd2af4a0e8c59d552a2d3d0a`.

The same audit with `--kind app` matched 13,872 of 13,900 instruction starts
and byte records in the owned app main. All 2,732 encoded direct targets
and all 256 direct call references matched. The stripped arm64 O2 app
omits 14 instructions from the reported `calc_dispatch_table` function
in each profile. At `0x100000ebc`, a normal fallthrough enters a block at
`0x100000ec0` that Ghidra treats as a second function. The linker confirms
the true entry at `0x100000e9c` and records no function start at the split.
DWARF and LLVM confirm one contiguous function through `0x100000ef8`
exclusive. The symbol-bearing counterpart retains the whole body.

The app-main instruction report SHA-256 is
`7143b3c2d12a0f035c5e58035035291e740524ecec44e1026f7a72a9964d31f9`.
The separate app-main discovery report matched all 880 independently
confirmed entries and 870 exact body extents. Its SHA-256 is
`057e2d05f2ec341417c7ea296691273ebb36e77b0aa20dfe4bf1a049b9f7e8b0`.

### Temporary split-body recovery

A separate planner reproduced the candidate from the binary-only saved
exports and linker starts. It found the same split in both profiles and
no candidate in the other 30 app and tool captures. The research script
`analysis/scripts/JoinUnconfirmedFallthrough.java` ran on read-only
Program copies. It checked the adjacent fallthrough, the default symbol
source, the next linker start and incoming references before joining the
body. It used the next linker start as a bound and derived the joined
extent from Ghidra's two saved bodies.

The evaluator matched all 23 recovered instruction starts and bytes
against LLVM in both profiles. Each separate unmodified read-only control
matched the joined output for the body ranges, disassembly, CFG,
pseudocode and decompile status of all 196 other functions. The archived
and disposable Program digests stayed intact. Production queries still
report the conflicting boundary as partial. A held-out test and a
production repair policy remain open.

The recovery report SHA-256 is
`eb4dbc98c09216b083ee0f1f0339f417337dfeb260876f66e5c484bfb86e8ebd`.
The control report SHA-256 is
`54298809ec08c85a22847e1db0d72d788b0b0076cadf62295bbecc5b3e2142c8`.

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

## Post-baseline display-layout correction

A live visual check of the v1.1 app found that the original 280-point field
clipped `INT64_MAX` at 28-point font despite exposing the complete AX value.
The AppKit delegate now derives its minimum/default width from the measured
signed-int64 extrema (at least 420×480 content), preserves a minimum window
size, stretches the display/error/history horizontally, and expands history
vertically while keeping the button grid visible. A normal application Quit
menu routes Command-Q to `NSApplication.terminate:`. Window/menu names honor
`CFBundleDisplayName`, falling back to the ordinary fixture name.

`fixture/tests/ui_layout.m` constructs the real production controls without
showing or activating a window. O0, O2 and ASan+UBSan each pass 1,383
assertions over minimum,
wider, taller, larger, and restored-minimum sizes. Checks compare full
`INT64_MAX`/`INT64_MIN` glyph extents with the cell drawing/title rectangles,
keep overflow text and both `2+3*4=` history entries visible, verify button
bounds/non-overlap, and inspect Command-Q routing. The matrix script now runs
this regression. It does not synthesize a Quit action or touch other apps.

The isolated visual-review build is reproducible with
`python3 fixture/build/build_ui_review.py build/ui-layout-review-<new-id>`. It uses
a copied Info.plist and Xcode overrides for bundle identifier
`org.macsdisassembler.CalculatorFixture.UIReview` and display name
`CalculatorFixture UI Review`, avoiding selection of an older running
same-ID app. Baseline identity files remain unchanged. The output manifest
records source hashes/revision, actual tool versions/command, temporary
Info.plist hash, and the new executable hash. No existing process is closed
or killed by the build. This UI change creates a new binary identity; the
prior full baseline stays frozen and is not a measurement of this UI build.
No new 16-case analysis is claimed for a layout-only correction.

Completed review build: `build/ui-layout-review-v2/evaluator/DebugAnalysis-arm64/CalculatorFixture.app`,
source revision `d8f9176`, with the exact manifest in
`build/ui-layout-review-v2/manifest.json`. The distinct bundle ID/display name
were verified from the built Info.plist, and code-signature verification
passed. An earlier `ui-layout-review-v1` Xcode service crash is retained as
failed evidence. The successful retry separates Xcode's build/cache writes
from the baseline worker's 64-MiB per-file cap, retaining the owned process
group timeout and captured-log bound. No automatic app launch or actual
keyboard Quit was performed by this build/test workflow; rendered visual
recheck belongs to the parent review.
