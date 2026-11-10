# Current status and remaining gates

Updated 10 November 2026. The specification is a staged roadmap; its historic
pre-development wording is not a statement that the current repository still
contains documentation only.

## Implemented

- Source-controlled AppKit calculator, pure-C calculation core and corpus,
  build matrix, core/controller tests and direct full-Ghidra baseline.
  Current measurements and any unresolved phase-1 gates are documented in
  [phase-1 findings](phase1-findings.md), not inferred from CLI completion.
- Initial installable `macscope` 0.2.0 wheel, with no third-party Python
  dependencies and no bundled engine. Uses full Ghidra12.2/JDK25 on the
  tested macOS arm64 host.
- Version/doctor, bounded Mach-O/app-main inspection, private project creation,
  explicit thin/universal slice import without autoanalysis, versioned baseline
  analysis and explicitly selected binary-derived parameter inference,
  function list/show, disassembly, cached and fresh selected-function pseudocode, references,
  CFG JSON/DOT, project/job status, cached search, bounded call traversal
  and normalized exports.
- Package-owned Java bridge, effective analyzer-option recording, real saved
  Program databases, immutable digest identities, SQLite committed snapshots,
  writer lock, atomic result/output publication and pagination-bound cursors.
- Owned-process cancellation, wall/per-function deadlines, bounded facets,
  partial/error envelopes, and explicit rejection of unsupported hard-memory,
  independent-startup and parallel-worker budgets. Group cleanup retains
  the launcher's child identity through signaling and checks budgets before
  accepting the result.
- Durable malformed-input, storage, selector, schema, dependency, cached-query
  and process-lifecycle tests; controlled thin/fat64 integration and a clean
  local wheel install. See [CLI validation](cli.md#reproduce-validation).

## Phase-2 boundaries still open

Engine operations are **trusted-owned-input-only experimental**, with an
explicit opt-in. The worker denies network access, restricts user-home
reads, and confines write paths to its own newly created job directory
and `/dev/null`. The shared index, saved inputs, and earlier jobs are
outside that write scope. Non-home reads remain broadly available.
Hard process-memory and disk quotas are unavailable. Isolation errors
fail closed.

Public queries default to completed snapshots. Explicit `decompile --fresh`
uses the saved Program and the read-only/noanalysis worker. Polished terminal
output, full Mach-O load-command and dyld decoding, and broader host support remain
incomplete. Some calculator batches correctly exit6 because their reference
collections exceed documented bounds despite successful pseudocode output.

## Later phases and separate gates

- [x] Reproduce owned stripped x86_64 instruction checks using independent
  function-start metadata. See [profile validation](parameter-inference.md).
- [x] Match 13,900 instruction starts and byte records and 2,732 direct
  targets across the full owned tool core in the patched captures. See
  [the instruction audit](phase1-findings.md#controlled-core-instruction-audit).
- [x] Match all 256 outgoing direct call references in the controlled tool
  core and verify that the 16 encoded indirect calls have no reported target.
- [x] Audit the owned app-main core across both architectures and profiles.
  All 2,732 direct targets matched. A stripped arm64 O2 function boundary
  accounts for the 28 missing instruction records across two captures.
- [x] Report that conflicting boundary in cached, fresh and replayed
  queries. The owned live test preserved the archived Program and snapshot.
- [x] Recover all 23 instructions in both profiles on disposable Program
  copies using the saved binary-derived boundary evidence. The
  [control comparison](phase1-findings.md#temporary-split-body-recovery)
  matched all 196 other functions per profile.
- [x] Validate split-body recovery on a [held-out arm64 fixture](heldout-fallthrough.md).
  Both profiles recovered the eligible 11-instruction body and refused a
  second join because of an outside branch into the competing body.
- [x] Expose guarded split-body recovery as an explicit analysis option.
  The 32-capture calculator comparison found the expected two joins and
  preserved the other functions. The held-out integration and live
  cancellation verified saved Programs and exact replay.
- [x] Match all 152 controlled PC-relative data references across the app
  and tool after opt-in recovery, including the two sites inside the
  previously split body. See [the data audit](phase1-findings.md#controlled-data-references).
- [x] Match three normalized exports per case and profile on the owned
  patched app and tool matrix. The [determinism run](parameter-inference.md#three-run-determinism)
  verified 96 distinct headless workers.
- [x] Expose uncached selected-function decompilation from the saved Program.
- [x] Link available Ghidra pseudocode tokens to machine addresses. The
  arm64/x86_64 thin and universal integration checked cached and fresh links.
- [x] Measure 20 rounds of CLI latency on the development Mac. See the
  [benchmark](benchmark.md) for scope and outstanding reference-host measurements.
- [x] Search committed function names, symbols, strings and pseudocode
  with resumable pages and scoped coverage.
- [x] Traverse saved call references with depth/edge bounds and explicit
  unresolved targets.
- [x] Store user labels and function/instruction comments with reversible
  revisions, search and separate opt-in export.
- [x] Round-trip full annotation history and accepted return-type hints
  between compatible workspaces, with validated identity and atomic import.
- [x] Apply explicitly accepted scalar return hints in fresh Ghidra queries.
  The owned arm64/x86_64 tests verified separate provenance and unchanged
  unassisted snapshots. Parameter and compound hints remain open.
- [x] Inventory physical bundle images and resources with hashes and
  resumable pages.
- [x] Import explicit embedded images and resolve bounded in-bundle framework
  links. The owned arm64 main and x86_64 helper passed real Ghidra import.
- [x] Query imported headers, segments, sections and file-backed bytes,
  plus saved symbol, string, import and export collections.
- [x] Record entry offsets, dylib dependencies, rpaths and linkedit extents,
  and decode bounded function-start and data-in-code tables. The owned
  16-binary comparison checked 708 function starts and 56 dylib paths.
- [x] Decode ordinary 64-bit chained bind and rebase pointers from immutable
  slices. The 16 owned inputs matched Apple tool output for 3,890 fixups.
- [x] Decode ordinary pointer operations in legacy dyld streams. Four
  separately linked owned binaries matched Apple tooling on 1,086 fixups.
- [x] Query bounded modern and legacy export tries from the immutable
  slice. Apple and LLVM comparisons verified 406 exports on owned images.
- [x] Decode arm64e userland chained fixups through data-only file queries.
  Apple tooling matched 18 records across a linked format-12 fixture and
  two derived format-1/9 copies. Universal selection distinguishes arm64e.
  The decoder handled 12,000 seeded fixup-table and pointer mutations.
- [x] Probe authenticated instructions on an owned arm64e fixture in
  disposable full Ghidra. The loader accepted the image, but low p-code
  omitted signing and authentication effects.
- [ ] Validate authenticated call and pointer semantics before enabling
  arm64e engine import and analysis. Shared-cache, kernel and other
  chained formats remain outside the decoder.
- [x] Expose Objective-C classes, methods and selector references with
  static provenance. The owned app matrix matched 216 method addresses.
- [x] Expose Swift symbol-table names and optional sandboxed demangling
  with tool provenance. Broader Swift metadata decoding remains open.
- [x] Run source-aware recovered-C calibration for the two scalar comparison
  functions. [Measured scope and results](parameter-inference.md#recovered-scalar-behavior-calibration).
- [x] Measure 100% branch-direction coverage for the owned reference core
  with directed and seeded stateful tests. See
  [reference coverage](semantics.md#reference-core-coverage).
- [x] Compare all seven held-out switch routines across the frozen patched
  and control captures. The [behavior check](heldout-switch.md#recovered-c-behavior)
  records signed overflow and caller arity failures separately from
  recovered control flow.
- [x] Inventory all 26 public routines across the 16 patched calculator
  captures and test unmodified comparison, history and state routines against
  the reference. See [recovered core behavior](semantics.md#recovered-core-behavior)
  for instruction-byte denominators and the distinct blockers.
- [x] Evaluate aggregate returns, state transitions and formatting with
  strict sanitizers and immutable capture evidence. Run the frozen
  aggregate policy on a separate fixture. See
  [the combined results](semantics.md#combined-core-behavior).
- [x] Test an experimental [fixed-width C printer](fixed-width-printer.md)
  in a separately selected full Ghidra engine. It preserved the paired
  machine evidence and moved 120 calculator instances to full passes.
- [x] Test [byte-offset store rendering](byte-offset-stores.md) across
  the calculator matrix. All 20 alignment failures moved to full
  passes. The independent fixture exposed a separate load-order error.
- [x] Verify [byte-range overlap handling](byte-offset-stores.md#paired-overlap-results)
  on the original reproducer and a separate fixture. All eligible
  overlap and adjacency cases passed. The calculator rerun retained
  the same 342 full passes.
- [x] Verify [declared aggregate widths and vectorized formatting](vector-widths.md)
  in a separate full Ghidra build. The parameter-inference O2 tool
  captures exceeded both 90% thresholds in each symbol state and on
  both architectures.
- [x] Verify [immutable dispatch tables](dispatch-tables.md) and score the
  recovered C in all arm64 and x86_64 O0 calculator captures and the
  arm64 O2 captures. The independent fixture verified the table entries
  and exposed separate recovered-C blockers.
- [x] Validate [automatic x86_64 O2 dispatch return recovery](dispatch-tables.md#automatic-recovery-on-saved-programs)
  in disposable full-Ghidra queries. Both calculator parameter-inference
  captures and all four independent fixture captures passed. Four
  no-observer controls declined recovery.
- [x] Integrate [verified return recovery](dispatch-tables.md#installed-cli-validation)
  into opt-in fresh queries in the installed CLI. The opt-in output brings
  O2 parameter inference to 52/52 routines and 4,269/4,269 instruction bytes
  in each symbol state. The cached score is 51/52 routines and 4,206/4,269
  bytes. All twelve receipts replayed with identical cached exports.
- [x] Verify [wide signed division and unsigned range guards](wide-division.md)
  on a separate full Ghidra build. Both x86_64 O2 baseline divisions and
  both opt-in baseline dispatch queries passed. The four independent
  signed x86_64 O2 cases passed on the same frozen inputs.
- [x] Verify [direct-call signature recovery](direct-signatures.md) in
  the installed CLI. With separate opt-in fresh queries for direct calls
  and indirect dispatch, O2 reaches 52/52 routines and 4,269/4,269
  instruction bytes in each profile and symbol state. The independent
  observer passed in all four captures and all four controls declined.
- [x] Validate [O0 byte-array compatibility](semantics.md#o0-byte-array-compatibility)
  on all 416 saved calculator instances. Eight previously untestable
  instances passed with zero mismatches.
- [x] Validate [scalar call signature recovery](scalar-call-signatures.md)
  in the installed CLI. The O0 parameter-inference profile reaches
  52/52 routines and 8,644/8,644 instruction bytes in each symbol
  state with separate opt-in fresh queries. All eight independent
  observers passed and all eight controls declined.
- [x] Meet the O0 calculator behavior gate under baseline on the
  separately selected experimental engine. [Callee parameter recovery](callee-parameters.md)
  and the scalar formatter query bring the installed CLI to 52/52
  routines and 8,644/8,644 bytes in each symbol state. The saved
  captures pass 41/52 routines and 5,360/8,644 bytes.
- [x] Verify [one-register return recovery](forwarded-return.md) in
  the installed CLI. All 16 behavior cases across two owned fixtures,
  both architectures, both profiles, and both symbol states passed.
  All 24 indirect, ignored, and byte-only controls declined recovery.
- [x] Measure owned-tool discovery against evaluator-side DWARF and linker
  starts. All 536 entries matched. LLVM confirmed a missed x86_64 O0 switch
  and adjudicated the x86_64 O2 padding discrepancy. See the
  [discovery measurement](parameter-inference.md#evaluator-side-discovery-measurement).
- [x] Freeze a [held-out switch variation](heldout-switch.md) before tuning.
- [x] Report unresolved computed jumps as partial in cached and fresh CLI
  views. Verified both owned switch fixtures and their resolved controls.
- [x] Recover the missing x86_64 O0 case blocks with a separately selected
  full Ghidra 12.2 tree containing the upstream native patch. Verified all
  calculator and held-out cases. See the
  [patch evaluation](heldout-switch.md#upstream-patch-evaluation).
- [x] Expose [guarded switch recovery](heldout-switch.md#stock-engine-fresh-query)
  for one fresh query on stock Ghidra 12.2. All eight x86_64 O0 scopes
  restored the verified case targets, and all four resolved or unsupported
  controls skipped. Saved exports were byte-identical after replay.
- [ ] Validate a released patched engine before changing the default pin.
  The installed 12.2 engine reports the affected cached and ordinary fresh
  results as partial.
  The latest published release still showed 12.2 on 10 November 2026,
  with the switch regression assigned to 12.2.1.
  [Ghidra release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build)
  · [Switch regression](https://github.com/NationalSecurityAgency/ghidra/issues/9996)
- [x] Exercise data-only parsers with 10,350 seeded Mach-O mutations and
  10,000 bundle plist mutations. Deep binary plist nesting, unexpected
  XML keys and unknown encodings now return typed `bundle_plist` errors.
- [x] Exercise [dyld and Objective-C metadata payloads](cli.md#targeted-malformed-mach-o-payloads)
  with 20,480 targeted mutations on owned calculator copies. Every
  mutation returned a complete or partial result or a typed error.
- [x] List and inspect worker jobs and request cancellation through their
  live owner. A second CLI process cancelled an owned calculator analysis
  while preserving its previously committed snapshot.
- [x] Restart eligible unpublished analysis jobs with their recorded
  input, engine, isolation, profile, and limits. A live cancellation and
  restart reproduced the request and retained the prior snapshot until
  publication. Publication receipts make repeated requests idempotent.
- [x] Restart eligible unpublished import slices from the immutable workspace
  copy. An owned universal import resumed its cancelled x86_64 slice after
  removal of the original input and preserved the committed arm64 Program.
  Journal recovery verifies and publishes a saved Program across interruption
  before or after its directory move.
- [x] Restart fresh decompilation with the original saved Program and
  accepted hint revisions. A live cancelled query resumed after a newer
  analysis, label and hint were committed. A repeat read the durable result
  without launching another worker.
- [x] Fence a disconnected worker until the launch guard or the same-boot
  process-group check confirms it has stopped. A live owned Ghidra query
  outlived its supervisor. The CLI refused replay until the group exited,
  then replayed successfully. Older disconnected jobs and unverified boot
  identities remain ineligible.
- [x] Verify [workspace manifest error handling](cli.md#envelopes-errors-and-explicit-omissions)
  and a byte-identical export from an earlier schema 1.0 workspace.
- [x] Validate [SQLite index error handling](cli.md#envelopes-errors-and-explicit-omissions)
  for corrupt data, missing schema, and a lock held by another connection.
- [x] Verify [per-job write confinement](cli.md#limits-and-safety-boundaries)
  with owned canaries and eight installed full-headless scopes. A
  worker could not modify an earlier Program or the shared index.
  Live import, analysis, and fresh-query restarts each used a new
  job-specific policy and replayed their receipts.
- [ ] Expand malformed-input coverage and exercise isolation, schema migrations and
  additional host versions before a wider release. Release SBOM and notices
  need dependency and packaging decisions.
- [ ] Separately gated: desktop UI acceptance, private real-app and Taskovsky
  evaluation, optional REA integration, licensing and publication.

## Independent decompiler research

An opt-in research harness and [documented regression](decompiler-review.md)
compare instruction evidence and binary-derived prototype inference on the
owned calculator. They do not change production defaults or establish
pseudocode behavioral equivalence. The alternate CLI profile is explicitly
selected with `--profile parameter-inference`; baseline remains unchanged
as the default. See [profile validation](parameter-inference.md).
