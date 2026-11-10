# Current status and remaining gates

Updated 10 November 2026. The specification is a staged roadmap; its historic
pre-development wording is not a statement that the current repository still
contains documentation only.

## Current priority for TickTick and Taskovsky

Prioritize the Calendar investigation in the [Taskovsky reuse scenarios](specification.md#10-taskovsky-reuse-scenarios).
The existing private TickTick 8.2.20 export indexes shipped images,
symbols, Objective-C metadata, assembly and selected Calendar resources.
It has no complete main-app pseudocode or cross-reference graph. The
Calendar resource subset identifies controls and wiring. Open scheduling
questions still need evidence about how handlers reach date and recurrence
logic. Taskovsky already has a local skip-occurrence workflow and is
verifying it independently. Start with the date-range and time-zone paths
or recurrence exceptions that could affect a remaining implementation
decision. Reuse recorded observations for gestures already covered.

- [x] **Rehearse one selected Calendar workflow on an owned app.** The
  [arm64 main and framework rehearsal](cli.md#owned-calendar-evidence-rehearsal)
  matched a selector to its exact implementation and a string lead to an
  incoming reference. It verified linked disassembly and pseudocode,
  the declared library bind and export, two framework call sites, an
  unresolved dispatch and a resource hash.
- [x] **Produce a small, private evidence handoff for the owned rehearsal.**
  The four-function report included image and slice hashes, exact function
  and analysis IDs, coverage and a typed missing-selection result. It
  separated the owned runtime result, static inference and open dispatch
  question. The saved workspace, resource record and query receipt
  reproduced the handoff byte for byte with the original bundle absent.
- [x] **Make the handoff reusable for a reviewer-selected lead list.**
  [`evidence`](cli.md#selected-evidence-handoff) pins the image and analysis
  for each lead and keeps saved code, references and optional fresh query
  receipts. The installed CLI checked eight leads across the owned Calendar
  app and framework, including a missing address, an ambiguous import name
  and a mismatched receipt. Changing the active analysis preserved the
  original handoff byte for byte without another worker for the export.
- [x] **Verify declared links to pinned embedded frameworks.** The opt-in
  handoff matched call and stub bytes, bind sites and export entries on
  both owned Calendar architectures. It withheld a target for an absent
  or ambiguous provider and preserved computed dispatch in the local trace.
- [x] **Reuse the authorized TickTick Calendar archive.** The saved arm64
  metadata and assembly trace the Week time-scale callback to the base
  controller's context date. When Week alignment is enabled, the setter
  retains the incoming date as context and separately computes a seven-day
  display range from the configured first weekday. The shared ruler can
  therefore use a date later than the range start. Which gestures refresh
  that context and when the labels redraw remain open.
- [x] **Run focused Ghidra validation on the exact TickTick images.**
  The user authorized static analysis of the archived arm64 main executable
  and versioned TTCalendarKit framework. A private, digest-bound launcher
  imported both with automatic analysis and library loading disabled.
  The framework analysis captured 450 of 630 functions with partial
  coverage. Whole-image analysis of the main executable reached its
  1,000-second wall limit before publishing a snapshot. A private pass
  recovered six exact Week functions from a read-only copy of the import.
  A second copy reproduced all six pseudocode outputs byte for byte.
  The installed worker keeps its owned-input policy.
- [x] **Decompile one exact function without whole-image analysis.**
  [`decompile --from-import`](cli.md#decompile-one-function-from-an-import)
  verifies the linker extent and each emitted instruction against the slice.
  The installed CLI reproduced focused results on the owned Calendar main
  and framework while both images had no active snapshot. The trust gate
  and typed missing-entry result were verified on both images. A generated
  arm64 image exercised an exact entry beyond the 10,000-row inventory
  limit. An x86_64 fixture returned pseudocode and reported the undecoded
  bytes in its linker extent as partial coverage.
- [x] **Resolve exact relocations and Calendar leads beyond the inventory cap.**
  `fixups --address` matched Apple tooling on four owned binaries covering
  chained and legacy formats on both architectures. A padded owned Calendar
  app put its class slot and framework bind beyond the first 10,000 records.
  The pinned handoff resolved both, withheld an invalid class slot and
  reproduced the report without starting another worker.
- [ ] **Include focused results in the pinned Calendar handoff.**
  Accept results from a verified import even when the main executable has no
  committed whole-image snapshot. Verify exact provenance, replay and
  explicit missing or unresolved coverage through the normal commands.

Defer unrelated fixture scenarios, broad Objective-C and Swift recovery,
arm64e execution semantics, additional host support, and general-purpose
reporting or packaging expansion. Keep isolation and correctness fixes
needed by the selected workflow in scope. Desktop UI acceptance, optional
REA, licensing, and publication retain their separate gates.

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
  analysis, explicitly selected binary-derived parameter inference and
  deep address-table discovery,
  function list/show, function and range disassembly, cached and fresh selected-function pseudocode, references,
  CFG JSON/DOT, project/job status, cached search, bounded call traversal,
  encoded strings with verified file bytes and incoming references,
  Mach-O symbol declarations and indirect slots, compact and DWARF unwind
  records, normalized exports, explicit terminal views and private HTML reports.
- Package-owned Java bridge, effective analyzer-option recording, real saved
  Program databases, immutable digest identities, SQLite committed snapshots,
  writer lock, atomic result/output publication and pagination-bound cursors.
- Owned-process cancellation, startup, wall and per-function deadlines,
  bounded facets, partial/error envelopes, and explicit rejection of
  unsupported hard-memory and parallel-worker budgets. Group cleanup retains
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
uses the saved Program and the read-only/noanalysis worker. Full Mach-O
load-command and dyld decoding and broader host support remain
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
- [x] Verify [whole-batch decompilation status](cli.md#implemented-commands).
  Full Ghidra captures capped at one of six functions returned partial
  on both owned architectures. A derived later-page timeout appeared
  in the batch summary on every page.
- [x] Validate [dependency preflight and full-headless doctor](cli.md#verify-the-local-engine).
  The installed CLI verified stock and experimental engines on a generated
  owned probe. Wrong-architecture, damaged launcher and JAR, and JDK
  override controls produced typed dependency failures. Six normal
  arm64 and x86_64 target jobs verified the selected native JVM.
- [x] Query saved disassembly by unslid VA range with explicit byte gaps.
  The installed CLI matched all 534 returned instruction records to LLVM
  and the owned slices across 27 thin and universal queries.
- [x] Select functions and bytes by explicit RVA or slice file offset.
  The installed CLI verified equivalent selections, annotation history,
  and fresh receipt replay on owned thin and universal images. Four
  owned dylib and bundle probes also passed with a zero image base.
- [x] Select functions and bytes by [runtime address and load slide](cli.md#implemented-commands).
  All 28 runtime queries matched the unslid evidence on owned arm64 and
  x86_64 thin and universal slices. Fresh queries retained the supplied
  slide on receipt replay, including an x86_64 publication retry.
- [x] Link available Ghidra pseudocode tokens to machine addresses. The
  arm64/x86_64 thin and universal integration checked cached and fresh links.
- [x] Verify [alternate function labels and immediate thunk targets](cli.md#implemented-commands).
  Apple tools matched a shared entry, local branch and imported stub on
  both owned architectures. Fresh aliases replayed their receipts and an
  entry with 36 labels reported the bounded scan.
- [x] Report [overlapping saved function bodies](cli.md#implemented-commands).
  Derived controls on owned arm64 and x86_64 snapshots kept agreeing
  instructions and separated contradictory bytes from ownership warnings.
  Fresh queries replayed the warning. Normal full-Ghidra reanalysis
  reproduced the original IDs and exports.
- [x] Measure 20 rounds of CLI latency on the development Mac. See the
  [benchmark](benchmark.md) for scope and outstanding reference-host measurements.
- [x] Search committed function names, symbols, strings and pseudocode
  with resumable pages and scoped coverage.
- [x] Verify [bounded opt-in regex search](cli.md#implemented-commands) in
  all four scopes on owned arm64 and x86_64 full-Ghidra snapshots.
  A slow expression timed out and preserved the output. Archived literal
  pages and cursors matched the previous wheel.
- [x] Traverse saved call references with depth/edge bounds and explicit
  unresolved targets.
- [x] Withhold [ambiguous callers](cli.md#implemented-commands) at shared
  callsite addresses. Derived controls on owned arm64 and x86_64 snapshots
  preserved the recorded targets and stopped traversal in both directions.
  Five thousand seeded maps matched exhaustive address checks.
- [x] Query [references at arbitrary addresses](cli.md#implemented-commands)
  from a bounded image capture. All 32 owned thin address queries matched
  exact Ghidra queries and reproduced on universal slices. The installed
  CLI preserved unresolved computed targets and reported the capture cap.
- [x] Recover and page [capped function references](cli.md#implemented-commands)
  from a complete saved image capture. On six owned slices, independent
  Ghidra queries matched 2,497 additional outgoing and 34 additional incoming
  records. Call graphs recovered 649 reference edges across the tested queries.
- [x] [Compare committed exports](cli.md#comparing-committed-exports) by
  metadata, functions, and pseudocode. Owned arm64 and x86_64 pairs
  verified changed code, renamed and added entries, ambiguous bodies,
  stripped matching, metadata-only differences, and thin/universal parity.
- [x] Store user labels and function/instruction comments with reversible
  revisions, search and separate opt-in export.
- [x] Round-trip full annotation history and accepted return-type hints
  between compatible workspaces, with validated identity and atomic import.
- [x] Apply explicitly accepted scalar return hints in fresh Ghidra queries.
  The owned arm64/x86_64 tests verified separate provenance and unchanged
  unassisted snapshots.
- [x] Apply [fixed parameter lists and pointer type hints](cli.md#accepted-type-hints)
  in fresh full-Ghidra queries on owned arm64 and x86_64 slices. Verify
  zero and nine parameters, pointer return and parameter types, annotation
  transfer, and restart from the original hint revisions after a later
  clear. The saved Programs and unassisted exports matched afterward.
- [x] Apply [named structure hints](cli.md#accepted-type-hints) to returns
  and parameters in fresh full-Ghidra queries. Eight owned arm64 and x86_64
  queries matched Clang's natural layouts, including a padded structure
  and a large hidden-storage return. The x86_64 float pair retained vector
  lane operations. Verify opt-in annotation transfer, unchanged Programs
  and cached export, and receipt replay after a later clear.
- [x] Apply [manual function boundary edits](cli.md#manual-function-boundary-edits)
  as a separate full-Ghidra analysis. On owned arm64 and x86_64, resize,
  add and remove functions, verify instruction-byte parity and reopen a
  corrected body. Check discontiguous ranges, rejection of unsafe ranges,
  opt-in transfer, and retry of the original edit set after a later clear.
  Guarded linker recovery retained both its join and refusal decisions.
- [x] Inventory physical bundle images and resources with hashes and
  resumable pages.
- [x] Verify [`resources list`](cli.md#bundle-resources) on an owned app
  and framework. Six sizes and hashes matched. Type filtering, cursor
  binding, JSONL and partial hash coverage passed. The inventory reproduced
  after all four arm64 and x86_64 slices completed full headless analysis.
- [x] Import explicit embedded images and resolve bounded in-bundle framework
  links. The owned arm64 main and x86_64 helper passed real Ghidra import.
- [x] Verify [Xcode debug companions](cli.md#xcode-debug-companions).
  The installed CLI matched the owned companion's UUIDs and hashes.
  Full Ghidra recovered probe pseudocode and matching instruction bytes
  on arm64 and x86_64 with partial reference coverage. An escaping link
  and a non-dylib file kept the main inspection available.
- [x] Query imported headers, segments, sections and file-backed bytes,
  plus saved symbol, string, import and export collections.
- [x] Record entry offsets, dylib dependencies, rpaths and linkedit extents,
  and decode bounded function-start and data-in-code tables. The owned
  16-binary comparison checked 708 function starts and 56 dylib paths.
- [x] Verify [modern and legacy process entry points](cli.md#mach-o-process-entry-points)
  on owned arm64 and x86_64 universal executables. Apple tools matched
  all four entry locations and full headless Ghidra matched the function
  entries and bytes. Older imported headers recovered the fields from
  their verified slice.
- [x] Verify [deployment and encryption declarations](cli.md#mach-o-deployment-and-encryption-declarations)
  against Apple tooling on owned arm64 and x86_64 binaries. Modern and
  legacy versions, build tools, source versions and the declared
  encryption extent matched. A nonzero encryption ID rejected the
  derived control before a Ghidra job was created.
- [x] Decode ordinary 64-bit chained bind and rebase pointers from immutable
  slices. The 16 owned inputs matched Apple tool output for 3,890 fixups.
- [x] Decode ordinary pointer operations in legacy dyld streams. Four
  separately linked owned binaries matched Apple tooling on 1,086 fixups.
- [x] Report [strong definitions in legacy weak-bind streams](cli.md#strong-definitions-in-legacy-weak-bind-streams).
  The installed CLI matched LLVM on four declarations and two weak pointer
  binds from owned arm64 and x86_64 binaries. Universal project queries
  reproduced after full headless analysis, and 12,000 seeded mutations
  exercised the bounded stream decoder.
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
- [x] Verify [Objective-C properties](cli.md#objective-c-and-swift-metadata)
  for classes, categories and protocols. Apple tooling and file bytes
  matched 36 declarations and 72 pointer sites on owned arm64 and x86_64
  slices with chained and legacy fixups. Queries reproduced after full
  Ghidra analysis of all four slices.
- [x] Verify [Objective-C instance variables](cli.md#objective-c-and-swift-metadata).
  Apple tooling and file bytes matched 40 declarations and 120 pointer
  sites on owned arm64 and x86_64 slices with chained and legacy fixups.
  Initial offsets, sizes, alignments and type encodings reproduced after
  full Ghidra analysis of all four slices.
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
- [x] Pass the full [held-out switch behavior matrix](heldout-switch.md#experimental-fixed-width-engine)
  on the separately selected experimental full Ghidra engine. Saved output
  passed 110/112 comparisons. Two verified callee-parameter queries brought
  the total to 112/112 with zero mismatches in 1,154,848 comparisons.
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
- [x] Refresh [stale dispatcher signatures](heldout-switch.md#refreshing-the-dispatcher-signature)
  from the restored body on stock Ghidra. Both symbol states of the
  calculator tool, calculator app main and held-out fixture recovered
  all three arguments under parameter inference. The eight strict
  calculator-tool and held-out comparisons reached signed overflow in
  recovered helpers.
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
- [x] Fence [workers from earlier retry attempts](cli.md#project-and-job-status).
  The installed CLI blocked a second retry while a disconnected analysis
  worker was live, including through the legacy history scan. After exit
  the original job restarted, and import, analysis and fresh queries
  each verified receipt reuse.
- [x] Fence [workspace writers after a disconnect](cli.md#project-and-job-status).
  A live owned Ghidra analysis blocked new import, analysis and restart
  commands. Cached export and fresh read-only decompilation still worked.
  All three writer commands completed after the worker group exited.
- [x] Report restart IDs after [result publication failures](cli.md#project-and-job-status).
  An owned universal import resumed its prepared second slice without
  another Ghidra worker. Analysis and fresh query failures preserved the
  previous results. All three retries reused their receipts on repeat.
- [x] Verify [workspace manifest error handling](cli.md#envelopes-errors-and-explicit-omissions)
  and a byte-identical export from an earlier schema 1.0 workspace.
- [x] Validate [SQLite index error handling](cli.md#envelopes-errors-and-explicit-omissions)
  for corrupt data, missing schema, and a lock held by another connection.
- [x] Validate [saved image and snapshot identity](cli.md#envelopes-errors-and-explicit-omissions)
  before opening stored work. Eight corrupt-workspace queries returned
  typed errors. Five archived exports matched, and both owned architectures
  completed full headless analysis and fresh decompilation.
- [x] Verify [project status](cli.md#project-and-job-status) for current,
  partial, stale and unavailable analyses. Owned arm64 and x86_64 jobs
  verified function counts and recorded versions. Archived timeouts and a
  nine-image control verified failure reporting and the snapshot limit.
- [x] Verify [per-job write confinement](cli.md#limits-and-safety-boundaries)
  with owned canaries and eight installed full-headless scopes. A
  worker could not modify an earlier Program or the shared index.
  Live import, analysis, and fresh-query restarts each used a new
  job-specific policy and replayed their receipts.
- [x] Verify the [deep analysis profile](cli.md#deep-analysis-profile) with
  installed full Ghidra 12.2 on owned arm64 and x86_64 fixtures. Deep
  added three byte-checked data references per architecture, preserved
  unresolved jump coverage, and reproduced each export on repeat.
  Fresh reads verified the saved profile, switching back reproduced
  baseline, and a cancelled arm64 job restarted and replayed its receipt.
- [x] Verify [string encoding, bytes, and references](cli.md#string-evidence)
  on owned arm64 and x86_64 slices of one universal binary. ASCII, UTF-8
  and UTF-16LE results matched the original bytes, file offsets, and
  reference sites. Invalid encodings stayed unknown, redacted text had
  no byte payload, and repeat exports were identical. Older snapshots
  still returned their saved text.
- [x] Verify [private HTML export](cli.md#private-html-export) from four
  owned full-headless snapshots, including arm64, x86_64 and partial
  analyses. Report evidence matched the corresponding JSON, output
  files were owner-only, and repeat exports were identical. Annotation
  history required explicit selection and markup stayed literal text.
- [x] Verify [Mach-O symbol declarations and indirect slots](cli.md#mach-o-symbol-declarations-and-indirect-slots)
  against Apple and LLVM tools on four owned arm64 and x86_64 slices.
  All 28 declarations and 18 slots matched, including universal offsets
  and legacy lazy pointers. File queries worked before analysis and
  reproduced their results after full headless analysis.
- [x] Verify [compact unwind ranges](cli.md#compact-unwind-lookup-ranges)
  on seven owned arm64 and x86_64 variants. All 1,261 ranges matched LLVM,
  including regular and compressed pages, LSDA entries, personality slots
  and two pages of common encodings. Apple `dwarfdump` confirmed the
  mixed fixture's FDE offset. The C++ queries reproduced after full
  headless analysis.
- [x] Verify [DWARF call frame records](cli.md#dwarf-call-frame-records)
  against Apple `dwarfdump` on owned arm64 and x86_64 inputs. Four CIEs,
  five FDEs, 57 instructions and their declared locations matched.
  The universal slices reproduced the same queries after full headless
  analysis. CFA expressions are retained as bytes and unsupported
  instruction formats have explicit coverage.
- [x] Verify [explicit terminal views](cli.md#terminal-view) on saved owned
  arm64 and x86_64 analysis and a fresh arm64 hinted query. Pseudocode,
  assembly, graph and byte views matched the saved evidence. Partial
  ranges, unresolved targets, cursors and private output kept their
  existing semantics, and default exports matched the archived JSON.
- [x] Protect [selected inputs and managed project files](cli.md#implemented-commands)
  from explicit report output. The installed CLI rejected 19 conflicts
  after validating both owned architectures through full headless Ghidra.
  Input and project hashes matched, and separate reports supported private
  creation and explicit replacement.
- [x] Bind [atomic output publication](cli.md#implemented-commands) to the
  opened directory. The installed CLI detected early and late directory
  swaps after full headless analysis of both owned architectures, preserved
  all 163 workspace files and reported the late publication explicitly.
- [x] Stream [JSONL serialization](cli.md#implemented-commands) to stdout
  and atomic output files. Ten outputs matched the previous installed CLI
  byte for byte on owned arm64 and x86_64 slices. Synthetic 32 MiB results
  exercised bounded serialization, and an interrupted write preserved the
  existing destination.
- [x] Enforce [a separate headless startup deadline](cli.md#limits-and-safety-boundaries).
  Six owned arm64 and x86_64 import, analysis and fresh queries recorded
  readiness. Controlled delays distinguished startup from total timeouts,
  preserved committed state, and verified a successful exact-limit replay.
- [x] Measure [decompiler initialization and individual calls](benchmark.md#bridge-190-timing).
  The 20-round owned calculator benchmark verified 60 worker manifests,
  40 open intervals and 740 calls. Installed arm64 and x86_64 repeat
  analyses reproduced the normalized exports with timings kept private.
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
