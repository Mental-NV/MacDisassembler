# Scoped investigation improvement plan

Reconciled 10 November 2026 against main commit `6bc177d2312f31a5448c0a02b9b007f13c9e21fd`.

Stage A implementation and source validation are now recorded separately in
[scoped-discovery-validation.md](scoped-discovery-validation.md). The baseline
reconciliation below is historical; installed execution parity remains deferred.

The Stage C owned resource-first workflow is documented in
[resource-first-calendar-workflow.md](resource-first-calendar-workflow.md), with
its separate [validation record](resource-first-calendar-validation.md).

## Purpose

Make bounded metadata discovery and selected-function investigation useful when a large image exceeds general inventory limits. Preserve useful partial results without converting missing evidence into absence, resolved runtime dispatch, or whole-function semantic equivalence.

This document distinguishes implemented foundations from remaining acceptance work. An existing test or implementation is not a claim that every acceptance gate below has passed.

## Scope and sequence

Complete one reviewable stage at a time:

1. **A, P0:** Scoped class discovery, explicit work limits, actionable diagnostics, and production-cap validation.
2. **B, P1:** Per-function unresolved-flow evidence and durable replay.
3. **C, P1:** Resource-first owned hidden-row investigation without whole-image analysis.
4. **D, P2:** Repeated focused-query measurements and an optimization recommendation.

Direct implementation is permitted. Review each stage’s actual diff and validation before proceeding to the next.

Linux enablement and installed CLI changes are deferred. Do not resume unrelated development, introduce a selected-address batch command, change trust/isolation policy, or analyze a third-party application for these stages.

Keep committed material project-owned: source, tests, documentation, and concise owned-fixture validation summaries. Generated binaries, engine projects, recovered output, private paths, and raw logs remain outside Git.

## Reconciliation with main

### A: Implemented foundation, incomplete acceptance

Relevant files:

- `src/macscope/objc.py`
- `src/macscope/dyld.py`
- `src/macscope/cli.py`
- `tests/test_objc.py`
- `tests/test_dyld.py`

Current metadata inventories use validated scoped chained-page resolution. The page cache preserves requested-slot failures and revalidates each slot’s segment mapping before cache reuse.

Current bounds include 2,048 class-list slots, 65,536 inventory pointer sites, 1,024 page lookups, and 65,536 cached fixup rows. These are not equivalent to the planned shared discovery ceiling of 8,192 unique pointer sites and 262,144 cumulative decoded chain nodes. Cache occupancy is not cumulative traversal work.

`test_class_discovery_after_ten_thousand_unrelated_fixups` already generates 10,001 preceding fixups, confirms the unmodified general inventory stops at 10,000, and verifies successful class/method/selector helper queries. It does not establish both-architecture filtered public CLI behavior or independent Apple-tool agreement.

`classes()` still maps every `ValueError` to `invalid_class_record`. The ObjC CLI passes coverage reasons but no diagnostic messages. These are the principal implementation gaps.

### B: Stronger flow safety, incomplete gap contract

Main includes:

- Raw instruction/CFG review before native optimization.
- Bounded byte-proven ordinary ARM64 tail-call recovery in a disposable Program.
- Separate byte-proven ARM64 BRK evidence.
- Native out-of-body operation checks.
- Partial results for unresolved transfers and selected-body escapes.
- Focused v2 receipt safety checks and immutable v1 replay behavior.
- Owned positive and adversarial focused-flow fixtures.

Reuse these capabilities. Do not replace them with presentation-based warning suppression.

The general `control_flow_gaps` contract still lacks consistent exact-site or explicit unavailable-site evidence and verified linkage/internal/unclassified categories. Existing tests do not establish every B1–B5 gate.

### C: Existing workflow is not the new regression

The owned Calendar fixture and integration already validate selected resource wiring, metadata, declared linkage, private handoffs, and some offline replay.

The current integration builds arm64, runs whole-image analysis, and lacks the planned load-time hide and conditional state-change behavior. It does not satisfy the new no-whole-analysis, dual-architecture focused workflow.

### D: Existing timing infrastructure is reusable

The benchmark records command wall time, worker time, observed startup, decompiler `openProgram`, and `decompileFunction` timing.

Its current workload uses analyzed snapshots and fresh queries. It does not measure five selected import entries plus their offline receipt replay. Decompiler `openProgram` timing must not be relabeled as opening the Ghidra project/database.

## Stage A: Complete scoped discovery and diagnostics

### A implementation contract

Preserve the current literal name filter, deterministic ordering, image/architecture selection, pagination contract, and public envelope/row shapes.

Class-name discovery covers declarations in the selected class lists. It does not cover categories, inherited methods, other images, or runtime-generated classes.

Reuse validated scoped chained-page resolution. Never reinterpret an unresolved chained encoding as an ordinary address.

For class discovery, enforce one shared query budget:

- At most 2,048 visited class-list slots.
- At most 8,192 unique selected pointer sites.
- At most 262,144 decoded fixup nodes cumulatively.

The 10,000-record general inventory limit and 1,024-site selected-method limit remain unchanged. Do not globally reduce unrelated method/property/selector budgets merely to implement class discovery.

Count actual resolution work, including failed decoding and repeated traversal after cache eviction. A verified cache hit performs no new chain decoding. Charge work before exceeding a ceiling, not after decoding a whole page.

Retain existing bounded cache and mapping protections. Any additional smaller internal limit must be explicit in diagnostics and documentation.

Internally distinguish:

- Incomplete relocation evidence.
- Exhausted discovery work.
- Unsupported pointer or metadata layout.
- Demonstrably malformed metadata or mapping.

Keep established reason codes where applicable. `invalid_class_record` must not be added merely because decoding was prevented by an evidence or budget failure.

Class records retain name, class VA, metadata VA, class-list slot, and image/architecture provenance. Missing optional superclass evidence must not discard an independently verified class name.

Preserve `data` as a list and `diagnostics` as strings. Report work counters, reached limits, and affected scope through the existing diagnostic channel and stable coverage reasons. Do not introduce an incompatible response wrapper.

For partial class queries:

- Preserve verified matches.
- Keep `known_total` unknown.
- Explain that an empty result does not prove absence.
- Explain that pagination only pages captured rows and cannot bypass exhausted discovery.
- When a real class-list slot is known, suggest `objc methods --class-slot` with that slot and label its class/metaclass-declaration scope.
- Otherwise describe the manual same-image procedure: pin binary hash and architecture, inspect `otool -arch ARCH -ov` or `xcrun dyld_info -arch ARCH -objc`, then verify selected slot and entry addresses.
- Never fabricate a slot or substitute a class-object address.
- Never launch Apple tools automatically.

Complete legacy metadata must remain correct. Legacy discovery beyond its inventory cap is outside this stage and remains explicitly partial.

### A acceptance

**A1: Production-cap discovery**

Retain the existing 10,001-prefix synthetic regression. Add an owned fixture/integration that exercises filtered public CLI class discovery on chained arm64 and x86_64 without patching production limits.

Verify that selected class/name pointer sites really follow more than 10,000 fixups. Independently confirm class and method entry evidence with Apple tooling.

A helper-only test, CPU-header change alone, or patched cap is insufficient to establish this integration gate.

**A2: Honest absence**

Test:

- Complete visited scope with no matching name.
- Empty partial scope with unavailable candidates.
- Exhausted discovery budget.
- A valid match plus an unresolved candidate.

Only complete visited scopes may report a known filtered total.

**A3: Fail closed**

Cover misaligned or non-file-backed class slots, ambiguous mappings, corrupt pointers, unsupported encodings, and external binds. Preserve current cached-page mapping and failure-retention regressions.

No missing evidence may produce a fabricated local target or method.

**A4: Bounded work**

Instrument and assert slot, unique-pointer, and actual decoded-node counts. Cover:

- Many requested sites on one page.
- Repeated class entries.
- Cache eviction and re-decoding.
- Failed page decoding.
- A late matching class.
- Exhaustion before and after a valid match.

Preserve completed rows and report the precise exhausted scope.

**A5: CLI continuity**

Verify deterministic ordering, page replay, stale or changed-filter cursor rejection, image/architecture ambiguity errors, text/JSON diagnostics, and existing legacy/chained class-slot behavior.

Metadata queries must not start Java, request trust, mutate project files, or invoke Apple tooling.

**A6: Useful next action**

Exercise zero-partial, some-partial, and true-zero public CLI output. Confirm that users can distinguish absence from incomplete discovery and select the correct existing next step.

**A7: Compatibility and package evidence**

Run the full unit suite and relevant metadata regressions. Check source/package content parity.

Installed-wheel execution parity remains a distinct original acceptance gate. While installation is deferred, mark that gate deferred rather than passed. Do not replace or upgrade the user’s installed command.

### First implementation slice

Expected changes:

- `src/macscope/objc.py`
- Necessary budget plumbing in `src/macscope/dyld.py`
- ObjC diagnostic handling in `src/macscope/cli.py`
- Focused additions to `tests/test_objc.py` and `tests/test_dyld.py`
- Owned fixture generation/integration for A1
- Corresponding CLI and status documentation

Begin with cumulative discovery accounting and differentiated diagnostic causes, preserving existing page-cache hardening. Then add public CLI acceptance cases and the dual-architecture Apple-tool oracle.

Do not claim A complete until the acceptance matrix distinguishes passed, failed, blocked, and deliberately deferred checks.

## Stage B: Actionable unresolved-flow evidence

Extend `control_flow_gaps`; do not rewrite pseudocode or relax partial policy.

For each gap, retain:

- Stable reason and raw source evidence.
- Exact instruction/edge site when independently available.
- Otherwise, the smallest evidenced block range.
- An explicit reason when a precise site is unavailable.
- Selected function identity and verified instruction bytes.

Never derive an exact site solely from a warning string.

Classify gaps as verified linkage/wrapper boundary, unresolved internal transfer, or unclassified. Verification requires instruction evidence plus relevant stub, relocation, or selector evidence. Names and plausible pseudocode are insufficient.

Selector evidence does not prove a unique runtime callee. Classification does not determine relevance to a business question; the analyst records that separately.

Preserve PR #3’s source/target proofs, original/effective flow, strict raw-CFG checks, BRK evidence, native-scope checks, and v1/v2 replay semantics.

### B acceptance

- **B1:** Owned wrapper-plus-handler case demonstrates a supported local effect while retaining an unresolved linkage/dispatch gap with supporting sites and bytes.
- **B2:** Unresolved internal transfers remain partial; unavailable sites and unknown categories stay explicit.
- **B3:** Capture, cached query, receipt replay, and JSON/HTML handoff preserve gap evidence and raw warnings. Old receipts replay without invented fields. Malformed new fields fail through production receipt validation.
- **B4:** Wrapper-like names alone never produce verified-linkage classification. Selector-only evidence never asserts a unique callee.
- **B5:** Validate actual focused `--from-import` output, source-byte checks, trust denial, timeout/cancellation, partial exits, and deterministic exports.

Review the additive field and validation contract before implementing this stage.

## Stage C: Resource-first owned end-to-end regression

Document and exercise:

1. Consult saved captures/receipts first.
2. Select compiled nib connections.
3. Resolve class/pointer evidence.
4. Verify exact linker entry.
5. Run selected import query without whole-image analysis.
6. Corroborate with instructions and same-slice selector/ivar evidence.
7. Produce a pinned private evidence handoff.

Use an existing parent directory and a new private project, with explicit image and architecture throughout. Carry each step’s coverage forward.

Extend the independently authored owned Calendar fixture with a control/row, load-time hide call, and state-change handler that updates configuration only when state differs. Retain a wrapper or indirect call that exercises unresolved evidence.

### C acceptance

- **C1:** Compiled nib wiring agrees with the owned XIB/ibtool output. Wiring alone makes no visibility or handler-behavior claim.
- **C2:** Exact selected functions expose the hide call and state comparison in independently checked instructions without whole-image autoanalysis. Unresolved wrappers/transfers remain visible.
- **C3:** Handoff separates facts, bounded inferences, and unknowns. It does not claim the row can never appear, a reachable UI path exists, or persistence/geometry is established. Any owned runtime oracle is separate from static conclusions.
- **C4:** With the original app absent and Ghidra unavailable, saved resources and focused receipts reproduce normalized private JSON/HTML handoffs with pinned hashes and source/Program identities.

Run arm64 and x86_64 independently or record the specific blocker for each. One architecture does not stand in for the other.

## Stage D: Measure before proposing batch optimization

Produce measurements and a recommendation, not a persistent worker or new batch implementation.

### D acceptance

- **D1:** Measure five exact owned linker entries as five separate focused queries on the same verified import, plus replay of their receipts. Use at least five repetitions for exploratory median/range and at least 20 before reporting p95 or a performance gate.
- **D2:** Separate command wall time, observed startup, Program/database opening, decompiler `openProgram`, per-function decompilation, and export/publication where measurable. Mark unavailable measurements unmeasured, not zero. Do not sum overlapping intervals. Keep timing outside normalized evidence.
- **D3:** Assess whether repeated launch/open cost is material and compare with offline replay. Replay is not fresh analysis. Existing analyzed-query benchmarks are context, not the new workload’s result.
- **D4:** If justified, write a separate bounded selected-address batch specification covering CLI/schema, entry/count/byte limits, per-function receipts, trust per invocation, timeouts, failures, cancellation, partial publication, and resume identities. Review that specification before coding.

Record source/input hashes, dependency and bridge versions, host details, limits, status counts, and individual samples.

## Validation and delivery

Each stage returns:

- Changed files and reviewed diff.
- Acceptance-ID result matrix.
- Exact commands.
- Tested source identity.
- Private log/artifact locations.
- Remaining limitations and deferred gates.

Minimum combined source check:

    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v

Run affected analysis tests and integration checks according to their actual argument contracts. Stages B and C require live focused receipts and replay; mocked unit tests alone cannot satisfy them.

For bridge/engine changes, include relevant receipt, resume, identity, isolation, cancellation, and source/package regressions. Never mark an unrun check passed.

Only summarize completed validation in current-status documentation. Commit reviewed project-owned work at useful boundaries under the current repository authorization. Do not include private corpus material or treat installation, Linux enablement, or batch implementation as implicit follow-on work.
