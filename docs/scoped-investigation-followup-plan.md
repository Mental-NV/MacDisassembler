# Scoped investigation follow-up plan

Status: reconciled through main `83b6bdf5057367d08551397f41bfa979b2a76a13`.
F1–F3 historical requirements are retained below. F4 checkpoints are merged,
but bounded implementation is not completion of the practical readiness gate.
New F5 acceptance items below are planned, not implemented or verified.

## Current reconciliation

F1 trust compatibility/partial-result handling, F2 selected class-slot ivars,
and bounded import disassembly remain working foundations. F3 supports bounded
callback observations, one-hop direct-destination links and conditional register
provenance. Preserve receipt identity, explicit unknowns and engine-free replay.

The following F4 slices are implemented:
- **F4a:** bounded ARM64 stack-pair writeback evidence, not general instruction
  coverage. Unsupported instructions remain barriers.
- **F4b:** [four-role callback composition](callback-composition.md), with facts,
  assumptions, unknowns and conditional register bindings kept separate. The
  complete positive chain is validated with owned synthetic receipts. Existing
  native Swift assignment/thunk fragments are verified; the native split-load,
  conditional-branch/intervening-call invocation chain remains **uncomposed**.
- **F4c:** [bounded ivar diagnostics](ivar-diagnostics.md) identify record-level
  failures, unknown locations and missing offsets without discarding valid rows.
  Field-specific rejection detail remains incomplete.
- **F4d:** [per-lead summaries](per-lead-summary.md) add a bounded header to text
  evidence, but still append the detailed tree. This is not a compact-only view.

The integrated tree passed 744 primary tests, 115 analysis tests and installed-
wheel synthetic receipt replay outside the checkout, without new engine jobs or
receipt mutation. These checks do not establish whole-chain native coverage,
application-state writer attribution, runtime behavior or general performance.
No remote CI success or fresh native capture is claimed by this reconciliation.

## Next priorities: F5 acceptance plan

Implement small reviewed slices in the order below. Write each slice's numeric
bounds, compatibility policy and owned fixtures before coding. Private evaluation
artifacts stay outside this plan; the requirements below are generic product
work, not a publication of application-specific findings.

### F5a — Destination versus attributed writer (P0)

A linked destination is not automatically an application-state writer. Separate
verified destination identity, observed stores, stack/frame stores, unresolved
store destinations and attributable non-stack effects. Preserve existing raw
facts and receipt identities. Do not infer attribution from a name, an offset,
a direct link, successful decoding or the mere presence of a store. Persistence
and runtime execution remain unknown even with an attributable store.

Acceptance: owned destinations with only stack spills, no stores, unknown bases,
and an explicitly evidenced non-stack store. Stack-only and unknown-base cases
must not be summarized as an application writer. Raw stores remain accessible.
Any change to existing field names/status semantics requires a reviewed version
or additive compatibility contract; do not silently rename the writer role.

### F5b — Compact-only multi-lead handoff (P0)

Specify an opt-in compact-only presentation that does not append the full tree.
Keep current detailed text, JSON, receipts and exit codes unchanged. Include
lead identity/status, highest-priority blockers, explicit omitted counts and a
supported route to full evidence; do not invent paths or commands. Truncate
before terminal escaping and enforce a documented total output budget as well
as per-field/per-lead caps.

Acceptance: an owned 12-lead fixture with deliberately large nested evidence
renders at most 200 lines and 32 KiB in compact mode, without dropping partial
status or hiding that material was omitted. Test oversize labels, controls,
missing reasons/sites and larger lead counts. Detail/JSON must retain all data;
partial evidence still exits 6. Offline replay is deterministic and creates no
jobs. Measure detailed and compact sizes on owned fixtures, not private reports.

### F5c — macOS test-path portability gate (P0, independent)

Canonicalize temporary fixture directory identities where the OS resolves a
temporary-directory alias to a different absolute path. Compare canonical paths
in tests when path identity, rather than user spelling, is the contract. Do not
weaken traversal, symlink, output protection or receipt-identity checks globally.

Acceptance: relevant terminal/output tests pass on macOS with both aliased and
canonical temporary paths; retain genuine mismatch/security negative tests.
Run the full primary suite on macOS and record toolchain/platform separately.
A Linux-only pass cannot close this gate. A missing Mac blocks this acceptance
item, not independent specification or implementation work.

### F5d — Bounded register-offset ADD (P1)

Inventory required ARM64 register-offset ADD forms from owned compiler output.
Specify exact encodings, width, extension/shift, SP/ZR behavior, overflow and
register clobbering. Reject unsupported flag-setting/extended forms rather than
approximating them. Symbolic base-plus-offset observations must not become alias,
object-layout or runtime-address proofs.

Acceptance: independent instruction-oracle agreement; positive supported forms,
near-miss encodings, 32/64-bit widths, extension/shift boundaries, wraparound and
unknown operands. Unsupported forms remain explicit barriers. Demonstrate the
newly supported prefix on an owned compiler artifact with exact byte evidence.

### F5e — Split loads and conditional-call obligations (P1)

Start from the explicit native-oracle gap in F4b. Specify separate target/context
load provenance, conditional-path coverage and intervening-call clobbering before
extending composition. Set finite path/hop/instruction budgets. Keep every branch
condition, ABI hypothesis and memory-identity obligation visible; do not remove
intervening instructions or treat callee-saved guesses as unconditional facts.

Acceptance: owned supported split-load paths and negatives for overwritten slots,
clobbered context/target, unknown call effects, divergent branches, cycles and
budget exhaustion. A claimed full native positive must use a contiguous,
independently verified compiler artifact and preserved receipts. Until that
passes, report synthetic positive coverage and native unresolved coverage
separately. Runtime target identity, application attribution and persistence are
not discharged by matching offsets or a structurally composed path.

### F5f — Field-level ivar rejection diagnostics (P1)

Extend F4c with stable field-level reason codes and verified field sites (or
explicit unknown): name pointer/string, type pointer/encoding, alignment, record
mapping and offset storage/value. Preserve legacy aggregate gaps, valid prefix
rows, null-versus-zero offsets, deterministic order, cap/omission totals and
separate filtering. Avoid emitting unbounded or untrusted string contents.

Acceptance: independently corrupt each field in an owned multi-record fixture;
assert the exact failing field/code and mapping confidence while later valid
records survive where supported. Cover external/unmapped/ambiguous pointers,
invalid alignment, truncation, field/record budget exhaustion and output caps.
No invalid-record diagnostic may invent a verified field address.

## Execution and completion rules

For each F5 slice: specification review, implementation, independent review,
full primary and relevant analysis tests, installed-package smoke, and precise
passed/blocked/deferred acceptance records. Use immutable offline replay with
engine access disabled where applicable; distinguish rendering replay from an
end-to-end pinned-receipt analysis trial. Re-run integration after combining
slices. If blocked, record the reason and continue an independent task.

After the current scoped improvements, run an owned native positive and a
negative practical-readiness session, then a separately authorized scoped
consumer trial. Record feedback without publishing private artifacts. Do not
call the final goal complete until the native path and attribution obligations
required by that goal are met; useful partial tooling remains explicitly partial.


This follow-up sets the next priorities after the historical
[scoped investigation plan](scoped-investigation-plan.md). Keep its A–D
acceptance records; do not reopen completed foundation work or interpret its
historical installation deferral as the current priority. Consult the separate
[discovery](scoped-discovery-validation.md),
[flow evidence](flow-gap-evidence-validation.md),
[resource workflow](resource-first-calendar-validation.md) and
[benchmark](focused-import-benchmark.md) validation records for actual coverage.

## Goal and constraints

Make selected-function investigation practical: discover the declaration,
inspect a bounded body, follow evidenced callback links, identify what is
still missing, and replay a useful handoff without repeating engine work.
Existing discovery, receipt replay and readable metadata are foundations to
retain, not substitutes for proving a callback's eventual effect.

Keep public fixtures, reports and examples independently authored. Do not
commit third-party binaries, recovered code, application-specific observations,
private paths, addresses or raw trial artifacts. This plan intentionally records
product requirements rather than publishing a private investigation transcript.

Do not broaden into whole-image analysis, general source recovery, runtime
execution of inspected inputs, Linux-first work or continuous installation
maintenance. The selected-address batch implementation remains deferred under
its [separate proposal](bounded-focused-batch-proposal.md); a lifecycle blocker
there must not block these independent improvements.

## Historical F1–F3 implementation requirements

### F1 — Trust compatibility and partial-result usability (P0)

Baseline CLI exposes `--experimental-trusted-input`; it does not provide the
intended `--trust-input` alias or interactive trust confirmation. Its engine
error still refers to user-owned fixtures. Reconcile the installed command,
source, help, examples and tests before asking users to repeat a workflow.

Specify and implement one shared trust decision: explicitly confirmed trusted
inputs need not be user-authored. Provide `--trust-input` as the clear public
option and preserve the old spelling as a compatibility alias. Without either,
interactive invocations may ask for affirmative confirmation before native
processing; refusal, EOF and non-interactive execution fail closed. No silent
persistent trust, implicit authorization from filenames, or relaxation of
isolation, identity, resource limits and timeout handling. Static metadata and
receipt-only replay must not acquire unnecessary trust prompts.

Explain job execution, individual evidence links and overall graph coverage
separately. A completed worker or verified link does not prove a complete
investigation. Exit 6 with `lead_evidence_incomplete` must preserve useful partial
artifacts and explicitly identify missing evidence; it is not an engine crash.
Do not suppress this exit or turn a partial graph into success for convenience.

Acceptance F1:
- Parser/help and installed-package smoke tests cover both flag spellings and
  every native operation affected, including resume and native demangling.
- Owned fixture tests cover affirmative/negative input, EOF, non-TTY execution,
  replay without engine access, and denial before native work begins.
- Text/JSON/export tests distinguish complete, partial-with-artifact, failed,
  timed-out and cancelled jobs. Existing exit and schema compatibility remains
  intact; additions must have an explicit version/compatibility contract.

### F2 — Bounded disassembly and exact class-slot ivars (P1)

Remove avoidable detours from an imported image to an external debugger when
only a selected wrapper's instructions are needed. Design a bounded import-based
disassembly operation; do not claim existing analyzed-only disassembly already
supports it. Select exact verified image, architecture, address and byte bounds,
retain instruction bytes/provenance, and report undecodable or unavailable ranges.
Never fall back silently to whole-image analysis or execute the input.

Add selected class-list-slot ivar lookup analogous to selected methods. Keep
recorded ivar offsets distinct from offset-slot addresses, runtime-resolved
layouts and inferred loads. Missing offsets remain unknown, not zero; emit the
exact missing evidence needed to continue. Preserve independently valid rows.

Acceptance F2:
- Owned arm64 and x86_64 wrapper fixtures agree with an independent instruction
  oracle without whole-image autoanalysis; malformed/ambiguous mappings,
  truncation, unsupported instructions and byte limits remain explicit.
- Selected ivar tests cover valid offsets including zero, unavailable offset
  storage, corrupt/external pointers, inherited vs declared scope, and bounded
  work. A class object address is not accepted as a class-list slot.
- Bind new options to cache/replay identity. Capture, offline replay and exports
  agree; stale identities fail. Define numeric budgets and schemas in a reviewed
  slice specification before implementation rather than guessing here.

### F3 — Swift callback assignment-to-effect evidence (P1)

Use F2 to investigate a small owned callback fixture. Represent assignment,
capture/context access, invocation and eventual writer as separate evidenced
edges. Support only explicitly described compiler/ABI patterns; do not infer a
unique target from a name, plausible pseudocode or an Objective-C declaration.
Unknown context, resilient layout, indirect targets and missing writer evidence
remain gaps. A successful assignment/invocation link alone must not answer where
state is persisted or establish runtime UI behavior.

Acceptance F3:
- Owned source oracle includes two possible callbacks, captured and uncaptured
  contexts, an overwritten callback and an unresolved indirect target.
- For each supported architecture/compiler combination, independently verify
  instruction sites, bytes and layout assumptions. Record unsupported cases.
- Negative fixtures prevent inventing targets/effects. Graph completion is
  based on declared evidence requirements, not worker success or edge count.
- Saved receipts and handoffs preserve verified links, bounded inferences,
  unknowns and source identities without Ghidra or the original app present.

## Delivery and practical readiness gate

Implement and review one slice at a time. Update its specification before code,
add independently authored regression fixtures, and report passed, failed,
blocked and deferred acceptance IDs separately. If blocked, record the reason
and continue an independent slice without silently weakening its gate.

For each code slice run the full primary suite, relevant analysis/receipt tests
and the required live owned-fixture checks. Package smoke tests must exercise
the actual entry point, not only a source checkout. Measure fresh and replay
latency separately; replay must be deterministic and create no new engine job.
Do not convert a single short trial into a general performance claim.

Practical readiness requires an owned end-to-end session that reaches a verified
state writer through a supported callback path and a negative session that
correctly remains inconclusive. Private real-world evaluations may corroborate
usefulness separately, but are neither public fixtures nor proof of unsupported
runtime behavior. Keep speculative type application and batch optimization
outside this gate. Review existing pending PRs independently; this plan does
not mark them merged or validated.
