# Scoped investigation follow-up plan

Status: historical F1–F3 requirements retained below; next-step priorities updated
against main `27bcef51b321f6610fb81ad7b56fdae23090f176`.
The original baseline was `b69b85feb048a9ec5c8e18f167b1b446287253c1`.
Pending work is not a claim of implementation or validation.

## Current reconciliation and next priorities

F1 trust compatibility and partial-result handling are implemented; see
[trust and partial results](trust-and-partial-results.md). F2 selected
class-slot ivars are implemented with explicit offset evidence; see the
[selected ivar contract](selected-ivar-contract.md). [Bounded import disassembly](import-disassembly.md)
is available, so obtaining selected instructions no longer inherently requires
whole-image analysis or an external debugger. Preserve those working paths.

F3 now includes bounded callback observations, selected direct-destination
receipt links and opt-in conditional register provenance. See
[callback sites](callback-evidence.md), [selected links](callback-links.md) and
[conditional provenance](callback-provenance.md). These are static evidence
components, not proof that an assigned callback executes, that two unknown
receivers are identical, or that a memory store persists application state.
Do not reopen those foundations or label all original F3 acceptance complete.

The following follow-ups extend the current contracts rather than duplicate
them. Implement in small separately reviewed slices; read the current branch's
contracts before editing because callback support is evolving.

1. **F4a, P1: ARM64 callback instruction coverage.** Inventory the current
   decoder's explicit barriers and select common callback instruction forms
   from independently authored compiler fixtures. Specify exact byte masks,
   widths, flags, register effects and pre/post-index writeback semantics for
   each added form before coding. Do not skip unsupported instructions. Keep
   unsupported, ambiguous, PAC and unknown ABI cases explicit. Acceptance:
   independent instruction-oracle agreement, positive and near-miss encodings,
   zero/sign extension, overlapping registers, stack/frame bounds, clobbering
   and unchanged strict-mode barriers. Extend architecture coverage only when
   its own evidence supports it; no claimed x86 coverage from ARM64 tests.
2. **F4b, P1: Compositional callback-to-writer evidence.** Build on the existing
   one-hop links and register correspondence, not a second graph mechanism.
   Specify a bounded composition contract before expanding hop depth: identities,
   limits, cycle handling, transferred values and accumulated assumptions.
   Keep assignment, context load, invocation, direct destination and memory
   writer as separate claims. A matching offset or plausible function name
   cannot equate receivers or prove runtime callback identity. Acceptance:
   owned positive chains and counterexamples with overwritten callbacks,
   mismatched contexts, intervening clobbers, uncertain loads, cycles and missing
   receipts. Unknowns survive composition and offline replay. A verified store
   remains distinct from attributed application-state mutation or persistence.
3. **F4c, P1: Exact skipped-ivar diagnostics.** Build on existing offset evidence.
   When a selected record cannot produce a row, retain a bounded diagnostic
   identifying its record index/site when verified, reason and missing evidence.
   Distinguish filtering, unsupported layout, pointer failure, invalid record,
   unavailable offset and exhausted budget. Do not fabricate a record address
   when the mapping is unknown. Acceptance: valid prefix rows survive a bad
   record or truncated tail; missing offsets remain null, real zero remains
   zero; no skipped record is silently interpreted as absence. Bound diagnostic
   count and report omitted counts/scope without unbounded allocations.
4. **F4d, P1: Per-lead gaps beside partial-result summaries.** Keep exit 6 and
   existing structured lead evidence. Improve the human-readable summary so
   users can immediately map each incomplete lead to its blocking evidence and
   a supported next action, rather than reading worker success as completion.
   Acceptance: mixed complete/partial/failed leads, absent gap sites, limits and
   terminal-safe rendering; do not suggest nonexistent commands or imply
   verification from successful jobs alone. Retain machine-readable schemas and
   raw reasons; review a versioned contract before any incompatible change.

For each follow-up, preserve receipt identity and deterministic offline replay.
Test a multi-lead saved handoff with the engine unavailable and assert no new
worker jobs; distinguish replay from fresh analysis. Private evaluations are
kept outside this public plan. Their operational usefulness does not establish
full callback identity, application behavior or general performance.


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
