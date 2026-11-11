# Scoped investigation follow-up plan

Status: proposed implementation sequence, 11 November 2026. Baseline: main
`b69b85feb048a9ec5c8e18f167b1b446287253c1`. This is a requirements document,
not a claim that the improvements below are implemented or validated.

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

## Ordered implementation slices

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
