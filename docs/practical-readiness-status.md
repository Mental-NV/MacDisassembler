# Practical readiness: merged capabilities and remaining gates

Snapshot: main `7e221748a77622f589b307dfd2f6cbe3adc9bd4a`, through PR36.
This is a generic product-status ledger. It contains no private evaluation
artifacts and does not claim that pending proposals, all original requirements,
or whole-application behavior are complete.

## What is implemented

Full Ghidra headless remains the importer/analyzer/decompiler. The original
[specification](specification.md) promises address-linked pseudocode and evidence,
not original source or arbitrary semantic equivalence. The recent work improves
bounded investigation around that foundation; it does not replace Ghidra.

F1–F5 foundations and acceptance references are reconciled in the
[follow-up plan](scoped-investigation-followup-plan.md). In particular, compact-only
handoff, field-level ivar diagnostics, destination-effect classification,
shifted-register ADD, split-load invocation obligations and the macOS test-path
fix are implemented. Their specific limits and validation scopes remain binding.

| Merged checkpoint | Available capability | What it does not establish |
| --- | --- | --- |
| PR30 | [Explicit writer-call obligations](writer-call-obligations.md) on four-role composition; actual owned native positive receipt chain | Callee purity, runtime invocation identity, matching live receivers or persistence |
| PR31 | [Native positive/counterexample gate](native-callback-negative-gate.md), including wrong-address and unresolved-input assignments | Broad Swift coverage or a recovered runtime callback |
| PR32 | [Bounded callback text summary](callback-text-summary.md), distinct from byte-decoding completion | Changed analysis decisions, complete evidence in the truncated summary |
| PR33 | [Assignment diagnostics](assignment-diagnostics.md) with scoped structural reasons and counts | Automatic selection of another code target or proof that an address-valued store is a callback |
| PR34 | [Selected adjacent checked-add guard](checked-add-guard.md), explicit opt-in | General NZCV/branch analysis, unsupported encodings or analysis of the taken path |
| PR35 | [Explicit three-receipt/two-hop view](pinned-twohop-thunks.md), destination guard opt-in, preserved derived-effect conditions | Proven outer complete extent, four-role integration or transitive register substitution |
| PR36 | [Scoped computed writer operands](computed-writer-obligations.md), explicit two-hop writer-call opt-in | Computed pointers/base attribution, recovered runtime values or application meaning |

## Validation: keep the evidence classes separate

- **Latest cloud checkpoint:** 856 primary tests and 115 analysis tests passed for
  PR36's candidate; its independently reviewed publication used this product
  scope. These are not counts from a newly executed full macOS suite.
- **Latest installed-wheel native-receipt replay:** the two-hop route was replayed
  with guard and writer proof independently off/on, twice in text and JSON
  (16 invocations). The prior native composition and selected checked-add gates
  also passed. Engine/JDK paths were unavailable and jobs/receipts stayed unchanged.
- **Actual native capture:** the owned compiler artifact's selected ranges were
  independently checked with native instruction/linker metadata and captured as
  bounded import-disassembly receipts. Offline replay is of those actual receipts,
  not a replacement synthetic instruction stream. It does not execute the input.
- **Earlier full native Mac checkpoint:** F5c recorded 764 primary and 115 analysis
  tests on macOS 27.0.1 / Python 3.14.6 after reproducing baseline path failures.
  That closes the test-path regression, not latest-main Mac compatibility.
- **Presentation measurements:** compact handoff's owned 12-lead fixture measured
  3,843 bytes / 67 lines. This is an output-size benchmark, not engine speed or
  a real application's completeness measurement.
- **Not established here:** current remote CI success, fresh whole-image analysis,
  a new consumer session, latest system CLI installation, general performance,
  or newly verified arbitrary-platform compatibility.

The native four-role positive is a **conditional static candidate**. The native
alternative route independently verifies two entry links and relates a computed
store operand under guard/call hypotheses. It remains separate from four-role
assignment/invocation composition. Wrong-address and unknown-input controls stay
inconclusive for evidenced reasons, not because the decoder failed vacuously.

## Gates that remain open

1. **Alternative-route integration:** define a sound outer-source scope proof and
   explicit register/value relations before joining the two-hop route to
   assignment/invocation composition. Preserve all path, call and memory-identity
   obligations; no automatic inference from matching offsets or register names.
2. **Application attribution:** mapped or unresolved stores and successful entry
   links are not evidence of a live application-state writer. Runtime execution,
   receiver identity, callee effects and persistence remain unknown in these views.
3. **Consumer usefulness:** the latest increments have owned native validation but
   no new scoped consumer trial. Do not restart an agent or install the CLI merely
   because this status lists that gate; obtain the relevant authorization first.
4. **Current native compatibility and measurements:** repeat the full Mac suite
   and fresh-versus-replay measurements when that task is authorized and relevant.
   Keep native capture, host regression tests, replay and consumer feedback distinct.
5. **Original broader roadmap:** foundational commands and prior owned validation
   do not close every quality, packaging, compatibility or release target in the
   original specification. Unsupported instruction/ABI patterns, arbitrary dispatch
   and broader reconstruction remain explicit limits rather than silent promises.

Future work should target a demonstrated missing capability with a small owned
reproducer. Keep specification, implementation, independent review, installed
validation and precise acceptance records together; report a blocker and continue
independent authorized work instead of weakening a gate.
