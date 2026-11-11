# Owned native negative controls: protocol

Spec first, after the [focused feasibility assessment](focused-parameter-assessment.md).
This is non-shipping analysis tooling only. No public CLI, receipt, automatic
recovery, user binary capture, application execution or Taskovsky session.

## Fixed scope and isolation

Use only the previously frozen positive owned Swift binary and the unchanged
caller/callee extent proofs. Each control has a separate fresh no-analysis Program
copy and JVM, on a private full clone of the original import-only project.
Retain the existing trust/dependency checks, pinned inputs, sandbox renderer,
launch gate, limits, cancellation and complete process teardown. Original imports
and earlier evidence remain unchanged. No permission expansion, cache cleanup,
source-supplied signature or synthetic analyzed snapshot is permitted.

These controls have their own experimental result contract. Never create a normal
query receipt, ordinary inference assessment or recovered pseudocode. An expected
negative must be distinguished from operational failure, an unrelated exception,
missing output, and native success. Validate all reported identities and preserved
pins before accepting the control result.

## Native preparation-proof refusal

In a fresh unprepared copy, call the unchanged native preparation script with a
controlled, deliberately mismatched expected extent digest. Keep actual bytes,
extents, input identity and all other arguments valid. Require the exact digest
mismatch refusal before disassembly/transaction work, with no preparation success
report. Compare selected listing/function inventory and bytes before/after.

This exercises native preparation-proof rejection of an injected mismatch. It is
**not** an observation of naturally unsupported instructions, decompiler escape,
or a comprehensive mutation audit. Do not loosen any verifier or report arbitrary
script failure as a passing negative. If the script runner swallows the exception
or does not expose its precise cause, stop and use a reviewed alternative rather
than infer refusal from absent files alone.

## Native preparation transaction rollback

Add a third, separate control with correct image/extent digests and a deliberately
invalid, canonically hashed tail proof: its fixed candidate targets an address
inside the selected caller extent. The unchanged script must reject with the
exact `Invalid tail-call source or destination` message after disassembly, inside
its explicit preparation transaction. Require no success report and exact
restoration of the selected instructions, functions, bodies, signatures and bytes.
Preserve a pre-control snapshot; do not accept merely unchanged object counts.

This exercises an injected proof rejection and its preparation rollback, not a
naturally unsupported decoder case. A generic exception or incomplete rollback
is a failed control. Never weaken the production proof selector or verifier to
manufacture this case. The injection exists solely in the owned control script.

## Injected AST scope-check refusal

In a separate prepared-only copy, run the unchanged exact body preparation and
positive scope checks. Obtain a real callee HighFunction without parameter
recovery or committing signatures. Require its positive native scope check.
Insert one dead synthetic p-code operation at the callee's end-exclusive address
using the pinned Ghidra public syntax-tree API. Then call the unchanged native
scope guard and require its exact outside-pinned-extent exception.

Prove the synthetic operation is in the scanned bank and that no successful scope
check was appended for the rejected graph. Recheck Program bytes and bodies.
No synthetic graph may subsequently reach decompilation, parameter/signature
commit, a bridge export or pseudocode publication. End and discard the JVM.
An explicit commit-denying override provides a further accidental-call guard.

Label this **injected AST checker-negative control**, not an actual out-of-body
result produced by the native decompiler. It tests the real Java guard's rejection
path but cannot establish that all native escapes or unsupported ABIs are detected.

## Review and acceptance

Review the design before implementation, and the implementation before native
launch. Unit tests must reject wrong control identity, generic failure, missing or
mismatched proofs, unexpected inference/commit, and malformed reports. Native
success means the intended exact refusal occurred under preserved isolation;
otherwise retain failure artifacts and stop the affected control. Repeat each
successful control once with a new Program/JVM to check local repeatability.

Afterward, assess a separately versioned, explicitly selected opt-in product
contract with immutable caller/callee evidence and replay validation. These
controls alone do not authorize shipment or prove runtime/source correctness.
