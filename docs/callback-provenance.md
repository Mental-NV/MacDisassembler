# F3c: explicit ABI-conditional frame and receiver provenance

Status: implementation contract, not runtime behavior or persistence recovery.
Policy 6 adds [explicit invocation path obligations](split-invocation-obligations.md)
for composition; default conditional-branch barriers remain.
Policy 5 additionally supports [shifted-register ADD](register-add-evidence.md).
Policy 4 additionally supports [bounded SP pair writeback](callback-stack-pairs.md).

`--callback-evidence --callback-provenance` enables symbolic selected-input
register tracking without a callee-preservation hypothesis; direct calls still
stop. This supports a no-call context-load/thunk/store path purely from bytes.
`--callback-evidence --callback-abi aapcs64` additionally opts into the conditional
register-provenance model. Default strict mode keeps unknown instructions/calls
as barriers. ABI mode is an explicitly declared hypothesis, not a recovered
compiler identity or proof an arbitrary callee obeys AAPCS64. arm64e/PAC,
exceptions, nonreturning calls and nonconforming callees are unsupported.

Each initial register is a symbolic input to the selected range, scoped to its
selection identity/start. It is not a function parameter or object type unless
separate evidence establishes that. SP is an unknown absolute stack base with
an optional bounded relative delta. Track 64-bit ADD/SUB immediate, unshifted
MOV register, and MOVZ immediate (32-bit writes zero-extend); byte-decoded
arithmetic retains precise address/stack values where possible, otherwise a
compact symbolic arithmetic origin. Stack deltas must remain within 4096 bytes.
No stack store forwarding or alias analysis is introduced. Loads remain
unresolved memory-read values, even when a preceding store looks related.

For direct BL only, report the exact byte target, then optionally continue at
the next instruction under explicit assumptions that the callee returns
normally, preserves SP and x19..x29, and may overwrite x0..x18/x30 and arbitrary
memory. Each subsequent observation carries the preceding call condition sites.
Indirect calls, conditional branches, flags-dependent arithmetic, unsupported
frame operations and instruction forms still stop interpretation. Numeric
external call targets are never assigned names or effects from suggestive
pseudocode or disassembler labels. Maximum 1024 instructions/4096 bytes unchanged; at most 32 conditional direct-call
continuations. A 33rd call is recorded but cannot extend the interpretation.

A direct-transfer observation retains selected input-register correspondence
(x0..x7,x19..x29 only) before a call clobbers values. When the F3b destination
receipt/linker entry verifies, its memory-store locations/values may be related
to those input registers. Report these as conditional register-to-store
relations, preserving destination load origins, unknowns, offsets, lane indices,
source/destination identities and all assumptions. A relation does not establish
that a stored callback is invoked, an unknown base is a particular object, a
closure capture layout is fixed, or application data is persisted.

The graph remains inconclusive about dynamic callback identity and writer
attribution. A verified memory-writing instruction and conditional input-value
relation are useful distinct evidence, not overall success. Without either opt-in, existing F3a/F3b barriers and unknown values remain the
conservative default. Register-only mode retains call barriers and does not
assert that a particular Swift ABI or context layout is identified.

## Acceptance

Owned compiler oracle setter contains a frame prologue, copy of incoming value
to x19, a direct runtime call, then STR x19,[x20,#16]. ABI mode must retain that
conditional store relation; strict mode must stop at the prologue. Caller-saved
values and memory contents must not survive BL. Unknown/resilient context stays
unknown. Contrasting no-call owned writer fixture should demonstrate byte-proven
store evidence without a call-preservation assumption. Test source selection
scope, unsupported instructions, stack bounds, 32-bit overwrites, forged flags,
normal-return conditions and deterministic immutable receipt replay.

Each store base/value correspondence explicitly declares `matched_input_register`
with source-transfer scope, or `not_correlated` with destination scope. A
destination-local load or unmapped input is never renamed source evidence; any
unmatched operand makes the relation `partial_register_correspondence`. Stack
observations remain distinct from unattributed non-stack memory.


## Owned compiler validation paths

Apple Swift 6.4 arm64 optimized pointer-callback fixture supplies a no-call
three-instruction thunk: copy incoming x0 to x1, load x0 from [x20+16], then
branch directly to the exact linker writer entry. That writer stores x1 through
x0 and returns. Independent `llvm-objdump`, its function-start view, and `nm`
verify the bytes and entries. Register-only mode proves the symbolic relation:
selected input x0 is written through the pointer loaded from selected input
x20+16. It does not identify the live context object, guarantee a callback is
invoked, or attribute persisted application state. No ABI call hypothesis is
needed for this selected path.

The separate owned class setter includes a runtime call. ABI mode preserves
the incoming value copied to x19 and incoming x20 receiver symbol through that
call only conditionally, marks the later store with its normal-return condition,
and invalidates all modeled caller-saved registers. Strict mode still stops at
the prologue. These are distinct positive/conditional cases, not equivalent
levels of evidence. No inspected binary was executed.

## Validation checkpoint and readiness distinction

- 705 primary tests and 115 analysis tests passed.
- 52 focused callback/provenance/link/import tests independently passed review.
- Built wheel exposes both opt-ins through its installed CLI.
- `tests/integration_callback_receipts.py` passes using that installed package
  outside the checkout: two replay invocations produce identical JSON, with
  nonexistent Ghidra/JDK paths, no new jobs and unchanged receipt files.
- Native owned Swift compiler oracles verify the no-call pointer path and the
  conditional class-setter path. Inspected binaries were not executed. F3 adds
  no native worker operation; these checks do not claim a new Ghidra capture run.

The supported static writer-path check is positive: a selected callback thunk
loads a pointer from its incoming context, transfers the incoming value and
branches to a linker-verified writer that stores through that pointer. The
unknown indirect-target and unsupported/conditional alternatives remain
inconclusive. This is useful for a scoped practical investigation, not a claim
of unrestricted Swift callback recovery or complete application persistence
analysis. Confirming a real application's receiver, invocation path or visible
behavior may still require additional static evidence or authorized UI checks.
