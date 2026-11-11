# F3c: explicit ABI-conditional frame and receiver provenance

Status: implementation contract, not runtime behavior or persistence recovery.

`--callback-evidence --callback-abi aapcs64` opts into policy3's conditional
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
compact symbolic arithmetic origin. Stack deltas must remain within4096 bytes.
No stack store forwarding or alias analysis is introduced. Loads remain
unresolved memory-read values, even when a preceding store looks related.

For direct BL only, report the exact byte target, then optionally continue at
the next instruction under explicit assumptions that the callee returns
normally, preserves SP and x19..x29, and may overwrite x0..x18/x30 and arbitrary
memory. Each subsequent observation carries the preceding call condition sites.
Indirect calls, conditional branches, flags-dependent arithmetic, unsupported
frame operations and instruction forms still stop interpretation. Numeric
external call targets are never assigned names or effects from suggestive
pseudocode or disassembler labels. Maximum1024 instructions/4096 bytes unchanged.

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
relation are useful distinct evidence, not overall success. Without ABI mode,
existing F3a/F3b barriers and unknown values remain the conservative default.

## Acceptance

Owned compiler oracle setter contains a frame prologue, copy of incoming value
to x19, a direct runtime call, then STR x19,[x20,#16]. ABI mode must retain that
conditional store relation; strict mode must stop at the prologue. Caller-saved
values and memory contents must not survive BL. Unknown/resilient context stays
unknown. Contrasting no-call owned writer fixture should demonstrate byte-proven
store evidence without a call-preservation assumption. Test source selection
scope, unsupported instructions, stack bounds,32-bit overwrites, forged flags,
normal-return conditions and deterministic immutable receipt replay.
