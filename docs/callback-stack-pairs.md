# F4a: bounded ARM64 stack pair writeback

Status: implementation contract; static evidence only.

Extend callback policy to version 4 with one small additional instruction family:
64-bit integer STP/LDP pre-index and post-index **SP-based** forms, only with
explicit `--callback-abi aapcs64`. Strict and register-only modes retain their
existing barriers. Non-SP writeback, SIMD, 32-bit pairs, zero-register lanes,
duplicate load destinations, pointer authentication and all other unsupported
forms remain barriers. No flags, branches or runtime identity are inferred.

Decode signed imm7 scaled by eight from instruction bytes. For pre-index,
observe both memory lanes relative to the pre-instruction SP plus that offset;
for post-index, observe lanes at pre-instruction SP and SP+8. Apply writeback
only after capturing both locations and both pre-instruction store operands.
Loads always become unresolved memory reads, never forwarded saved values.
Each lane includes `addressing_mode` and a `writeback` record with register,
delta, before and after symbolic SP values. Subsequent observations use updated
SP. Existing offset-pair output remains unchanged except the policy version.

Reject a writeback taking relative SP outside [-4096, 4096] before emitting any
lanes or changing state. Preserve all previously verified prefix observations;
record the exact unprocessed instruction and `stack_delta_budget` reason.
Selection start, receipt digest and previous normal-return call assumptions
remain attached through existing provenance. A decoded stack save does not
prove function entry, ABI conformity, a closure layout or a runtime writer.

## Acceptance

- Independently verify owned compiler-generated pre-index save and post-index
  restore bytes against a native disassembler; do not execute the fixture.
- Cover both load/store directions and pre/post modes, positive/negative/zero
  offsets, cumulative bounds, pre-state store operands and unresolved loads.
- Ensure strict/register-only and unsupported forms stop without extra lanes.
- Replay is deterministic and input immutable; run full primary and analysis
  suites and installed-package smoke. Keep instruction/call budgets unchanged.
- Report native fixture blockers explicitly; do not replace a missing native
  oracle with a claim based only on hand-encoded words.

Exact decode: `(word & 0xffc00000)` must be `0xa9800000` (STP pre),
`0xa9c00000` (LDP pre), `0xa8800000` (STP post), or `0xa8c00000`
(LDP post). Rn bits 9..5 must equal 31 (SP); Rt bits 4..0 and Rt2 bits
14..10 must not equal 31. Imm7 bits 21..15 is signed then scaled by 8.
Each lane is 8 bytes. These instructions do not modify condition flags.
Non-SP overlap encodings never enter the supported family. Duplicate load
registers are rejected before producing observations; duplicate stores are
valid and retain both lanes. No 32-bit extension behavior is added by this slice.

## Validation checkpoint

- Independent review passed: 46 focused tests, 480 legacy offset-pair differential
  cases unchanged except policy version, and 124 unsupported non-SP variants
  retain their barrier.
- Primary suite: 713 tests passed. Analysis suite: 115 tests passed.
- Built-wheel CLI replay passed from outside the checkout using nonexistent
  Ghidra/JDK paths: the existing writer-path receipts and a separate owned stack
  prologue receipt each replay identically, with no new jobs or receipt changes.
- Native oracle reverified the existing owned `OwnedPointerCallback.swift`
  library compiled using Apple Swift 6.4, optimized arm64. `llvm-objdump` and
  independent Mach-O byte extraction agree: `f44fbea9` is
  `stp x20, x19, [sp, #-32]!`; `f44fc2a8` is
  `ldp x20, x19, [sp], #32`. The compiler's adjacent offset pair and frame-pointer
  ADD also agree with the supported prologue. No inspected binary was executed.

This slice changes Python receipt projection only; the native disassembly
worker is unchanged. The oracle above is revalidation of an existing owned
compiler artifact, not a new compiler build or native Ghidra capture. Tests
concatenate selected prologue/epilogue words only to test state propagation;
that synthetic sequence does not assert transparency of an omitted real body.
Non-SP indexed pairs and broader callback arithmetic remain deferred F4a work.
