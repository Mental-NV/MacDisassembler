# F5d: bounded ARM64 ADD shifted-register evidence

Spec-first callback policy 5. With `--callback-provenance` or explicit
`--callback-abi aapcs64`, recognize non-flag-setting ADD shifted register only:
`(word & 0x7f200000) == 0x0b000000`. Sf bit31 selects 32/64 bits; Rm bits20..16,
Rn bits9..5 and Rd bits4..0. Shift bits23..22 select LSL=0, LSR=1 or ASR=2;
3 is reserved. Imm6 bits15..10 is 0..31 for W or 0..63 for X. Reject W shifts
32..63 before any observation/write. ADDS, SUB/SUBS, extended-register ADD and
other near-misses retain unsupported barriers. No flags or SP updates occur.
Register31 means ZR for **all** operands in this form; writes to it are discarded.

Operands are read before writing Rd, including overlapping registers. Truncate
both operands to operation width; shift Rm in that width (ASR sign-extends its
sign bit), then add modulo 2^width. W writes zero-extend to X. If both operands
are numerically evidenced, retain the exact result. Only a 64-bit address-valued
Rn plus an integer/ZR Rm preserves address provenance; all other concrete results
are integer values. Width truncation or shifting a pointer never preserves its
address provenance. These are static arithmetic observations, not runtime-address
or object-layout/alias proofs.

Unresolved operands produce `register_add_result` with selection/receipt identity,
origin instruction and width, not recursively nested expressions. A separate
`register_add` site retains the two input values, shift, result and discarded-
write indicator. Subsequent arithmetic refers to that compact result identity.
No algebraic alias simplification, memory forwarding or frame-relative offset
propagation is added for symbolic operands. Existing 1024-instruction/4096-byte
and conditional-call budgets apply; at most one new site per instruction.
Unknown/call-clobbered inputs remain unknown arithmetic, not restored registers.
Strict mode keeps the old unsupported-instruction barrier.

Compatibility: additive site/value kinds under versioned callback policy 5;
receipt bytes/schema, earlier site kinds and default strict semantics unchanged.
Consumers must not treat arbitrary numeric arithmetic results as function targets
or application fields. Existing direct transfer/link/composition obligations stay.

Acceptance: exact instruction oracle from owned Swift compiler output; X/W,
LSL/LSR/ASR limits, reserved shifts, ZR and overlap, truncation/zero-extension,
wraparound, unknown inputs, bounded long chains, near-miss flag/extended forms,
strict-mode barrier and deterministic immutable saved-receipt replay. Distinguish
compiler prefix coverage from whole-function or runtime behavior.

## Native owned compiler oracle

Apple Swift 6.4 (`swiftlang-6.4.0.34.1`, clang 2100.3.34.1), arm64 macOS,
`xcrun swiftc -emit-library -O`, independently disassembled with native tools.
The checked-in sources reproduce the two independently compiled modules;
function-start metadata and file-mapped bytes confirm these ADD;RET prefixes:

| Owned module | Entry | Bytes | Instruction |
| --- | --- | --- | --- |
| OwnedArithmetic | 0x398 | 2000008b | ADD x0,x1,x0 |
| OwnedArithmetic | 0x3a0 | 000c018b | ADD x0,x0,x1,LSL #3 |
| OwnedArithmetic | 0x3a8 | 000c418b | ADD x0,x0,x1,LSR #3 |
| OwnedArithmetic | 0x3b0 | 000c818b | ADD x0,x0,x1,ASR #3 |
| OwnedArithmetic | 0x3b8 | 2000000b | ADD w0,w1,w0 |
| OwnedArithmetic | 0x3c0 | 000c010b | ADD w0,w0,w1,LSL #3 |
| OwnedRight32 | 0x390 | 000c410b | ADD w0,w0,w1,LSR #3 |
| OwnedRight32 | 0x398 | 000c810b | ADD w0,w0,w1,ASR #3 |

Each prefix is immediately followed by RET `c0035fd6`. The pointer-offset source
aliases the same optimized shifted ADD at 0x3a0; that compiler alias does not
establish arbitrary application pointer/object identities. Negative native
prefixes remain barriers: 0x3c8 `0040218b` (ADD x0,x0,w1,UXTW) and 0x3d0
`000001ab` (ADDS x0,x0,x1, followed by overflow branch). The oracle compiled and
inspected owned binaries; it did not execute them or perform a Ghidra capture.
Tests retain exact native bytes separately from constructed arithmetic cases.

## Validation checkpoint

758 primary and 115 analysis tests passed in the cloud environment. Independent
review passed 70 focused arithmetic/callback tests. Built-wheel replay outside
the checkout passes with Ghidra/JDK unavailable: arithmetic and existing
multi-role receipts replay identically without new jobs or receipt changes.
The native checks above establish exact compiler-generated instruction prefixes,
not unrestricted Swift coverage, runtime equivalence or application semantics.
