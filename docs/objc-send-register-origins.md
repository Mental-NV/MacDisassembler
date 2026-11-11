# Selected message-send register origins

Spec-first bounded addition to `evidence --objc-sends`. The owned ARM64
forward/discard fixture has `MOV x0,x2; B selector_stub`. The selector path alone
does not show that the dispatched receiver register carries the selected entry's
x2 value. Expose that static relation without changing decompiler code or
injecting a signature.

A nested `macscope-send-register-origins/1` record is additive to selector-context
policy 1. Only a verified selector path qualifies. Independently verify a
contiguous prefix from the exact saved selected entry to that transfer, at most
32 preceding instructions. All prefix bytes must match the mapped executable
input section. Support only unshifted 64-bit MOV (ORR Xd,XZR,Xm) and NOP. Any
other instruction, missing/duplicate/out-of-order address, byte mismatch, or
limit makes the entire origin record unavailable. Do not jump across a call,
load, branch, stack operation or unsupported clobber. No partial suffix proof.

Initialize entry x0–x30 as symbolic values and xzr as zero. Apply supported moves
in order; writes to xzr are discarded. Report x0's entry origin and raw x2–x7
register origins at the selector stub transfer. The proven stub replaces x1
with its selector value and x16 with the dispatch pointer, leaving the reported
registers unchanged. The enclosing receipt digest and image/Program pins must
accompany this nested record; it is not standalone evidence. These are register
values, not a declaration of argument count or parameter types. All expressions
are conditional on execution along the selected entry prefix. Entry-register
values, receiver object/class, dynamic target, return behavior and effects remain
unknown. A copied entry register is not an alias/identity proof about live objects.

Retain original partial query status and graph gaps. Default non-opt-in exports,
raw pseudocode and receipts remain unchanged. Summary shows only receiver x0
origin or unavailable reason, leaving full register facts in JSON.

Acceptance: native owned forward/discard agreement, instruction mutations and
clobber/barrier negatives, zero/self/transitive moves, limits and malformed
prefixes, exact installed replay without engine and unchanged portable files;
full primary and analysis tests and independent review. No input execution,
system installation or Taskovsky session.

## Validation checkpoint

Independent design and implementation review found no blocker. The exact MOV
mask excludes 32-bit, shifted, inverted and non-ZR-first-operand near misses;
unit tests cover barriers, address/byte mismatches, move chains, overwritten
origins, ZR and the 32-instruction limit.

The installed wheel replayed the four existing actual owned native receipts
without an engine. Selected entries `0x6f8`, `0x700` and `0x724` each independently
retain `e00302aa` (MOV x0,x2) before their verified send, yielding entry x2 as the
conditional receiver-register origin. Entry `0x708` begins with unsupported
stack handling and remains unavailable, even though its selector path is valid.
Forward/discard have the same register relation: this does not distinguish their
return contracts. Repeated JSON exports were byte-identical and all portable
project file hashes stayed unchanged. The integration script requires supplied
owned artifacts and is not a substitute for native capture.

No fresh native engine, app execution, current full-Mac-suite pass, system CLI
installation or consumer session is claimed. This slice improves interpretation
of existing captured bytes; it does not add general argument reconstruction.
