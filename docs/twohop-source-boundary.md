# Independently bounded two-hop source

Spec first. The owned two-hop route's outer instruction now has an independently
validated terminal linker boundary, but its two-hop view still unconditionally
says that source extent is unproved. Expose that byte fact without silently joining
assignment/invocation evidence or substituting registers across either edge.

Pinned two-hop policy 2 adds `source_extent_evidence`. Recompute focused policy 4
from the verified image, require exact equality of the selected start/end and
entire payload with the one direct-B site, complete selected disassembly and a
verified first destination entry link. Bind the proof to the selected source
receipt digest and require the decoded target equals the pinned inner start.
Distinguish `next_linker_start` from `terminal_linker_branch` basis. A prefix of a
larger linker extent is not a whole source proof. Failed, partial, malformed,
non-entry, padded or unsupported shapes retain selected-bytes-only status with
a scoped reason. Do not replace successful independent edges with a global failure
merely because this extra source proof is unavailable.

Only a successful exact proof changes `source_extent` to
`verified_complete_selected_thunk`. Existing statuses, independent link decisions,
role identities, effects, path/call assumptions and runtime unknowns remain. The
new field is a derived view, not a rewritten receipt, native query or claim of
execution, callee purity, source-language function recovery, live receiver
identity or persistence. No changes to one-hop links, four-role composition,
focused policy 1/2/3 replay or default disassembly.

Acceptance: owned native three-receipt immutable offline replay with exact source
boundary; guard and writer-call flags off/on retain their distinct outcomes;
synthetic ordinary exact linker source, proper prefix, terminal and padded source,
wrong pinned target, incomplete instruction evidence and altered word controls.
Text must show bounded source status and basis. Existing native replay gates and
full cloud suites must remain passing. No input execution, install or agent restart.

## Validation

The actual owned optimized ARM64 three-receipt route now exposes the complete
0xd78:0xd7c source extent, word `8effff17` (B 0xbb0), with terminal-section basis
and independently bounded target. It retains independent 0xbb0-to-0xa90 linking;
this is not a new transitive register proof. The source receipt remains pinned to
SHA-256 `7072540be2e0e395a7efe5a3ee23c5e6470f54233d36b28550f0b363a82499ff`.
The existing actual-native gate checks source identity, exact bytes/extent/basis,
role identities, destination guard and call conditions, and all four combinations
of guard/writer proof flags in text and JSON twice. Saved receipts stay unchanged.

887 primary and 115 analysis tests passed in the cloud. Independent review passed
60 targeted tests and the actual owned three-receipt replay gate. An installed
isolated wheel replayed that gate plus the previous native positive/counterexample
and terminal-focused pseudocode gates without engine/JDK availability. This is
replay of previously captured native receipts, not a new native engine capture or
new full Mac suite. No inspected input was executed, no system CLI was installed,
and no consumer agent restarted. Runtime identity and persistence remain unknown.
