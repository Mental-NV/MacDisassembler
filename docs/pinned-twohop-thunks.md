# Explicitly pinned two-hop thunk evidence

Spec first. The owned alternative callback has two one-instruction ARM64 thunks,
`0xd78 -> 0xbb0 -> 0xa90`. A single selected destination link stops at the second
thunk. Add a bounded independently verified two-hop view, not recursive discovery
or four-role callback composition.

`disasm --from-import --receipt OUTER --range START:END --callback-evidence
--callback-via-receipt INNER --callback-target-receipt DESTINATION` requests the
view. All three receipts must be explicit and distinct. Each source/inner receipt
must contain exactly one contiguous four-byte unconditional ARM64 B instruction.
BL, indirect transfers, extra prefix instructions, incomplete decoding and reused
selections are gaps. Each destination must begin at an independently verified
linker entry with a following start; both selected destinations fit their extents.
The outer receipt establishes selected instruction bytes only: a last linker
function lacking a following start does not acquire a synthetic extent proof.

Each receipt remains limited to 4096 bytes/1024 instructions. Exactly two edges
are evaluated. No target discovery, extra native jobs or automatic fallback.
Identity-invalid receipts fail closed; unsupported edges retain their reasons.
Reject source/inner/final overlaps and final direct calls/branches back into any
selected source or intermediate range or its own verified linker extent. Keep
independent observations on failure; do not silently manufacture transitive
register correspondence, callback identity, aliases or execution order.

Optional `--callback-destination-checked-add-fallthrough` enables the existing
adjacent overflow-guard policy only for the destination. Require explicit
provenance or AAPCS64. Ordinary target projection remains unchanged by default.
The source-only guard option and assignment/invocation composition are rejected
with this two-hop mode. Every destination store keeps scoped branch/call
conditions and symbolic operands. Derived store relations and destination-effect
rows also carry source/destination branch-condition sites. Both link/effect views
include scoped path-obligation lookup tables, so the guard is not lost in a
summary classification. These fields are additive and empty for unguarded views. A complete pair of direct entry links does
not prove destination coverage: report its prefix stop/gaps separately, and keep
application writer attribution, runtime execution and persistence unknown.

Add `two_hop_chain` under callback evidence with policy
`macscope-pinned-twohop/1`, overall status inconclusive, link status, role identity
pins, two independent link reports, structural gaps and final destination effects.
No global source-to-writer value substitution is performed. Existing one-hop
field semantics, exit codes and receipts remain unchanged; path-condition fields
are additive. Text shows bounded chain status,
structural gaps, final prefix stop, final guard/call hypotheses and unknown effects;
it remains within the callback-summary 64-line/16-KiB budget.

Acceptance: actual owned three receipts with/without destination guard; exact
edge instructions/identities, preserved conditional store, cycles/reentry,
wrong targets/interior destinations, BL/multi-instruction prefixes, stale receipts,
strict default barriers and deterministic immutable engine-free installed replay.

## Native validation checkpoint

Existing owned `OwnedCallbacks` artifact: Apple Swift 6.4 arm64 `-O`, binary SHA
`5cd6f86bce7b918a44ce97f0990c8a8c11ec69e5ffb6cdfe92a13e69d5e1423f`.
Native instruction and linker metadata independently confirm:

| Role | Selected range | Byte/extent evidence | Receipt SHA-256 |
| --- | --- | --- | --- |
| Outer | 0xd78:0xd7c | `8effff17`, B 0xbb0; last linker start, no following start | 7072540be2e0e395a7efe5a3ee23c5e6470f54233d36b28550f0b363a82499ff |
| Inner | 0xbb0:0xbb4 | `b8ffff17`, B 0xa90; next linker start 0xbb4 | b358096611b42ac8093f3666c9acd38a657a4c83cb6b785328cffdca5b5ea29c |
| Destination | 0xa90:0xad4 | next linker start 0xad4; contiguous checked-add guard/call/store | d267f18e52531dce3ce6dd73fd0dafa44b0cae74d967ba1089e2612880e98224 |

849 primary tests and 115 analysis tests passed. Independent review reran 42
focused tests and the actual native gate. An installed wheel outside the checkout
replayed the route twice in text and JSON, with and without the destination guard
(eight CLI invocations), without engine dependencies or receipt/job mutations.
The prior native three-case composition and selected checked-add gates also passed.

Both independent entry links verify; without the guard option the destination
still stops before ADDS. With the option, the store at 0xabc remains conditional
on branch 0xaa4 and call 0xab8 in raw evidence, store relations and classified
destination effects. Scoped guard lookups retain the unverified no-overflow
predicate. Four stack/frame stores and one unresolved-base store are reported;
none is upgraded to an attributed application writer. The outer extent remains
explicitly unproven despite independent knowledge of the executable section end.

This does not compose an assignment/invocation chain, substitute registers through
both hops, prove runtime behavior or validate consumer usefulness. No inspected
application was executed, system CLI installed, or whole-image analysis performed.
