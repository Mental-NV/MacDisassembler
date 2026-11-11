# Explicit two-thunk register forwarding

Spec first. The owned alternative callback route has two exact ARM64 B-only
thunks. Its source boundary and both entry links are now verified, but the view
still offers no correspondence from the outer entry inputs to the final writer
entry inputs. A bounded forwarding proof can close that static gap without
inventing runtime callback identity or substituting into destination facts.

Two-hop policy 3 adds `register_forwarding`, a separately versioned view. Require
no chain gaps, independently complete exact four-byte source extents for both
outer and inner thunks, and the existing two verified pinned entry links. Both
instructions must decode as B to the corresponding pinned next entry. Reject
prefix-only inner extents, missing boundaries, altered bytes/targets, BL, branches
with side effects, overlap/cycles and incomplete disassembly. No automatic target
discovery, recursive traversal, additional instruction interpretation or ABI
hypothesis is introduced. This slice handles exactly two B instructions.

Success means the tracked general-purpose input registers x0-x7 and x19-x29 are
unchanged along these two instruction edges. Expose explicit scoped outer-input
to final-destination-input bindings, each bearing both source receipt identities,
selection starts and register, with both proven edge sites and intermediate
identity shared in the enclosing forwarding view. Do not infer register
names/types at source-language level or values at runtime. No SP, flags, x18,
SIMD or hidden ABI-state claim. ABI assumptions about calls inside the destination
remain separate and are neither discharged nor added to this instruction fact.

`register_forwarding` status is `verified_static_register_forwarding` or `gap`
with scoped reasons. On success remove only the prior unknown
`transitive_register_correspondence_not_applied`; replace it with
`forwarded_inputs_not_substituted_into_destination_facts`. All destination effects,
writer proofs, path/call obligations, runtime identity and persistence unknowns
remain unchanged. Overall status remains inconclusive. Failed forwarding does
not erase independent source/edge evidence. Text states static forwarding status
and destination entry, not successful execution or composed callback recovery.

Acceptance: actual owned three-receipt replay with all guard/writer opt-ins,
exact x0 and x20 scope bindings and immutable destination facts; ordinary full
B-thunks positive; longer inner extent, absent source proof, wrong bytes/target,
cycle/gap and unproven first link negative. Full regression suites, installed
wheel replay and independent review. No new native capture, installation or
consumer restart is required for this derived immutable receipt view.

## Validation

Actual owned native receipts prove d78:d7c (B bb0) and bb0:bb4 (B a90).
The existing pinned three-receipt gate now checks 19 scoped register bindings,
including x0 and x20 from outer d78 entry to writer a90 entry, and the exact inner
extent. All four combinations of destination guard/writer-call flags pass in
text and JSON, twice; receipts/jobs remain unchanged. Forwarding remains valid
when destination interpretation stops at its unsupported checked guard, because
it establishes entry-input equality only, not successful destination execution.

892 primary and 115 analysis tests passed in the cloud. Independent review
passed 18 forwarding/route/source and 29 text/computed-writer/writer tests, plus
the actual native replay gate; its two minor presentation/spec corrections were
applied and 14 affected tests rerun. An isolated installed wheel passed the route,
positive/counterexample, and terminal-pseudocode replay gates. Comparing the old
and new installed wheels across all four flag combinations confirms identical
existing JSON evidence, except the declared policy, added forwarding object and
replacement unknown label. No writer facts or conditions were substituted.

These are offline replays of previously captured native evidence, not a new native
capture or full Mac test run. No system installation, input execution, consumer
restart, callback alias inference or persistence claim is part of this change.
