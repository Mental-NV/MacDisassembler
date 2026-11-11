# F5a: linked destinations and observed effects

Additive contract, policy `macscope-destination-effects/1`. Preserve all existing
link statuses, raw stores, `store_relations`, `storage_role`, `writer_attribution`
and the historical composition role/key called `writer`/`writer_stores`.
Those legacy names mean observations at a selected destination, not attributed
application-state writers. New `destination_effects` on a saved direct link is
the canonical classification view. It is also copied into composition beside
legacy writer observations; it never upgrades composition to runtime proof.

Separate `destination_identity` (verified direct entry or unverified) from
`observed_stores`. Each store has its instruction identity, lane, source receipt,
base evidence/scope, call conditions and one classification:
- `stack_or_frame`: explicit SP-relative/unknown-SP base, including a frame
  register copied from SP or source-transfer SP evidence. Register name x29 alone
  is not frame evidence.
- `mapped_image_nonstack`: an address derived from instruction address facts
  resolves the full eight-byte store to exactly one writable, non-executable,
  file-backed section and nonoverlapping segment in the verified Mach-O bytes.
  This attributes a static effect to an image range only, not a named application
  field. Retain the image VA, file offset, mapping identity and conditions.
- `unresolved_destination`: unknown input/load/arithmetic/clobbered base,
  literal integer without address provenance, out-of-range/overflow, ambiguous,
  non-writable/executable, zero-fill or unavailable mapping evidence.

No heap-object, application-field, runtime address or persistence attribution is
introduced. Matching offsets, section/function names and writable mappings do
not establish application semantics. `application_writer_attribution`,
`runtime_execution` and `persistence` remain `unknown` in every case.

Bounds: at most 2048 observed store lanes from the existing 1024-instruction
projection. Mapping uses at most 4096 sections and 4096 segments; beyond this,
retain stores with explicit mapping-budget reasons. No target traversal or
native job occurs. All classifications concern the interpreted selected prefix,
not all reachable instructions. `no_observed_stores` means no stores in that
prefix, never a proof of effect freedom. Stack-only and unresolved-only summaries
must not describe the destination as an application writer.

Acceptance: owned no-store, stack/frame-only, unknown-base and explicit mapped
image-store destinations; positive source-to-destination stack correspondence;
read-only, executable, overlapping, boundary-crossing and overflow negatives.
Preserve legacy output and immutable deterministic offline receipt replay with
missing engine/JDK. Tests use owned fixtures only. A native application-semantic
claim is out of scope.

## Validation checkpoint

- 755 primary and 115 analysis tests passed in the cloud environment.
- Independent review passed 43 focused destination/link/composition tests.
- The same 43 tests passed using the built installed package outside its checkout.
- Packaged multi-receipt replay is deterministic with Ghidra/JDK unavailable and
  unchanged job files/receipts. A context-loaded pointer remains unresolved;
  successful direct linking does not upgrade it to an application writer.
- Owned Mach-O fixtures cover unique image data, stack/frame and source-transfer
  stack provenance, unknown bases, absent stores, literal addresses, overflow,
  read-only/executable mappings, duplicate sections, zero-fill shadows, section
  boundaries and explicit mapping/store budgets. These are synthetic fixtures,
  not native application-runtime validation.

The effect view includes both receipt-envelope identities and destination
selection. Source-transfer bases remain explicitly scoped; per-store ABI and
call hypotheses are retained. If a store cap omits observations, the summary is
`partial_store_classification` with a count, not a claim of absent stores.
