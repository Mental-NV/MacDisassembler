# Selected class-slot ivars (F2 slice)

Specification, 11 November 2026. This slice adds `objc ivars --class-slot SLOT`.
SLOT is an aligned file-backed entry in exactly one `__objc_classlist` or
`__objc_nlclslist` section, never a class-object address. It selects only that
class's declared instance ivars; inherited, category and metaclass members and
runtime-resolved layouts are excluded. No native worker or execution is needed.

## Bounds and identity

Use the same verified slice, mapping and pointer-resolution proofs as selected
methods: 1,024 distinct pointer slots, 1,024 chained-page queries, 65,536 cached
fixups, and at most 10,000 ivar records. Existing Mach-O parser byte/string caps
remain unchanged. Budget exhaustion preserves independently valid rows and is
partial, not absence. No fallback to global declaration inventory is permitted.
The existing envelope schema is unchanged. Additive row evidence is available
for ivars. Pagination identity binds image ID (including content identity),
project, action, exact class slot, filtering and type-decoding policy. Static
queries re-verify source identity; existing export preserves their rows.

## Offset evidence

`declared_offset_bytes` is the signed nonnegative 32-bit initial value read from
file-backed offset storage, including legitimate zero. `offset_storage_va` is
the location of that value, not the offset itself. New `offset_pointer_va` is
the metadata pointer's slot; `offset_evidence` describes either the exact
file-backed four-byte value, or the missing evidence. Missing, external,
negative, ambiguous or truncated values remain null and mark coverage partial.
An anonymous bitfield with no offset pointer remains explicitly anonymous.
This is never a claim about final runtime layout, inferred machine loads or
persisted state. Valid names/type rows survive an unavailable offset.

## Acceptance

Test zero and positive offsets, missing/truncated/ambiguous storage, external
pointer resolution, negative offsets, unrelated class exclusion, class-object
rejection, row/pointer budget exhaustion, CLI selection and stale cursors.
Exercise independently authored metadata on arm64 and x86_64. A native
instruction-oracle check belongs to the separate import-disassembly slice.

## Verification checkpoint

Cloud validation: 641 primary tests and 115 analysis tests passed. Eight new
regressions cover both architecture headers, zero/positive/negative/missing/
external offsets, ambiguous storage, truncated list tails, declared-only scope,
class-object rejection, budgets, deterministic static replay and cursor/export
identity. Independent review found and resolved whole-list validation discarding
valid prefix rows. A maximum uint32 declared count is bounded by the 10,000-row
budget; no allocation proportional to that count is performed. This checkpoint
is static metadata validation, not a native instruction-oracle claim.
