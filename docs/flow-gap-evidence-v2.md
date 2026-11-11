# Stage B: proof-bearing flow-gap evidence

This follow-up builds on PR #5, head
`54565019d66fe568e1923d1f38c1ac8c2f6dd00d`, tree
`aebf97f5b3d4d515fe48480be8f785631c1f7b33`. The complete published tree was
verified before editing. The first-slice contract and its historical validation
are recorded in [flow-gap-evidence-plan.md](flow-gap-evidence-plan.md).

## New focused captures

New captures use `macscope-focused-import/3` and gap evidence policy
`macscope-control-flow-gap-evidence/2`. These versions deliberately distinguish
the new proof interpretation from saved focused v2/evidence v1 receipts.

The request's selected extent contains a bounded
`macscope-flow-gap-classification/1` plan. It is constructed from the saved,
hash-verified Mach-O slice before launching the worker, bound to the producing
request, and recomputed from that slice on public replay and evidence export.
It does not change the Ghidra analysis settings or Java bridge protocol.

All original gap fields, warnings and pseudocode remain intact. The evidence
retains selected function/image/architecture/entry, slice, extent and imported
Program hashes. Exact locations contain verified source bytes and original and
effective flow. Unsupported locations retain an evidenced block range or an
explicit unavailable reason. Warning strings and outside-body native-operation
addresses never become inferred transfer sources.

### Positive classifications

`verified_linkage_boundary` requires a decoded ordinary import-pointer
sequence, a unique strong dyld binding, and matching captured instructions:

- ARM64 `ADRP x16; LDR x16; BR x16`, with exact decoded slot, ordinary
  fallthroughs, one complete supporting CFG block and no incoming interior
  edge.
- x86_64 RIP-relative `FF 25` indirect jump with its exact decoded slot and
  complete supporting capture.

The binding must use an ordinary two-level dependency, a positive matching
library ordinal, zero addends, and a non-weak, unauthenticated declared symbol.
Flat, weak, authenticated, ambiguous and incompletely decoded bindings do not
qualify. No bundled provider or runtime symbol implementation is invented.
The classification explicitly says `runtime_target=unresolved`. A Ghidra
computed edge to a synthetic external address is correlated with the exact
captured source/edge; that address is not relabeled as the decoded pointer
slot or a resolved runtime implementation. Unrelated unresolved transfers
which could enter an ARM64 sequence interior prevent promotion.

`unresolved_internal_transfer` requires an independently decoded direct
non-call branch, safely mapped executable destination bytes in the same slice,
and an exact match between the source instruction, raw gap edge and decoded
target. Supported encodings are ARM64 B/B.cond/CBZ/CBNZ/TBZ/TBNZ and x86_64
relative JMP/Jcc. The target is not automatically called a function or a valid
instruction boundary. A gap for a branch's missing fallthrough is not a proof
about its taken target.

`unclassified` remains the result for unsupported, incomplete, ambiguous or
exhausted evidence. An unknown register jump is not evidence of internal
rather than external dispatch. Wrapper-like names and selector labels do not
participate in positive classification. This implementation does not attempt
selector-based runtime-callee recovery.

The scanner examines at most 8 KiB, 64 candidate sites, 16 binding slots and
128 KiB of serialized plan evidence. Exhaustion discards the partial candidate
prefix and records the reached limit. Byte-pattern scanning does not establish
instruction boundaries; promotion separately requires the captured boundaries.
No whole-image analysis or metadata inventory is introduced.

### Validation and old receipt behavior

Both production publication and receipt reading rederive raw gaps and their
extension. For focused v3, these checks are mandatory even if every new field
or every gap is removed from a modified receipt. Merely recomputing result and
producer hashes cannot bless a fabricated classification.

Completed focused v1/v2 receipts retain their original contents and policy.
Evidence v1 keeps its original unclassified interpretation. An unfinished v2
job resumes using v2, rather than silently adopting v3's new request. The
existing refusal to resume an unsafe unfinished v1 job remains unchanged.
Old receipts are not rewritten, backfilled or reclassified during replay.

## Selected analyzed snapshot and fresh-query views

Analyzed results use a separate policy,
`macscope-analyzed-flow-gap-evidence/1`, rather than claiming focused capture.
The source is a committed snapshot whose identity and selected instruction
bytes can be checked against the saved slice. The extension pins selected
function/image/architecture/entry, slice hash, analysis ID, snapshot hash and
analysis Program hash. It records `derivation=saved_snapshot` or
`fresh_query_with_saved_flow` explicitly.

Cached `functions show`, `decompile`, `cfg` and `disasm` derive this view without
writing the snapshot or starting a worker. Annotations remain separate. The
selected analyzed function in a JSON/HTML evidence handoff uses the same view.
A historical snapshot without durable snapshot/Program pins is left unchanged;
malformed supplied pins or a mismatched saved slice are errors, not excuses to
invent provenance.

A newly published ordinary fresh query borrows its saved instruction/CFG
sources and captures fresh pseudocode/native scope. Boundary gaps are attached
before publication. New ordinary query requests pin `flow_gap_policy`, and the receipt's
`flow_gap_sources` marker identifies its saved raw sources. Production writer/reader
validation rederives expected gaps even if every result extension is removed.
A no-gap result cannot invent gaps or a source marker. It is not presented as
a new instruction capture. The query handoff preserves the gap extension,
raw warnings, original engine outcome and native scope.

These analyzed classifications remain conservatively `unclassified`.
Incoming-fallthrough evidence from a predecessor is explicitly unavailable as
`source_belongs_to_related_function`; the predecessor's instruction is never
assigned to the selected function. Missing or ambiguous instruction evidence
falls back to a supported range or unavailable site. Up to 2,000 instructions,
512 body ranges and 8 KiB of selected bytes are considered.

Switch-assisted fresh queries preserve their existing contract because their
reviewed CFG differs from the snapshot and needs its own durable proof design.
They are not falsely enriched using the old CFG. Old general requests without the policy and receipts without the extension
still replay unchanged. An unfinished legacy request retains its original policy
absence when resumed. The stored receipt is never modified by
a display-time legacy ownership review.

## Owned validation

The new `fixture/flow-gap-evidence/` assembly sources are independently authored
static fixtures. They must never be loaded or executed. Each architecture has:

1. A handler that compares the stored value and writes only when it differs.
2. A wrapper that calls that handler, then performs an unresolved ordinary
   import-pointer transfer to the declared `_puts` binding.
3. A wrapper-named function with an unknown register jump.
4. A direct branch to same-image executable code outside the selected body.

`tests/integration_flow_gap_evidence.py` builds arm64 and x86_64 separately,
uses fresh private import-only projects, and queries only those selected
entries. It compares captured bytes to the saved binary, checks the independent
compare/store encoding oracle, retains Apple disassembly/load/fixup output,
checks partial outcomes and positive/unknown categories, and verifies the
wrapper-to-handler selected-call link. It then makes the external fixture path
and Ghidra/JDK unavailable while replaying receipts and repeating handoffs.
The immutable project slice remains available for source verification.

The earlier `tests/integration_focused_control_flow.py` remains the independent
regression for ordinary local/import tail calls, terminal traps, unknown BR and
six out-of-body escape cases. Real trust denial, timeout and cancellation use
public commands and distinguish interrupted workers from committed partial
function results. Killed jobs do not acquire manufactured success receipts.

Exact-source test counts and live acceptance results are recorded in
[flow-gap-evidence-validation.md](flow-gap-evidence-validation.md), separately
from mocked fixture coverage. No installation, Linux
worker enablement, third-party application analysis, Stage C/D implementation,
or merge is included in this change.
