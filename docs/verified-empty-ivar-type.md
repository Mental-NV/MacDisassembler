# Preserve ivar evidence with a verified empty type string

Status: implemented and portable-tested; authorized real-data verification pending.
Baseline: local commit `3e92a65921ed4f151a9bea9abde4585421d4f1b5`, with exact runtime
`src` tree `3433c99565da63cded8064d79ec8104057547910`. Requested newer main commit
was unavailable locally; this source tree matches the supplied runtime baseline.
No private application material is included here.

## Owned reproduction and loss

Extend the existing `tests/test_objc.py` property fixture with one ivar record:
list pointer at file offset 0x3b0 to BASE+0x600; list entry size 32/count 1;
record 0x608 points to offset storage BASE+0x680, name BASE+0x790 and type
BASE+0x7a0, with alignment exponent 2 and recorded size 4. Offset storage is
signed int32 value 12 and name is `owned` followed by NUL. Type `i` followed by
NUL currently retains the row. Replacing it with an immediately recorded NUL
currently discards the entire row as `invalid_ivar_record`, losing otherwise
independently verified name and offset evidence.

## Implemented bounded behavior

Leave `MappedImage.string` strict and unchanged everywhere. Only in ivar type
reading, after existing pointer resolution proves a nonzero local target, use
`MappedImage.mapping(target, 1)` to prove an unambiguous file-backed byte and
inspect that exact byte. If it is NUL, retain the empty recorded encoding `""`.
Otherwise call the existing strict string reader unchanged. Do not catch arbitrary
string failures and reinterpret them as empty evidence.

Continue validating name, complete record, alignment and offset using the current
paths. Empty type does not enable anonymous-bitfield inference; a missing name
still fails. A retained row is evidence of recorded metadata, not a source type,
ABI, actual receiver or runtime layout. Size/alignment remain recorded metadata
fields, never substitutes for an unknown type. Offset-storage evidence remains
independent and subject to its existing unavailable/external handling.

Only the newly accepted empty-type row gains explicit `encoding_evidence`:
`status: unavailable`, `reason_code: empty_recorded_encoding`, `pointer_va` equal to the type-pointer field and
`storage_va` equal to the verified type target, `bytes: 00`, `scope: recorded_metadata_not_inferred_type`.
Add gap `ivar_type_unavailable` and an ivar diagnostic identifying the type target
and stating that the row was retained with unknown type. Existing nonempty rows
remain byte-for-byte unchanged. Existing gap propagation makes selected CLI output
partial rather than complete. Empty encoding continues through the unchanged type
decoder as `invalid` with `empty_or_nontext_encoding`, never decoded or synthesized.
Its usability remains unknown; preserve the empty string, do not normalize it to
`None` (which has a different existing decoder result).

Missing/null, external-bind, unmapped, ambiguous, unterminated and oversized types
keep their existing rejection behavior. No generic reader relaxation, type
injection, engine work, new CLI option or private evidence publication.

## Owned regression plan

1. Positive baseline `i` remains unchanged; exact mapped immediate NUL retains
   `owned`, offset storage and initial int32 value 12 with explicit unknown-type
   evidence and partial gap. Exercise inventory and selected-class APIs.
2. Decode-types on the retained empty row remains invalid with
   `empty_or_nontext_encoding`, while nonempty
   decode remains unchanged. Assert filtered CLI partial status/exit through the
   existing route; filtering or decoding must not remove the unknown-type gap.
3. A missing name plus empty type remains rejected, never anonymous bitfield.
4. Missing/null type, external binding, unmapped target, ambiguous one-byte
   mapping, nonterminated and oversized string retain their existing rejection.
   Include a mapped final-byte NUL positive control and malformed alignment.
5. Empty-name and other generic metadata string reads stay strict; add direct
   `MappedImage.string` assertion. Existing ivar offset failure controls and all
   Objective-C tests must pass without changing their expected nonempty rows.
   A zero-fill offset-storage control retains the slot with unavailable offset
   and both the offset and type gaps.

Run focused metadata/decoder/CLI tests and then the full portable suite. Independent
implementation review follows. Native execution is unnecessary for this byte-backed
owned fixture; any later authorized real-data validation remains private and is
not a prerequisite to invent broader behavior.

## Portable verification checkpoint

Implementation commit: `4894ba530122914b71786113dee47a7feff6dbb7`.

- `PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_objc*.py' -q`:
  89 tests passed in 4.733 seconds.
- `PYTHONPATH=src python3 -m unittest discover -s tests -q`:
  1,012 tests passed in 22.740 seconds against the final patch.
- Coordinator independently ran 37 metadata tests: passed in 2.864 seconds.

The filtered `--decode-types` CLI regression verifies partial output and exit 6.
The external-pointer negative is an injected resolver failure, not a newly captured
real dyld binding. Tests use owned byte fixtures only; there was no native engine
execution or private application validation in these runs. Generic string reader
and type decoder code are unchanged. Real-data validation remains a separate gate.
