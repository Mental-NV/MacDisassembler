# Field-level ivar failures (F5f)

Extend F4c additively, retaining row/gap behavior, diagnostic ordering and caps.
Each record failure adds field, field_reason_code, field_va and
field_mapping=verified|unknown. A verified field VA proves all consumed field
bytes, not pointer target validity. A failed record mapping has unknown
record/field VA; no field address is invented from a declared range.

Fields: record, name_pointer, name_string, type_pointer, type_encoding,
alignment, offset_pointer, offset_storage, offset_value. Missing name/type
pointers have missing_name_pointer/missing_type_pointer codes; invalid alignment
has invalid_alignment; unreadable/empty/oversized strings use invalid_string
unless mapping ambiguity/unmapped bytes is established. Pointer failures retain
their exact resolution reason, including external_binding and budget codes.
No raw string content is emitted. String failures have unknown field VA since
the whole string was not proved; pointer slots remain available through the
verified record identity. Type syntax is not newly validated: recorded encoding
text remains raw metadata, not a claim of valid ABI or recovered source.

Offset evidence retains existing reason/status and gains the same field
metadata. A failed pointer identifies its verified slot; missing/ambiguous
storage has unknown field VA; a negative int32 identifies verified value bytes.
Legitimate zero, anonymous bitfields and later valid rows are unchanged.

Acceptance uses independently authored multi-record metadata: corrupt each
field; verify precise reason and mapping confidence, external pointers,
ambiguous/unmapped storage, missing/truncated strings, invalid alignment,
pointer and record budgets, caps and deterministic engine-free repeated queries.
No worker/native execution or private data is required.

## Verification checkpoint

757 primary tests and 115 analysis tests pass. Seven owned field-diagnostic
regressions cover each failing field, real and injected pointer exhaustion,
ambiguous storage/records, huge list count, diagnostic caps and deterministic
repeat queries. Existing selected-ivar engine-disabled replay tests still pass.
The installed wheel passes all 23 ivar tests; its CLI help entry point works.
Independent review found no blocking issues and independently checked ambiguous
storage and real pointer exhaustion. These are static metadata checks, not a
native compiler or consumer-app trial; those broader readiness gates remain
separate. No private artifacts or native input execution were used.
