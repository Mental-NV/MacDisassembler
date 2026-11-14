# Batch resume receipt validation

## Bounded contract

A cached analyzed-image batch is reusable only when its record bytes match the
index hash **and** its embedded provenance matches the frozen export manifest.
Each record must name the current export and shared-session semantics, its exact
original ordered chunk, its function address and the indexed terminal status.
All records in one committed chunk must name the same well-formed worker job ID.
Reject malformed or mixed evidence before starting any worker or rewriting files.

This validates internal consistency, not authenticity against a malicious owner
who can replace every file. It does not change Ghidra output, discovery coverage,
per-chunk shared analysis semantics, cleanup policy, or the export identity.
Previously generated valid receipts remain resumable. Interrupted cleanup and
full streaming/import preparation remain separate follow-up work.

## Acceptance cases

- Untouched existing receipts resume with no native worker call.
- A consistently rehashed record with the wrong export, semantics, function,
  status, original chunk/order, malformed job ID or non-object payload fails.
- Individually plausible records from different worker jobs cannot form one
  shared-session chunk.
- Separate chunks may legitimately come from different jobs.
- Rejection preserves all artifacts and runs no worker, including when only a
  later chunk is corrupt.
- Original chunk replay after an interrupted index write remains unchanged.

## Validation checkpoint (14 November 2026)

On the supported Mac, 1,054 primary tests and 115 analysis tests pass with
`TMPDIR=/private/tmp`. The 13 focused coordinator tests use a mocked native
worker; they do not measure Ghidra throughput. Against unchanged baseline
`68d1849`, the new inconsistent-receipt controls failed in all 13 corruption
cases as expected. Valid cross-chunk jobs, `not_requested` receipts and original
interrupted-index replay remain accepted. No engine or native ABI claim is added.
