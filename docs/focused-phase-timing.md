# Focused supervisor phase diagnostics

`decompile --from-import` now adds `focused_phase_timing` to its private
`jobs/<job-id>/job.json`. Schema `macscope-focused-phase-timing/1` contains
`phases`: fixed phase names mapped to `elapsed_ns` and `outcome` (`complete` or
`failed`). Durations use a monotonic clock. No paths, input content or exception
text are included. No new CLI flag, pseudocode field, receipt field or identity
input is introduced. Cached replay does not rerun these phases.

The sequential, non-overlapping phases are:

- `selection_proof`: selection and byte/extent proof construction.
- `baseline_verification_request`: import Program hashes, request construction,
  and retry identity check.
- `program_copy_verification`: existing copy and copied-tree verification.
- `auxiliary_jdk_verification`: pre-worker auxiliary JDK verification.
- `bridge_read`: bounded launcher diagnostic check and bridge JSON read.
- `result_validation`: aggregate output/proof/runtime validation, including
  post-worker Program/JDK hashes. This is not pure shape-validation CPU time.

Existing `elapsed_seconds` measures the worker/supervision interval separately.
Native open/call intervals are nested inside it: **do not add them to worker
elapsed time**. New phases do not measure dependency discovery, setup between
phases, manifest writes, CLI receipt publication, rendering, or total CLI time.
They do not by themselves identify Java startup or database-open overhead.

Diagnostics use existing manifest writes. Failures before manifest creation
(selection/baseline) leave no timing artifact. Interruptions outside existing
manifest-writing handlers may leave the latest phase only in memory. An absent
phase is unmeasured/unpersisted, not zero or success. No additional failure
recovery, cache, integrity-check removal, or speedup is claimed.

## Verification (14 November 2026)

Four timing controls cover success, exception/interrupt propagation, nonfocused
no-op behavior and nonnegative durations. Full suites: 1,099 primary and 115
analysis tests. Independent source review found no execution/identity changes.

A bounded native query used the repo-owned `fixture/batch/owned_batch.c` import
from the PR80 experiment, entry `0x100000328`. All six phases persisted; no timing
field appeared in its query receipt. Candidate and baseline public envelopes
were identical after removing only their fresh job IDs. Engine-free saved-job
replay succeeded with unavailable Ghidra/JDK paths. This is a compatibility smoke
check, not a throughput benchmark or an actual TickTick phase profile.

Observed phase durations on that single warm owned sample: selection 0.582ms,
baseline/request 2.971ms, copy/verification 3.224ms, auxiliary JDK 5.296ms,
bridge read 1.033ms, result validation 10.139ms; worker interval 4.240s.
Do not extrapolate those tiny-fixture measurements to larger Program databases.

## Next performance decision

The existing TickTick exporter uses isolated focused imports; analyzed-image
`batch-export` is not a drop-in replacement. Its explicit shared-session contract
requires a committed analysis snapshot. A practical import-to-bulk preparation
path must separately define collective function preparation, discovery gaps,
shared-state provenance and order-dependence tests. Repeating single-function
focused mutations in a shared Program must not be labeled isolated output.
See [bulk plan](bulk-export-plan.md) and
[lifecycle assessment](batch-lifecycle-api-assessment.md).
