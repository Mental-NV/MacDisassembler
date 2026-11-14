# Export benchmark harness

Standalone comparison harness for saved isolated/bulk timing receipts.
Plan context: [export readability roadmap](export-readability-roadmap.md),
[bulk export plan](bulk-export-plan.md), and the measured
[focused-import benchmark](focused-import-benchmark.md). This harness is
synthetic-fixture tooling only: no batch engine, no
TickTick/Ghidra execution, no CLI/engine integration. That integration is
a later reviewed job.

## What it does

`scripts/export_benchmark.py` (stdlib only, no new dependencies) compares
one saved `isolated` receipt against one saved `bulk` receipt recorded on
the exact same immutable image/address selection:

- Validates comparable identities: `image_id`, `arch`, `input_sha256`
  (plus `slice_sha256` when present), the sorted address selection, and
  the `attempted`/`succeeded`/`partial`/`failed` counts.
- Reports `speedup_isolated_over_bulk` only when every comparability
  check passes and both wall times are positive. Any identity, selection,
  count, or coverage difference yields `comparable: false`, a listed
  reason, and no speedup. A smaller output is never a valid speedup.
- Carries wall time and each named timing interval side by side without
  summing across interval names, because worker, startup, open, and call
  intervals nest and overlap (see the focused-import benchmark's
  "do not add rows" rule). Unmeasured intervals stay explicit `null`.
- Deterministic: selection addresses are canonicalized and sorted numerically, interval tables use
  sorted names, and repeated comparisons of equal inputs are equal.
  `summarize_samples` reports median/minimum/maximum over sorted values
  and nearest-rank p95 only with 20+ samples.

## Frozen artifact contract

Inputs and outputs are plain JSON-compatible records with
`schema_version: 1`, image identity (image identifier, architecture,
input hash), coverage copied verbatim from the isolated input, and
explicit limitations. Partial outcomes are explicit coverage, not a
mismatch, provided both sides agree. Raw evidence travels by reference
(`evidence_refs`); any record containing `pseudocode`, `raw_c`,
`raw_text`, or `decompiled_text` is rejected. Nothing here asserts
complete discovery.

## Receipt shape (synthetic input)

```json
{
  "schema_version": 1,
  "receipt_kind": "isolated",
  "image": {"image_id": "owned-image-1", "arch": "arm64",
            "input_sha256": "<64 hex>", "slice_sha256": "<64 hex>"},
  "selection": {"addresses": ["0x1000", "0x1040"]},
  "counts": {"attempted": 2, "succeeded": 1, "partial": 1, "failed": 0},
  "wall_seconds": 10.0,
  "intervals": {"worker_seconds": 9.0, "launch_to_ready_seconds": 2.0,
                "decompile_call_seconds": 0.05,
                "program_database_open_seconds": null},
  "coverage": {"scope": "...", "status": "partial", "returned_count": 2,
               "known_total": 2, "next_cursor": null,
               "truncation_reason": null},
  "limitations": ["Synthetic owned fixture; not a TickTick measurement."],
  "evidence_refs": ["fixture:job-isolated-1"],
  "status": "partial"
}
```

`counts.attempted` must equal `succeeded + partial + failed` and cannot
exceed the unique numeric address selection. Alternate spellings of the same
address are duplicates. Raw evidence keys are prohibited recursively, not only
at the top level.

Speedup and interval ratios require both runs to finish (`complete` or `partial`),
attempt the entire selection, have zero failed functions and provide evidence
references. A semantic partial result can compare if the recorded coverage and
counts match. Failed, timed-out, cancelled or unfinished runs are not throughput
successes. A one-sided or unequal `selection_id` is incomparable. Ratios outside
the finite numeric range are withheld, and incomparable inputs retain timing
values without interval ratios.
`intervals` must be a non-empty object mapping names to finite
nonnegative seconds or `null` (unmeasured). `coverage` must be a
JSON-compatible object; it is copied through, never recomputed.
`limitations` must be a non-empty list of strings.

## Usage

```sh
python3 scripts/export_benchmark.py isolated.json bulk.json --output comparison.json
```

Exit 0 when both receipts parse and a comparison record is produced
(check its `comparable` field); exit 2 on malformed input or unreadable
files, existing output paths, or output I/O errors. The output must be a new
file, so a mistaken input/output path cannot overwrite evidence. Tests live in `tests/test_export_benchmark.py` and use only
synthetic owned fixtures.

## Limitations

- Synthetic receipts only; no validation against live engine output yet.
- Comparability is exact-match on identity, selection, counts, and
  coverage; differences are listed, but there is no fuzzy equivalence judgment.
- Matching metadata does not prove semantic equivalence, equal engine settings,
  or valid referenced artifacts. The harness does not read evidence references;
  the measurement producer and independent review must establish these facts.
  It cannot consume existing macscope batch indexes without a separate adapter.
- No statistical treatment beyond median/min/max (p95 at 20+ samples);
  no cold-cache, battery, RSS, or confidence-interval claims.
- Native Mac/Ghidra checks from the bulk plan acceptance gates remain
  unrun; see the task report for the tests that were run.

## Recovery validation

Recovered the previously completed Muse artifact after its queue orchestration
failed with an open-file limit. The original worktree and queue state are left
untouched. Independent review identified failed-run speedup, nested raw evidence,
address aliasing and finite-arithmetic defects; bounded regression tests now cover
those cases. No engine invocation or TickTick performance result is implied.
