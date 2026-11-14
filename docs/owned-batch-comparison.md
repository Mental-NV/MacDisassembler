# Owned native batch comparison

14 November 2026. This is a small native validation/measurement checkpoint for
analyzed-image `batch-export`, not a new decompiler or a TickTick performance claim.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/integration_batch_export.py \
  --run --out /private/tmp/macscope-owned-batch-NEW --rounds 3
```

Requires the existing supported macOS arm64 Ghidra/JDK and Xcode toolchain. It
installs nothing and accepts no external binary. It compiles the repository-owned
`fixture/batch/owned_batch.c`, imports/analyzes it once, selects exactly the three
named functions, and copies that analyzed baseline into new trial workspaces.
`--out` must be new and use physical non-symlink paths. All runs/evidence are
retained; there is no automatic deletion or installed-CLI modification.

Trials alternate sizes `[1,3]`, `[3,1]`, `[1,3]`. Both modes use `batch-export`:
size 1 is not the focused-import CLI or a cached query. Wall time measures the
batch CLI invocation, including dependency checks and its Program copies, but
excludes fixture compilation, initial import/analysis, and trial workspace copying.

The runner requires identical selected identities/engine/options (except the
intentional chunk-dependent function budget), complete outcomes, exact equality
of all returned function records, unchanged analyzed snapshots/Program digests,
and expected worker counts. Successful chunk Program copies must be absent.
It preserves every raw CLI response, command time, manifest, function record,
worker diagnostic, and validated decompiler timing. Nested intervals are never
summed with whole-command wall time. Timeouts first interrupt the supervisor to
allow its owned-worker teardown; forced termination is a fallback. Any timeout
stops the experiment, retains output, and reports teardown **unverified**.

## Observed result

Exact runner SHA-256:
`4b2e97f1a86f4da55d1e93b13d14df26dc1da35bd05908ba621ea862f819438a`.
Fixture source SHA-256:
`ea5becc98546d65503ea71e49c39b1af6f2795116839ae53df5bf33338e09115`.
macOS 27.0.1 arm64, Python 3.14.6, Apple clang 21.0.0; exact runtime digests are
retained in local manifests. Ghidra/JDK are the existing pinned runtime.

| Chunk size | Three wall samples (seconds) | Median |
| --- | --- | --- |
| 1 | 14.051, 13.582, 13.652 | 13.652 |
| 3 | 5.268, 5.374, 5.410 | 5.374 |

Size 3 was **2.54× faster in this tiny warm fixture**. All six runs returned
identical function records, with matching selected identity/options, and preserved
the baseline. Native decompiler calls totaled roughly 0.023–0.060 seconds per
three-function run; most wall time was outside those calls. That observation
supports setup amortization, but does not separately measure startup/copy/hash cost.

## Limits and next gates

- Three rounds on a warm, otherwise uncontrolled host; fixed alternating order,
  not randomized/cold trials. No p95 estimate, RSS measurement or disk-peak claim.
- Tiny uncomplicated C fixture, not representative of TickTick, Swift, Objective-C,
  or complex functions. Equal output does not prove semantic equivalence.
- Imported-image focused exports still have different semantics and cannot simply
  use this command; this does not accelerate the user's existing focused exporter.
- No A/B/A order-isolation, crash/cancellation live experiment, large-image
  inventory, type-hint interaction, or exhaustive discovery claim.
- Timeout/no-overwrite controls are mocked unit tests, not native teardown proof.
- The next performance gate remains a fixed same-coverage application sample and
  resource profiling. This measurement is not a full bulk feature completion claim.
