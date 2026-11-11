# Focused-import query benchmark

Measured 11 November 2026 on the unchanged product runtime of main `68b2944`,
bridge 1.15.0, Ghidra 12.2, OpenJDK 25.0.5.0.3, and Python 3.14.6.
The development host was an Apple M5 arm64 Mac, macOS 27.0.1, with 24 GiB RAM.
Apple clang 21.0.0 (`clang-2100.3.34.2`) compiled both owned assembly fixtures.
No installed CLI, engine, safety policy, or product runtime was changed.

## Workload and validation

The measurement driver invokes the existing public CLI separately for each of
five exact linker entries: `_owned_handler`, `_owned_linkage`,
`_owned_wrapper_named`, `_owned_internal`, and `_owned_boundary`.
The final `_owned_end` symbol is excluded because it has no following linker
entry, which the focused-selection contract requires.

For each architecture, one new private project imports one project-owned
`fixture/flow-gap-evidence/OwnedFlowGap*.s` library without autoanalysis.
Twenty serial rounds each run five separate `decompile --from-import` commands
on that same verified import. Every fresh result has a distinct job ID, exact
entry/extent/source bytes, and the unchanged import Program identity. Raw bridge
and job-manifest timing records agree, with one native decompiler call per query.

Each round then hides the original fixture, points Ghidra/JDK settings at
nonexistent locations, and replays all five receipts. The complete normalized
envelope is equal after removing only the documented command/reuse metadata.
Receipt bytes and job count remain unchanged. JSON and HTML handoffs are each
published twice and compared byte-for-byte. The original fixture is restored.
Public `status --verify-programs` checks run before and after each architecture.

All 200 fresh queries, 200 receipt replays, and 160 export commands completed
with their expected complete/partial exits. Each architecture has 101 jobs:
one import and 100 focused queries. No fixture/application execution, whole-image
analysis, third-party input, installation, or concurrent Stage C workload occurred.

## Five-command round results

Each cell summarizes 20 rounds. Times are seconds; p95 is nearest rank (the
19th sorted sample). The five fresh or five replay command intervals are
disjoint and summed within each round. Export timings are single five-receipt
publications, not sums of the duplicate determinism check.

| Architecture / operation | Median | p95 | Minimum | Maximum |
| --- | ---: | ---: | ---: | ---: |
| arm64 / Five fresh queries | 22.500 | 22.894 | 21.497 | 23.009 |
| arm64 / Five saved replays | 0.736 | 0.770 | 0.729 | 0.797 |
| arm64 / JSON export | 0.152 | 0.156 | 0.147 | 0.157 |
| arm64 / HTML export | 0.155 | 0.169 | 0.151 | 0.221 |
| x86_64 / Five fresh queries | 23.362 | 23.649 | 23.060 | 23.679 |
| x86_64 / Five saved replays | 0.744 | 0.781 | 0.728 | 0.846 |
| x86_64 / JSON export | 0.155 | 0.186 | 0.151 | 0.186 |
| x86_64 / HTML export | 0.158 | 0.168 | 0.154 | 0.171 |

## Individual fresh-query wall time

Each entry/architecture has 20 samples. Status counts are envelope outcomes,
not a claim that every native decompile status or coverage facet is identical.

| Entry | arm64 median / p95 (s) | x86_64 median / p95 (s) |
| --- | ---: | ---: |
| `_owned_handler` | 4.482 / 4.587 | 4.706 / 4.794 |
| `_owned_linkage` | 4.471 / 4.590 | 4.715 / 4.787 |
| `_owned_wrapper_named` | 4.469 / 4.604 | 4.674 / 4.763 |
| `_owned_internal` | 4.489 / 4.681 | 4.688 / 4.735 |
| `_owned_boundary` | 4.488 / 4.595 | 4.650 / 4.737 |

## Independently observed intervals

The table sums the same interval across five distinct commands, then takes the
median across 20 rounds. **Do not add rows:** worker, startup, open, and call
intervals are nested or overlapping. Launch-to-readiness includes supervisor
observation/polling delay; Ghidra startup is its own reported timer.

| Interval, five-query round | arm64 median (s) | x86_64 median (s) |
| --- | ---: | ---: |
| Worker process/supervision | 18.403 | 19.265 |
| Observed launch to readiness | 7.103 | 7.217 |
| Ghidra reported startup | 5.382 | 5.546 |
| Decompiler openProgram | 1.118 | 1.177 |
| Native decompileFunction calls | 0.050 | 0.046 |

`DecompInterface.openProgram` initializes/registers the native decompiler
interface. It is **not** Ghidra project/Program database opening. Database-open
and receipt-publication intervals are **unmeasured**, explicitly null in the
samples. Do not attribute wall-time residuals to either. Export wall time
includes CLI startup, validation, rendering, and atomic publication; disk
publication alone is also unmeasured. Timing is outside normalized evidence.

## Recommendation

- arm64: median five-command fresh wall 22.500 s versus replay 0.736 s. Observed launch-to-readiness is a median 31.7% of each fresh round's wall time; all five native decompile calls together take a median 0.050 s.
- x86_64: median five-command fresh wall 23.362 s versus replay 0.744 s. Observed launch-to-readiness is a median 30.7% of each fresh round's wall time; all five native decompile calls together take a median 0.046 s.

Repeated launch cost is material for this small selected workload; optimizing
native function work alone would miss most observed time. Consult saved
receipts first when they answer the question. Replay is substantially cheaper
here but does not provide fresh analysis.

The measurements justify reviewing an ephemeral bounded selected-address
prototype, not a persistent worker or an asserted speedup. The separate
[batch proposal](bounded-focused-batch-proposal.md) retains pristine independent
Program and decompiler state per entry, so not all opening costs would be
amortized. Interface/receipt/lifecycle review must precede implementation.
No batch command or runtime implementation is included in Stage D.

## Limits, outcomes, and costs

Focused worker limits: one function and one CPU per command, 150 s worker wall,
60 s startup, 25 s native decompilation, and 1024 MiB Java heap. The existing
8,192-byte selected-extent bound remains unchanged. Process memory has no hard
cap; job storage is sampled against 512 MiB, not enforced as a filesystem quota.

- arm64: 20 complete and 80 partial; 100 fresh samples and 101 total jobs.
  Per-entry envelope/native status: `_owned_handler` complete/complete; `_owned_linkage` partial/partial; `_owned_wrapper_named` partial/partial; `_owned_internal` partial/partial; `_owned_boundary` partial/complete.
- x86_64: 20 complete and 80 partial; 100 fresh samples and 101 total jobs.
  Per-entry envelope/native status: `_owned_handler` complete/complete; `_owned_linkage` partial/partial; `_owned_wrapper_named` partial/partial; `_owned_internal` partial/partial; `_owned_boundary` partial/complete.

The measured run launched 202 engine jobs including imports. The 200 fresh
query command intervals total 914.453 s; 200 replay intervals total
29.929 s. All 568 recorded CLI intervals, including imports,
verification and duplicate exports, total 979.901 s. These are summed
command durations, not CPU time or total elapsed experiment time. No purchase
or installation was made. The measured private captures occupy about 313 MiB
of allocated disk space. Native CPU/RSS/energy costs were not measured.

## Reproduce and source identity

Use a new canonical private directory and existing compatible pinned Ghidra/JDK.
Paths below are examples, not recorded user paths. Run from the source checkout:

```sh
TMPDIR=/private/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  MACSCOPE_GHIDRA="$GHIDRA_ROOT" MACSCOPE_JAVA_HOME="$JAVA_HOME" \
  python3 analysis/benchmark_focused_import.py \
  --output-dir /private/tmp/new-focused-measurement \
  --arch both --runs 20 --experimental-trusted-input

TMPDIR=/private/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -v
TMPDIR=/private/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis \
  python3 -m unittest discover -s analysis/tests -v
```

Use unoptimized Python; the driver rejects `-O`/`PYTHONOPTIMIZE`. Runs below 20
publish no p95 or performance gate. Use at least five repetitions for
exploratory median/range; runs of one to four are workflow smoke checks only.
The private report
retains every command, sample, job/receipt identity, exact entry/extent, limits,
and dependency/source hashes, with adjacent raw output and worker logs.

Runtime fingerprint is the SHA-256 of canonical JSON mapping every relative
`src/` file path to its SHA-256 (69 files). It matches the Stage C verified
export and main runtime; Stage C added only fixture/test/document material.

- Runtime: `0e3a72e7722fd21a0283a951522b32f3ebe129010539d9d865774c757e5ccf42`.
- Measured driver: `6e050d7d4e03594dd0eaf92d1ab8b10f72ee377defd969efbf0421ba5e0d9fdc`.
- Complete private report: `a7ac26632c533b628a42b698884ad1dea7c17bb8a54f4ca2806d21c6b76a8d32`.

### arm64 input identity

- Fixture source: `c52e88d7e6c6304d59bebc086c3dd5f60097babb365452e275bd7c2f24099644`.
- Built slice/artifact: `e0fbca676c9085efd4d91a5692aee923837064531bfbc8d875fd45030b6e64ac`.
- Imported Program: `9a3d85ccf828224ed18cf23fcf56278cd23276c2c727a46cd9fc8a8744b2a0b2`.
- Exact entries: `_owned_handler` = `0x358`, `_owned_linkage` = `0x36c`, `_owned_wrapper_named` = `0x388`, `_owned_internal` = `0x38c`, `_owned_boundary` = `0x398`.

### x86_64 input identity

- Fixture source: `0ec9bd9515af96e5a1e4f70b08836a9568aa4c9ae93810c28b6db9ebe940e2d4`.
- Built slice/artifact: `6cd4bed926ef687d4987b481c9bcfec9d2bffa4bb83ad4b430be5524e693afef`.
- Imported Program: `59d495b4b3d5bb83c6ccaf9786c492d69f52a50b0f6650d39bc1990501b3e6c4`.
- Exact entries: `_owned_handler` = `0x368`, `_owned_linkage` = `0x36f`, `_owned_wrapper_named` = `0x37f`, `_owned_internal` = `0x381`, `_owned_boundary` = `0x38c`.

### Pinned dependencies

- `ghidra_tree_sha256`: `72b7d1c417bf822927ba839647d1cc85268a165e9680e06781fa5f54ba1e9dbc`.
- `bridge_sha256`: `547c3b210c669312c4f7ca2de94280bb98d875d0e40daea7d6ddcd3a31c6c776`.
- `java_sha256`: `8cccd49f6c87c6762b9753f7e7415d15b7043ffa12be57eb9a93b39725ac3273`.
- `jvm_sha256`: `21596dd8760a573a4447a403b72a655fa208db3abf7323da4bae4a2a57b25f77`.
- `native_decompiler_sha256`: `bbbe0c16cb5446ab6c338faa28f777a3d923e30cfd5546fab661ccf51c95f6cb`.

## Acceptance and limitations

| Gate | Result |
| --- | --- |
| D1 | Passed: five exact entries, one verified import per architecture, 20 separate-query/replay rounds each, individual samples retained. |
| D2 | Passed for observable intervals; database opening and isolated receipt/export publication explicitly unmeasured. No overlapping intervals added. |
| D3 | Passed: repeated launch cost is material for this owned fixture; replay comparison and scoped recommendation recorded. |
| D4 | Review-only bounded specification written and reviewed; no implementation. Its release/implementation acceptance gates remain unrun. |

Validation: 619 primary tests and 115 analysis tests passed, including nine new
engine-free measurement/replay checks. Review caught and corrected incomplete
replay-envelope comparison and optimization-mode assertion removal before the
20-round run. The successful preflight smoke run and all measured captures verified
unchanged source bytes, native timing agreement, saved receipts, and imports.

Canonical `TMPDIR` is necessary for inherited tests that otherwise hand macOS's
`/var` symlink to fail-closed path validation. Analysis tests also require the
`analysis` directory on `PYTHONPATH`. The final commands above passed without
changing product path policy.

OS caches were allowed to warm, including a prior smoke check; no measured
samples were discarded. Entries ran in fixed order, arm64 before x86_64.
The two architectures therefore do not form a randomized head-to-head test.
Other ordinary host activity was not controlled; no cold-cache, battery, RSS,
or confidence-interval claim is made. Twenty samples meet the plan's minimum
for nearest-rank p95 but are not a broad statistical characterization.
The tiny owned fixture, one development host, and steadily growing job history
do not establish performance on large applications, the 16 GiB reference host,
installed-wheel execution, Linux, or a future batch implementation. No
performance gate is proposed from these results.
