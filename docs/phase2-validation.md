# Phase-2 validation checkpoint (9 November 2026)

This checkpoint validates the narrow trusted-fixture CLI, not the complete
specification, hostile-input security, or semantic equivalence of pseudocode.
It does not replace the independent phase-1 evidence/quality gates.

## Reproducible commands and results

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /opt/homebrew/bin/python3 \
  -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /opt/homebrew/bin/python3 \
  tests/integration_macscope.py
```

- **126 unit tests passed**, 2.396s on the pinned arm64 host. Evidence:
  `build/cli-unit-tests-final.txt`. Includes malformed thin/fat/fat64 and app inputs,
  parent-symlink swap, FIFO, encryption/subtype rejection, bounded reads,
  atomic no-replace/force/failure cleanup, writer conflicts, database rollback/
  connection closure, integrity checks, cursor binding, ambiguous selectors,
  dependency errors, schema checks, all cached queries without JVM access,
  timeout/interrupt/failure cleanup, descendant cleanup after launcher exit,
  and second-slice import failure preserving the committed first slice.
- **69 CLI command checks passed** across four fresh space-containing
  workspaces: arm64 thin, x86_64 thin, explicitly selected arm64 fat64,
  explicitly selected x86_64 fat64. Every phase-2 public command, JSON
  envelopes, CFG DOT, output overwrite refusal/force, and deterministic
  export bytes were exercised. Evidence:
  `build/cli-integration-20261109-095203/report.json` and numbered stdout/
  stderr artifacts. All inputs came from this repository's own calculator.
- Each case exported **44 functions**, **36/36 requested pseudocode results
  completed**, **8 external/thunk results not requested**, zero native
  decompiler failures/timeouts/cancellations. The aggregate analysis/export
  status is **partial**, correctly exiting6 because `entry` reaches the
  200-reference outgoing-reference cap. It must not be called full recovery.
- Both architecture pairs had identical selected slice SHA-256 and identical
  function names, addresses, pseudocode and instruction bytes/text between
  thin and fat64 imports. Container/image IDs intentionally differ.
- The **actual production query runner** reopened the active analyzed Program
  with `-process -readOnly -noanalysis`: 44 functions, automatic analysis
  disabled, source Program digest unchanged. Evidence:
  `production-query-verification.json` in that integration directory.
  A separate earlier direct API smoke is in `build/cli-query-smoke/`.
- Actual sandbox probes under the generated worker profile returned EPERM
  for loopback network connection, other user-home reads and writes, while
  own-workspace reads succeeded. Evidence: `build/cli-integration-20261109-094732/sandbox-verification.json`.
  This proves these restrictions, **not full filesystem confinement**.
- A real import also succeeded in `build/cli Unicode Ω`, verifying non-ASCII
  and space-containing paths. Workspace quotes/backslashes/linebreaks are
  explicitly unsupported before engine invocation.
- Real Ghidra deadline/interrupt probes returned exit7 and exit130, preserved
  the prior active snapshot and left no owned process group. Evidence:
  `build/cli-integration-20261109-094732/timeout-interrupt-verification.json`.
- The final invocation uses verified `-loader-loadLibraries false`,
  `-loader-linkExistingProjectLibraries false` and `-loader-reexport false`.
  No requested loader safety option was skipped. A skipped option now fails
  closed, instead of relying on an assumed flag spelling.

## Local timings, not release performance gates

The four import commands took 3.8435, 4.0832, 3.9686 and 4.8150 seconds.
The four analysis commands took 5.2200, 5.8068, 5.4609 and 16.4262 seconds.
Successful cached query commands ranged 0.0455–0.1688 seconds, median0.0564s.
These measurements include CLI process startup; import/analyze also include
full installed-engine tree hashing. Java user-state/class caches can already
be warm. They are not OS-cache-cold or cross-machine performance claims.

## Wheel verification

```sh
mkdir -p dist
/opt/homebrew/bin/python3 -c \
  'import macscope_build; print(macscope_build.build_wheel("dist"))'
/opt/homebrew/bin/python3 -m venv build/cli-wheel-env
build/cli-wheel-env/bin/python -m pip install --no-index --no-deps \
  dist/macscope-0.2.0-py3-none-any.whl
build/cli-wheel-env/bin/macscope version --json
build/cli-wheel-env/bin/macscope doctor --json
```

The local wheel installed and its entrypoint, isolated import, package schemas,
doctor and cached queries passed without global Python changes or downloaded
dependencies. Final wheel SHA-256:
`b93e0b805029a2c02e4669d3eee6fc99ebc2d295aa9c661bbbed199daf782783`.
A checksum file accompanies the generated artifact; commits identify source. No
Ghidra/JDK files are redistributed in it.

## Installed CLI matrix against frozen direct evidence

The installed macscope 0.2.0 and bridge 1.14.0 used full Ghidra 12.2
with JDK 25.0.5.0.3 on the owned calculator matrix. In separate disposable
projects, the
baseline profile imported, analyzed and exported 16 thin slices, eight
slices from the build's universal apps, and eight slices packed into
FAT64 containers from the exact thin bytes. This covered arm64 and x86_64,
O0 and O2, and stripped and symbol-bearing variants. Job manifests and
bridge records confirmed the selected slice SHA-256, an import with
autoanalysis and library loading disabled, and analysis of the saved
Program. Five analysis/export pairs reported complete and 27 reported
partial. All 2,263 native pseudocode requests completed.

To repeat a thin case, select its input from the owned build manifest and
use a fresh project. A partial analysis or export returns exit 6 and
retains its facet statuses.

```sh
macscope project create "$project" --json
macscope import "$binary" --project "$project" --arch "$arch" \
  --experimental-trusted-input --json
macscope analyze --project "$project" --profile baseline \
  --experimental-trusted-input --json
macscope export --project "$project" --json --output "$export"
```

The [frozen direct captures](phase1-findings.md#isolated-binary-captures)
and the installed CLI shared all 1,273 RAM function entries across the
16 thin cases. The CLI also exported 308 external-space records. Names,
signatures, calling conventions, body ranges and instruction records
matched across the shared entries. Pseudocode text and CFG matched on
1,272 entries. The public CLI marked six pseudocode results partial for
unresolved control flow while preserving their text. The independent
[LLVM checker](decompiler-review.md#repeat-the-read-only-instruction-check)
verified 30,296 instructions and 5,570 direct targets over 933 selected
non-external, non-thunk function ranges, with zero mismatches. That
check is scoped to Ghidra's selected ranges.

The remaining text and CFG difference occurred at `0x100001744` in the
stripped arm64 O2 app. A direct rerun reproduced the frozen result.
Both paths decoded the tail branch at `0x100001770` to the selector stub
at `0x1000026a0`. LLVM and Apple dyld metadata show the stub loading the
`refreshViews` selector and branching through the `_objc_msgSend` bind.
The CLI additionally exported Ghidra's inferred override at
`0x100001984`. Its call graph reports that target as
`indirect_or_inferred`, while the decoded stub edge resolves as direct.
Runtime dispatch and pseudocode equivalence remain unevaluated.

All eight exact-slice FAT64 pairs had identical full normalized exports
across 1,249 function records. The comparison mapped analysis, image and
function identities, including thunk references, by the selected slice
and address space. It checked container offsets against the slice base
and kept slice-relative offsets in the comparison. The build's eight
original universal slices had different hashes from their thin
counterparts. Their compared RAM facets matched across 973 entries and
are recorded separately.

The private matrix comparison SHA-256 is
`4b4acde7a90c268cf52c5155a90e12a43753a81669eebd407e3102522ba622cc`.
The tail-branch adjudication SHA-256 is
`bac713b613d0fd8b5e219853b5d1092a58696f1b8ba09e1acb6a5bf2a2f1d209`.

## Remaining phase-2 and release gates

Public uncached refresh, token/address spans, exhaustive Mach-O/dyld metadata,
strong hostile-input isolation, hard process-RSS/disk quotas, independent
startup budgets, multiworker execution, version migration and broader hosts
remain unsupported. Phase-3 annotations/search/resources and optional REA are
separate work. No license was chosen, no remote push performed, no Taskovsky
files changed and no analyzed input executed by this CLI.
