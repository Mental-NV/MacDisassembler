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

- **126 unit tests passed**, 1.637s on the pinned arm64 host. Evidence:
  `build/cli-unit-tests.txt`. Includes malformed thin/fat/fat64 and app inputs,
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
  `build/cli-integration-20261109-094732/report.json` and numbered stdout/
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
  own-workspace reads succeeded. Evidence: `sandbox-verification.json`.
  This proves these restrictions, **not full filesystem confinement**.
- A real import also succeeded in `build/cli Unicode Ω`, verifying non-ASCII
  and space-containing paths. Workspace quotes/backslashes/linebreaks are
  explicitly unsupported before engine invocation.

## Local timings, not release performance gates

The four import commands took 3.9690, 4.4717, 3.8736 and 4.5955 seconds.
The four analysis commands took 5.5293, 6.0769, 5.6956 and 6.5848 seconds.
Successful cached query commands ranged 0.0466–0.0686 seconds, median0.0551s.
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
dependencies. Final wheel SHA-256 is recorded beside the generated artifact
when rebuilt; implementation/checkpoint commits identify the source. No
Ghidra/JDK files are redistributed in it.

## Remaining phase-2 and release gates

Public uncached refresh, token/address spans, exhaustive Mach-O/dyld metadata,
strong hostile-input isolation, hard process-RSS/disk quotas, independent
startup budgets, multiworker execution, version migration and broader hosts
remain unsupported. Phase-3 annotations/search/resources and optional REA are
separate work. No license was chosen, no remote push performed, no Taskovsky
files changed and no analyzed input executed by this CLI.
