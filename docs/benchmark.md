# Owned calculator CLI benchmark

Measured on 9 November 2026 using the code at `1e31d12`, bridge 1.2.0,
full Ghidra 12.2, OpenJDK 25.0.5.0.3, and Python 3.14.6. The host was
macOS 27.0.1 arm64 with 24 GiB of RAM. This checkpoint covers the owned
arm64 O0 symbol-bearing v1.1 command-line fixture.

Each of 20 serial rounds created a private project, imported and analyzed the
fixture, and decompiled `_calc_add` once from the snapshot and once from a
reopened Program. The runner verified the input against its build manifest,
compared the two pseudocode results, and checked that the query preserved
the saved analysis. All 120 CLI commands completed with their expected status.
Analysis can report partial cross-reference coverage.

| End-to-end command | Median (s) | p95 (s) | Maximum (s) | Proposed p95 (s) |
| --- | ---: | ---: | ---: | ---: |
| Inspect metadata | 0.062 | 0.080 | 0.161 | < 2 |
| Create project | 0.057 | 0.070 | 0.163 | |
| Import | 3.970 | 8.499 | 10.614 | |
| Analyze | 5.255 | 8.949 | 17.521 | < 60 |
| Decompile from snapshot | 0.066 | 0.087 | 0.149 | < 5 |
| Decompile from reopened Program | 4.046 | 5.041 | 12.857 | |

The three scoped timings met their proposed thresholds on this host. The
specification's 16 GB reference host remains unmeasured. Each worker command
includes Python, dependency preflight, and a new JVM. OS file caches were
allowed to warm naturally. The reopened query starts a worker and has no
warm-query threshold. Percentiles use nearest rank.

Import, analysis and fresh query worker p95 values were 7.801 s, 7.600 s
and 4.340 s respectively. Ghidra reported headless startup p95 values of
2.222 s, 2.240 s and 1.270 s for those stages. Its analysis timer reported
2 s at p95, at whole-second resolution. That run recorded JVM startup
from Ghidra's own timer and grouped decompiler work into the worker total.

## Bridge 1.9.0 timing

The runner now records launch-to-readiness from the supervisor alongside
Ghidra's JVM startup and autoanalysis reports. It measures the decompiler
open interval around `DecompInterface.openProgram`, which initializes or
registers the native interface, and measures each `decompileFunction`
invocation separately. The call sample count covers actual invocations.
Native interface timing includes the Java call and Program registration.
[Ghidra 12.2 decompiler source](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompInterface.java#L2841)

On 10 November 2026, 20 rounds on the same 24 GiB arm64 development
Mac completed all 120 commands on the same owned calculator fixture.
The benchmark samples matched all 60 worker manifests and their raw
timing records. Ghidra's autoanalysis p95 was 2 s at whole-second
resolution. End-to-end p95 was 0.162 s for inspection, 7.690 s for import,
11.290 s for analysis, 0.306 s for cached decompilation, and 5.875 s for a
fresh query. The 16 GB reference host remains unmeasured.

| Phase | Launch to ready p95 | Ghidra startup p95 | Decompiler open p95 | Per call p95 |
| --- | ---: | ---: | ---: | ---: |
| Import | 2.003 s | 1.621 s | | |
| Analysis | 3.340 s | 2.502 s | 230 ms | 10.8 ms across 720 calls |
| Fresh query | 1.932 s | 1.460 s | 231 ms | 34.2 ms across 20 calls |

The updated private benchmark report SHA-256 is
`23d8edf6e69269b5abc97ccf9f075a83890d51aa8a42609c3321f785f6e6ba7e`.
An installed-wheel comparison on separate owned arm64 and x86_64 slices
matched the prior function signatures, pseudocode, instruction bytes and
incoming references for all 14 functions. Repeat analysis reproduced
the normalized export on both slices. Its report SHA-256 is
`703d018494f16768dc5418862bf5336b9e48e2b97087214ca6005966eec6e4ea`.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/benchmark_cli.py \
  --fixture-build-root /path/to/owned/build/review-v2 \
  --output-dir /private/tmp/new-macscope-benchmark \
  --experimental-trusted-input
```

The output directory must be new. `--runs 1` checks the workflow without
evaluating the 20-sample thresholds. The private report includes every
duration and command exit, engine digests, and the fixture manifest identity.

- Fixture SHA-256 `7c6a6a903251005b815d8198465291223db542eb138dffb4abfeee812bec646d`
- Fixture manifest SHA-256 `15effb94a6a2db4b9db26128dd60012d6c937fa6818828c9ca925d82a63cda8b`
- Original runner SHA-256 `13b1b9faeac4b594657b16d96a80547afb5c0e0eb52634946d0393aa9bf7d16a`
- Original private report SHA-256 `70027fa3420ae73398550374d9c0e7dc9bf99b2c247f9ef00a1a3a49a3ed665d`
