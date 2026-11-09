# Host / dependency lock manifest — Phase 1 and hardening (9 November 2026)

Pinned, verified-installed environment. Nothing was downloaded or installed
during Phase 1; Homebrew paths are recorded for identity only.

## Host

- Product: macOS 27.0.1, build 26A434, arm64, 24 GiB RAM
- Xcode 27.0 (27A266a), macOS SDK 27.0 (`MacOSX27.0.sdk`)
- Apple clang 21.0.0 (clang-2100.3.34.2), target arm64-apple-darwin27.0.0
- Apple LLVM 21.0.0 (Optimized build) — `xcrun llvm-objdump`
- Python 3.14.6 (`/opt/homebrew/bin/python3`)
- Java: OpenJDK 25.0.5.0.3 (Homebrew `openjdk@25 25.0.5.0.3`),
  `.../Cellar/openjdk@25/25.0.5.0.3/libexec/openjdk.jdk/Contents/Home`
- 64-bit JVM confirmed (OpenJDK 64-Bit Server VM, mixed mode)

## Engine

- Ghidra 12.2 (build 2026-Oct-23), Homebrew `ghidra 12.2`
  at `/opt/homebrew/opt/ghidra/libexec`
  (`/opt/homebrew/Cellar/ghidra/12.2/libexec`)
- `Ghidra/application.properties` sha256:
  `7bf69ade52e5530d6534a1202cc4ded88ca1940747456fe3d38ea03b2e3d99be`
  (version 12.2, layout 3, build date 20261023)
- Native arm64 decompiler
  `Ghidra/Features/Decompiler/os/mac_arm_64/decompile`:
  Mach-O 64-bit executable arm64, sha256
  `bbbe0c16cb5446ab6c338faa28f777a3d923e30cfd5546fab661ccf51c95f6cb`
- Installed tree digest from `macscope doctor --full-digest`:
  `72b7d1c417bf822927ba839647d1cc85268a165e9680e06781fa5f54ba1e9dbc`
- No x86_64 decompiler directory present (only `mac_arm_64` under
  `Decompiler/os/`); x86_64 targets are analyzed by the same arm64 worker —
  target arch never implies a separate worker.
- Headless launcher supports (verified from usage text): `-import`,
  `-noanalysis`, `-processor`, `-cspec`, `-loader`, `-preScript`,
  `-postScript` (with script args), `-scriptPath`, `-analysisTimeoutPerFile`,
  `-max-cpu`, `-readOnly`, `-deleteProject`, `-okToDelete`.
- Original runs used `~/Library/ghidra/ghidra_12.2_PUBLIC/` for shared state.
  New direct runs set `application.settingsdir`, `application.cachedir`, and
  `application.tempdir` to private per-run paths through `JAVA_TOOL_OPTIONS`.
  The exact JVM option string and JDK version are recorded per experiment.

## Fixture toolchain pins

Original v1.0: `build/manifest.json` (historical, retained unchanged).
New v1.1: `build/review-v2/manifest.json` with exact git revision, dirty diff
and per-source hashes, actual command evidence, and tool versions.

The original `text_hash` field hashed formatted otool output. New schema
`macscope-phase1-manifest/2` uses `text_bytes_sha256` over raw section bytes.
Do not compare these fields as if their definitions were the same.

- Scheme `CalculatorFixture`, configurations `DebugAnalysis` (`-O0`) and
  `ReleaseAnalysis` (`-O2`); `LLVM_LTO=NO`; `OTHER_CFLAGS=-fno-fast-math`;
  `ENABLE_DEBUG_DYLIB=NO`; `MACOSX_DEPLOYMENT_TARGET=14.0`;
  `DEBUG_INFORMATION_FORMAT=dwarf-with-dsym` (dSYMs evaluator-side only);
  `LD_GENERATE_MAP_FILE=YES`; ad-hoc `CODE_SIGN_IDENTITY=-`.
- Strip command: `xcrun strip <binary>` (removes symtab; verified
  `__TEXT,__text` byte-identical pre/post, 8/8 cases), then ad-hoc re-sign.
- No-inline subset (both configs): `calc_add`, `calc_div`,
  `calc_apply_op`, `calc_dispatch_table`, `calc_parse_digits`,
  `calc_engine_input_op`, `calc_engine_equals`, `calc_history_sum`.

## Isolation (tested)

- `sandbox-exec -f analysis/nonet.sb` (`(deny network*)`, `(allow default)`)
  verified: sandboxed TCP connect fails with EPERM, unsandboxed times out.
  All 16 baselines ran under this profile.
- Not claimed: filesystem confinement (none), sandboxing of untrusted
  inputs in general (inputs limited to our own fixtures by runner design).
- Outputs written with umask 077 (owner-only) under ignored `build/`.

## Hardened direct runner

- `bash fixture/build/build_matrix.sh <new-output-directory>` creates a new
  build matrix. It refuses any existing output directory, even interrupted.
- `python3 analysis/run_baseline.py --build-root build/review-v2 --run-id <new-id>`
  analyzes the selected matrix and freezes a new isolated experiment.
- Full Ghidra 12.2 remains the only selected engine. Loader class is
  `MachoLoader`, with `-loader-loadLibraries false` and
  `-loader-linkExistingProjectLibraries false`. Trusted pre/post scripts
  only; no scripts or library paths discovered from input directories.
- Trusted pre-script explicitly disables DWARF/PDB/source/external symbol
  discovery, including when an analyzer is inapplicable/unregistered.
  The complete effective analysis options and pre-script success marker
  are exported and checked. Export diagnostics retain warnings.
- New baseline schema: `macscope-baseline/2`; run manifest records engine,
  bridge, runner, native worker and input hashes, JDK, host architecture,
  effective command arrays and budgets. New freeze schema: version 2.
- No source/dSYM filesystem confinement is claimed. Network denial remains
  required; this is restricted to our own calculator/corpus inputs.

The separate [switch patch experiment](heldout-switch.md#upstream-patch-evaluation)
records its own native binaries and full engine-tree digests. The installed
distribution above is the CLI default.
