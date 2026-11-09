# Host / dependency lock manifest — Phase 1 (9 November 2026)

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
  `7bf69ade52e5530d6534a1202cc4ded88ca1940747456fe3d38ea03b2e399be`
  (version 12.2, layout 3, build date 20261023)
- Native arm64 decompiler
  `Ghidra/Features/Decompiler/os/mac_arm_64/decompile`:
  Mach-O 64-bit executable arm64, sha256
  `bbbe0c16cb5456ab6c8faa28f777a3d923e30cfd5546fab661ccf51c95f6cb`
- No x86_64 decompiler directory present (only `mac_arm_64` under
  `Decompiler/os/`); x86_64 targets are analyzed by the same arm64 worker —
  target arch never implies a separate worker.
- Headless launcher supports (verified from usage text): `-import`,
  `-noanalysis`, `-processor`, `-cspec`, `-loader`, `-preScript`,
  `-postScript` (with script args), `-scriptPath`, `-analysisTimeoutPerFile`,
  `-max-cpu`, `-readOnly`, `-deleteProject`, `-okToDelete`.
- Ghidra writes user state to `~/Library/ghidra/ghidra_12.2_PUBLIC/`
  (preferences/log). No network use observed or configured.

## Fixture toolchain pins (recorded per build in `build/manifest.json`)

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
