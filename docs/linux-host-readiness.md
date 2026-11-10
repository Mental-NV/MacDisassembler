# Linux host readiness

10 November 2026. This is groundwork for a Linux host port, not a completed
Linux Ghidra backend or a claim of hostile-input safety.

## Scope and architecture

The target format remains 64-bit Mach-O. Host architecture is independent of
target architecture: an x86_64 Linux host can in principle run Ghidra's native
x86_64 decompiler against an arm64 or x86_64 Mach-O. This change does not add
ELF input analysis, a second decompiler, or native execution of analyzed apps.

The design follows specification sections 2.4 and 11: full Ghidra headless,
explicit dependencies, immutable inputs, private output directories, no
automatic installation, no network, and no weaker fallback. The existing
macOS Seatbelt policy and its historical-profile matching remain unchanged.

Implemented:

- Explicit macOS arm64 and experimental Linux x86_64 host contracts. Unsupported
  hosts, including Linux aarch64 and macOS x86_64, remain explicit failures for
  native-engine preflight. Data-only commands do not depend on these contracts.
- Bounded ELF64 little-endian x86_64 checks for the Linux native decompiler,
  Java, javac and libjvm.so. These check file type, architecture, program-header
  extents and executable load ranges without executing code. They are not an
  authenticity check, ELF input loader, or complete dynamic-linker validation.
- Static Ghidra layout, launcher markers, required Java classes and bridge-file
  checks shared with the existing macOS path.
- Read-only host and dependency reports that never start Java or Ghidra.
- A deterministic, non-executable Linux isolation requirements document with
  job/input/runtime path scopes and a digest. It does not emit launcher argv.
- Typed refusal for native Swift demangling outside macOS. Raw Swift symbol
  inventory continues to work without a demangler.

## Commands

```sh
# No dependency files are inspected and no subprocess is started.
PYTHONPATH=src python3 -m macscope doctor --host-only --json

# Explicit paths on Linux; no download, installation, or native execution.
PYTHONPATH=src python3 -m macscope doctor --static \
  --ghidra /path/to/ghidra --java-home /path/to/jdk --json

# Optional whole Ghidra tree fingerprint, still without native execution.
PYTHONPATH=src python3 -m macscope doctor --static --full-digest \
  --ghidra /path/to/ghidra --java-home /path/to/jdk --json
```

`MACSCOPE_GHIDRA` and `MACSCOPE_JAVA_HOME` can supply the two explicit paths.
Linux does not use the macOS Homebrew defaults or search PATH for a runtime.
`--host-only`, `--static` and `--verify-worker` are mutually exclusive.

A successful host report means the report completed, not that engine execution
is available. Read `capabilities.engine_operations` and `isolation.status`.
A successful static report means file-layout checks passed. Its JDK version
is explicitly unknown, runtime and worker probes are `not_run`, and auxiliary
libraries are `not_checked`. It is not a launchable engine dependency record.
Static fingerprints describe the inspected files, not supplier authenticity.

The Linux candidate contract is Ghidra 12.2 with
`Ghidra/Features/Decompiler/os/linux_x86_64/decompile`,
`lib/server/libjvm.so`, and OpenJDK build `25.0.1+8` with Java architecture
`amd64`. This is a **synthetic compatibility candidate only**. No installed
Linux distribution or JDK build has been validated or recommended for deployment.
The pinned runtime choice and security updates must be reviewed against an
approved actual installation before enabling execution. The existing macOS
pin stays OpenJDK `25.0.5.0.3`, Java architecture `aarch64`.

Ordinary Linux `doctor`, `doctor --verify-worker`, and dependency-gated engine
operations return `linux_isolation_unverified` before native startup. The
trusted-input flag does not override this gate. There is no environment
variable, saved approval file, or unsafe mode that enables the Linux worker.

## Why execution remains closed

Bubblewrap namespaces and read-only mounts are useful but do not by themselves
reproduce the current executable-path allowlist. A writable job directory must
not become an executable directory. A future implementation must establish
all of these requirements together:

1. Deny network, including host/loopback access and access to host Unix sockets.
2. Start from an empty filesystem view; expose only the selected runtime,
   explicit runtime library closure, bridge scripts, the selected immutable
   input, and the current job. Do not bind the user's home or entire host root.
3. Allow execution only of pinned launch utilities, the selected Java runtime
   and native decompiler. Deny execution from inputs/jobs and all other paths.
4. Confine writes to the current job. For query copies, protect every Program
   database `.gbf` file while allowing the necessary local metadata operations.
5. Fingerprint auxiliary runtime libraries and bind the effective isolation
   policy to each job and retry, without accepting the requirements document
   as evidence that the policy was enforced.
6. Verify owned-process cleanup, cancellation, startup and wall-clock limits.
   Restart fencing must distinguish PID namespaces; a shared host boot UUID
   alone must not imply that a worker in another namespace stopped.
7. Run allow/deny canaries and real import, analysis and fresh-query tests on
   owned arm64 and x86_64 fixtures, including library-load failure, timeout,
   cancellation, read-only integrity, restart and repeat-result checks.

The existing macOS-only boot-session probe has not been replaced with a weaker
Linux check. Linux disconnected worker identities remain unverified and cannot
be used to relax writer/restart fencing. macOS fixture compilation and Apple
reference-tool harnesses also remain macOS-only.

## Validation boundary

New tests use synthetic native files and mocked process boundaries. They verify
host-specific native checks, exact version matching, non-executing doctor
modes, immutable plan scopes, typed Linux refusal, and preserved macOS defaults.

Validation on the Linux cloud Python 3.12 environment: 457 primary regression
tests and 105 analysis tests passed. Python AST parsing, wheel construction,
and an isolated `doctor --host-only` run from the extracted wheel also passed.
The policy/native checks use synthetic files; these counts do not include live
Ghidra, Linux namespace canaries, or a new macOS engine acceptance run.

No real Linux isolation probe, Linux Ghidra worker, installation, or private
third-party app analysis was performed for this change. Full Linux execution
remains an open acceptance gate, not a passed test.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 -m unittest discover -s analysis/tests -v
```
