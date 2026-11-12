# MacDisassembler / macscope

A local-first macOS binary-analysis CLI built around **full Ghidra headless**:
Mach-O import, analysis, address-linked disassembly, C-like pseudocode, typed
references and control-flow graphs. No Hopper, paid engine, REA or remote
model is required.

**Status (9 November 2026):** calculator baseline implemented and under
continued validation; initial narrow phase-2 CLI implemented. Engine use is
currently **experimental for explicitly trusted inputs**, not a release for
hostile binaries. Trust does not require authorship: use `--trust-input`
(legacy alias `--experimental-trusted-input`) or affirm the terminal prompt
before native processing. Cached queries work without starting Java.
The [current trust and partial-result contract](docs/trust-and-partial-results.md)
supersedes older ownership-only wording in historical CLI documentation.
The broad specification is a roadmap, not a completion claim.

- [CLI installation, examples, safety boundaries and validation](docs/cli.md)
- [Finite Muse implementation queue](docs/muse-queue.md)
- [Current improvement priorities: bulk export, grouping and strings](docs/export-readability-roadmap.md)
- [Current status and remaining gates](docs/current-status.md)
- [Detailed specification](docs/specification.md)
- [Phase-1 findings](docs/phase1-findings.md)
- [Pinned development environment](docs/lock-manifest.md)
- [Independent decompiler review and opt-in experiments](docs/decompiler-review.md)
- [Experimental parameter-inference profile and measured scope](docs/parameter-inference.md)

```sh
PYTHONPATH=src python3 -m macscope --help
PYTHONPATH=src python3 -m macscope doctor --json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 -m unittest discover -s analysis/tests -v
```

The independent repository contains project-owned code, documentation and a
source-controlled calculator fixture. Generated binaries, private workspaces
and recovered outputs are ignored. It does not modify Taskovsky or include
third-party application binaries or proprietary recovered material. No
project license has been selected. Remote pushes, publication, paid-engine
work and optional REA integration remain separate decisions.

## Portable static metadata and failure checks

Objective-C inventories resolve the chained-fixup pages needed by their
metadata instead of depending on the first 10,000 image-wide fixups. Page
validation, per-slot mapping checks, a bounded cache and lookup budgets still
apply. A malformed relevant page or exhausted budget produces partial coverage;
legacy-fixup inventory limits are unchanged. Exact class-slot method queries
remain bounded separately. These static queries do not start Ghidra or Java.
Class discovery additionally shares a 2,048-slot, 8,192-pointer and
262,144-chain-node work budget, including failed decodes and cache eviction
rework. Partial output keeps verified matches, an unknown total and actionable
diagnostics. See the [scoped investigation plan](docs/scoped-investigation-plan.md)
for remaining acceptance gates and follow-on stages.

The direct baseline runner records missing-input and missing-toolchain failures
in its immutable run summary. It fingerprints the engine only after staging an
input. This permits failure-path testing without a macOS Ghidra install;
it does not make engine execution portable or relax the macOS isolation gates.

## Linux host groundwork

Static Mach-O inspection and cached queries work independently of the host's
native decompiler. `doctor --host-only --json` now reports the host capability
matrix without launching anything. `doctor --static --ghidra PATH --java-home
PATH --json` checks dependency files without executing Java or Ghidra.

Linux x86_64 has an explicit experimental native-layout contract and bounded
ELF checks. **Linux engine execution is still disabled.** A namespace/mount
plan is not an executable sandbox: executable-path confinement, runtime
library pinning and live isolation checks remain required. macOS arm64 keeps
its existing runtime pin and Seatbelt worker policy. See
[Linux readiness and remaining gates](docs/linux-host-readiness.md).
