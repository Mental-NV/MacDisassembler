# MacDisassembler / macscope

A local-first macOS binary-analysis CLI built around **full Ghidra headless**:
Mach-O import, analysis, address-linked disassembly, C-like pseudocode, typed
references and control-flow graphs. No Hopper, paid engine, REA or remote
model is required.

**Status (9 November 2026):** calculator baseline implemented and under
continued validation; initial narrow phase-2 CLI implemented. Engine use is
currently **experimental for explicitly trusted, owned inputs only**, not a
release for hostile binaries. Cached queries work without starting Java.
The broad specification is a roadmap, not a completion claim.

- [CLI installation, examples, safety boundaries and validation](docs/cli.md)
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
```

The independent repository contains project-owned code, documentation and a
source-controlled calculator fixture. Generated binaries, private workspaces
and recovered outputs are ignored. It does not modify Taskovsky or include
third-party application binaries or proprietary recovered material. No
project license has been selected. Remote pushes, publication, paid-engine
work and optional REA integration remain separate decisions.
