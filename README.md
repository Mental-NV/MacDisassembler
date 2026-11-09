# macOS Analysis CLI

This is a new, independent specification repository for a reusable macOS binary-analysis CLI. The working command name is `macscope`; the final product name remains open.

Start with [the implementation specification](docs/specification.md). The selected architecture is full Ghidra headless through its headless launcher and a project-owned Java bridge. The specification also covers optional REA MCP integration, a source-controlled calculator experiment, and later Taskovsky-oriented analysis workflows.

**Status:** Phase 1 complete, 9 November 2026. Calculator fixture, build
matrix, durable tests, and direct Ghidra baseline are implemented and
measured — see [current status](docs/current-status.md), [Phase 1
findings](docs/phase1-findings.md), and [lock manifest](docs/lock-manifest.md).
No `macscope` CLI exists yet; commands in the specification remain proposed
interfaces. Numeric gates in the specification remain proposed release
targets; measured Phase 1 results are in `docs/phase1-findings.md`.

This repository is separate from Taskovsky. It contains no third-party application binaries, recovered proprietary code, proprietary assets, credentials, or remote origin. Do not add those materials to this repository. Publishing a remote repository and choosing its owner, visibility, and license are separate decisions. No license has been chosen.

## Review decisions

1. Full Ghidra headless is selected. Review the detailed launcher/Java bridge contract and candidate dependency pins; development remains subject to explicit authorization.
2. Approve the calculator and blind validation protocol before implementation.
3. Confirm that the intended REA project is `morluto/rea` and select a pinned release.
4. Choose the future remote owner, repository visibility, and license.
5. Review the Taskovsky workflow acceptance cases before authorizing development.

