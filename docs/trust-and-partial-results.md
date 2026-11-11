# Trust and partial-result contract (F1)

Native processing accepts explicitly trusted inputs, including inputs not authored
by the operator. `--trust-input` and the compatible
`--experimental-trusted-input` spelling mean the same invocation-scoped decision.
Without either flag, a terminal may confirm with exactly yes/y (case insensitive).
Refusal, EOF, or non-terminal stdin fails closed with isolation_required (exit 3).
Prompts go to stderr; machine-readable stdout remains clean. No trust is stored.
All existing host checks, isolation, identity validation, limits and deadlines
remain mandatory. Trust does not make the worker a hostile-input sandbox.

Static metadata and saved-receipt replay do not prompt. Resume requires a new
decision only when it actually needs native processing. Native demangling and
the doctor worker probe use the same decision.

Schema 1.0 and exit codes remain unchanged. Additional human-readable strings use
the existing diagnostics list; consumers must not parse diagnostic prose.
Partial results still exit 6 and are written/exported normally. Evidence reports
retain each lead's reason and gaps: worker completion, individual link verification
and overall graph coverage are different claims. Missing links are not invented
and partial coverage is not an engine crash. Failed, timed-out and cancelled
operations retain their existing status/error/exit conventions.

## Validation record

- Primary suite: 645 tests passed; analysis suite: 115 passed.
- Owned synthetic receipts replay without trust or new worker execution.
- Terminal affirmative/refusal/EOF and non-terminal refusal tested; denied
  demangling, doctor and resume do not load native dependencies.
- Both flag spellings parse for import, analyze, fresh/from-import decompile,
  resume, Swift demangling and doctor probe.
- Built wheel installed in a temporary isolated cloud virtual environment:
  actual console entry point exposes both spellings for all seven command
  families and rejects noninteractive unconfirmed demangling with exit 3.
- JSON, JSONL, text and DOT partial-output tests retain artifacts and exit 6;
  error tests retain failed/timeout/cancelled behavior.
- Independent review found no isolation bypass; help wording and DOT diagnostic
  omissions identified in review were corrected.
- Live macOS owned-fixture validation passed: 645 primary and 115 analysis
  tests; noninteractive denial, PTY refusal, explicit trust-alias import,
  interactive affirmative analysis and prompt-free receipt replay. The isolated
  worker's sandbox evidence was checked. This is owned-fixture validation, not
  a claim about arbitrary inputs or complete investigation graphs.
- Validated runtime SHA-256:
  `585f3b23c548232e31ac9b4caf5bb05f58af30195cb69b151d1d33df6a3c11d1`.
- Existing engine isolation identity strings remain unchanged for saved-receipt
  compatibility; they are not an authorship enforcement rule.
