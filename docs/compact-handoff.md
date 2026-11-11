# Compact-only evidence handoff (F5b)

`macscope evidence --format compact` is an opt-in human presentation. Existing
JSON, JSONL rendering, detailed text, HTML, receipts and exit statuses are
unchanged. Partial evidence still exits 6. Compact output never appends the
nested evidence tree and never treats successful jobs as complete evidence.

Budgets: at most 24 leads, two blocker entries per lead, 80 input characters per
untrusted field before terminal escaping, 200 lines and 32768 UTF-8 bytes total.
Each lead block is emitted atomically or omitted, reserving space for a footer.
The footer gives exact omitted lead and blocker-entry counts (for displayed
leads), and says nested details were omitted. Clipped fields have an explicit
marker. Reason takes precedence over gaps; subsequent gap priority is failure
or unavailable evidence, ambiguity, limit/budget, then other gaps, stable within
priority. Priority categories use code text (failed/unavailable/unpublished,
ambiguous, limit/budget), not new evidence. Unknown codes are retained verbatim;
next actions are conservative review suggestions, not diagnoses or fix promises.

Every displayed lead includes recorded identity/status, blocking reasons when
present, and a conservative supported next action. A resolved lead means only
selected static requirements were met. Missing reasons or sites remain unknown;
a lead address is not a gap site. Job outcomes and complete links do not establish
full graph coverage, runtime execution or persistence.

Output always retains the overall status and partial exit-6 meaning. The route
to full evidence is to rerun the same `evidence` invocation with `--format json`
or `--format text`; no private paths, guessed IDs or invented commands are given.
No work or native analysis is triggered by presentation.

Acceptance uses owned synthetic 12-lead data with large nested evidence: compare
byte and line sizes for compact versus detailed text/JSON, preserve input data,
verify deterministic offline replay with native/job entrypoints disabled, and
exercise actual CLI output/exit6. Cover >24 leads, extreme control/unicode labels,
missing reason/site and explicit budget exhaustion. This is a presentation test,
not a fresh native or pinned-receipt analysis claim.

## Owned measurement and validation

Reproduce the size benchmark with
`PYTHONPATH=src:tests python3 -c 'from test_compact_handoff import measurements; print(measurements())'`.
The independently authored fixture has 12 partial leads, each containing 1000
pseudocode lines and 500 instruction records. Measured output:

| Presentation | UTF-8 bytes | Lines |
| --- | ---: | ---: |
| Compact | 3843 | 67 |
| Detailed text | 675642 | 18226 |
| JSON | 515628 | 1 |

These are fixture sizes, not general performance claims. All six focused tests,
750 full primary tests and 115 analysis tests passed on Linux. Independent review
approved the slice; additional adversarial 50-lead/control/unicode cases remained
within both limits. An isolated installed wheel exposes the opt-in format and
reproduces the same 3843-byte/67-line output outside the checkout, with engine/job
entry points disabled and the serialized fixture unchanged. This is deterministic
presentation replay, not native analysis or a fresh pinned-receipt trial. No
installed system CLI or private artifacts were changed.
