# Selected-method dossier presentation

`macscope evidence --project WORKSPACE --leads leads.json --objc-types --format dossier`
uses an existing pinned manifest. It performs the same read-only evidence export
as other formats, not discovery, fresh decompilation, type injection or execution.
`--objc-types` remains explicit and optional. All existing defaults, JSON schemas,
receipts, graph statuses and exit codes remain unchanged; partial still exits 6.

The dossier answers practical reading questions in one bounded view: which lead
and exact function is this, what declaration is associated, which argument labels
are generated/conditional, what raw pseudocode and instruction/reference evidence
is available, and what remains unknown? Do not infer implementation semantics,
receiver identity, runtime dispatch or persistence from displayed names or types.

Layout per lead: identity and recorded status; top-level reason/gaps; selected
function/query origins; optional declaration and conditional ABI roles; recorded
control-flow gap reasons; raw pseudocode lines; instruction samples; incoming and
outgoing reference samples. Query pseudocode, when present, is labeled as the
selected saved query; otherwise use the function's saved pseudocode. Never merge
code lines from different sources, rewrite code or fabricate line/address links.
Line numbers are presentation indices, not source-code line numbers. No field
absence is interpreted as proof of absence of behavior.

Bounds: display at most 4 leads in manifest order; 12 KiB and 96 lines per lead,
64 KiB and 512 lines total including headers/footers. Truncate each untrusted field
before escaping (160 characters; pseudocode line 160 characters). Render at most
4 top-level blockers, 4 control-flow gaps, 8 ABI argument rows, 40 pseudocode lines,
8 instructions, 4 incoming and 4 outgoing references per lead. Budget exhaustion
skips further lines; reserved footer space reports exact skipped items for each
section and clipped-field count. All snippets label samples and retain recorded
coverage/status where available. Full data remains available by rerunning the
same invocation with `--format json` or `--format text`; no guessed paths/IDs.

Acceptance: owned selected-method handoff with return-value and conditional-type
questions; unsupported/mismatched declaration cases; selected-query vs snapshot
pseudocode; incomplete references; absent code/reasons/sites; large nested data;
controls and Unicode; all bounds/omission counts; unchanged input/default reports;
deterministic installed offline replay with no jobs. A consumer regression checks
that the required facts and explicit unknowns are visible without parsing the raw
tree. It does not claim human speed, native semantic equivalence or recovered source.

## Validation record

- Six owned consumer/cap/source-selection tests pass. Full cloud primary suite:
  875 passed; analysis suite: 115 passed. Independent review approved source
  selection, binding, omission accounting and limits after clarifying generated
  declarations and recorded signatures. No existing format/schema was changed.
- A separate reader was shown only an owned synthetic dossier, not source/tests.
  It correctly identified the method/entry, hidden versus explicit register roles,
  generated-label/type limitations, raw return expression, saved-function fallback
  rather than query code, partial incoming-reference coverage, runtime unknowns,
  and full-evidence route. Feedback removed an ambiguous absent limit-flag label.
  This is one synthetic reading exercise, not a human performance benchmark.
- For an owned one-lead fixture with 1000 repeated pseudocode lines and 500 generated
  instruction rows: dossier 3598 bytes/89 lines; detailed text 70672 bytes/2235 lines;
  JSON 52501 bytes/1 line. These measure presentation size, not application behavior
  or native decompilation quality. Caps/adversarial controls are separately tested.
- An isolated installed wheel's actual console command ran twice outside the
  checkout with nonexistent engine paths. Dossier output matched source rendering
  byte-for-byte, no jobs were created, and partial exit 6 was retained.
- Native macOS validation also passed 875 primary and 115 analysis tests with
  the default TMPDIR unchanged. No fresh native capture or live consumer trial
  is claimed by these checks.
