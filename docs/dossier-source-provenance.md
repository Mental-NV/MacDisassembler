# Truthful selected-query dossier provenance

An owned actual-Ghidra workflow found a presentation bug: a completed import-only
query was labelled a saved-function fallback and "not a successful query".
`evidence.focused_lead` places its verified receipt's function data in `function`
and only status, coverage and origin in `query`. An analyzed-image query instead
places pseudocode directly in `query`; an analyzed snapshot without query code
may genuinely fall back to `function`.

Preserve this data contract and selection precedence, receipt validation, raw
JSON, spans, exit codes and graph coverage. Change only dossier labels:

- Inline query pseudocode remains the selected saved query source.
- With an import Program pin, matching function/query origins with mode
  `focused_readonly_import`, matching extent Program pin, a recorded job ID and
  complete/partial query status, identify the selected import-focused query's
  function payload. Query partial is not a failure or complete graph claim.
- Otherwise label the displayed function as the recorded function payload, and
  explain when its relationship to a requested query is unestablished. Never
  infer query success merely from pseudocode or an origin mode marker.
- An analyzed function fallback remains explicitly separate from query output.
- Identify whether instruction/reference samples also come from the focused
  function payload; don't claim they are from a distinct saved snapshot.

These are labels for recorded provenance, not a replacement for export/receipt
verification. No new job, engine, annotation, type application or code rewriting.
Describe the recorded function signature as metadata that may differ from the
pseudocode's inferred arguments, without parsing or adjudicating either. Only
recommend --objc-types for an Objective-C selector lead.

Acceptance: actual owned focused receipt installed offline replay with unchanged
project bytes and exit6; complete and partial focused query, analyzed inline query,
real fallback, mismatched/missing origins or Program pins, unsuccessful query,
resumed source job identity, empty pseudocode, and no input mutation. Preserve
bounds and run primary/analysis suites plus independent review.

## Validation

919 primary and 115 analysis tests pass on Linux. Independent review approved
source separation, resumed/partial jobs, mismatches and downstream sample labels.
The actual owned `OwnedCallbackBox.writeSecond` Ghidra receipt from the practical
assessment was replayed with an isolated installed wheel, outside the checkout,
with unavailable engine environment paths. Two dossier runs were byte-identical,
correctly named the focused query source, retained its source job, increment and
overflow pseudocode, and preserved exit 6 for incomplete graph coverage. JSON
output was byte-identical to the pre-fix practical assessment and hashes of every
portable project file remained unchanged. No engine capture, app execution or
system installation was needed; this is a presentation correction tested against
an existing native receipt, not a fresh native decompilation claim.
