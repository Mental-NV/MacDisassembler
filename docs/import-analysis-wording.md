# Import-only success versus whole-image analysis

Spec before implementation. A committed no-analysis import is a legitimate input
for focused queries, not a failed attempt to analyze the entire image. Text status
and selected-method dossiers must separate import state, analysis selection,
query outcome and graph coverage without changing JSON, errors or exit codes.

For text `status`, add a bounded summary of at most eight images before the existing
full raw status tree. When analysis.status is not_analyzed, both committed analysis
IDs are absent, and import is recorded or verified, say "No whole-image analysis
recorded". Import recorded without verification is explicitly labelled unverified;
a failed import verification must not receive success wording. Any unavailable,
failed, stale, corrupt or unverified analysis retains that status and diagnostic,
never converts to reassuring absence. Existing job outcomes/history and all raw
diagnostics remain visible. Import success does not prove complete evidence or
success of a subsequent query; job outcomes remain independent.

For dossier evidence, an available committed-import pin without analysis_id says
"No whole-image analysis recorded in this import-pinned report; other snapshots
not checked." This is report scope, not a global database claim. Unavailable or
ambiguous image evidence keeps its reason and no successful-absence inference.
An existing analysis pin remains visible. Import Program identity and image status
are separate from the already shown query status and graph completeness.

No database scans, new jobs, validation bypass, schema change or engine operation.
Owned tests cover imported/no query, complete/partial focused query, existing
analysis, failed analysis job without committed snapshot, unavailable/invalid
snapshot, failed import verification, and report-scope distinctions. Full suites,
independent review and installed text/JSON replay must pass; errors and partial
exit6 persist and existing project file hashes remain unchanged.

## Validation record

939 primary and 115 analysis tests passed on Linux. Seven focused cases cover
lifecycle distinctions, missing/inconsistent IDs, error-bearing records, analysis
Program verification, failed jobs, report scope and summary limits. Independent
review prompted explicit diagnostic guards and a separate analysis Program line.

An isolated installed wheel replayed text status and dossier against the actual
owned portable import/focused-query project. Each repeated byte-identically;
status exit0 and partial evidence exit6 stayed unchanged. Both commands' JSON was
byte-identical to the pre-change installed CLI, and every project file hash was
unchanged. A separate owned corrupted-snapshot installed check retained unavailable
analysis, its diagnostic and exit6, without reassuring absence wording. No engine
capture, native full-suite claim, application execution, system install or consumer
agent restart was needed for this presentation correction.
