# Read-only references from an explicitly pinned focused query

Spec first. The owned practical trial found `calls` and `xrefs` demand a committed
analysis even when a saved import-focused decompilation contains useful selected
references. Add `xrefs --query-job JOB --address ENTRY --direction from|to|both`.
This slice exposes recorded references, not a guessed call graph or recursive
traversal. It never launches an engine, resumes an unfinished query, analyzes an
image, resolves imports automatically, or executes input code.

Require an explicit canonical focused-query job pin and exact unslid function
entry. Other function selectors and --to/--from address filters are unsupported
with this option. Reuse the production focused-query verifier: project/image/
input/import Program, exact recorded boundary policy, byte extent, request,
publication/retry identity and captured instructions must match. Missing, stale,
wrong-image/entry or unpublished evidence fails closed, with no native fallback.

Output policy `macscope-focused-receipt-xrefs/1` binds source envelope SHA-256,
requested and actual publication job, image/slice/import identities, selected
extent, function ID and original query status. Rows are unchanged recorded xrefs,
separated into incoming-to-entry and outgoing-from-body groups. Preserve raw
reference type and unresolved targets; do not infer dynamic dispatch, actual calls
or target implementation from type labels. No references outside the receipt
are discovered.

Outgoing completeness is limited to the verified selected function receipt and
its recorded facet, not the image/universe/runtime. Incoming is always partial
because no-analysis import references are not a global caller inventory, even if
the recorded local facet says complete. Query partial status, incomplete/truncated
facets, control-flow gaps and unresolved recorded targets remain explicit. An
empty partial group does not prove absence. Overall partial status exits 6.

Retain at most 4096 recorded rows across requested sides, incoming first in both
mode; budget gaps remain partial. Page using existing --limit/--cursor (default100)
with binding to project, receipt digest, entry and direction. Cursors cannot be
reused across a changed receipt or selection. Pagination counts captured rows only;
known_total is unknown whenever discovery coverage is partial. Text shows scope,
source pin and gaps alongside reference rows. Existing analyzed xrefs and all
other defaults stay unchanged. No call-graph API is changed.

Acceptance: actual owned writer receipt yields branch aa4→ad0 and call ab8→d94;
terminal receipt yields d78→bb0; incoming remains partial. Repeated installed
engine-free runs preserve all project bytes. Owned synthetic tests cover stale
receipt/selection, retry publication, missing result, partial/empty/unresolved
references, record budgets, pagination/cursor invalidation, invalid selectors and
no engine probing. Independent review and full regression suites required.

## Use and validation

```sh
macscope xrefs --project PROJECT --query-job SAVED_FOCUSED_JOB \
  --address EXACT_ENTRY --direction from --format text
macscope xrefs --project PROJECT --query-job SAVED_FOCUSED_JOB \
  --address EXACT_ENTRY --direction both --limit 100 --format json
```

Use the selected function's entry, not an individual call-site address. Reference
rows retain call-site addresses and numeric targets for subsequent explicitly
scoped inspection. This option does not follow those targets or imply that imported
runtime implementations are present. Omit --query-job for the existing analyzed
snapshot workflow. Unfinished jobs are not resumed by this read-only command.

920 primary and 115 analysis tests passed in the cloud. Independent review passed
all five new receipt-reference tests and the actual native writer/thunk replay
gate. The isolated installed wheel also passed that gate, including repeated text
and JSON in all directions, captured-row pagination, and unchanged complete
portable-project file snapshots. Outgoing writer references are aa4→ad0 and
ab8→d94; terminal thunk reference is d78→bb0. Incoming results exit6 with unknown
global totals even when their recorded local reference facets are complete.

The native gate is `tests/integration_native_focused_xrefs.py WRITER_PROJECT
TERMINAL_PROJECT`. It pins the existing owned writer receipt SHA-256
`68e46e45d926d9b13422de266956aedd56c3523370b834aefe56fa33e7783f1f`
and terminal receipt SHA-256
`a210afeb015a2dbdb025afdf2174d9feceb68ecffcf44d22af5158d9e2667d2a`.
These are actual prior Ghidra captures replayed offline, not synthetic replacements,
a new engine capture, a new full Mac suite or a live consumer session. No system
CLI was installed and no application was executed.
