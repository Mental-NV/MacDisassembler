# Compact selected receipt references and replay hints

Spec first. Add opt-in evidence `--format links`, or `--reference-links` to retain
the same additive versioned view in JSON. Existing formats/default evidence remain
unchanged without the opt-in. This complements dossier and pseudocode windows.

Reverify each selected import-focused query using its exact image pin, entry,
request, saved publication, byte extent and receipt integrity. Up to20 distinct
(image, requested job, entry) selections, deduplicated in manifest order; the
existing16-lead manifest limit is not expanded. An unavailable/stale/unsupported
selection is explicit and receives no runnable hint. Never discover another job.

Retain outgoing raw references from each verified receipt in captured order,
up to100 total, preserving reference type/source/target and local coverage.
Bind every row to source image, receipt envelope digest, job and entry. Match
selected destinations only within the same verified image at the exact entry;
multiple receipt identities at that entry remain ambiguous. Mark a joined link
as verified only when existing byte-decoded focused direct-call evidence agrees
with the raw source site and target. Unsupported, indirect, data or unresolved
references remain observations, not invented direct links. A cycle may be shown
as two independent edges but is never traversed or claimed to terminate. Targets
not selected stay numeric/unresolved, with no auto-import or analysis.

All receipts explicitly retain partial/not-global incoming scope, recorded
outgoing facets, query status and gaps. No graph-completion or runtime claim.
Counts distinguish selected verified edges, unproven observations and omitted
references. View and opt-in envelope status are partial (exit6) because incoming/global
coverage is unknown; invocations without this opt-in retain their existing status.

Suggest `macscope xrefs --project PROJECT --image IMAGE --query-job JOB --address ENTRY
--direction from --format text` only for verified receipts. Use POSIX shlex quoting
for the verified local project path and canonical IDs; never interpolate binary
strings into commands. Withhold commands for nonprintable or overlong paths,
rather than clip runnable shell text. Suggestions are never executed by rendering.

Renderer limits:32KiB/200lines, reserve footer; display receipts in manifest order
and their outgoing records in capture order, at most20 receipts/100 references.
Clip untrusted display labels to160chars before terminal escaping, but omit whole
commands exceeding4096bytes rather than truncating them. Explicit exact omitted
receipt/reference/hint counts survive output-budget exhaustion. Full native
reference data remains available using each saved xrefs hint; JSON with
--reference-links retains the bounded full view. No private fixtures are committed.

Acceptance: actual owned positive joined receipts, unselected/unresolved targets,
cross-image same addresses, ambiguous/missing/stale/wrong-entry receipts, cycles,
partial incoming, deterministic caps. Execute generated commands from outside the
checkout against owner-private project paths containing spaces and quotes; verify
selection/status and unchanged project bytes. No engine, app execution, new
capture, recursive traversal or Taskovsky restart.

## Invocation and validation

```sh
macscope evidence --project PROJECT --leads PINNED_LEADS.json --format links
macscope evidence --project PROJECT --leads PINNED_LEADS.json --reference-links --format json
```

The actual owned pair produces one verified selected direct link d78→bb0;
bb0→a90 remains a numeric unselected target because a90 was not selected in that
manifest. The original terminal query and new four-byte inner query were captured
by Ghidra 12.2 in isolated runtimes, not by inventing pseudocode or installing the
CLI system-wide. Inner query native scope is complete (one instruction, two native
operations, zero outside-body operations). No application was executed.

The installed gate pins both actual query receipt hashes, creates an owner-private
copy under a path containing spaces and a single quote, builds the view twice,
parses and executes each exact suggested xrefs command from outside the checkout,
and verifies all copied/original project bytes remain unchanged. A separate owned
writer gate exercises two unselected numeric targets without inventing selected
edges. The native gate is `tests/integration_native_selected_links.py PROJECT
LEADS_MANIFEST EXPECTED_SELECTED_LINKS` (1 for paired thunks, 0 for writer).

932 primary and 115 analysis tests passed in the cloud. Independent final review
passed eight module tests and the installed positive native gate. It required
explicit partial opt-in envelope status and a compatible recorded direct-reference
type in addition to byte proof; both corrections and regressions are included.
DATA/indirect records are not promoted by numeric address coincidence.

For this owned two-receipt fixture, the compact view was 1862 bytes / 17 lines versus
20633 bytes for its additive JSON view using the same local project path. This is
an output-size observation, not a human-speed or general decompilation benchmark.
No new full Mac regression suite or consumer-agent session is claimed.
