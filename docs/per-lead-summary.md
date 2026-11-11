# Per-lead partial-result summary (F4d)

The `evidence --format text` view adds a summary immediately below coverage and
existing diagnostics, before the unchanged detailed evidence tree. This is a
presentation-only contract: JSON/JSONL, saved receipts, report schema, statuses,
raw reasons and exit codes do not change. Partial evidence still exits 6.

List leads in manifest order with their recorded ID and status. For each
incomplete lead, show its recorded reason followed by recorded gaps, and a
conservative next action. Do not infer completion from job success or from
individual links. A resolved lead means its selected static requirements were
met, not exhaustive graph coverage, runtime behavior or persistence.

The compact summary shows at most 32 leads and 8 reason/gap entries per lead.
Report omitted counts, pointing to the detailed evidence below. Limit each
untrusted label to 160 characters before terminal escaping. Never emit terminal
control characters. Limits affect only the compact presentation, not evidence.
Do not manufacture a gap site from a function entry, candidate, or lead address:
these top-level reason codes do not specify a site. Say so and direct readers to
the detailed evidence for any recorded locations. If an incomplete lead has no
reason/gaps, explicitly say missing evidence was not specified.

Actions describe review, not automatically executed commands: disambiguate a
selection for ambiguous leads; inspect/restore matching saved evidence for
unavailable receipts; narrow selected scope for explicit limit reasons; inspect
recorded instructions/flow for incomplete code evidence; otherwise inspect the
lead's detailed evidence. Never promise that retrying resolves an unknown.

Acceptance: mixed resolved/partial/unresolved/failed leads; missing reasons and
sites; bounded lists/labels with omission counts; terminal controls; unchanged
JSON and input objects; deterministic offline rendering with engine entry
points disabled. No native execution is needed for this presentation layer.

## Validation

- Six focused tests cover mixed outcomes, absent IDs/reasons/sites, count/label
  limits, terminal escaping, JSON default and unchanged machine data, repeated
  offline serialized-envelope rendering with engine/job entry points disabled,
  and the actual CLI exit-6 text-output path.
- Independent review approved the presentation-only scope. The offline unit test
  is rendering replay, not a new end-to-end pinned-receipt/native analysis trial.
- Packaged console entry point exposes the new opt-in text format; existing
  JSON default is unchanged. No installed system CLI was modified.
- Full primary suite: 719 passed. Analysis suite: 115 passed. Diff whitespace
  checks passed. No third-party binary or application-specific evidence is
  included in this change.
