# Callback evidence in terminal disassembly

Specification first. Currently text disassembly ignores `callback_evidence`:
the owned native positive and two rejected compositions produce identical
thunk-only output headed complete. Completion describes byte decoding, not the
callback investigation. Users need the distinction without parsing all JSON.

Append a bounded summary only when callback evidence exists. Leave ordinary
text disassembly, JSON schemas, saved receipts, exit codes and analysis decisions
unchanged. Label analysis inconclusive independently of decoding status. Show
composition candidate status when present, selected receipt scope, bounded gap
reasons, assumptions, call/path obligations, destination-effect counts and
unknown runtime/application attribution/persistence. Linked views show the link
reason and destination-prefix stop as well as link status. A candidate remains
conditional; never label it a recovered runtime callback or application writer.

For composition show up to four independent assignment-store observations
(site, lane, value kind and address/input register only). This distinguishes a
mismatched address from an unresolved input without treating other stores as
callback targets. Include the expected selected thunk entry for comparison.
Do not infer aliases, executable targets or function names.

Composition-level explicit gap reasons precede role-local boundaries in text,
so the display cap cannot hide a sole decision behind expected transfer stops.
JSON ordering remains untouched.

Each of six detail lists (gaps, assumptions, paths, calls, unknowns, assignment
stores) displays at most four entries with exact omitted counts. Each rendered
field consumes at most 240 UTF-8 bytes, with a visible truncation marker; slice
input before terminal escaping and never recursively stringify containers.
The appended section must fit 64 lines and 16 KiB. Preserve critical status and
unknown-effect lines before optional details. Identify the summary as bounded,
refer to `--format json` for full evidence, and do not imply zero omissions
means complete analysis. No new engine jobs or receipt mutation.

Acceptance: actual native positive, overwritten and unknown-input cases have
distinct useful text; solo callback evidence and linked destination views render;
no callback means byte-identical old text; hostile controls/large fields/lists
stay safe and bounded with omission markers; JSON and repeated offline replay
remain unchanged. Run complete suites and installed-entry-point native tests.

## Validation checkpoint

826 primary tests and 115 analysis tests passed. Independent review reran seven
presentation tests and the actual owned native gate. An installed wheel outside
the checkout replayed the three owned positive/negative configurations in text
and JSON twice each (12 CLI invocations), with unavailable Ghidra/JDK paths.
Outputs were deterministic, text distinguished all three outcomes, the existing
pinned JSON evidence gate passed, and job/receipt bytes remained unchanged.
The native gate is `tests/integration_native_callback_text.py`, taking the same
private local owned-receipt project and manifest as the native negative gate.
No inspected application was executed and no system CLI was installed.

This is a presentation improvement, not additional instruction coverage,
application-writer attribution or a consumer usefulness validation.
