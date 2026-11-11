# Address-linked pseudocode in the CLI

Spec first. Actual owned Ghidra receipts already contain validated token-to-machine
address spans, but ordinary text decompilation discards them. Add opt-in
`--format addressed` to `decompile` and `jobs resume`; no default output, query
identity, receipt, native engine behavior or analysis result changes.

Render exact recorded pseudocode lines alongside the union of recorded token
machine ranges intersecting each line. Label these as token ranges, not instruction
ownership of the entire line, source line numbers or runtime execution. Use
existing UTF-16 span validation on the exact original pseudocode before any
terminal escaping. Presentation line numbers count original newline-separated
lines, including leading blank lines. Multiline tokens may contribute to each
intersected line. Do not infer addresses for unmapped lines, rewrite symbols,
strip leading newlines or apply declarations/types. Escape terminal controls and
clip fields only after mapping. Label mapping as belonging to the entire original
line and the displayed snippet as possibly clipped, since mapped tokens may lie
after the displayed prefix. No raw engine text may inject terminal controls.

Keep recorded decompile and span-coverage status visible, including partial or
missing coverage. Invalid spans must not produce plausible mappings: show a
mapping-unavailable reason while retaining bounded raw code. This is presentation,
not silent repair of invalid receipts; existing replay validation remains binding.
For non-decompilation resume results, explicitly say address-linked pseudocode is
unavailable and render a small bounded outcome summary, without inventing code.

Bounds: at most 8 functions, 256 code lines per function, 512 lines total and
128 KiB output; at most 8 unique ranges per line, 256 displayed code characters
per line and 160 metadata characters per field. At most 1 MiB original pseudocode
and 8192 spans/total range entries per function are considered for mapping. Exceeding mapping budget
retains bounded code with unavailable mappings. Emit exact omitted function/line/
range counts where measured and clipped field counts, with a reserved footer.
Do not claim unseen mappings absent. Full evidence remains `--format json`.

Acceptance: actual owned focused-pseudocode receipt offline replay; correct d78
token ranges without new jobs; UTF-16 supplementary characters, multiline tokens,
leading newlines, unmapped lines, empty/missing/partial code, invalid offsets and
range metadata, controls/large inputs and deterministic caps. Existing text/JSON
and exit codes unchanged. Installed wheel and independent review; no input
execution, native recapture, system installation or consumer restart.

This complements the selected-method dossier: dossier answers multi-lead identity,
declaration and reference questions with short raw code samples. Addressed format
focuses on decompile/resume pseudocode with validated existing token ranges; it
does not require a leads manifest or replace dossier metadata context.

## Use and validation

```sh
macscope decompile --project PROJECT --address ADDRESS --format addressed
macscope jobs resume SAVED_JOB --project PROJECT --format addressed
```

These select a presentation only. The first command follows the existing
snapshot/fresh/import selection rules; resuming an unfinished job follows the
existing lifecycle and trust rules. This format does not by itself request an
offline-only run. The validation below uses an already complete saved job.

The actual owned terminal-thunk receipt contains two Ghidra token spans at d78.
Addressed replay correctly labels the call and return on presentation lines 5
and 6, preserving the original leading blank line and unmapped function signature.
The gate `tests/integration_native_addressed.py PROJECT MANIFEST` first validates
the original native receipt and unchanged JSON replay, then renders the addressed
view twice with nonexistent engine/JDK paths and confirms every portable file is
unchanged. No mapping is invented for an unmapped line.

904 primary and 115 analysis tests passed in the cloud. Independent review passed
the six initial presentation tests and actual native replay gate with no blocker;
its suggestion to distinguish whole-line mappings from clipped snippets was
implemented and covered by a seventh targeted test. The final full suite and
isolated installed wheel gate passed. This validates saved native token mapping
presentation, not newly recovered source or a fresh native capture/Mac suite.
