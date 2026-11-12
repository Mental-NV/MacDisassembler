# Export performance and readability roadmap

Updated 12 November 2026 following the owner's request. **Plan only**: this
update does not implement or authorize starting these features. No Rust rewrite.
This document sets the next improvement priorities; historical validation in
[current status](current-status.md) remains evidence, not a claim that these
new capabilities have shipped. The CLI and source remain implementation truth.

## Desired result and delivery order

Make a large application's pseudocode practical to generate and navigate:

1. **Batch export**: profile the real workload, amortize Ghidra setup, stream and
   resume finite per-image batches. See the [execution plan](bulk-export-plan.md).
2. **Improved grouping**: build reliable image/class/type indexes over shared
   function artifacts; expose uncertainty, unassigned functions and discovery gaps.
3. **String discovery and annotations**: improve evidence retrieval and annotate
   proven references without changing raw decompiler output or inventing values.

Grouping and string sidecar work can use cached artifacts while batch execution
is being designed. Neither requires a whole-application export to begin tests.
No target execution or modification, private binary/pseudocode publication,
remote integration, engine replacement or language rewrite is included.

## Baseline, not a completion claim

- The current Python supervisor calls Java Ghidra headless and its native C++
  decompiler. Existing analyzed-image export already reuses `DecompInterface`;
  focused single-function queries repeat setup. The standalone full-export script
  is a slow best-effort workaround, not the proposed bulk product feature.
- Objective-C class/method records expose owner metadata, category, method kind,
  selector and implementation address. Swift demangling supplies symbol text,
  not a recovered source ownership graph. There is no general built-in
  class-grouped pseudocode export.
- `strings` reports Ghidra-defined ASCII/UTF-8/UTF-16LE strings and recorded
  references; `resources strings` reads bundle string resources. It is not an
  exhaustive raw-byte scanner. Raw pseudocode is Ghidra output, without a general
  macscope string-inlining layer.
- Current capture caps include 2,048 Objective-C classes, 10,000 methods,
  100,000 symbol-table entries/10,000 Swift names and 5,000 defined strings from
  up to 100,000 defined-data entries, with up to 32 incoming references per
  string. Selected queries have separate behavior and bounds. Pagination is not
  proof of exhaustive discovery and does not remove capture caps.
- The delivered grouped helper passed 12 synthetic/mocked tests; no fresh grouped
  end-to-end Mac export or completed owner export is established. Its
  `--group-only` mode indexes an existing export; it does not decompile it.

## G: Grouping workstream

### G1: Evidence-backed Objective-C index

Join implementation addresses to exact image/slice identities and store raw
pseudocode once. Class indexes refer to it; one function may have multiple owners.
Preserve class-versus-instance methods, categories and selectors. Identity must
include metadata location/image, not just display name. Keep metadata-only
addresses, missing pseudocode, unassigned and unresolved functions visible.

Report discovered, assigned, multi-owner and unassigned counts with the captured
inventory denominator and its truncation. Do not report these as application-wide
class recovery percentages. Categories and inheritance must not be silently
invented from selected-class queries.

### G2: Conservative Swift grouping

Use surviving symbol/demangler evidence for a nominal-type index. Label inferred
ownership and keep classes, structs, enums and protocols distinct where evidence
permits. Ambiguous nested names, closures, thunks, generic specializations and
stripped functions remain unresolved instead of guessed from punctuation or
similar names. Preserve raw symbol plus inference/version provenance.

Deeper metadata/vtable/witness-table reconstruction is a later bounded research
item, not a prerequisite for the useful index and not promised full coverage.

### Grouping acceptance

- Fixtures cover duplicate names across images, categories, aliases/multiple
  owners, missing code, Unicode/path collisions and unresolved Swift forms.
- Index generation is deterministic, bounded and near-linear in records/links;
  it does not scan all functions once per class.
- Index refresh preserves raw artifacts and clearly distinguishes stale directories
  from current authoritative indexes. Resume rejects incompatible identities.
- Native smoke checks against an owned ObjC/Swift fixture validate address joins;
  a private TickTick sample measures usability without publishing its contents.

## S: String discovery and annotation workstream

### S1: Evidence sidecars and discovery gaps

Export per-image and per-function `strings.json` records with exact decoded text,
encoding, source bytes/address, image/slice identity, reference sites and limits.
Separate binary constants, bundle localization resources and unresolved dynamic
values. A resource key/value is not proof of which localization the app displays.

First reuse captured strings and references. Then design a separately labeled,
bounded raw-section candidate scan and validated C-string/CFString resolution
where current Ghidra-defined data misses useful literals. Preserve invalid
encoding, missing terminators, ambiguous mapping and pointer/object distinctions.
Candidate discovery is not confirmed use; do not silently drop old limits or
claim complete recovery after increasing a cap.

### S2: Derived annotated pseudocode

Keep `raw.c` byte-for-byte unchanged. A separate view may add a comment or linked
reference only when a recorded instruction/reference supports the association.
Persist the evidence chain and uncertainty. A string object pointer is not
interchangeable with a C string; token-to-instruction mappings alone do not prove
which semantic argument contains a value. Never replace arbitrary hexadecimal
numbers with text or use AI rewriting as evidence.

Typed Ghidra definitions and re-decompilation for proven C-string/CFString cases
come after fixtures establish correct representation; preserve both original and
new result provenance. Swift packed small/large strings need explicit ABI/version
scope. Dynamic, encrypted or constructed strings can remain unavailable.

### String acceptance

- Fixtures cover ASCII/UTF-8/UTF-16LE, malformed/truncated encodings, object versus
  character pointers, integer lookalikes, duplicate text at different addresses,
  missing/partial references, localization and unavailable runtime values.
- Every annotation navigates back to verified bytes/reference evidence; negative
  controls produce no invented annotation. Raw output remains unchanged.
- Native owned fixtures verify useful C/ObjC rendering; Swift support is gated
  independently, not generalized from one encoding or engine version.

## Effort and gates

Estimates are engineering person-days including tests/review, not delivery dates.

| Increment | Estimate |
| --- | --- |
| Batch profile and contract review | 0.5–1.5 days |
| Finite batch prototype | 2–4 days |
| Batch resume/lifecycle/coverage hardening | another 4–8 days |
| Optional measured independent-image concurrency | another 2–4 days |
| ObjC helper grouping | 1–2 days |
| Productized ObjC grouping/schema/resume | 3–5 days total, includes helper scope |
| Conservative Swift symbol grouping | another 3–5 days |
| Stripped Swift ownership research | 1–3+ weeks, uncertain coverage |
| Existing string/reference sidecars | 1–2 days |
| Reliable annotations and bounded C/ObjC constant handling | another 3–5 days |
| Bounded Swift packed-string support | 1–2+ weeks |

Before implementation, record the chosen increment and acceptance cases in its
spec. Each increment requires independent review, relevant exact-head tests and
native validation for engine/ABI claims. Measure speed on identical selections,
profiles and coverage; a smaller output is not a valid speedup. Partial evidence
must remain partial. Do not start a Rust rewrite: no measured benefit justifies it.
