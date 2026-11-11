# Objective-C type evidence beside selected functions

```sh
macscope evidence --project WORKSPACE --leads leads.json --objc-types --format html --output typed-evidence.html
```

Use an existing pinned manifest with `objc_selector` leads and verified
`class_slot` values. JSON output contains the same optional section. This
read-only export can use saved analyzed functions or valid focused receipts;
it does not start a new capture. Existing manifests need no schema change.

## Contract before implementation

Add an opt-in `evidence --objc-types` sidecar for reviewer-selected
`objc_selector` leads with an exact `class_slot`. Bind a declaration only when
the existing verified-slice metadata query produces one matching method record
and that record's implementation address equals the selected function entry.
Never select a declaration by a similar name, body containment, guessed receiver
class, an unresolved import, or an assumed Swift symbol.

The sidecar is separate from the function's engine `signature`, `pseudocode`,
address spans, receipts and Program database. It reports three distinct facts:

1. The image's method record declares this selector, kind, raw type encoding and
   exact implementation address. Retain its record/class-slot identity and image,
   artifact/slice, analysis/import and function pins.
2. The bounded type decoder can or cannot interpret that encoding. Retain the
   decoder policy and generated-label provenance. Unsupported syntax remains
   explicit; no complete declaration is invented from a partial parse.
3. For a narrow, compiler-checked Darwin ABI subset, those declared fixed
   arguments would occupy the reported register roles **if this is a conforming
   Objective-C IMP**. This is a conditional ABI projection, not proof that the
   implementation actually uses these types or that a runtime message calls it.

Method encodings cannot prove the absence of a variadic tail, source argument
names, ownership, nullability, dynamic receiver class, Swift layout or runtime
dispatch. Record these limits explicitly. No type or name is injected into
Ghidra, applied as an annotation, or used to rewrite machine effects.

## Initial ABI subset

Support arm64 and x86_64 Darwin, 64-bit pointer/object/Class/SEL/C-string arguments
and returns, encoded 64-bit signed/unsigned integers (`q`/`Q` only), and
void return. Include the hidden receiver and selector arguments in register
allocation. All supported fixed arguments use the integer register sequence:
`x0` through `x7` on arm64; `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` on x86_64.
Return is `x0` or `rax`, or no value register for void.
Register roles follow argument ordinal, never encoded frame/argument offsets.
`l`/`L` are not in the validated subset. `q` can encode source `long` as well as
`long long`, so a canonical type display cannot recover that source distinction.

Reject overflow into stack arguments, by-value aggregates, floating/vector or
small-integer types, block parameters/returns, unvalidated integer codes/qualifiers,
and incomplete type decoding. Pointers do not imply knowledge of pointee layout;
decoded block markers do not supply a block signature or a validated mapping
in this first subset. Keep every unsupported reason without
changing the independently observed function, metadata or code coverage.

The mapping policy is versioned separately from type decoding and is not
enabled until owned compile-only fixtures on both architectures independently
confirm the selected register roles and type-code widths. The compiler checks
do not establish arbitrary-binary ABI correctness.

## Determinism, identity and compatibility

- The option is absent by default. Existing output remains byte-identical.
- Only reuse metadata already selected by an exact class-slot lead. No extra
  image-wide scan, native tool, engine launch or runtime execution is needed.
- Ambiguous matching declarations, a partial method-selection scope, absent
  functions, mismatched entry addresses or missing pins yield a typed sidecar
  failure. Preserve the underlying evidence and its original status.
- Sidecars have a versioned policy, decoder/ABI policy identities, exact binding
  and a deterministic digest. They are derived from pinned saved input, not
  added to or accepted as an authority over a saved engine receipt.
- One optional top-level `objc_type_evidence` section is indexed by lead ID;
  existing lead and function objects are unchanged. Each sidecar has a separate
  96 KiB budget. Metadata-selection gaps are recorded separately from code and
  reference coverage, so an incomplete caller graph cannot invalidate an
  otherwise exact declaration match.
- The optional section is emitted only with the flag. HTML shows the
  sidecar and its limitations beside code. Evidence diff must measure its
  meaning separately from engine signature changes, and must not silently
  ignore added, removed, changed or unsupported policy fields.
- Diff validates known policies and recomputes each sidecar from the report's
  raw matching declaration, pins and separately recorded metadata-selection
  gaps. A supplied digest alone is insufficient. These are internal consistency
  checks, not cryptographic attestation of an externally supplied report.
- Engine-free replay from the same retained image and receipts is deterministic.
  Changing the active analysis cannot rebind a pinned report. If the selected
  input is missing or corrupt, fail explicitly; never silently recapture.
- Existing home-path redaction remains unchanged. If it changes a selected
  declaration or lead, withhold that sidecar as `declaration_redacted`; do not
  present redacted text as an exact raw type. Diff may retain this conservative
  unavailable outcome but cannot recover the original redacted declaration.
- Excessive output size or structural nesting yields an unavailable sidecar,
  retaining the original lead and its code. No changes to receipt schemas.

## Acceptance

1. Owned arm64/x86_64 compiler fixtures establish the narrow ABI projection.
2. Unit tests cover register order, hidden arguments, pointer versus value
   aggregates, signedness, void return, limits and all excluded cases.
3. Synthetic exact-slot handoffs cover analyzed and focused results, ambiguous
   selectors, partial metadata, mismatched/missing inputs, unavailable results,
   sidecar policy/digest tampering, JSON/HTML and evidence diffs.
4. Old reports and flag-off queries remain unchanged. Opt-in reports reproduce
   without Ghidra/JDK, and no tests need a proprietary input.
5. Independent review and the complete primary/analysis suites pass before
   publication. Decompiler type application requires a later contract.

## Owned compiler validation

The source-controlled [`owned_objc_abi_fixture.m`](../analysis/owned_objc_abi_fixture.m)
compiled to assembly with Apple clang 21.0.0 (`clang-2100.3.34.2`) for both
targets using:

```sh
clang -x objective-c -target arm64-apple-macos14 -O2 -fno-inline -S owned_objc_abi_fixture.m -o arm64.s
clang -x objective-c -target x86_64-apple-macos14 -O2 -fno-inline -S owned_objc_abi_fixture.m -o x86_64.s
```

Both compilations succeeded. Static checks observed explicit stores of the
hidden and explicit parameters from the register sequences above, and seven
word/pointer passthrough methods returning `x2` through `x0` or `rdx` through
`rax`. Class-method stores retained the hidden parameter positions. `long`
and `long long` both encoded as `q`; unsigned variants as `Q`; `sizeof(long)`
was 8 on both targets. Expected deprecated SEL-to-integer cast warnings were
limited to the deliberately observable fixture stores.

Source SHA-256:
`b4912e0aa98311fc12dff2f3179c8c7f32cfc1ac28903145713aa05a4e3bb68f`.
Assembly SHA-256: arm64
`e90a7be9810bfaaabe73ec5c257222448a6c43e6e7067cf654e1270a35bebe0d`;
x86_64 `fc0dcd595366313b71e3c8b8346783bdabd254eee2ca7d0677215264a84eb992`.
The assembly is generated, not source-controlled. No binary was executed,
no SDK header/framework was imported, and no installation was changed.

These observations validate only the stated compiler examples and conditional
mapping. The Python tests use real owned metadata bytes and saved synthetic
function rows; the focused-reader integration test substitutes a synthetic
receipt result. This feature has not undergone a new live Ghidra capture or
third-party input validation.

## Current-main selective port

Port the existing draft onto main `7e221748a77622f589b307dfd2f6cbe3adc9bd4a`.
The historical compiler checks above are reusable ABI syntax/register evidence,
not proof that the current integrated implementation has passed validation.
Revalidate the sidecar against current exact-slot metadata, focused receipts,
redaction, evidence diffs, detailed text/HTML and compact output.

Preserve current callback, writer and compact presentation behavior. Keep the
96 KiB per-sidecar cap and original default/receipt schemas. In compact output,
explicitly disclose that optional type details require full JSON/HTML/text;
do not silently imply that --objc-types was ignored. Opt-in type enrichment must
not change graph status or exit6 merely because a declaration/ABI is unavailable.
No automatic type application or new ABI subset is part of this port.

Owned consumer acceptance: from an exact selected-method handoff, a reader can
identify the declared selector, distinguish hidden receiver/selector from
explicit generated argument labels, locate the selected function entry and raw
pseudocode, and see that register mapping is conditional. A second unsupported-
encoding example must retain raw declarations and code without plausible mapped
roles. A mismatched class-slot or entry must not acquire context from a nearby
method. Exercise CLI, HTML and full text without a JVM; compare the flag-off
report exactly. This is a structured usability regression, not a claim that
human research speed or decompiler accuracy has been measured.

### Current port validation

- Cloud Linux: 869 primary tests and 115 analysis tests passed. Thirteen focused
  sidecar tests include the new owned consumer-context and four-format CLI cases.
- Independent implementation review approved the selective port; thirteen sidecar
  and six compact tests were repeated independently. An adversarial compact
  case including type disclosure stayed within 31861 bytes and 73 lines.
- An isolated installed wheel, invoked through its actual console entry point
  outside the checkout with nonexistent engine paths, exported the owned saved
  synthetic snapshot in JSON/text/HTML/compact. Repeated JSON was byte-identical,
  no jobs were created and exit6 remained intact. No system CLI was changed.
- Consumer regression verifies declaration identity, hidden versus explicit
  argument roles, generated labels, exact entry/raw pseudocode and unsupported
  bool mapping. It is not a human usability or speed benchmark.
- Fresh native macOS validation of implementation commit `871637b` passed 869
  primary and 115 analysis tests with the default TMPDIR unchanged. The later
  candidate commit changes documentation only. An isolated wheel/version smoke
  also passed; no system installation was changed.
- The owned fixture was freshly compiled for arm64 and x86_64 macos14 with Apple
  clang 21, `-O2 -fno-inline -S`. Argument/return register-role assertions and LP64
  sizes agreed with the source; only expected SEL-cast warnings were observed.
  The fixture was not executed and no Ghidra analysis or consumer session ran.
