# Objective-C type evidence beside selected functions

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
and returns, encoded 64-bit signed/unsigned integer arguments and returns, and
void return. Include the hidden receiver and selector arguments in register
allocation. All supported fixed arguments use the integer register sequence:
`x0` through `x7` on arm64; `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` on x86_64.
Return is `x0` or `rax`, or no value register for void.

Reject overflow into stack arguments, by-value aggregates, floating/vector or
small-integer types, unvalidated integer codes/qualifiers, and incomplete type
decoding. Pointers do not imply knowledge of pointee layout; a block pointer
does not supply a block signature. Keep every unsupported reason without
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
- Optional report/lead fields are emitted only with the flag. HTML shows the
  sidecar and its limitations beside code. Evidence diff must measure its
  meaning separately from engine signature changes, and must not silently
  ignore added, removed, changed or unsupported policy fields.
- Engine-free replay from the same retained image and receipts is deterministic.
  Changing the active analysis cannot rebind a pinned report. If the selected
  input is missing or corrupt, fail explicitly; never silently recapture.

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
