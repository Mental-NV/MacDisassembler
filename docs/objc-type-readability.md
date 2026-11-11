# Readable Objective-C metadata types

## Narrow implementation contract

Objective-C method and ivar queries currently expose their recorded type
encodings without interpreting them. Add an opt-in `--decode-types` view to
`objc methods` (including `--class-slot`) and `objc ivars`. This is a static,
engine-free presentation layer over the verified imported slice. Existing
queries, saved evidence reports and Ghidra output must remain unchanged when
the option is absent.

Each requested row preserves its exact original encoding and gains a
`decoded_types` object with a versioned policy, source, status, diagnostics,
and bounded structured types. Methods additionally expose the encoded return
type, optional frame/argument offsets, hidden receiver and selector arguments,
explicit arguments, and a readable declaration only when the entire encoding
and selector arity agree. `arg1`, `arg2`, etc. are generated labels, not recovered
source parameter names. Ivars decode exactly one complete encoded type.

Supported syntax: standard scalar codes, object/Class/SEL, blocks with unknown
signature, pointers, qualifiers, bounded fixed arrays, structs/unions (including
opaque names and quoted field names), and bitfield widths. Preserve encoded
aggregate names and fields; do not invent typedefs, layout, field offsets,
alignment, calling convention, nullability, ownership or function-pointer/block
signatures. In particular, `c` remains `char`, not an inferred `BOOL`.

Unknown codes, unknown `?` types, truncated or trailing input, invalid numeric
fields, invalid method hidden arguments, and selector/argument disagreement
produce explicit per-row incomplete decoding. Never drop the raw declaration,
invent a type for the remainder, or print a complete method declaration from
a partially understood encoding. Decoding completeness is separate from
metadata-inventory completeness; metadata rows remain valid observations even
when their type strings are unsupported. Report the page's decoding failures
in diagnostics without mislabeling inventory truncation.

The parser has independent maximum input length, nesting depth, node count,
argument count and decimal width. Decode only the selected page. Bind the
option and decoder policy into pagination identity. No subprocess, native
demangler, engine, input execution, network call, database mutation or type
application is permitted. All presentation strings remain terminal-safe.

## Acceptance

- Synthetic project-owned encodings cover every supported kind, nested types,
  absent offsets, class/instance methods, missing encodings and generated names.
- Invalid/unknown inputs, exact bounds and deterministic seeded mutations
  terminate with typed results and never a plausible complete declaration.
- CLI tests cover exact class-slot selection, ivars, filtering, pagination,
  cursor-policy separation, JSON/text rendering and absent engine dependencies.
- Existing raw queries and complete primary/analysis regression suites pass.
- Independent review precedes publication. A fresh native compiler/runtime
  comparison is optional follow-up and is not claimed by synthetic tests.

## Scope boundary

These are readable binary declarations beside disassembly and pseudocode, not
recovered Objective-C/Swift source and not proof of an implementation's ABI.
No Ghidra signature injection, ivar-load rewriting, runtime dispatch resolution,
Swift resilient layout recovery or proprietary app output is part of this
change. Any later application of types to decompilation needs a separate
ABI-validated contract and cache identity.
