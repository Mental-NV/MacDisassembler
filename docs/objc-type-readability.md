# Readable Objective-C metadata types

Implemented as an opt-in static view. For example:

```sh
macscope objc methods --project WORKSPACE --class-slot 0x100000300 --decode-types
macscope objc ivars --project WORKSPACE --name-contains value --decode-types --json
```

Use a class-list slot from the selected image, not the illustrative address
above. A recorded method `take:enabled:` with encoding `v32@0:8@16B24`
displays `- (void)take:(id)arg1 enabled:(bool)arg2` and retains all four encoded
arguments, including `self` and `_cmd`, in structured output. `^[3i]` displays
`pointer to array[3] of int`, distinct from `[3^i]`.

The existing `objc` metadata queries use no Ghidra worker. This option does
not improve the engine's generated pseudocode or make dispatch targets known.

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

`decoded` means the bounded encoding syntax was interpreted, not that a compiler
would accept it as source or that its layout matches the implementation. A
quote after an object code inside an aggregate can name that object's class or
the next field. Ambiguous cases are explicitly unsupported, even when Clang's
all-named field convention suggests an interpretation. Do not guess by name
capitalization. Empty selector keyword components are supported; spellings
outside the bounded ASCII identifier policy are reported as unsupported.

The parser has independent maximum input length (4,096 characters), nesting
depth (32), node count (256), argument count (64 including hidden arguments),
decimal width (10 ASCII digits), and decoded output (65,536 JSON bytes).
Qualifiers cannot repeat. Frame sizes, array counts and bitfield widths are
unsigned; encoded argument offsets may have a sign. None are ABI-validated.
Type nodes point to half-open character spans in the retained encoding instead
of copying nested substrings. Decode only the selected page. Bind the
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

## Owned compiler cross-check

Compile-only observations with Apple clang 21.0.0 (clang-2100.3.34.2), targeting
arm64-apple-darwin27.0.0, verified the declarations represented by
[`owned_objc_encoding_fixture.m`](../analysis/owned_objc_encoding_fixture.m).
No generated executable ran and no framework or SDK header was imported.

- An `accept:(id)` method emitted `v24@0:8@16`.
- `signed char` emitted `c`, `_Bool` emitted `B`, and a block emitted `@?`.
- Pointer-to-array emitted `^[3i]`; array-of-pointer emitted `[3^i]`.
- `@encode` erased object class/protocol names and aggregate field names;
  runtime ivar metadata retained them. These sources are not interchangeable.
- Two `id` fields emitted `{Pair="first"@"second"@}` in ivar metadata. The
  decoder withholds this ambiguous tree instead of inventing a class named
  `second`. A mixed object/integer union has the same ambiguity.
- Selectors `foo::` and `:` compiled and emitted `v24@0:8i16i20` and
  `v20@0:8i16`. A Unicode selector compiled too; its spelling remains explicitly
  outside this decoder's ASCII declaration policy.

These checks establish compiler-emitted syntax for owned examples, not layout,
runtime equivalence, broad compiler compatibility or third-party app accuracy.

## Decoder v2 opaque pointees

The v1 unknown-type restriction above remains the replay rule for v1 reports.
New v2 output can preserve an immediate `^?` as a pointer to an explicitly unknown
pointee, without a callable signature. Bare `?` and qualified unknown pointees
remain unsupported. See [the bounded policy](objc-opaque-pointee.md); no engine
signature or pseudocode is changed.
