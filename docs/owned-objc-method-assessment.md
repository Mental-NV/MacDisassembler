# Owned Objective-C selected-method assessment

Assessment only, not a speculative product change. Freeze a small no-SDK root
class with three pure methods and one unresolved message-send control. Compile
arm64 and x86_64 Darwin dynamic libraries at O2/no-inline, never execute them.
Capture only exact selected method entries using current import-only Ghidra
headless CLI. Retain image/architecture, metadata record, source/assembly hash,
query/extent provenance, raw pseudocode and graph coverage. Existing trust and
resource bounds apply; no whole-image analysis or system installation.

Source-known questions:
1. Inclusive signed range membership: lower <= day <= upper. Reversed bounds
   produce false, with no arithmetic overflow required.
2. Clamp a signed index into [0,limit-1], or return -1 when limit<=0. Check zero,
   negative/extreme inputs; subtract only on a positive limit.
3. Select primary object only when enabled and nonnull, otherwise fallback.
   Object identity/dereference/ownership must not be invented from pointer roles.
4. Forward ownedValue to a supplied target. Static message-send evidence cannot
   establish the runtime receiver class, target IMP, return value or side effects.

Independent reader sees only selected exported code/address/context, not source.
Compare its answers against frozen source and independent emitted assembly;
record correct, incorrect and unknown separately. This is static source/oracle
comparison, not execution-equivalence or generalized accuracy benchmarking.
Do not repair bad pseudocode with metadata or rewrite signatures to make it pass.
If a real gap appears, preserve reproducible artifacts and recommend the smallest
follow-up. No application execution, private code, Taskovsky session or installation.

## Actual capture results

Eight selected functions were captured using full Ghidra 12.2 on macOS 27.0.1,
Apple clang 21.0.0 and the unchanged main 7b5792c runtime. Both source/binary and
assembly hashes and all eight receipt hashes were independently rechecked against
[the owned manifest](../analysis/owned_objc_methods_manifest.json). No source
signature hints were supplied to Ghidra. No fixture application was executed.

| Method | arm64 | x86_64 | Static source comparison |
|---|---|---|---|
| contains:lower:upper: | complete | partial extent bytes | signed inclusive range agrees |
| clamp:limit: | complete | partial extent bytes | four return cases agree |
| select:fallback:enabled: | complete | partial extent bytes | agrees for conforming Boolean inputs |
| forward: | partial unresolved dispatch/outside-body operations | partial unresolved dispatch/extent bytes | target and result unavailable; declared return lost in pseudocode |

The three x86 pure-method native decompilations and native scopes are complete.
Their envelopes remain partial because linker extents include respectively 12, 8 and 9
undecoded trailing NOP bytes. This is not an engine crash or demonstrated wrong
pseudocode; do not suppress partial byte coverage. All six pure-method stored
signatures still say `undefined ...(void)`, unlike the parameterized inferred code.
The existing signature-metadata caution correctly prevents treating that field as
a recovered prototype.

A reader given only raw exported code, instructions, method metadata and coverage
correctly identified the three pure-method behaviors and unresolved dispatch.
It also caught two important limits: ARM64 computes the clamp subtraction before
the final validity selection (fixed-width arithmetic), whereas x86 computes it
after guards; and noncanonical flag-register values can differ between ARM64's
low-bit test and x86's 32-bit nonzero test. Comparisons here assume conforming 0/1
Boolean arguments. Neither difference contradicts the source's valid-input return
behavior. Object ownership, dynamic types and actual execution remain unknown.

[The manual expression check](../analysis/check_owned_objc_expressions.py) pins
all six exact pseudocode hashes and checks 2,438 boundary cases per architecture,
with zero mismatches. An independent reviewer inspected source/instructions/models
and reran all 4,876 cases. These are handwritten expression-model comparisons, not
compiled recovered-C execution, binary execution or exhaustive equivalence.

Both forwarding pseudocode results show an apparent void call/bare return even
though the exact method encoding declares a 64-bit integer result. The ARM64
native scope also identifies seven operations at 0x770 outside its 8-byte selected
body. The x86 indirect jump binding remains unverified. The reader correctly
refused to conclude that the method returns void or that a runtime target was
resolved. This is a concrete return-information/readability gap, not permission
to assign objc_msgSend a universal signature.

The x86 request contains raw byte-pattern candidates at 0x71a and 0x721 inside other
captured instructions. Existing boundary validation does not promote those into
actual gap evidence; this is candidate noise, not a demonstrated false executed
branch claim. Keep that boundary check intact.

## Reproduction and next recommendation

The native evidence archive contains both portable owned projects, raw query
results, metadata, disassembly, linker starts, assembly, source, toolchain and hash
manifest. Cloud replay through an isolated installed CLI reproduced all eight
results twice with nonexistent engine paths. Complete/partial exits 0/6 and all
portable project file hashes stayed unchanged. Only documented resume fields were
removed when comparing semantic data. Extraction required restoring owner-private
permissions on the two temporary project roots; no security check was disabled.

Next investigate a bounded, source-known feasibility case for preserving an
Objective-C tail-message return channel, with exact IMP/encoding/bytes provenance
and explicit unknown runtime target. Check existing signature-assistance limits
before proposing a product flag. Include void-return and unsupported/wrong-binding
negative controls. Do not automatically inject metadata as verified types, change
raw pseudocode to hide the gap, or promote unknown dispatch to complete. Padding
clarity and raw candidate presentation are lower priority than this lost return
information. No product changes were made by this assessment.
