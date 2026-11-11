# Owned Objective-C stateful-loop assessment

Assessment first, not an ABI or pseudocode-rewriting feature. Freeze three
source-known Objective-C methods on a no-SDK root class. Compile O2 ARM64,
without executing or instantiating the class. Capture exact selected methods
with the current isolated full-Ghidra import-only runtime, no whole-image
analysis and no signature recovery options. Keep raw results and partial status.

## Frozen questions and domains

1. Filter fixed-layout records by low flag bit and inclusive signed date bounds,
   count matches, and save the count in a declared unsigned ivar. Empty, null,
   oversized and reversed-bound inputs must be distinguished. Maximum count is
   64; null/oversized inputs take an explicit early return with no ivar write.
2. For matched records, OR a selection bit and accumulate their unsigned weights
   with defined modulo-2^64 arithmetic; store the sum in the same ivar. Records
   must be writable, valid for count, and disjoint from the receiver. Reversed
   bounds yield no matches. Nonmatching fields remain unchanged.
3. Count records accepted by an indirect function-pointer predicate, then store
   the count. Missing/null/oversized guards avoid predicate calls and receiver/record writes. On valid input,
   predicate effects and result are unknown; never claim purity, deterministic
   filtering, non-reentrancy, runtime dispatch identity or equivalent behavior.

Use count 0/1/64/65, signed minimum/maximum date and interval boundaries,
flags 0/1/2/3, unsigned overflow weights and missing pointers. The source-domain
requires valid receiver/array/predicate whenever dereferenced and no aliased
receiver/array for mutation; these are assumptions, not discovered facts. For
normal-return scoring the predicate must return normally and preserve receiver
and array lifetimes; other effects remain unknown. Pin the actual Darwin ARM64
LP64 layout (64-bit long, 32-bit unsigned int, 24-byte record stride), and read
ivar offsets from metadata rather than assuming NSObject layout. Non-null
count-zero input writes zero; null input does not write even with count zero.
Do not instantiate this root class or execute compiler-generated binaries.

## Evidence and scoring

Freeze source hash before capture. Independently record compiler/version/flags,
Mach-O identity, method metadata, LC_FUNCTION_STARTS, exact assembly/bytes and
query receipt IDs/hashes. A separate reader receives raw pseudocode, instructions,
address links and declared metadata, but not source or the expected answers.
Ask it to characterize iteration, guards, matching predicate, writes, arithmetic,
and uncertainty. Compare its answer with source and emitted instruction oracle.

Record correct/incorrect/unknown separately and distinguish native query
completion from static source agreement. If a symbolic/manual expression model
is used, label it as such; it is not execution-equivalence. Preserve vectorized
or unrolled code as captured, rather than compiling with simplifying flags after
seeing the answer. No new product option unless a reproducible failure justifies
one and is independently reviewed. Useful correct output is a valid assessment
result, not pressure to manufacture a feature.

## Stop conditions and follow-up

Missing native access is a blocker for actual capture, not permission to claim
native success. Continue independent review/spec work and report it. Unsupported
encoding, unresolved indirect effect, non-fragile ivar layout, vectorization or
ambiguous register semantics must remain unknown until separately evidenced.
Do not loosen gates, edit generated pseudocode, inject method types, restart
Taskovsky, or change the installed system CLI.

## Completed recovered assessment

The frozen source SHA-256 is
`e7c3ef7452c4aa6ead9cff4b7d4ed293a24d818b59fe22ee1bde6d1ba44d6591`.
Apple clang 21.0.0 compiled ARM64 macOS 14 with `-O2 -fno-objc-arc`.
The binary was never executed. The isolated PR57-equivalent runtime imported it
without whole-image analysis, then captured all three exact method extents.
All three envelopes were complete; count and mark retain the compiler's eight-way
unrolling. A source-blind reader recovered guards, inclusive signed bounds,
24-byte stride, matching flag, mutation order, final receiver write and count
limits from pseudocode and metadata. Its initial JSON read also exposed recorded
instructions, so this was source-blind, not strictly assembly-blind.

Source and assembly agree on unsigned wrapping in mark; Ghidra's inferred
`long` is not the source unsigned declaration. Accepted's indirect call consumes
W0 via `add x20,x20,w0,uxtw`; pseudocode correctly shows low-32-bit accumulation.
The frozen source's Boolean callback contract is an external ABI assumption,
not inferable from these instructions or the opaque `^?` encoding. Under a
conforming normally returning Boolean callback this counts accepted records;
nonconforming callbacks and arbitrary side effects are outside that statement.

No product semantic defect is established by this assessment. A concrete
metadata usability gap is established: v1 rejects the entire accepted declaration
at `^?`, despite its other fields being valid. The narrow follow-up is explicit
opaque-pointee decoding, not inferred callback signatures.

Three actual receipts replayed twice identically with nonexistent engine paths.
Portable copy setup initially omitted lock files; its first replay created a
lock. Subsequent full file hashes were unchanged. Native project and installed
system CLI were not modified after capture. No Taskovsky session was started.
