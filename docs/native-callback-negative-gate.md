# Owned native callback counterexample gate

Spec-first validation increment following bounded writer-call obligations.
The tool now has a native four-role conditional positive; practical readiness
also requires real compiler-generated negative evidence, not only constructed
instruction fixtures. This gate adds no decoder heuristics or runtime claims.

Use the existing independently authored optimized `OwnedCallbacks` library and
its original pinned positive assignment/invocation/thunk/destination receipts.
Capture at most two additional assignment selections, each at most 4096 bytes,
using bounded read-only/no-analysis import disassembly:

1. `overwritten_target`: independently confirm the optimizer leaves the final
   assignment to a different callback than the original positive thunk. Preserve
   the contiguous address materialization and pair store. Reuse the original
   positive thunk/writer on purpose; composition must reject that pairing.
2. `unknown_target`: independently confirm an externally supplied callback is
   stored as a register-sourced pair. Capture the actual contiguous store prefix;
   selected input registers are unknown values, never inferred function pointers.
   Reusing the positive thunk/writer must remain inconclusive.

Preserve byte, image, import, project and receipt identities. Do not rewrite
receipts, trim through an intervening instruction, insert target addresses or
infer alias identity from source-level intent. Document selection boundaries and
what the native oracle actually establishes. Selected prefixes are not entire
source-method analyses. No third-party input, app execution, system installation,
or whole-image autoanalysis belongs to this gate.

A reusable validation harness must require all three cases: the original positive
returns a conditional candidate under explicit ABI/path/writer-call assumptions;
each negative returns a gap with retained independent assignment-store evidence.
For the overwrite case, verify the observed target address is different from the
selected positive thunk. For the unknown case, verify the target operand is not
address-valued. Reject swapped, missing or stale/mutated receipt manifests rather
than accepting a vacuous failure. Bounds: a 64 KiB manifest, exactly two named
negative cases, six pinned job IDs, fixed role schema and a 60-second replay
subprocess timeout. Receipt JSON is capped at 2 MiB per file; job snapshots
stream hashes with caps of 256 files, 16 MiB per file and 64 MiB total. Symlinked
job entries are rejected. Streamed byte counts must respect those caps even if
a file grows after its metadata check. Scoped nonempty branch and call evidence,
all context/lifetime/side-effect unknowns, and same-instruction paired stores
are required; mere nonempty placeholder lists cannot satisfy the gate. No shell invocation or native worker creation is allowed.

Run each selected configuration twice with nonexistent Ghidra/JDK paths; outputs
must be byte-identical and the full job-file set/content unchanged. Retain all
unknown runtime target/context/slot identity, lifetime, side effects and
persistence facts. The positive is still conditional static evidence. These
negatives establish only the described native counterexamples, not arbitrary
Swift recovery, runtime correctness, semantic equivalence or general performance.
