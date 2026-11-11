# Bounded callback investigation evidence (F3a)

Status: F3a implementation contract, not the F3 practical readiness gate.
Current policy version 6 adds [explicit invocation path obligations](split-invocation-obligations.md).
Policy version 5 adds [opt-in shifted-register ADD](register-add-evidence.md).
Policy version 4 adds [bounded SP pair writeback](callback-stack-pairs.md)
to the version 3 [opt-in input-register and conditional ABI
provenance](callback-provenance.md), following [F3b paired storage and direct
destination links](callback-links.md). Version 1 below describes the original
F3a projection. All versions leave runtime callback identity and writer
attribution inconclusive.

`disasm --from-import --range START:END --callback-evidence` adds an optional
read-only `callback_evidence` projection of the selected byte receipt. It is
also available with `--receipt JOB`. The original disassembly receipt is not
changed. Policy `macscope-callback-sites/1` binds the interpretation; the
projection includes the complete selection identity and instruction bytes at
each reported site. `source_envelope_sha256` hashes the original response as
UTF-8 JSON (sorted keys, ASCII escapes, compact separators), separately from the
on-disk receipt digest verified by F2. Receipt replay still verifies the original identity/digest.
No additional native worker, mutable Program, trust grant or whole-image scan
is introduced. JSON is the authoritative representation.

## Supported facts, not assumed Swift semantics

Only arm64 little-endian instruction bytes are interpreted. At most 4096 bytes
(1024 instructions) are inspected, in selected linear order. Supported forms:
ADR/ADRP; 64-bit ADD immediate without flags; MOV register (unshifted ORR alias);
64-bit unsigned-offset LDR/STR; BLR; RET. x31 is not tracked as a pointer value. Unsigned LDR/STR base31 is explicitly
an unknown stack pointer, not XZR or a recovered context/object address. Other
SP/ZR operand forms are unsupported. Stack stores are not object-field writes. Address arithmetic wraps at
64 bits. NOP is accepted. All other instructions stop interpretation with an explicit gap.
BLR ends interpretation after recording its operand; RET also ends the segment.
Unvisited suffixes are not interpreted. Unknown instructions do not disappear: emit a gap. There is no speculative
control-flow following, branch joining or memory alias analysis.

A store reports its base register, displacement and value provenance at that
instruction. A load reports a symbolic memory read, not the contents of memory.
An indirect call can reference that read's instruction site, not a recovered
runtime target. Register copies preserve provenance; overwritten registers
replace it. Unknown initial registers remain unknown. Address materialization
is not proof of an executable function, closure entry or allocation identity.
Repeated stores are not collapsed or treated as a unique callback assignment.

These observations are candidate assignment/context/invocation sites for human
investigation. They do not establish a Swift closure representation, captured
context, unique target, state writer, persistence, or runtime UI behavior.
Every result remains `inconclusive` with explicit requirements for context,
invocation target and writer evidence. The disassembly's status/exit code stays
unchanged: projection coverage and investigation completeness are separate.
Unsupported architectures return no edges and an explicit gap.

## Acceptance and remaining work

Owned byte fixtures cover two materialized values, copies, overwritten stores,
loads feeding invocation, unknown input targets, unsupported instruction barriers,
branch/return barriers, x31 rejection, malformed byte rows and bounded work.
Mnemonic text must never affect interpretation. Projection is deterministic,
JSON-serializable and does not mutate the original receipt.

F3 remains incomplete until a compiled owned Swift fixture independently checks
compiler/ABI patterns for captured and uncaptured callbacks and reaches a verified
writer, with negative overwritten/unresolved cases. This slice does not replace
that gate. x86_64 and resilient Swift layout support are intentionally deferred.

Projection reports `interpreted_end_va` (exclusive) and `stop_reason`; an
unsupported instruction is not counted as interpreted. Ordinary Swift prologues
may immediately stop this slice. Interior ranges can expose supported facts, but
their initial registers are still unknown and no path from function entry is
asserted. The full selected byte identity is not a claim of interpreted coverage.

## F3a validation checkpoint

Cloud primary suite: 678 passed. Analysis suite: 115 passed (run with
`PYTHONPATH=src:analysis:tests`). Targeted callback/import tests: 25 passed.
Independent code review checked decoder masks, control-transfer barriers,
unknown values and load-versus-address distinction. Fresh/replay integration
proves projection follows raw receipt publication, leaves its bytes unchanged,
and does not invoke the native worker on replay. Selected native Swift oracle validation is recorded below; the full F3 writer
gate remains pending. These results do not certify Swift ABI recovery.

### Owned Swift oracle (F3a only)

Apple Swift 6.4 (`swiftlang-6.4.0.34.1`, clang `2100.3.34.1`),
arm64-apple-macosx27.0.0, compiled the independently authored captured,
uncaptured, alternative, overwritten and unknown callback cases with `-O` and
`-Onone`. The binaries were not executed. Apple `llvm-objdump` plus
`swift-demangle` independently identified instruction sites and symbols.

The `-Onone` materialization-to-stack fragments and load-from-stack/BLR fragment
are regression-tested from their exact bytes. The annotation distinguishes
stack storage from object fields and memory-read values from known call targets.
The optimized source oracle proves a limitation: the first assignment in the
overwrite case is eliminated, so source statements cannot stand in for binary
assignment evidence. Alternative callback selection uses TST/CSEL; invocation
uses CBZ and retain calls; paired storage uses STP; the writer thunk uses B.
Those forms are intentionally not traversed by this slice.

This validates selected byte observations, not closure ABI or end-to-end writer
recovery. The next independent F3 slice must specify paired storage, selected
function/body identity, and bounded direct thunk-to-writer links, with explicit
branch/alias/context gaps. Do not promote a stack slot or a materialized address
to a closure field or callback target to bypass that work.

Events use `memory_load`/`memory_store`; these labels do not imply object fields.
A built wheel installed into a disposable cloud virtual environment exposes
`--callback-evidence` through its actual `macscope disasm --help` entry point.
