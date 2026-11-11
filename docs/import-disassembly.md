# Bounded import disassembly (F2 slice)

Status: implemented; owned-fixture native validation passed on macOS.

`disasm --from-import --range START:END` decodes one caller-selected range
of an existing no-analysis import. Exclusive bounds cover 1..4096 bytes in one
unambiguous file-backed executable instruction section. arm64 bounds must be
4-byte aligned; x86_64 permits byte alignment. Selection is not proof that the
start is a function or instruction boundary. Embedded data/encrypted ranges
are rejected. The decoder receives only the remaining selected bytes through Ghidra 12.2's
byte-array overload (memory-less ByteMemBufferImpl); no padding or Program-memory
fallback extends its reads beyond the bound. No function creation, decompiler, autoanalysis, flow following,
or input execution occurs. Linear decoding can interpret embedded data that
is not described by loader metadata; it does not prove reachability.

Use the normal native-operation trust, pinned engine/JDK, sandbox, heap and
wall-clock gates. One disposable read-only import copy is used. Preserve both
the original and disposable Program database digests. Maximum output is 4 MiB,
maximum 4096 instruction rows; decoding stops at the first unavailable or
undecodable instruction. Report the remainder as a gap rather than guessing a
resynchronization point. Cross-boundary instructions are not emitted.

The additive `macscope-import-disasm/1` receipt records project/image/slice,
architecture, exact bounds, payload hash, import Program digest, engine/bridge
identity and row bytes. Every row must be contiguous, within the range and
match the original slice. A terminal gap is explicit. `complete` means bytes
were decoded, not that control flow, ABI or runtime behavior is proved.

`--receipt JOB_ID` together with the same `--from-import --range` replays the
saved envelope without native work or trust prompt. Changed bounds, slice,
project, recorded Program identity, receipt hash or row bytes fail closed.
Offline replay does not inspect retained Program database bytes; they may be
unavailable. A new capture verifies the actual import database digest. No implicit
cache lookup. JSON/JSONL/text and `--output` share the same validated envelope.
Job cancellation/status use the existing worker manager; native restart via
`jobs resume` is intentionally unsupported for this receipt version: repeat
the explicit range command instead. Offline replay needs the project input
and receipt, but not an installed Ghidra/JDK or original source application.

Acceptance: owned arm64/x86_64 instruction oracle; malformed mappings, limits,
alignment, data-in-code/encryption, undecodable and crossing instructions;
tampered bytes/receipts/identity; unchanged database and no autoanalysis;
package entrypoint capture/replay with no extra jobs. Unrun native checks
remain a release blocker, not an implied pass.

## Verification checkpoint

The final implementation passed 666 primary tests and 115 analysis tests.
The packaged entrypoint was checked on owned arm64 and x86_64 Mach-O fixtures:
instruction bytes matched the native disassembly oracle, the read-only/no-analysis
worker left both Program databases unchanged, and a crossing x86 instruction
returned explicit partial coverage (exit 6). Offline receipt replay created no
new jobs, required no trust prompt, and succeeded without available engine/JDK
paths. These checks establish the bounded fixture contract, not general semantic
equivalence or support for arbitrary malformed binaries.
