# Focused terminal linker-thunk boundary

Spec first. The owned final thunk is a verified last LC_FUNCTION_STARTS entry,
occupying exactly four bytes at the end of its executable instruction section.
Existing focused import policy 3 cannot select it because there is no following
linker start. This prevents direct focused pseudocode despite the bounded bytes.

Focused import policy 4 adds only this shape: ARM64, a complete unique linker
start stream proving the selected last entry, exactly four remaining bytes in
one unambiguous executable file-backed instruction section, and an unconditional
B word. Require section and segment mapping agreement, no overlapping virtual
mappings, no encryption/data-in-code uncertainty, aligned bytes and a branch
target independently proved by the existing next-linker-start policy 1. The
target cannot be self or an interior/unproved cold block. Do not infer arbitrary
last-function sizes, accept RET/BL/indirect transfers, or scan for terminators.

Retain existing mapping, byte-limit, selected native scope and tail-call checks.
Record boundary subpolicy `macscope-terminal-linker-boundary/1`, its terminal
section basis, exact source word, section endpoint and independently verified
target extent. This is a narrow terminal instruction proof, not a following-linker
boundary or general source-function recovery. A real native decompile must still
pass all worker-byte/scope/flow checks; selecting an extent alone is not success.

Default new focused captures use policy 4. Policies 1, 2 and 3 retain exact old
selection/replay semantics, including rejection of this last-entry case. Policy 3
keeps its flow classification; policy 4 uses the same classification semantics
with its own full extent/request identity. No old receipt is rewritten or silently
upgraded. Callback policy-1 extent callers remain unchanged and therefore do not
inherit a new outer-function proof or compose additional routes automatically.

Acceptance: owned actual last-thunk focused decompile and immutable saved replay;
negative RET/BL/conditional/indirect, longer final prefix, padding after B, wrong
architecture/alignment, unknown/interior/self target, overlapping sections or
segments, section/segment disagreement, malformed/ambiguous linker table,
encryption and data-in-code uncertainty. Policy-2/3 proof/replay regressions and
full native scope checks remain. No system installation or input execution.

## Native focused pseudocode validation

The actual owned `OwnedCallbacks` optimized ARM64 artifact has binary SHA-256
`5cd6f86bce7b918a44ce97f0990c8a8c11ec69e5ffb6cdfe92a13e69d5e1423f`.
Its final linker entry is 0xd78; the executable instruction section ends at 0xd7c.
Bytes `8effff17` are B 0xbb0, whose independent next-linker extent is 0xbb0:0xbb4.
Policies 1/2/3 still reject the outer entry; policy 4 records the explicit terminal
boundary and does not describe it as a next-linker-start proof.

An isolated candidate performed an actual Ghidra 12.2 read-only/no-analysis focused
decompile of those four bytes (JDK 25.0.5.0.3/aarch64, one decompiler call). The result is complete within the selected native
scope: one instruction, four decoded bytes, verified tail-call recovery, no
outside-body native operations and pseudocode forwarding to the earlier thunk.
This does not establish the earlier thunk's writer semantics or runtime reachability.
Native capture used the unchanged Java bridge, not synthetic pseudocode.

The saved native query receipt SHA-256 is
`a210afeb015a2dbdb025afdf2174d9feceb68ecffcf44d22af5158d9e2667d2a`.
The minimal portable project retains the exact owned input, manifest/index,
focused proof and query receipt, without native databases or logs. Native and
installed cloud replay with nonexistent engine/JDK paths reproduce the captured
semantic data; only normal resume metadata differs from capture. Repeated replay
is identical and leaves every portable project file unchanged.
The gate is `tests/integration_native_terminal_thunk.py PROJECT MANIFEST`.

876 primary tests and 115 analysis tests passed independently in the cloud and
on macOS 27.0.1 (26A434), Python 3.14.6, with its default temporary-directory
configuration. Independent review
passed 70 focused/flow tests and independently replayed the actual native receipt.
All 83 captured runtime source hashes matched the reviewed candidate. Explicit
policy-3 capture/replay regression coverage preserves its proof and saved bytes;
legacy behavior was not replaced by the new default. No inspected input was
executed, no system CLI was installed, and no consumer agent was restarted.
