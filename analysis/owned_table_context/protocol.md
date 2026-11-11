# Owned constant-table context assessment protocol

Status: source/questions frozen before compilation or capture. This is an owned
experiment, not a product feature. Keep the paused focused-callee WIP untouched.
No user application, Taskovsky session, library invocation or runtime test.

## Fixture and compiler acceptance

Compile `membership.c` and `table.c` as separate C11 translation units without
LTO. They form a shared library with two exported noinline functions and hidden
read-only table data. No executable entry point or wrapper supplies a static
pointer to the pointer-negative function. Source constants are deliberately not
a recognizable domain encoding; source remains hidden from blind readers.

Use recorded stock clang on the native operator's Mac. Initial flags:
`-std=c11 -O1 -fPIC -fno-lto -fno-vectorize -fno-slp-vectorize -fno-unroll-loops`.
Compile each file separately, then link objects with `-dynamiclib -fno-lto`.
Record compiler/toolchain version, exact commands, target/SDK, source/object/library
SHA256, final symbol entries and disassembly. Do not compile or capture before
independent protocol review. No source-generated expected pseudocode is injected.

Accept only if final assembly retains actual table memory reads in the static
function and runtime-pointer reads in the negative. Establish the full bounded
footprint, load width and signed input transformation from final assembly.
Read-only file mappings must identify the static object uniquely. If optimization
folds the table, changes the intended data-access shape or creates an ambiguous
selection, report that fixture failure. Freeze a separately reviewed replacement
rather than silently changing the source/flags after seeing blind answers.

## Conditions and fairness

Use one frozen binary and the same questions for both conditions. The independent
reader receives names/addresses needed for exact selection, but no source, table
values, oracle, build comments, expected answers or source/assembly reconciliation.
An agent with source exposure must not serve as the blinded reader. Give readers
only the permitted receipt inputs and questions, not this source directory.

A. Current-tool baseline: permit the actual current decompile/dossier, xref and
byte-reading routes, including follow-up calls and manual byte decoding. Do not
handicap baseline by hiding an available byte command or forcing one-shot output.
Record the concrete commands attempted, outputs, dead ends, questions resolved,
manual decoding work and uncertainty. A current-tool answer may already succeed.

B. Attributed context packet: retain the exact same baseline artifacts and add a
small derived packet containing only the statically justified table byte range,
its request/image/receipt identities, mapping/address/file-offset proof, element
width/stride/bound evidence, raw bytes and explicitly attributed integer decoding.
Do not insert source facts, semantic labels, inferred runtime pointer identity or
an answer narrative. Keep unknowns when a chain cannot be established. The
runtime-pointer negative must not receive a guessed table packet.

Prefer independent readers with comparable tool access, or label a same-reader
A-then-B session as a non-independent paired observation with learning effects.
Freeze each baseline answer before showing the packet. Record assistance/tool
execution supplied by the coordinator equally, with no unrecorded oracle hints.
This small assessment supports a case-specific usefulness claim, not a benchmark
performance/generalization claim.

## Reconciliation and decision

Only after blind answers are frozen, compare them with independently inspected
source and final assembly. Score separately: signed transform, stored values,
reachable values, full footprint, provenance correctness, pointer-negative
restraint, missing/incorrect claims, tool steps/manual effort and known timing.
Do not conflate formatting preference with a recovered fact or saved effort.
An improvement must add a correct useful answer or measurably reduce work, without
inventing context for the pointer-negative case. If current xrefs/bytes suffice,
record that result and prefer documenting the workflow over a product feature.

No product context-join change is authorized by this protocol alone. Report
results and limitations for a separate decision. Keep all artifacts owned; no
private application numbers, addresses, pseudocode or binaries enter the repo.
