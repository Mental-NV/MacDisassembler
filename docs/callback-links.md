# F3b: paired storage and selected direct destination evidence

Status: implementation contract. Extends F3a without claiming full Swift ABI,
callback identity, storage receiver or persistence recovery.

## Paired memory operations

Policy `macscope-callback-sites/2` adds arm64 64-bit STP/LDP signed-offset forms
(no pre/post-index writeback, no vector or non-temporal forms). Each lane has
its own memory observation, eight-byte width, signed displacement and lane
index. Loads use the original base value; duplicate destination registers and
XZR operands are unsupported boundaries. SP remains unknown stack storage.
No aliasing, store forwarding or automatic closure-code/context pairing.

Unconditional direct B/BL produces a separate direct-branch/direct-call byte
observation and stops interpretation. Signed imm26 targets are decoded from
bytes; labels and names do not establish function identity. Branches never
implicitly start further native queries. Conditional branches remain gaps.

## Explicit selected receipt link

With `--callback-evidence --callback-target-receipt JOB`, inspect exactly one
already saved F2 receipt as the candidate destination. Verify its committed
digest, project/image/import identity, exact byte range, contiguous decoding and
selected input bytes using the existing replay checks. Bound each receipt to
4096 bytes and allow only one hop. No additional worker is launched.

A direct observation must target exactly that receipt's start, which must be a
complete linker function start with a known following start and a verified
executable, non-encrypted, non-data-in-code extent. The selected destination
range must fit that extent. Missing, unsupported, mismatching or ambiguous
function-boundary evidence stays an explicit link gap. Invalid receipt identity
fails closed using normal receipt errors, not a best-effort alternate target.

The report retains both source-envelope identities, both selections, the direct
instruction site/bytes, and destination linker proof. It projects destination
memory observations separately. A verified branch-to-entry is not proof that
a callback executes it, that two unknown receivers are the same, or that an
observed memory store persists application state. Original receipts remain
immutable. Every overall callback report remains inconclusive with those
missing requirements. A destination with unsupported instructions can retain
the verified direct link but cannot claim a writer beyond its stop boundary.

## Validation

Owned arm64 paired-operation words and independently compiled Swift fragments
cover signed offsets, both lanes, old-base load semantics, overwrite, stack
versus object-unknown bases, writeback/32-bit/vector exclusion, and direct branch
sign extension. Wrong destination, wrong image/import, non-entry destination,
truncated or stale receipts and unsupported prefixes must never create a false
writer. Fresh/replay/exportable JSON keeps all limits and missing evidence.
Full F3 assignment-to-writer readiness still requires proving callback target
and storage receiver, not merely collecting more memory instructions.

## Owned Swift oracle and limits

Apple Swift6.4 arm64 `-O` independently checked with `llvm-objdump` instruction
bytes, `--function-starts` and `nm` provides a paired-store fixture:
ADRP+ADD materializes the captured thunk, then STP stores that value and an
unknown x20 value at offsets24/32 from unknown x20. The tool reports two
memory facts, not a closure-layout declaration or known receiver identity.

The thunk consists of a direct B to the exact linker start shared by the source
writer and property setter. The independent linker stream proves the entry and
next boundary. Names alias that entry, so labels cannot establish a unique
source method. Its body begins with an unsupported stack prologue; a later
store follows a runtime call. The projection correctly refuses to claim the
later store is reached or attributed. These exact owned byte fragments are
regressions, including the negative writer-prefix case.

A full callback-to-writer proof remains deferred, not complete. Further work
needs a reviewed bounded model of frame setup and runtime-call effects, plus
receiver/closure-context identity evidence. Treat external disassembler stub
labels as unverified without bind/stub evidence; numeric branch bytes and
linker entries are the oracle used here.

## Validation checkpoint

- 692 primary tests passed; 115 analysis tests passed.
- 39 callback/import/link tests independently reviewed and rerun successfully.
- Two-receipt CLI projection is deterministic and launches no native worker;
  original receipt files remain unchanged.
- Built wheel smoke passed through the installed `macscope disasm --help`
  entry point in a disposable cloud environment.
- Owned Swift compiler oracle checks passed for paired storage and exact direct
  branch/linker entry. The real writer-body traversal is explicitly unsupported.

No binary execution, CLI installation on the user's Mac, or Taskovsky session
was part of this checkpoint. It is safe groundwork, not full F3 completion.
