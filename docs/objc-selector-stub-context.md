# Selected ARM64 Objective-C selector-stub context

## Evidence and purpose

Owned fixture `OwnedReturnChannels` establishes an actual usability gap: raw
message-send pseudocode may preserve selector text but cannot resolve dispatch;
return-only annotation was rejected because it hides arguments and can fabricate
a return contract. Instead expose exact static selector/import facts separately.
Native disassembly and independent Mach-O parsing agree for the owned arm64
binary SHA256 `84c26dc727d7ba388fec3b805aec6dfc72caea961c8b4b613c4c5bc9acff51ee`:
`B 0x760` at `0x6fc`, five-instruction selector stub at `0x760`, selector reference
`0x8098` to `ownedInteger`, and GOT slot `0x4010` declared `_objc_msgSend`.

## Bounded opt-in contract

Add `evidence --objc-sends`, with additive versioned `objc_send_context` sidecar.
Only explicit query_job leads pinned to committed import Programs qualify.
Reopen and validate exact saved focused receipts and verified input bytes. Never
run an engine, infer a function from a selector name, or scan the entire image.
Default report bytes and raw pseudocode stay unchanged without the flag.

Support arm64 only, not arm64e or x86. At captured instruction boundaries decode
four-byte unconditional B/BL and verify bytes/target against the imported slice.
The target must start an exact 32-byte slot boundary relative to the start of one executable
`__objc_stubs` section. Accept only this narrow 20-byte instruction template:
ADRP x1; LDR x1,[x1,#imm]; ADRP x16; LDR x16,[x16,#imm]; BR x16.
Require remaining 12 slot bytes to be three BRK #1 padding instructions.
Prove mapped, unambiguous section and byte ranges; require aligned source/target.
Do not generalize authenticated, small or differently padded stubs.

The selector slot must lie wholly in one `__objc_selrefs` section. Resolve it
with existing bounded metadata pointer/fixup validation and read the bounded
selector string. The x16 slot must lie in one non-executable pointer section;
require exact `_objc_msgSend` declaration from both validated indirect-symbol
slot evidence and a matching zero-addend bind relocation. Conflicting, weak,
missing, ambiguous or unsupported pointer evidence stays unresolved. No lookup
by string alone, unchecked pointer masking or raw fixup-word interpretation.

Record input/slice/Program/receipt hashes, callsite bytes and B versus BL, stub
bytes/addresses, selector-reference address/string and import-slot declarations.
Callsite-to-stub is a static instruction target, not proof execution occurred.
Selector text does not identify receiver class, method IMP, return contract,
side effects or runtime implementation. All remain explicitly unknown. Do not
label this resolved runtime dispatch, erase flow gaps or promote graph completion.

Bound to 16 selected leads, 512 captured instructions per receipt, 16 candidate
sites per receipt and 64 total candidate sites; explicit omissions/unknowns when
limits hit. Reuse bounded parser limits and pointer cache. Sidecar status remains
partial because dynamic dispatch/global coverage are unknown; requested sidecar
retains exit6. Output in JSON/text and short dossier summary with terminal-safe
escaping. No automatic code rewriting or new inferred callgraph edges.

## Acceptance gates

- Independent native oracle and exact owned input reproduce selector/import
  evidence for integer and float stubs and B/BL sources.
- Mutated instruction/register/target, wrong section/alignment, padding, selector
  pointer, symbol/bind/addend and architecture cases never claim a match.
- Stale receipt/Program/image identity fails; bounds and omission counts truthful.
- Raw pseudocode, saved receipts and defaults unchanged; no engine or original
  app needed for repeated installed-package export; repeated sidecars identical.
- Full primary and analysis tests plus independent review before publication.

## Presentation and compatibility refinements

Slot alignment is **relative to the __objc_stubs section start**, not absolute
32-byte alignment. Independently require ARM64 instruction alignment. Each
verified row means only `verified_static_selector_path`; overall status remains
partial. Empty/unsupported/limited results never mean no Objective-C sends.

JSON/text carry the additive sidecar; existing HTML escapes and includes it as
report metadata. Dossier shows at most four safe summaries; compact explicitly
says context details are omitted. Sanitization changing a receipt's context
suppresses its site facts with `context_redacted`, avoiding verification claims
about altered strings. Dossier rejects unknown sidecar policies. Saved handoff
diff with this optional section is explicitly unsupported and fails rather than
silently omitting it; baseline handoffs without --objc-sends remain comparable.

`return_contract: unknown` refers specifically to the dispatched call, not all
return behavior of its containing function. Receipt context stays partial with
an explicit dynamic-dispatch/global-coverage reason even when the source query
was complete. Original engine gaps and additive static path facts have different
scopes and are both retained. This is not an exhaustive send inventory.

## Usage and measured validation

Use an existing pinned evidence lead manifest with explicit `query_job` entries:

```sh
macscope evidence --project WORKSPACE --leads selected-leads.json --objc-sends --format dossier
macscope evidence --project WORKSPACE --leads selected-leads.json --objc-sends --format json
```

The owned four-receipt trial yields these static selector paths, not return types:

| Captured source | Instruction | Stub | Recorded selector |
| --- | --- | --- | --- |
| `0x6fc` | B | `0x760` | ownedInteger |
| `0x704` | B | `0x760` | ownedInteger |
| `0x714` | BL | `0x760` | ownedInteger |
| `0x728` | B | `0x740` | ownedFloat |

Independent native disassembly and Mach-O readers corroborate the stub bytes,
selector slots and `_objc_msgSend` import declaration. The sidecar deliberately
makes no distinction between a source-level return and discarded result: that
cannot be recovered from this transfer shape. Independent consumer review found
that the added paths aid dependency investigation without changing raw evidence.

Independent implementation review caught and corrected nonzero inline chained
bind addends and conflicting symbol-table/bind library identity. Regression tests
cover those counterexamples, missing chained addend, unsupported pointer format,
weak symbols, stub-word mutations, duplicate sections/imports, stale receipts,
source bytes, bounded sites/instructions and redacted context. Final cloud tests:
955 primary and 115 analysis, passing. Installed offline replay is deterministic;
baseline output without the flag is byte-identical and optional context preserves
all original lead/pseudocode/coverage fields. The initial exact native candidate
also passed 955 primary and 115 analysis tests and the four-receipt installed
replay, with all portable project hashes unchanged and no new jobs.

Exact final runtime `a28641fa` passed the native rerun on macOS 27.0.1 with
Python 3.14.6: 955 primary and 115 analysis tests. A fresh temporary installed CLI
again reproduced all four owned selector paths, retained baseline lead/pseudocode
payloads, exported JSON/dossier/HTML offline with exit6, and left every portable
project file hash unchanged with no new jobs. Sidecar diff returned exit2 with
`evidence_diff_unsupported`. Archive SHA-256:
`54af23331856eb962b68a715513a5751fceda2d6fe4d5557cfdb6a5fb289219f`.
No native engine, UI, installed system CLI or Taskovsky session was changed.
