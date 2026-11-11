# Selected checked-add overflow guard evidence

Spec-first callback policy 7. The owned alternate writer contains adjacent
64-bit `ADDS x19,x0,#1; B.VS overflow_trap`, currently an interpretation barrier.
An explicit selected-range `--callback-checked-add-fallthrough` permits a narrow
projection of this compiler pattern, not general flag analysis or runtime proof.

Require callback evidence and register provenance or explicit AAPCS64. Reject
combination with target/assignment/invocation receipts: this slice annotates only
the selected receipt. Defaults retain existing ADDS barriers. Receipt bytes and
capture identity do not change; projection policy and explicit mode are reported.

Recognize only 64-bit ADDS immediate `(word & 0xff800000)==0xb1000000`, with
Rn!=31 (SP source unsupported). Imm12 may shift left 12. Rd31 discards the result
but still defines the flag. Require the immediately following contiguous word
to match B.VS/B.VC `(word & 0xff00001f)` equal to `0x54000006/7` (not BC forms).
No intervening instructions, stale flags, W forms, register ADDS, SUBS or other
conditions. Unsupported pairing stops before interpreting ADDS; no skipped bytes.

Read operand before Rd write; add modulo 2^64. Concrete operands yield integer
results, never pointer provenance. Signed overflow is determined from signed
64-bit operand plus unsigned immediate. Unknown operands yield a compact scoped
`checked_add_result`, not a recovered parameter or nested algebraic expression.
Zero immediate cannot overflow, including symbolic operands. A zero-extended
32-bit shifted-ADD result plus the bounded immediate also cannot overflow
signed 64 bits; these two simple static cases discharge V=false. No general
range analysis or algebraic simplification is added.
Only the overflow flag is represented; N/Z/C are not supported.

The branch target is signed imm19*4 relative to the branch VA. Require forward
target, at most 16 path obligations total, existing 1024-instruction limit.
B.VS fallthrough requires no signed overflow; B.VC requires signed overflow.
Known contradictory flags stop at the branch, before subsequent effects.
Repeated guards with an exactly equal identity-bearing operand and immediate
retain their arithmetic relation; opposite predicates stop as contradictory.
Fresh loads and overwritten symbolic values are distinct. No guessed alias or
name-based equivalence is allowed.
Unknown flags retain an explicit unverified predicate; taken path is not analyzed.
Each later site retains the branch condition. No trap execution, callee purity,
memory alias or runtime/path feasibility claim is introduced. Calls still require
explicit AAPCS64; their memory effects and normal return remain assumptions.

Acceptance: owned contiguous native writer bytes and receipt agree with independent
oracle and expose the later store only under explicit guard+ABI assumptions;
B.VS/B.VC signed boundaries, shifts, overlapping registers, discarded Rd, unknown
inputs, impossible predicates, backwards branches, missing/foreign condition,
reserved encodings, strict default barrier and path budgets. Installed offline
replay must remain deterministic and immutable. General flag handling, two-hop
composition and attributed writer/persistence remain out of scope.

## Independent native oracle and validation

Existing owned `OwnedCallbacks` compiler artifact, Apple Swift 6.4 arm64 `-O`.
Source SHA-256: `c50bebc1ad59e159f7c353262f1440b6d3b9249c6584cb6cb1b55b82024d475a`;
binary SHA-256: `5cd6f86bce7b918a44ce97f0990c8a8c11ec69e5ffb6cdfe92a13e69d5e1423f`.
The captured source preserves its original formatting. Native linker starts
bound the selected writer to `0xa90:0xad4`, 68 contiguous bytes. Independent
native decoding verifies ADDS at `0xaa0` (`130400b1`), B.VS at `0xaa4`
(`66010054`) targeting `0xad0`, BL at `0xab8` targeting `0xd94`, and STR at
`0xabc` (`930a00f9`) storing x19 at x20+16. The overflow route ends in BRK#1.
The complete selected receipt SHA-256 is
`d267f18e52531dce3ce6dd73fd0dafa44b0cae74d967ba1089e2612880e98224`.

841 primary tests and 115 analysis tests passed. Independent review reran 49
focused tests and the actual native gate. An installed wheel outside the checkout
replayed default and opt-in twice each using nonexistent Ghidra/JDK paths, with
identical repeated output and unchanged jobs/receipts. The default still stops
before ADDS; the opt-in reaches the store with an unverified no-overflow predicate
and explicit call-preservation/normal-return hypotheses. The store value remains
a scoped symbolic arithmetic result, not an identified application field or
runtime value. The gate is `tests/integration_native_checked_add.py PROJECT MANIFEST`.

Review added impossible-path controls for symbolic addition by zero and repeated
identical arithmetic with opposite predicates. Fresh loads and changed operands
remain distinct. These are bounded path checks, not a general feasibility solver.
The input was not executed; no system CLI installation or full analysis occurred.
Two-hop linking, application attribution and consumer usefulness remain unverified.
