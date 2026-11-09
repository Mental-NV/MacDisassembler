# Calculator fixture: signed-int64 semantics v1.1

Version 1.1 — frozen 9 November 2026 for the post-baseline corrections.
This document is the correctness oracle for current core tests and controller
journeys. It supersedes v1.0 for new builds, not for historical measurements.

The original **v1.0 baseline** remains historical: semantics and fixture at
commit `216f28b`, baseline evaluation at `1b6e6d7`. Its outputs must not be
relabeled v1.1. New v1.1 binaries need newly recorded build hashes and test
outputs before any new baseline evaluation.

Changes from v1.0:

- Format capacity is the actual rendered length plus NUL, not an unconditional
  21-byte minimum. This matches the existing formatter and its original test.
- Digit append preserves a negative entry's sign. An explicit negative-zero
  entry sign permits sign-before-digits, including direct `INT64_MIN` entry.
- Sign before a pending RHS begins that RHS without negating the LHS.
- Successful operator-triggered chained computations enter controller history
  exactly once. This fixes the implementation to satisfy the history rule
  already present in v1.0; failed chains and consecutive operators add nothing.

## 1 Domain

- All arithmetic is signed 64-bit two's-complement (`int64_t`).
- The display shows base-ten integers. The display is a decimal rendering of
  an integer value; it does not imply floating-point arithmetic.
- Every fallible operation returns a structured status, never a wrapped
  value or a trap:
  - `CALC_OK` — value is valid.
  - `CALC_ERR_OVERFLOW` — signed overflow (add/sub/mul/negate/abs,
    `INT64_MIN / -1`, digit entry or parsing outside the signed limits).
  - `CALC_ERR_DIV_ZERO` — division with a zero divisor.
  - `CALC_ERR_INVALID` — malformed input (bad operator, bad digit string,
    unknown dispatch character).

## 2 Operator semantics

| Op | Meaning | Error cases |
|----|---------|-------------|
| `+` | checked add | overflow |
| `-` | checked sub | overflow |
| `*` | checked mul | overflow |
| `/` | C truncating division toward zero | divisor 0 → `DIV_ZERO`; `INT64_MIN / -1` → `OVERFLOW` |

- `INT64_MIN / -1`: mathematical result `9223372036854775808` is not
  representable → `OVERFLOW`. (Also avoids the single C UB case.)
- Truncation toward zero: `-7 / 2 == -3`, `7 / -2 == -3`, `-7 / -2 == 3`.
- Remainder is not exposed as an operator in this fixture.
- Unary negate of `INT64_MIN` → `OVERFLOW`. Absolute value of `INT64_MIN`
  → `OVERFLOW`.
- Unknown operator character → `INVALID`, never a default operation.

## 3 Digit entry and parsing

- Digits `0`–`9` append to the magnitude in base ten, preserving the entry
  sign: nonnegative `display * 10 + digit`, negative `display * 10 - digit`.
  Thus `-12`, then digit `3`, becomes `-123`, not `-117`.
  `calc_digit_append(0, d)` is nonnegative; only engine state can retain an
  explicit negative-zero entry sign. Negative accumulation permits direct
  entry of `-9223372036854775808` without a positive intermediate overflow.
- If the append overflows, the engine latches an error (see §5) and keeps
  the previous display value.
- Bounded string parse (`calc_parse_digits`): optional single leading `-`,
  then 1+ ASCII digits, input length capped at 64 chars. Empty string,
  lone `-`, non-digit characters → `INVALID`. Representability overflow
  → `OVERFLOW`. No whitespace skipping, no `+` sign, no hex/octal.
- Formatting (`calc_format_int64`): plain base-ten with a leading `-` for
  negatives, including `-9223372036854775808`. The buffer must hold the actual
  rendered characters plus NUL: `1` needs 2 bytes, `-1` needs 3, `INT64_MAX`
  needs 20, and `INT64_MIN` needs 21. Insufficient capacity or a null buffer
  → `INVALID`, with no writes. A 21-byte buffer is sufficient for every value.
  Integer zero formats as `0`; the controller renders an active negative-zero
  entry as `-0` (an entry sign, not a distinct arithmetic value).

## 4 Engine (state machine)

State: `display`, `accumulator`, `pending_op` (0 if none), `last_op`,
`last_operand`, `has_last`, `fresh_entry`, `negative_zero`, latched error.
`negative_zero` is meaningful only when `display == 0` and an entry is being
edited. Computations treat signed entry zero as integer zero.

- `input_digit d`: ignored while an error is latched (must clear first).
  If `fresh_entry`, display becomes nonnegative `d`; else checked append (§3),
  using the negative entry sign if `negative_zero` is set. Leading zeroes
  preserve that sign until a nonzero digit makes the value negative.
  Clears `fresh_entry`.
- `input_op op`: ignored while latched. Unknown op char → latch `INVALID`.
  - No pending op: `accumulator = display`.
  - Pending op and `fresh_entry` set (consecutive operators, no new digits):
    replace the pending op with the new one — last wins, no computation.
  - Pending op and new digits entered: first compute
    `accumulator = accumulator pending_op display`; on error latch it,
    else store the new pending op.
  - Set `fresh_entry` and clear the negative-zero entry sign.
- `equals`:
  - Ignored while latched.
  - Pending op present: compute `display = accumulator pending_op display`;
    on success remember `last_op = pending_op`,
    `last_operand = <second operand as entered>`; clear pending op;
    set `fresh_entry`; clear the negative-zero entry sign.
  - No pending op but `has_last` (repeated equals): compute
    `display = display last_op last_operand`; set `fresh_entry` and clear
    the negative-zero entry sign.
  - No pending op and no history: no-op, display unchanged.
- `clear`: resets all state including latched error, entry sign and repeat
  history. Display is `0` and `fresh_entry` is set.
- `sign_toggle`: ignored while latched.
  - If a pending op has no entered RHS (`fresh_entry`), start a zero RHS and
    toggle its entry sign to negative. Leave the accumulator unchanged.
  - Otherwise negate the displayed value, checked (`INT64_MIN` → latch
    `OVERFLOW`). At zero, toggle `negative_zero` instead.
  - A successful sign toggle clears `fresh_entry`: the signed value is now an
    editable entry. A sign-only RHS counts as an entered zero operand, so a
    subsequent operator computes with it rather than replacing the pending op.
  - With no pending op, this edits the displayed value, including a result
    immediately after equals. Repeat-equals memory is unchanged.

Worked examples (normative):

- `3 + * 4 =` → pending `+` replaced by `*` (consecutive operators),
  result `12`.
- `2 + 3 = =` → first `=` gives `5`; second repeats `+ 3` → `8`.
- `2 + 3 * 4 =` → left-to-right with pending compute: `(2+3)=5`,
  then `5*4` → `20`. No precedence beyond pending-op chaining.
- `C ± 0 1 2` → `-12`; `C 8 ± 2` → `-82`.
- `3 + ± 4 =` → `-1`, with LHS `3` and RHS `-4`.
- `3 + ± ± 4 =` → `7`; the second sign toggle restores positive entry.
- `3 + ± * 4 =` → `12`, recording `3 + 0 = 3` and `3 * 4 = 12`.
- `2 + 3 = ± 4` → `-54`: sign edits the result and the digit appends to it.
- `C ± 9 2 2 3 3 7 2 0 3 6 8 5 4 7 7 5 8 0 8` → `INT64_MIN`.
- `C` after any error clears the latch; digits then work again.
- Any digit/operator/equals key while latched (except `C`) is a no-op.

## 5 Errors

- First error wins and latches: the engine keeps the display value from
  before the failing operation and shows an error indicator until `C`.
- Errors never wrap, trap, or produce a sentinel value in `display`.
- History records only successfully completed computations, never errors.

## 6 History

- Fixed ring of the last 16 completed binary computations
  (operand1, op, operand2, result).
- `history_sum` returns the checked sum of stored results (may overflow →
  `OVERFLOW`); empty history sums to `0` with `OK`.
- History is cleared by `clear`. Repeated equals appends each repetition.
- Operator-triggered chaining records the completed pending operation once,
  before later computations: `2 + 3 * 4 =` records `2 + 3 = 5`, then
  `5 * 4 = 20`. Pressing `=` again appends only `20 * 4 = 80`.
- Consecutive operators, sign/digit entry, no-op equals, view refreshes,
  invalid new operators and failed computations add no history. A failed
  later operation preserves earlier successful history until `clear`.

## 7 Dispatch table

- A static function-pointer table maps `+ - * /` to the corresponding
  checked routine. Characters outside the table → `INVALID` without
  calling any routine.

## Reference core coverage

The instrumented calculator reference tests reached 168 of 184 branch
directions before the added edge cases. They now reach all 184 directions
in `calc_core.c` and pass 59,211 assertions. The additional cases exercise
null state and history inputs, both sides of the unsigned ordering,
oversized strings, overflow while accumulating an unsigned magnitude,
a negative digit, and overflow on a repeated equals after a successful
first result. The original directed and seeded stateful sequences still run.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/reference_coverage.py \
  --output-dir /private/tmp/new-reference-coverage \
  --experimental-trusted-input
```

The test executable is built and run in a private, network-denied directory.
Apple Clang instruments the native arm64 reference and LLVM counts source
branch directions. The report records the tool and source fingerprints and
checks the 95% reference coverage requirement. Recovered-code coverage and
behavior are measured separately. The measured report SHA-256 is
`75ed6bf9766a6bf9aeba16d7db98496cffc430196490fc259f9c9f9467f87293`.

## Recovered core behavior

The evaluator mapped all 26 public core routines by DWARF and linker-confirmed
entry after the owned tool exports were frozen. It used arm64 and x86_64
at O0 and O2, symbol-bearing and stripped copies, and both analysis profiles.
All 416 instances had complete pseudocode. LLVM decoded each confirmed body
independently, checked every instruction byte against the immutable binary,
and excluded linker-marked data. The four captures per build share a byte
denominator, so the table counts those bytes once per capture.

| Build | Routines | Primary domain complete | Full pass | Instruction bytes | Primary domain bytes | Full pass bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| arm64 O0 | 104 | 32 | 28 | 19,168 | 3,200 | 2,592 |
| arm64 O2 | 104 | 28 | 28 | 8,864 | 704 | 704 |
| x86_64 O0 | 104 | 32 | 28 | 15,408 | 2,408 | 1,876 |
| x86_64 O2 | 104 | 32 | 24 | 8,212 | 1,152 | 696 |
| Total | 416 | 124 | 108 | 51,652 | 7,464 | 5,868 |

The harnesses compile the exact recovered text on the arm64 evaluator host
with UBSan. The history and state harnesses also use ASan and compile with
strict aliasing disabled for raw memory accesses. They check the Darwin
layout, bind the printed zeroing helpers to their libc operations, and
compare observable state and returned entry addresses.
Each comparison has 121 directed pairs and 10,000 seeded pairs. Each history
routine has 111 directed cases, 10,000 seeded calls, and a separate 110-case
wide-counter run. Each state test has 145 directed cases and 10,000 checks
on states generated by a seeded reference sequence. The 124 completed
primary runs had zero mismatches, including all initialization and clear
outputs.

- Four arm64 O2 `calc_history_get` outputs overflowed signed arithmetic for
  large indices before checking whether the index was in range.
- Sixteen more outputs passed the primary domain and hit signed overflow
  in the wide-counter run. Twelve `calc_history_push` outputs overflowed at
  `LONG_MAX`. Four x86_64 O2 `calc_history_get` outputs overflowed when
  signed 32-bit arithmetic combined a large count with the ring offset.
- Eight O2 `calc_engine_sign_toggle` outputs negated `INT64_MIN` before
  checking overflow. The eight O0 outputs use Ghidra aggregate subfields
  that the C compiler cannot accept.
- 202 aggregate-return instances printed Ghidra's `undefined1 [16]` return
  form. Six printed scalar forms with an unverified aggregate ABI.
  The remaining 64 instances require buffer or state-machine harnesses.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 analysis/audit_core_behavior.py \
  --fixture-build-root /path/to/owned-calculator-build \
  --profile-matrix /private/tmp/owned-patched-profile-matrix \
  --output-dir /private/tmp/new-core-behavior \
  --experimental-trusted-input
```

Exit 6 records partial coverage. The measured report SHA-256 is
`6592ed5ee95d80eb37ebdf76ce371874ce4c30ab9715187c5d22f27a42e81f94`.
The full behavior and O2 testability gates remain open.

### Aggregate returns

Policy `macscope-ghidra-aggregate-compat/1` lowers the printed
`undefined1 [16]` form to a 128-bit value with a byte-definedness mask.
It supports fixed byte and subfield reads and writes, copies, byte-aligned
constant shifts, and the declared `SCARRY8`, `SBORROW8`, `SEXT816`,
`ZEXT816` and `SUB168` intrinsics. It supports wide multiplication when
the recovered expression explicitly sign-extends an operand. Undefined
stack bytes copied into an aggregate stay undefined. A computation that
reads an undefined byte fails. The harness checks all 12 observable
bytes of the Darwin value and status layout and records unspecified
padding separately. The parse and history cases also check input memory
for mutations.

Direct calls use captured definitions with their printed arity and
parameter types. Unresolved linkage and scalar forms with unverified
aggregate ABI receive an untestable verdict. Clang diagnoses unsupported
operations and inconsistent direct calls. UBSan and ASan run without
signed wraparound flags. The reference implementation runs separately
and supplies the expected result only.

| Build | Cases | Full pass | Undefined behavior | Compile failed | Untestable | Instruction bytes | Full pass bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| arm64 O0 | 52 | 12 | 30 | 4 | 6 | 8,816 | 3,104 |
| arm64 O2 | 52 | 32 | 16 | 0 | 4 | 3,696 | 2,096 |
| x86_64 O0 | 52 | 12 | 30 | 2 | 8 | 7,128 | 2,508 |
| x86_64 O2 | 52 | 32 | 12 | 2 | 6 | 3,216 | 2,170 |
| Total | 208 | 88 | 88 | 8 | 24 | 22,856 | 9,878 |

Each complete case ran 148 to 4,800 directed inputs and 10,000 seeded
inputs. The 917,976 completed comparisons had zero mismatches and zero
undefined observable results. The 88 UBSan failures were signed overflow
in the printed arithmetic, including negation of `INT64_MIN`.
Clang diagnosed four incorrect direct call arities, two 12-byte array
assignments and two ambiguous whole-aggregate divisions. All 16 table
dispatch captures remained untestable. The complete O2 domains across
this and the preceding disjoint cohorts cover 124 of 208 routine
instances and 6,122 of 17,076 instruction bytes. The corresponding
full-pass totals are 116 instances and 5,666 bytes.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 analysis/compare_aggregates.py \
  --fixture-build-root /path/to/owned-calculator-build \
  --profile-matrix /private/tmp/owned-patched-profile-matrix \
  --output-dir /private/tmp/new-aggregate-behavior \
  --experimental-trusted-input
```

Exit 6 records partial coverage. The measured report SHA-256 is
`e148486e3cd31d934a8de17acdf62a5aa3ade199d700e14c34b3e7c94f79cff3`.

#### Frozen held-out contract

The separate owned fixture returns a 64-bit word and 32-bit flags. One
routine rotates and masks unsigned input, and the other checks signed
addition overflow. The compatibility policy, both reference routines,
and the harness are committed before capture. The harness runs 256
directed pairs and 10,000 seeded pairs per routine. Four builds cover
arm64 and x86_64 at O0 and O2. The baseline and parameter-inference
profiles analyze symbol-bearing and stripped copies in separate projects.
The worker cannot read the evaluator files, alternate binaries, or other
projects. The fixture binaries are data-only. All exports are hashed
before evaluator-side address mapping. A matching dSYM and linker
function starts identify the routines. UUID, text, function starts and
symbol states verify the pairing.

#### Held-out results

Full Ghidra captured 16 exports with the locally patched 12.2 engine.
The policy and fixture were committed in `e9feb4d`. The final capture
revision `0896f5b` added explicit project creation and baseline analysis.
The scoring rules and fixture stayed byte-identical.

| Build | Packet routine | Checked-add routine |
| --- | --- | --- |
| arm64 O0 | 4 passed | 4 signed overflows |
| arm64 O2 | 4 passed | 4 passed |
| x86_64 O0 | 4 passed | 4 untestable `memset` calls |
| x86_64 O2 | 4 passed | 4 passed |

The 24 complete domains ran 246,144 comparisons with zero mismatches.
The arm64 O0 checked-add output adds 1 to `INT64_MAX` before checking
overflow. The four x86_64 O0 cases call an external `memset` that the
frozen policy does not bind.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 analysis/compare_heldout_aggregates.py \
  --ghidra /path/to/local-patched-ghidra \
  --java-home /path/to/pinned-jdk \
  --output-dir /private/tmp/new-heldout-aggregates \
  --experimental-trusted-input
```

The frozen plan, raw export manifest, and behavior report have SHA-256
digests `0b7e3fd94c9e2e2c09c6985f814a69d92e3e0d53e58f4174e1545aa4877e761c`,
`c0236b395972c824876c591ee10b042e56738bf167acd366438693dc4586ade5`,
and `1360166cac58ae761b62aa9c2cf47fc4893c09cec40d75c039593512de1cfec9`.

### State transitions and integer formatting

The state harness compares all named fields of the Darwin state layout
after each call. It tests initialized boundary states and states
produced by a seeded sequence of reference operations. The compatibility
policy is unchanged. Direct dependencies come from uniquely named
captured functions, including private helpers. The formatting harness
compares the status and all bytes in the caller's buffer. It binds the
printed stack-guard reference to libSystem only when LLVM-decoded
instructions and the Mach-O bind record agree on its slot. The exact
stack-check failure call compiles against the libSystem prototype.

| Routine | Cases | Full pass | Undefined behavior | Compile failed | Untestable |
| --- | ---: | ---: | ---: | ---: | ---: |
| `calc_engine_input_digit` | 16 | 0 | 12 | 0 | 4 |
| `calc_engine_input_op` | 16 | 2 | 2 | 2 | 10 |
| `calc_engine_equals` | 16 | 0 | 6 | 2 | 8 |
| `calc_engine_sign_toggle` | 16 | 0 | 12 | 2 | 2 |
| `calc_format_int64` | 16 | 4 | 0 | 4 | 8 |

Both x86_64 O2 parameter-inference operator cases passed 6,252 directed
and 10,000 seeded cases each. All four x86_64 O0 formatting cases passed
1,005 directed and 10,000 seeded cases each. Clang rejected the arm64 O0
formatting calls that pass an argument to `__stack_chk_fail`. The O2
formatting output still requires vector operations and, on x86_64,
global-data linkage. The state harness recorded 22 signed arithmetic
failures, ten misaligned stores, and six direct-call type or arity
errors. Sign toggle had no complete domain in either audit.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 analysis/compare_state_operations.py \
  --fixture-build-root /path/to/owned-calculator-build \
  --profile-matrix /private/tmp/owned-patched-profile-matrix \
  --output-dir /private/tmp/new-state-and-format-behavior \
  --experimental-trusted-input
```

The state and formatting report SHA-256 is
`536d5302877f7b20fa6db1459b3874a62352e4bd3ed02dd6e7a4f3a18a2fb9ae`.

### Combined core behavior

The three calculator reports account for all 416 routine instances.
Matching their capture keys, pseudocode digests, and instruction-byte
counts preserves the original denominator. Sixteen history cases that
completed the primary domain failed the separate wide-counter domain.
The earlier sign-toggle verdicts are superseded by the expanded state
check.

| Build | Cases | Primary domains complete | Full pass | Instruction bytes | Primary domain bytes | Full pass bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| arm64 O0 | 104 | 44 | 40 | 19,168 | 6,304 | 5,696 |
| arm64 O2 | 104 | 60 | 60 | 8,864 | 2,800 | 2,800 |
| x86_64 O0 | 104 | 48 | 44 | 15,408 | 6,596 | 6,064 |
| x86_64 O2 | 104 | 66 | 58 | 8,212 | 3,652 | 3,196 |
| Total | 416 | 218 | 202 | 51,652 | 19,352 | 17,756 |

All complete domains had zero mismatches. The O2 testability gate
remains open with 126 of 208 routine instances (60.6%) and 6,452 of
17,076 instruction bytes (37.8%) completing their primary domains.
Both measures require at least 90%.
