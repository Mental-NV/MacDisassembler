# Owned constant-table context assessment

Status: blind baseline complete and independently reconciled against the actual
Mac source, final assembly and all 16 baseline-manifest entries. No product
context feature or enhanced packet has been implemented.

## Question and frozen material

The question was whether existing MacDisassembler commands already expose enough
evidence to recover a bounded constant table and explain its use, while leaving
a runtime-supplied pointer unresolved. This uses only the owned two-translation-unit
fixture and [frozen blind questions](questions.md), not a third-party application.

- Source/questions/protocol freeze: `e706073cdc6dc916654e938e35df5bec34e2874f`.
- Library SHA256: `6cc5e8ba67a5d4396f3d8e5f078d909fb656d678ee4e691166222502aba14423`.
- Baseline packet: 16 manifest entries. The operator's earlier count of 15 was
  corrected. The packet manifest file `reader-baseline/manifest.json` (not an archive) has SHA256
  `d05bcebf4eef3a32f531431b53351712b4ce46c2d6d05dde3fe5e812c5426972`.
- Image identity: `349bc7c2d3051d0a130d8733b7d633059e38057fef756ce519c3c6d21c1e452f`.
- Analysis identity: `38e38f58bfd587932986e837ac8533f4298501e0b0132cb863ccee9b1f20c59b`.
- The independent reader did not receive source constants or an answer oracle.
  Source and assembly reconciliation occurs only after the baseline answer froze.

The baseline packet is the evidence supplied for condition A, not an enhanced
condition-B context packet.

## Blind baseline findings

The reader independently recovered:

- Signed remainder by 19, with possible remainders from -18 through 18. This is
  signed remainder, not a mathematical modulo operation returning only positives.
- Static table address `0x3f0`, eight-byte elements, and a maximum bounded span of
  56 bytes. Early return means not every invocation necessarily reads all entries.
- Stored signed values, in order: `[-17, 0, 4, 9, 15, 23, -31]`.
- Values capable of matching the remainder: `{-17, 0, 4, 9, 15}`. Stored 23 and -31
  lie outside the remainder range and cannot produce a match.
- The second function's table is supplied through runtime register `x1`; its
  actual contents and target remain unknown. The reader did not substitute the
  nearby static table or infer application-domain meaning.

An existing 56-byte query exposed the table values. Manual `struct` decoding was
needed; no new product context join or pseudocode rewriting was necessary.
The independent source/assembly adjudication confirmed these frozen findings;
it did not replace or correct the blind answer with an oracle-derived response.

## Effort and timing observations

The reader recorded six shell calls and five CLI invocations, including two help
requests and one 56-byte query plus manual decoding. Reported command wall times
sum to approximately 0.54 seconds. This is reader-reported command time, not an
independently measured end-to-end effort figure. This excludes reasoning, coordinator/operator
work, packet preparation and orchestration. It is not total task latency, a speedup
measurement or a generalized performance result.

Separately, the native operator reported import at 4.468 seconds and baseline
analysis at 4.532 seconds, with two of two functions complete. Cached operations
were reported at 0.146–0.164 seconds. These are different stages from the reader's
command-time total and should not be added or compared as equivalent measurements.

Native logs contained trust-store, cache NullPointerException and packed-database
cache warnings. They are retained as observed diagnostics, not silently removed
or treated as evidence of a product fix. No environment changes were made for them.

## Existing-command recipe

First use current saved decompilation and instruction evidence to establish an
actual data reference, address mapping, load width, loop bound and byte order.
Inspect xrefs as supplemental evidence, not an assurance of data-reference
completeness: this case's xrefs contained only two loop branches, with no data xref
to `0x3f0`. The successful recovery used pseudocode/assembly plus bytes.
Do not start from an assumed domain or a nearby symbol. For this **owned binary
only**, the established range can be read with the existing CLI:

```sh
macscope bytes --project "$PROJECT" --address 0x3f0 --length 56 --json > owned-table-bytes.json
python3 - <<'PY'
import json
import struct
with open('owned-table-bytes.json') as source:
    result = json.load(source)
raw = bytes.fromhex(result['data']['bytes'])
assert len(raw) == 56
print(struct.unpack('<7q', raw))
PY
```

The little-endian signed 64-bit interpretation must come from the recorded image
and instruction evidence. `<7q` is appropriate for this proven owned range, not a
generic interpretation of arbitrary bytes. Preserve the bytes response's image,
virtual address and file offsets with the decoded values. Signed transformation
semantics determine which stored values can affect the result.

For the runtime-pointer negative, stop at the supported statement that the
function reads through the supplied pointer. A byte query at an invented address
would not resolve that missing runtime identity.

## Assessment and decision boundary

Condition B was not run: the honest current-tool baseline already answered the
behavior questions. There is therefore no baseline-versus-enhanced comparison,
no demonstrated automated speedup and no evidence justifying a new context feature
from this case. Documenting this existing command recipe and its caveats is the
recommended outcome, supported by the independent source/assembly confirmation.

This is one small owned example. It does not establish general recovery of Swift
metadata, dynamically selected tables, relocated or encrypted data, runtime object
identity, or arbitrary optimized control flow. The source-known negative tests
restraint about a runtime pointer; it does not prove all false associations are
prevented by the product.

### Independent adjudication

Passed. The independent reviewer inspected the actual Mac source and final
assembly, verified the source/library identities and checked all 16 files against
the baseline manifest. The signed remainder, bounded table loads, stored values,
reachable matches and unresolved pointer-negative target agree with the frozen
blind answer.

The original C functions return `int32_t`, while Ghidra prints a Boolean-like
return type. The final machine `CSET w0` yields 0 or 1, so the observed return
behavior is supported; this does **not** prove recovery of the original source
prototype. Likewise, successful byte recovery does not establish xref completeness:
the recorded xrefs show two loop branches and omit the static table data reference.

No enhanced condition B, new context feature, application/library execution or
Taskovsky session was performed. This result supports using and documenting the
existing analyzed workflow, not resuming the paused import-only product work.
