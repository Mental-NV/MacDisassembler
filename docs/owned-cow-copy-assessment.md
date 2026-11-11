# Owned copy-on-write assessment

## Decision

Defer a product change. Explicit file cloning worked in this bounded owned APFS
experiment, but it has not demonstrated a meaningful end-to-end workflow benefit
or validated the Ghidra Program lifecycle. There is no engine, retention, cleanup
or CLI change. This result does not commit the project to implementing cloning.

## Evidence and scope

The experiment used the reviewed analysis-only harness at commit
`838d12fd54b4a8ad86460f7f9e89f8f5c8a01c39`, following the
[owned-copy protocol](owned-cow-copy-feasibility.md). The operator reported three
ordinary-copy and three explicit-clone samples for each owned fixture, plus
separate injected fallback controls. Independent raw adjudication passed: the scale review rehashed all 55 manifest
files, independently recomputed the synthetic generator, verified its 36 database
and synthetic mutation checks, and confirmed the 226-file prior inventory stayed
unchanged. The separate small-tree assessment also passed review.

- Whole owned Program tree: 967,916 logical bytes. All clone arms passed content
  hashes, distinct-inode and mutation-isolation checks. The selected nonempty file
  was a 534-byte metadata file, so this alone did not test database-page mutation.
- Owned database-file control: 966,656 bytes, separately exercising the large file.
- Deterministic synthetic control: 64 MiB, not a valid Ghidra Program.

Each fixture had 18 mutation checks: destination first-byte change, destination
append and reverse source first-byte change for each of six samples. The database
and synthetic controls also passed full-file hashes and inode checks. These are
selected mutations, not an exhaustive test of writes at every offset or concurrent
access. The original 226-file inventory was verified unchanged. No inspected
application was executed, and no Program database was loaded by Ghidra. Database
files were opened for byte-level hashing and scratch-copy mutation controls.

## Timings and storage interpretation

| Fixture | Ordinary copy median | Explicit clone median |
| --- | ---: | ---: |
| Whole Program tree | 1.755 ms | 1.153 ms |
| Database file | 0.252 ms | 0.164 ms |
| Synthetic 64 MiB | 7.571 ms | 0.226 ms |

These are copy-phase measurements from three samples per method. The synthetic
recorded copy-plus-inventory subtotal was approximately 51–53 ms for ordinary copy
versus 48 ms for clone. That subtotal **excludes the unrecorded post-copy source
hash**, so it is not total workflow latency. Whole-run wall times of 2.540 seconds
for the synthetic control and 0.113 seconds for the database control mix methods,
setup and isolation controls; they cannot compare individual methods. Warm-cache,
small-sample results do not predict larger real workloads.

The sampled peak retained logical footprint was 1,429,653,868 bytes; the later
post-report count was 1,429,667,832 bytes. Both are below the 2 GiB experiment bound. Logical bytes and allocated-block observations do not establish
unique APFS physical storage or space savings. No source or evidence was cleaned up.

## What remains unproven

The fallback result is an injected `ENOTSUP` decision-path test, not an actual
unsupported-volume observation. Clone success on this volume says nothing about
other volumes, real Ghidra opening/writing/closing, crash recovery, interruption,
worker disposal, or concurrent Program access. Existing hash verification remains
necessary and limits the practical significance of a faster copy primitive.

Reconsider a product proposal only if a measured real workflow has a material copy
bottleneck and a separate lifecycle assessment justifies the integration. Until
then, retain the existing copying behavior.

## Owned evidence identity

SHA256 identities of the reviewed owned evidence (not proprietary application
artifacts):

- Small-tree report: `40659c1723a5d8b5ed2d70654aecff55be943ca8aab428a1ea335227c87c59fe`
- Small-tree assessment: `47e5e2ff8d4c78af01e870b3aa249c2d9539df453542bb894a8d4ebbfb5db915`
- Database report: `c7f636b126e4427183d0c409178d89c2ad87856357926c1ed7a971d474868abd`
- Synthetic report: `8b9f228a14ff54fb04d454cf399c89db568c800f261cc7d13f41e03011e0ea1a`
- Scale assessment: `65f78c0d5b97c3c34c9f5178b29b3b79cc776e15d57fd2ea0197e0345caa9913`
- Scale manifest: `285cd64494b5c9af6222c24102d4555dc7bbb936cf4d6889582b207239382ea0`
