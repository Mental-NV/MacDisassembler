# Practical hybrid investigation workflow

Use this recipe to answer one concrete behavior question with existing tools.
Choose a bounded function capture in a large image, or analyze a small relevant
framework once and reuse its cached results. This is a workflow, **not a new
recovery feature**, an application emulator or evidence of UI parity. The recent
seven-question investigation could answer or explicitly bound its questions with
current tools; that does not establish general decompiler completeness.

## 1. Verify the tool, trust and workspace

Only inspect binaries the owner has explicitly authorized and trusts. Ghidra
processing is not a hostile-input sandbox. `--trust-input` acknowledges that
risk; it does not execute the inspected application or authorize unrelated work.
Do not install/upgrade anything as part of this recipe.

```sh
macscope version --json
macscope doctor --static --full-digest --ghidra "$GHIDRA" --java-home "$JAVA_HOME" --json
```

Set the same verified runtime paths for subsequent commands; doctor does not set
these defaults for you:

```sh
export MACSCOPE_GHIDRA="$GHIDRA" MACSCOPE_JAVA_HOME="$JAVA_HOME"
```

Record tool/package version and source commit, dependency fingerprints, host and
input hashes. Static doctor checks files, not successful native startup. An initial
worker probe, import or analysis has separate startup/time/storage costs.

Use a new project, or a **quiescent private full copy** of an existing project.
Never copy a project while a worker writes it. Keep the original untouched.
The following checks are for an **existing quiescent project copy only**. For a new
path, skip this block, create/import the project in section 2 first, then inspect
jobs and verify Program digests before continuing:

```sh
macscope jobs list --project "$MAIN_PROJECT" --json
macscope status --project "$MAIN_PROJECT" --verify-programs --json
```

All `$...` values below are operator-supplied placeholders, not discovery results.
`MAIN_IMAGE`/`SMALL_IMAGE` are exact saved image IDs, `FUNCTION` is an independently
selected unslid function entry in that image, and `QUERY_JOB` is a completed
focused capture job ID. Never transplant an address between builds/images.
Native examples use one worker, bounded wall/startup/function budgets and a
2048 MiB **Java heap**, not a hard whole-process memory limit. Resolve defaults
with the verified `MACSCOPE_GHIDRA`/`MACSCOPE_JAVA_HOME` environment, or supply the
corresponding explicit paths on each native invocation.

## 2. Large image: exact import-focused selection

If no suitable saved import exists, create a private project and import only the
selected executable. Skip these two commands when using an already verified copy.
Do not include every bundled image just in case.

```sh
macscope project create "$MAIN_PROJECT" --json
macscope import "$MAIN_BINARY" --project "$MAIN_PROJECT" --arch arm64 --trust-input --timeout 300 --startup-timeout 120 --function-timeout 25 --heap-mib 2048 --jobs 1 --json
```

Read import/status output for the saved image ID. Obtain an exact candidate entry
from existing symbols, Objective-C metadata or byte-backed references. Then:

```sh
macscope decompile --project "$MAIN_PROJECT" --image "$MAIN_IMAGE" --from-import --address "$FUNCTION" --preflight --json
macscope decompile --project "$MAIN_PROJECT" --image "$MAIN_IMAGE" --from-import --address "$FUNCTION" --trust-input --timeout 240 --startup-timeout 120 --function-timeout 25 --heap-mib 2048 --max-functions 1 --jobs 1 --json
macscope xrefs --project "$MAIN_PROJECT" --image "$MAIN_IMAGE" --address "$FUNCTION" --query-job "$QUERY_JOB" --direction both --limit 50 --json
```

Preflight verifies static selection, **not** native support, successful startup or
pseudocode quality. A rejection is a boundary to investigate, not permission to
force a function body. Capture prepares only the selected extent in a disposable
copy; it does not perform whole-image analysis. Save the output and producing job.
`xrefs --query-job` reads that saved focused receipt without starting an engine;
it requires the same exact function address, not `--to`/`--from` address mode.
Focused xrefs can legitimately return a partial report with **exit code 6** and
`incoming_scope_not_global`: the selected capture cannot establish global incoming
references. Retain the report and diagnostics; do not assume every useful result
exits 0, or retry native capture merely to remove this expected coverage limit.
Never combine this path with analyzed-query signature-recovery options or assume
that a planned import-only feature exists.

## 3. Small framework: analyze once, read cached evidence

Use this when the question falls inside a suitably small relevant executable and
a bounded analysis is affordable. Keep it separate from the large-image project.

```sh
macscope project create "$SMALL_PROJECT" --json
macscope import "$SMALL_BINARY" --project "$SMALL_PROJECT" --arch arm64 --trust-input --timeout 300 --startup-timeout 120 --function-timeout 25 --heap-mib 2048 --jobs 1 --json
macscope analyze --project "$SMALL_PROJECT" --image "$SMALL_IMAGE" --profile baseline --trust-input --timeout 300 --startup-timeout 120 --function-timeout 25 --heap-mib 2048 --max-functions 200 --jobs 1 --json
macscope functions list --project "$SMALL_PROJECT" --image "$SMALL_IMAGE" --name-contains "$NAME_HINT" --limit 20 --json
macscope decompile --project "$SMALL_PROJECT" --image "$SMALL_IMAGE" --address "$FUNCTION" --json
macscope disasm --project "$SMALL_PROJECT" --image "$SMALL_IMAGE" --address "$FUNCTION" --json
macscope xrefs --project "$SMALL_PROJECT" --image "$SMALL_IMAGE" --address "$FUNCTION" --direction from --limit 50 --json
```

The last four commands read committed evidence. A function cap or timeout can leave
partial coverage; inspect status, diagnostics and truncation, not just exit code.
Absence from a capped result is not evidence that a function/reference is absent.
Cached reads are not comparable to first import/analysis time. Record both stages,
project/cache storage, manual analysis and coordinator effort separately.

Only when a specific missing direct-call input justifies it, compare an explicit
fresh parameter-recovery result with the untouched cached baseline:

```sh
macscope decompile --project "$SMALL_PROJECT" --image "$SMALL_IMAGE" --address "$FUNCTION" --fresh --recover-callee-parameters --trust-input --timeout 240 --startup-timeout 120 --function-timeout 25 --heap-mib 2048 --max-functions 1 --jobs 1 --json
```

This reopens the saved analyzed Program in a query copy. It is not a cached read,
not a source-prototype oracle, and not a fix for arbitrary hidden context or an
unknown indirect target. Record the actual applied/skip/refusal outcome and both
job identities. Do not enable every recovery option or rerun blindly after failure.

## 4. Join exact context; keep unknowns visible

Use either project/image pair consistently for these static queries. `DATA_VA`,
`SLOT_VA`, `CLASS_SLOT` and `LENGTH` must come from evidence; length is a proven bounded span
(maximum 4096 bytes per command), not a guessed neighboring object.
These are optional queries, not a checklist to run blindly: use a metadata family
only when applicable to the selected image, and use slot-based queries only with
a verified slot. An absent metadata family can yield an empty result; that is not
a coverage guarantee or permission to invent a class/fixup slot.

```sh
macscope bytes --project "$MAIN_PROJECT" --image "$MAIN_IMAGE" --address "$DATA_VA" --length "$LENGTH" --json
macscope fixups --project "$MAIN_PROJECT" --image "$MAIN_IMAGE" --address "$SLOT_VA" --kind all --limit 50 --json
macscope objc methods --project "$MAIN_PROJECT" --image "$MAIN_IMAGE" --name-contains "$NAME_HINT" --decode-types --limit 20 --json
macscope objc ivars --project "$MAIN_PROJECT" --image "$MAIN_IMAGE" --class-slot "$CLASS_SLOT" --decode-types --limit 20 --json
macscope swift symbols --project "$MAIN_PROJECT" --image "$MAIN_IMAGE" --name-contains "$NAME_HINT" --limit 20 --json
```

Keep image/analysis/job identities, virtual and file offsets, raw bytes, load width,
endianness, signedness, bounds and the decoding calculation with each conclusion.
A table's maximum bounded footprint need not be read in full on every execution.
Decode integers only after establishing representation; preserve negative-value
semantics instead of assuming mathematical modulo or domain-specific meanings.

- **Xrefs:** missing data references are possible. Verify pseudocode against
  instructions and mapped bytes; a branch-only xref list is not a complete data map.
- **Fixups and zero-filled/writable data:** file bytes may need relocation and may
  not exist for zero-fill. A static slot is not its post-initialization value;
  writable state is not a runtime snapshot. Do not turn unmapped bytes into zeroes.
- **Selectors and receivers:** a selector string or method declaration does not
  identify the actual receiver class or dispatch result. Metadata type decoding
  displays declarations; it does not apply source signatures to pseudocode.
  Ivar names/offsets require the verified class-list slot in the same image; they
  do not identify a runtime receiver on their own.
- **Vtables, callbacks and pointers:** an offset or conditional call relationship
  does not establish the runtime object, table contents or indirect target. Say
  which receiver/context/path remains unknown rather than choose a nearby symbol.
- **Output types and UI:** a decompiler's Boolean-like return may only establish
  machine 0/1 behavior, not the original prototype. Static evidence can establish
  dimensions or conditional paths, but not by itself actual runtime layout,
  animation, scrolling or other visible behavior; those need separately
  authorized observation of the real application.

## 5. Close the investigation

Return a compact answer with evidence links, known conditions, unresolved facts,
actual commands/jobs, diagnostics and costs. Keep binaries, source excerpts and
application-specific packets in the authorized private workspace; public docs use
only generic instructions or owned fixtures. Do not publish proprietary artifacts.
On timeout, cancellation, uncertain teardown or integrity failure, retain logs,
stop the affected attempt and report the blocker. Do not raise limits, delete
caches, edit original projects or install tools silently. Prefer a documented
existing-command recipe when it already answers the question; request a new
feature only after a concrete, independently demonstrated gap remains.

## Validation scope

All examples have parser/help-only checks. A separate owned small-fixture exercise
ran 19 commands and four native jobs across the main routes. Its focused-xref
partial exit stopped a success-only wrapper; the report was retained and unaffected
checks continued. This was not a native worker failure. That exercise does not
validate large-image cost or coverage, nor the optional fresh recovery, fixup or
ivar routes. Those still require applicable evidence and their own validation.
