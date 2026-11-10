# macOS Binary Analysis CLI Specification

Version 0.2 for review | Updated 10 November 2026 | Working command name `macscope`

## 1 Selected architecture and scope

**Architecture decision:** full Ghidra headless is selected for MacDisassembler. Use the full Ghidra distribution for Mach-O loading, program analysis, disassembly, function/reference recovery, and C-like pseudocode. The CLI supplies orchestration, evidence records, persistence, macOS-specific presentation, and validation around that pipeline. This selection uses Ghidra's loader and analyzers as well as its decompiler; it is not a standalone decompiler library or an r2ghidra/rz-ghidra plugin. Do not implement a new instruction lifter or decompiler for the first release.

The full Ghidra headless approach is approved and an experimental implementation now exists, including owned fixtures and measured validation. This broad specification remains a roadmap rather than a completion claim. Use [current status](current-status.md) and the [implemented CLI contract](cli.md) for supported commands and recorded results. Numeric gates below remain proposed targets unless a validation record explicitly reports that they passed.

The intended outcome is a reusable, local-first alternative to the essential analysis features of Hopper, not a replica of Hopper's interface or all of its capabilities. The tool must work without Hopper, paid IDA editions, or an LLM subscription. REA already supports a Ghidra provider and remains an optional comparison and integration path. The initial experiment must establish which additional CLI capabilities need to be built around the selected full Ghidra headless pipeline. [REA repository](https://github.com/morluto/rea)

**Primary users:** developers inspecting their own macOS software and authorized third-party binaries, including the existing Taskovsky research workflow. **Primary output:** address-linked disassembly, function pseudocode, references, metadata, and machine-readable reports. **Not promised:** original source, original variable names, a compilable recreation of an app, equivalent UI, or verified semantic equivalence of an arbitrary binary.

### 1.1 Required outcomes

- Inspect thin and universal Mach-O files for arm64 and x86_64, and resolve a selected executable from a macOS app bundle.
- Find functions, symbols, strings, imports, exports, sections, Objective-C metadata, and available Swift names.
- Produce assembly, control-flow graphs, call relationships, and C-like pseudocode with address provenance and explicit unknowns.
- Persist user names, comments, type hints, and analysis results without modifying the input binary.
- Expose stable CLI commands and versioned JSON for scripts and future MCP clients.
- Validate on a purpose-built calculator whose source is known to the evaluator but hidden from blind analysis.
- Support repeatable project analysis and private exports for future Taskovsky scenarios.

### 1.2 Explicit exclusions

Version 1 excludes a GUI, live debugger, process injection, binary patching, re-signing, DRM removal, decrypting protected apps, dumping protected process memory, bypassing platform security, exhaustive runtime target resolution, kernel collections, and dyld shared-cache extraction. It does not recreate Apple frameworks. Packed or encrypted code receives a clear unsupported or partial status. SwiftUI source reconstruction and complete Swift semantic recovery are not release requirements.

Hopper's published feature list includes pseudocode, CFGs, Objective-C and Swift assistance, scripting, and debugging. This specification selects the static-analysis subset and replaces GUI navigation with queries and exports. It does not claim feature-for-feature or quality parity. [Hopper features](https://www.hopperapp.com/)

## 2 Product architecture

### 2.1 Components

**CLI and orchestration:** Python 3.12 or a later explicitly tested version, with a small argument parser and structured models. Prefer the standard library where practical. Keep CLI help/version, bounded input preflight, and queries against completed metadata snapshots independent of JVM startup. Fresh engine import, analysis, and uncached decompilation require the headless worker; do not present cached-only queries as fresh analysis. Package as a Python wheel first; consider a signed macOS launcher later after the workflow is proven.

**Analysis worker:** the full Ghidra installation's `support/analyzeHeadless` launcher, with a small, project-owned Java script/bridge compiled and tested against one exact Ghidra release. This is the MVP integration baseline. Launch it as a separate process with explicit argument arrays, not shell interpolation or an embedded JVM in Python. Use Ghidra's Mach-O loader, Program database and configured auto-analyzers; invoke `DecompInterface` against the resulting Program for pseudocode. The bridge uses public Java APIs and exports normalized records instead of scraping UI text. A CLI process communicates through bounded request and result files in a private workspace. A persistent full-Ghidra worker may be considered later only if measured startup cost warrants it; it is not an MVP assumption.

**Storage:** a project manifest, immutable input snapshots, the full Ghidra project's Program database, a SQLite metadata index, append-only annotation revisions, and versioned JSON exports. A schema version and migration policy apply to the CLI index independently of the Ghidra project version. Do not use the engine database as the public interchange format.

**Reference tools:** Apple/Xcode command-line tools and LLVM objdump for independent header and instruction checks during validation. These are validation aids, not additional mandatory engines for ordinary pseudocode generation.

**REA adapter:** optional integration to a pinned REA MCP server using its Ghidra provider. The core CLI works without REA. Initially consume REA evidence for comparison and workflow validation; do not assume an arbitrary custom provider can be registered without a separate integration effort.

The Ghidra decompiler API returns C markup and a high-level function representation and reports per-function errors. Its headless analyzer is documented as not thread-safe. Isolate workers and serialize operations per project rather than sharing one analyzer instance across threads. [Decompiler API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html) [Headless API](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessAnalyzer.html)

### 2.2 Reuse versus new work

Reuse Ghidra's loader, instruction semantics, function analysis, p-code, SSA and data-flow analysis, type recovery, control-flow structuring, and C printer. New work is the CLI contract, policy controls, job management, artifact identities, address normalization, JSON schema, evidence links, annotation history, safe bundle handling, quality checks, and Taskovsky-facing report workflows. Improve an engine analyzer only after a small reproducer demonstrates a real gap.

Do not add LLVM IR lifting, symbolic execution, another disassembler, or an LLM to the critical path merely because these are available. Each adds compatibility and validation costs. Optional tools should answer a demonstrated question.

### 2.3 Selected approach and evaluated alternatives

| Option | Suitable role | Tradeoff and decision |
| --- | --- | --- |
| Full Ghidra headless | Selected importer, analyzer and decompiler | Required core engine. Accept the JVM/native component footprint and validate the complete loader-to-pseudocode pipeline. |
| PyGhidra | Alternative binding to full Ghidra | Not selected for the MVP integration. Use the headless launcher and Java bridge above; there is no pending bridge-selection spike. A future binding change needs a separate design review. |
| radare2 with r2ghidra | Evaluated native CLI alternative | Not selected and not a fallback. Its loader and analysis are not full Ghidra, even though the decompiler shares upstream code. |
| Rizin with rz-ghidra | Evaluated CLI and decompiler plugin | Not selected and not a fallback; separate loaders, APIs and release coupling. Cutter is not a dependency. |
| RetDec | Evaluated secondary engine | Not selected for the product. Limited maintenance and packaging costs would require a separately justified comparison effort. |
| angr | Advanced research and targeted symbolic checks | Powerful analyses, but Mach-O integration and path explosion make it a poor default for the first macOS product. |
| LLVM objdump or Capstone | Assembly decoding and differential checks | Neither alone reconstructs high-level pseudocode. They are not substitutes for a decompiler. |
| LIEF | Optional Mach-O metadata helper | Useful parser; not an instruction decompiler. Avoid a second parser in the mandatory path unless it closes a verified gap. |

The engine choice is settled. This comparison records the rationale, not a set of backends to implement or automatically select. Missing, incompatible, or failing Ghidra components produce typed failures; they never trigger a switch to another engine. Licenses, candidate version pins, and distribution constraints are specified in section 13. Capability advertising does not replace acceptance tests on the actual Mach-O corpus.

### 2.4 Full headless execution contract

1. **Preflight:** resolve an explicitly configured full Ghidra installation, its headless launcher, compatible JDK, host-native decompiler executable, and the matching project-owned Java bridge. Record versions and integrity identifiers. Check host architecture separately from target Mach-O architecture; analyzing an x86_64 target on an arm64 host does not imply an x86_64 worker or Rosetta. Do not download, build, install, or substitute missing components automatically.
2. **Import:** create the immutable input/slice snapshot, then use headless import into a private Ghidra project. Select and record the actual Mach-O loader, language and compiler specification. Keep import separate from analysis using the pinned release's supported no-analysis mode; validate the exact flags before implementation. Bounded CLI header preflight does not replace Ghidra's authoritative loaded Program.
3. **Analyze:** process the imported Program through headless Ghidra with an explicitly versioned analyzer profile. Trusted project-owned pre/post scripts apply the tested options and export analysis metadata. Record the complete effective options, warnings, coverage and stage status; no arbitrary scripts or plugins from the input directory are discovered or executed.
4. **Query and decompile:** serve completed normalized snapshots when available. For uncached work, reopen the selected Program through the headless worker and call the public Java APIs, including `DecompInterface` for requested functions. Query-only runs disable automatic reanalysis and use the pinned release's supported read-only project mode. Analysis and annotation changes instead take the project writer lock and use explicit transactions. No Hopper, REA, PyGhidra, r2ghidra, or rz-ghidra process is in this core path.
5. **Complete or fail:** export bounded, schema-validated results atomically, close the Program/project, and release the worker and lock. Record launcher/JVM, import, analysis and native-decompiler failures separately. A successful process exit alone does not prove analysis or every function completed; combine process status with bridge results, timeout state and per-function errors. Cancellation may terminate only the job's owned worker process group, including its native decompiler child.

The startup and memory cost of the full distribution is an accepted architectural tradeoff, not an excuse to omit limits or silently use a lighter engine. Batch selected functions in one worker job where useful. Preserve completed results across worker failures, and measure cold worker, reopened-project and cached-query latency separately.

### 2.5 Focused-query control-flow evidence amendment

The implemented experimental focused path is described in
[the CLI contract](cli.md#decompile-one-function-from-an-import). A successful
native C printer is not sufficient for complete selected-function coverage.
The CLI must review instruction fallthroughs and raw CFG edges before native
optimization, reporting non-call scope escapes and incomplete or unresolved
boundary evidence as partial. It must also report unresolved computed jumps
and native operations outside the selected body. Zero outside operations in
optimized p-code cannot establish confinement because optimization may remove
those operations or propagate their constants. Complete address spans cover
retained in-body tokens only. Scope scans and recovery requests must be bounded
and include their limits and evidence.

For exact no-analysis ARM64 queries, a direct unconditional terminal branch
may be modeled as a tail call only from verified instruction bytes to an
independently confirmed linker start or ordinary, strongly bound import stub.
Record the original flow, effective flow, source/target proof and worker
request digest. Never infer a function boundary from an arbitrary executable
destination or remove a warning merely to improve a status. Recognize a BRK
exception only from architecture-gated terminal instruction bytes; retain
original CFG and printer evidence. Real register/conditional indirect jumps
remain unresolved without independent target evidence.

All such flow overrides belong only to the disposable read-only Program
copy. Input bytes, persisted imports and the isolation policy remain unchanged.
Use project-owned positive and adversarial fixtures before any authorized
private acceptance check; never commit third-party binaries or recovered code.
This amendment is a scoped implementation contract, not a claim of arbitrary
binary completeness or semantic equivalence.

## 3 Input support and macOS requirements

### 3.1 Support levels

**Required:** little-endian 64-bit Mach-O executable, dylib, and bundle images; arm64 and x86_64 slices; fat and fat64 containers; local files and app bundles; symbol-rich and stripped binaries; common Clang C/C++ and Objective-C code. Analyze each universal slice independently. Universal is a container, not a third instruction set.

**Best effort with warnings:** Swift metadata and demangling, blocks, C++ exception paths, indirect calls, optimized code, stripped Objective-C classes, newer load commands, and unfamiliar chained-fixup pointer formats. A warning must name the affected image or function and the missing capability.

**Experimental after validation:** arm64e and pointer-authenticated call/data paths. Recognizing a CPU subtype does not establish correct decompilation. Unknown PAC semantics or pointer formats must not silently be treated as ordinary arm64 pointers.

**Out of scope initially:** 32-bit Mach-O, iOS application packaging, object archives and relocatable object files as a full project workflow, firmware, encrypted code, kernel collections, and standalone shared-cache containers.

### 3.2 Bundle and image handling

Accept either an explicit Mach-O path or `.app`. For an app, read `Contents/Info.plist` as data, obtain `CFBundleExecutable`, resolve `Contents/MacOS/<name>`, and verify that it is a regular file within the allowed bundle boundary. Never execute the app to discover its main image. Reject missing or ambiguous entries with actionable diagnostics.

`bundle list` enumerates potential embedded code and resources without importing all of them. `import --include-images` requires explicit relative image selections or a deliberate `all` value. Resolve framework symlinks within the bundle safely; do not follow escapes or read devices, sockets, or FIFOs. Never recursively scan the user's filesystem through a bundle link.

Recent Xcode Debug products may place app logic in a companion `.debug.dylib`, with a small launcher executable. The calculator baseline must set `ENABLE_DEBUG_DYLIB=NO`, and general bundle inspection must identify a companion debug image rather than report that the application has no useful code. [Apple build product layout](https://developer.apple.com/documentation/xcode/understanding-build-product-layout-changes)

### 3.3 Loader evidence

Record CPU type/subtype, file type, UUID, segment/section ranges and protections, preferred image base, entry point, dependent libraries, rpaths, symbol tables, export trie, indirect symbols, stubs, lazy/non-lazy pointers, function-start information, data-in-code records, unwind information, and code-signature/encryption-command presence. Parse supported dyld binds/rebases and chained fixups without loading or executing dependencies. Distinguish an unresolved external reference from a pointer whose fixup format is unsupported. [Apple Mach-O definitions](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)

`__PAGEZERO` and zero-fill regions have virtual addresses but no backing file bytes. Metadata output must allow a null file offset. System framework imports remain external unless the user explicitly supplies a compatible image. Displaying a code-signature blob is not signature validation or a statement that the app is trustworthy.

### 3.4 ABI handling

Select the correct processor language and macOS compiler specification from the installed engine's supported identifiers, and record both. Do not hard-code a generic ARM64 ABI as interchangeable with Apple's ABI. Model argument/return registers, stack alignment, preserved registers, stack arguments, variadics, structure returns, sign/zero extension, and floating-point/vector registers through tested backend specifications. Include x86_64 RIP-relative addressing and arm64 ADRP/ADD address formation in the corpus. [Apple ARM64 ABI](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)

Objective-C output must preserve selector names, class/method metadata, and observable message-send sites. A selector is not proof of a unique runtime target. Swift demangling improves labels but cannot reverse inlining, specialization, protocol dispatch, ARC, async lowering, or source-level SwiftUI declarations.

## 4 Required CLI contract

The proposed command name `macscope` is provisional. Every command supports `--help`. The executable exposes `--version` and a machine-readable `version --json` with CLI, schema, backend, bridge, and dependency versions. Unknown options fail instead of being ignored.

### 4.1 Common conventions

- Read-only commands never mutate a binary. Analysis and annotations mutate only the explicit project workspace.
- `--project PATH` selects a workspace; `--image ID` and `--arch arm64|x86_64` disambiguate multi-image projects. For a multi-slice input, omission of architecture on a slice-specific operation is an error, not a host-dependent default.
- `--format text|json|jsonl` applies where appropriate. JSONL is streamed for large collections; JSON is a single versioned object. Diagnostics go to stderr, data to stdout. `--output PATH` writes atomically and refuses overwrite unless `--force` is explicit.
- Function selectors are mutually exclusive: `--function-id ID`, `--address 0x...`, or `--name EXACT`. Duplicate names produce candidates and require an ID or address. Never silently choose the first match.
- Addresses are unslid virtual addresses by default. `--file-offset` and `--rva` are explicitly typed alternatives, not ambiguous bare integers. Runtime addresses require an explicit, recorded load slide.
- Collection queries accept `--limit`, `--cursor`, and documented filters. Search defaults to literal matching. Regex is opt-in and bounded.
- Noninteractive commands never install dependencies, request credentials, download symbols, or open a GUI. `doctor` explains missing prerequisites without changing the system.
- Long operations accept `--startup-timeout`, `--function-timeout`, `--timeout`, `--max-memory-mib`, and `--jobs`, with units and effective values included in the job manifest. Default to one engine writer per project. Reject a budget the selected platform cannot enforce rather than implying protection.

### 4.2 Core command catalogue

| Command family | Proposed syntax and required result |
| --- | --- |
| Environment | `doctor [--json]`; verify the full Ghidra installation/headless launcher, compatible JDK, host-native decompiler, Java bridge compatibility, permissions and capability profile. Report missing/incompatible prerequisites without installation or backend fallback. |
| Inspect input | `inspect INPUT`; file identity, architectures, Mach-O summary and limitations without full analysis. |
| Inspect bundle | `bundle list APP`; executable candidates, embedded images and resource inventory. |
| Create project | `project create PATH`; initialize an empty private workspace and schema manifest. |
| Import | `import INPUT --project P --arch ARCH`; create immutable input identity and slice record, then import into the full Ghidra Program database without automatic analysis. `--arch all` is explicit. |
| Analyze | `analyze --project P [--image ID] --profile baseline|deep --timeout S`; run full Ghidra auto-analysis on selected imported slices and record effective options and completion state. |
| Project state | `status --project P`; jobs, partial stages, failures, counts, versions and stale outputs. |
| Job control | `jobs list`, `jobs show ID`, `jobs cancel ID`, `jobs resume ID`; ownership-safe cancellation and restart of unfinished work under the original inputs/profile. |
| Metadata | `headers`, `segments`, `sections`, `imports`, `exports`, `symbols`, each with `--project P` and filters. |
| Strings | `strings --project P [--encoding ascii|utf8|utf16le|auto] [--min-length N]`; bytes, locations, evidence and xrefs. |
| Functions | `functions list` and `functions show`; entry, body ranges, origin, signature, references and status. |
| Assembly | `disasm --function-id ID` or `--range START:END`; bytes, addresses, decoded operands, branches and comments. |
| Pseudocode | `decompile --function-id ID` or `--all`; C-like output, tokens/address spans, diagnostics and per-function outcome. |
| Relationships | `xrefs --to ADDRESS` or `--from ADDRESS`; typed code/data/call references, resolved and unresolved targets. |
| Call graph | `calls --function-id ID --direction callers|callees|both [--depth N]`; bounded traversal with unresolved edges. |
| Control flow | `cfg --function-id ID --format json|dot`; basic blocks, typed edges and uncertain exits. |
| Search | `search QUERY --in names|strings|comments|pseudocode|all`; indexed hits with context and function IDs. |
| Bytes | `bytes --address ADDRESS --length N`; bounded hex/data view with backing file offsets. |
| Annotations | `rename`, `comment set`, `comment list`, `comment remove`, `type set`, `annotations history`; reversible overlay edits. |
| Export | `export --format json|jsonl|text|html --output PATH`; reproducible manifest and selected analysis artifacts. |
| Compare | `diff LEFT RIGHT --scope metadata|functions|pseudocode`; observed differences and uncertain matches, not equivalence claims. |

`decompile --all` enumerates engine-recognized functions, not every possible routine in a binary. Summary totals include completed, partial, timed out, unsupported, and failed functions. A batch with ten successful functions and one failure must not look like full success.

`baseline` uses an explicitly versioned set of tested standard Mach-O analyzers and bounded decompilation. `deep` may add more expensive reference/function discovery and propagation but must still preserve unknowns. Neither profile is an undocumented alias for whatever analyzers the latest engine enables. Export the complete effective analyzer/options list; a new engine release gets a new profile revision. Resume requires identical artifact/profile identities or starts a new analysis with clear provenance.

### 4.3 macOS and workflow commands

`objc classes`, `objc methods`, and `objc selectors` expose decoded runtime metadata and known references. `swift symbols` retains raw mangled names beside demangled names and failure status. `resources list` reports names, types, sizes, and hashes; it does not copy assets by default. `demangle NAME` is pure input-to-output transformation and identifies the tool/version used.

`rea doctor` checks the selected REA server and provider without setup mutations. `rea import-evidence FILE` validates a recorded evidence bundle and stores it under its own origin. `report --template calculator|calendar-investigation` builds a report from already collected facts. These are optional phase 3 commands, not blockers for the initial core CLI.

Future `serve --transport stdio` may expose a narrow read-only MCP layer for the same operations. It must reuse the CLI domain model instead of implementing a second analysis path. Do not expose arbitrary shell, arbitrary Python/Java scripts, runtime attach, or unrestricted filesystem access as default MCP tools.

### 4.4 Annotation rules

Retain original names, engine-inferred names, and user labels separately. Each annotation records scope, author label, timestamp, revision, origin, and previous value. Comments may be attached to a function or instruction address. User type hints require explicit acceptance, are stored as hints, and invalidate affected decompiler caches. A failed type parse leaves the prior state unchanged. Unknown Objective-C targets must not become facts merely because a user wrote a plausible name.

Support explicit manual function boundary and prototype corrections after MVP validation. These are project edits with an audit trail, not modifications of input bytes. Export hints separately so a later blind experiment cannot accidentally consume them.

### 4.5 Exit codes and errors

Use 0 for complete success, 2 for usage or selector ambiguity, 3 for unsupported input/capability, 4 for missing or incompatible dependency, 5 for malformed input or integrity failure, 6 for partial batch success, 7 for timeout/resource limit, 8 for workspace conflict, and 10 for unexpected internal failure. Conventional interrupt termination is 130. Record `error.code`, a human message, affected object, retryability, and available partial results in JSON. An empty result is distinct from unavailable data.

## 5 Evidence and persistence model

### 5.1 Stable identities

Use SHA-256 of complete input bytes as the artifact identity. Identify a slice by parent hash, CPU type/subtype, slice offset/size, and slice hash. The analysis identity includes artifact/slice identity, Ghidra version and distribution checksum, language/compiler specification, enabled analyzers, options, limits, bridge version/build hash, and permitted auxiliary input hashes. Record the JDK version, host architecture, native decompiler identity and exact effective headless invocation in the job manifest. Annotations have a separate revision identity.

A function ID is stable only within that analysis identity and slice, based on its entry virtual address. Cross-build matching is heuristic. Do not treat equal function names or nearby offsets as global identity. Store multi-range function bodies, thunks, aliases, and overlap warnings explicitly.

### 5.2 Address model

Every address-bearing object includes image ID, architecture, address space, unslid virtual address, and optional RVA, slice-relative file offset, and container offset. Encode addresses and 64-bit offsets as hexadecimal strings to avoid JavaScript precision loss. Where an address maps to file bytes, container offset equals slice offset plus slice-relative file offset. Keep runtime loaded addresses separate with their supplied slide. Never subtract a slide from an on-disk address implicitly.

### 5.3 Function result contract

Each function record contains: schema version; analysis and function IDs; names by origin; entry and body ranges; bytes hash; calling convention and signature with provenance; instructions; CFG; direct/indirect calls; data references; pseudocode text; token-to-address spans where available; annotations; status; diagnostics; evidence origin; coverage scope; and timing/resource measurements.

Suggested result states are `complete`, `partial`, `timeout`, `unsupported`, `failed`, and `not_requested`. `complete` means the requested backend operation returned normally, not that every runtime behavior was recovered. A facet carries `available: true|false` and a reason when unavailable. Empty known caller lists differ from caller discovery not performed.

### 5.4 Confidence and reproducibility

Use evidence categories such as `decoded`, `metadata`, `inferred`, `user_supplied`, and `unresolved`, with a reason and supporting locations. Do not invent numeric confidence probabilities. Calibrated scores are a future research task. Preserve backend warnings verbatim in a diagnostic field while presenting a concise summary.

Sort deterministic exports by image, architecture, virtual address, and stable secondary key. Keep timing, timestamps, local paths, and host labels outside the normalized comparison payload. Cache keys include all analysis inputs and annotation revisions. Never share a cache between blind and source-assisted experiments. Engine upgrades require fresh analysis or an explicit migration with the original retained.

### 5.5 Workspace behavior

One writer per project; concurrent read queries use an immutable completed snapshot. Job cancellation leaves committed prior results usable and marks unfinished outputs. Failed or killed workers must not publish half-written JSON as a completed record. Store bounded logs and redact home directory prefixes by default. Reject incompatible schema versions with an upgrade/export route, not destructive automatic conversion.

## 6 Decompilation pipeline and algorithms

This section specifies required behavior and failure handling. The loader, instruction semantics, auto-analysis and decompilation algorithms are supplied by the selected full Ghidra stack. The following stages describe the engine behavior the product must expose and test, not a second implementation to build in the CLI. A missing capability remains an explicit limitation until a tested, scoped fix is approved. Ghidra's SLEIGH/p-code documentation is the primary engine reference. [SLEIGH documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh.html) [P-code reference](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html)

### 6.1 Parse and map the binary

Validate header/load-command counts, sizes, offsets, and arithmetic before allocating or reading. Map file-backed segments to virtual address spaces, represent zero-fill memory separately, select one architecture, and resolve supported relocations and dyld bindings. Record unknown commands without guessing their effect. A structurally valid Mach-O can still contain malicious input for a parser.

### 6.2 Decode instructions and distinguish code from data

Decode bytes using the selected ISA and processor context. Seed code discovery from entry points, symbols, exported addresses, Objective-C method implementations, function-start data, unwind ranges, direct calls, and explicit user seeds. Follow reachable branches and call targets, respecting data-in-code regions. Use conservative additional discovery for gaps. Blind linear sweeping can decode embedded data as instructions, especially on x86_64; mark heuristic discoveries and conflicts.

### 6.3 Recover functions and control flow

Build basic blocks at entries, branch targets, fall-through boundaries, and terminators. Create typed edges for conditional branches, fall-through, calls, returns, exceptions when recoverable, and unresolved indirect exits. Handle tail calls, thunks, shared epilogues, jump tables, nonreturning calls, and split function ranges. Do not assume one source function corresponds to one machine function after optimization.

Compute dominators/post-dominators and loop structure as inputs to structuring. Resolve jump tables using bounded data-flow/range analysis and relocation evidence, not arbitrary memory execution. Preserve unresolved edges. A guessed switch table must not be presented as exhaustive.

### 6.4 Lift into a semantic intermediate representation

Translate instructions to p-code operations over explicit bit-width values, registers, flags, memory, and control flow. Retain signed/unsigned interpretation where known, subregister behavior, byte order, and floating-point operations. An unknown instruction semantic must remain an opaque effect with a warning, not be dropped or replaced by a no-op.

Assembly text is only a display. Pseudocode generation should operate from the original binary and semantic IR, not a lossy text listing exported by another tool. REA-produced assembly is useful for comparison, but the core input remains machine bytes plus loading context.

### 6.5 SSA and data flow

Construct single static assignment representations with merge nodes, def-use chains, and conservative memory effects. Apply constant propagation, copy propagation, dead-value elimination, expression simplification, and stack-pointer tracking with explicit bit-width and side-effect rules. Validate preservation of observable operations for the declared instruction/ABI cases, and expose calls, alias uncertainty and exception-sensitive effects rather than knowingly discarding them. Source-level volatile qualifiers may be unrecoverable; the backend is heuristic and does not provide a general formal soundness guarantee. Retain raw instructions for audit.

Recover stack locals and arguments through frame/stack analysis; propagate types and prototypes across known calls. Distinguish pointer arithmetic from scalar arithmetic when supported by evidence. SSA variable names are not original source variable names. A conservative unknown pointer or type is preferable to an attractive false structure.

### 6.6 Structure and print pseudocode

Recognize reducible conditionals, loops, short-circuit expressions, switches, and returns. Use labels/gotos where irreducible flow or incomplete targets prevent safe structuring. Preserve uncertain casts, intrinsics, bit operations, and low-level helpers rather than hiding them. Infer function signatures and locals only to the strength supported by ABI, metadata, call sites, and data flow.

Print C-like pseudocode with address links. Keep raw engine output available alongside a presentation-normalized view. Never relabel output as recovered Objective-C, Swift, or source code unless a separate method establishes that representation. Comments and formatting do not establish semantic correctness.

### 6.7 Optional semantic checks

For small pure calculator functions, compile the emitted pseudocode through a fixed, versioned compatibility shim and generated wrappers, then compare it against the reference implementation. Score only outputs requiring no manual semantic repair. If a function cannot compile or run under that contract, mark it not testable and count it against coverage. Manually repaired diagnostic variants may be studied separately with every change recorded. Bounded symbolic equivalence can supplement testing for selected integer functions, with explicit domains, memory model, ABI, and solver limits. It is not an MVP dependency and cannot prove an entire Cocoa application correct.

Freeze shim and wrapper rules before held-out evaluation. Permit only predeclared generic typedefs/intrinsics and mechanical linkage/address plumbing. Correcting inferred signatures, signedness, object layouts, missing computations, or unresolved application calls using ground truth is a semantic repair even if a wrapper generator performs it. Such output is not testable for the blind score.

An optional LLM may explain already collected evidence or propose names, but outputs are labeled generated hypotheses with citations and are never silently substituted for deterministic pseudocode. No remote model receives binaries, source, strings, or pseudocode without explicit user permission.

## 7 Optional REA MCP integration

The public project that appears to match the requested name is `morluto/rea`, an MIT-licensed CLI/MCP orchestrator that can use Ghidra. Confirm that identity before implementing the optional REA adapter because the user may have a different installation. REA is not itself the machine-code decompiler. REA is not the launcher or mandatory broker for the core full headless pipeline. The optional no-Hopper REA path must explicitly select and verify the Ghidra provider; do not rely on automatic provider choice or setup defaults. [REA installation](https://github.com/morluto/rea/blob/main/docs/getting-started/installation.md)

### 7.1 Baseline workflow

1. Record REA package version, source revision/integrity, Node version, Ghidra version, provider configuration, and MCP protocol/tool catalog.
2. Start only an authorized local server over stdio, or an already approved local endpoint. No public listener is required.
3. Discover the live tool schema. Select the exact binary/slice and verify its identity against the experiment manifest.
4. Request image overview, procedures, selected function assembly and pseudocode, strings, references, callers/callees, and CFG where available.
5. Save the complete returned evidence and coverage declarations, not only an agent's prose summary.
6. Normalize addresses and compare against the direct Ghidra-backed CLI and LLVM output.

REA's documented contract includes operations such as `list_procedures`, `analyze_function`, and `procedure_pseudo_code`; request shapes and tool availability must come from the pinned server's catalog. Its evidence model distinguishes missing facets from empty findings. Import adapters must preserve those distinctions and cannot manufacture missing data. [REA MCP contracts](https://github.com/morluto/rea/blob/main/docs/reference/mcp-contracts.md)

### 7.2 Independence and failure rules

REA with Ghidra and this CLI with Ghidra share an engine. Agreement verifies adapter consistency, not independent correctness. Use known build artifacts, independently decoded bytes, and behavioral tests as additional evidence. If REA cannot select a slice reliably, provide an explicitly extracted test copy with recorded hash and original slice mapping.

If REA depends on an unavailable paid provider, reconfigure to Ghidra only after verifying support. Do not circumvent trial limits. If a capability is missing, record it and continue independent CLI validation; the final experiment remains incomplete for the REA integration gate. The product itself must still be useful without MCP.

## 8 Calculator experiment specification

### 8.1 Application design

Create a small macOS AppKit application with Objective-C UI and a pure C calculation module. AppKit keeps the first experiment's binary behavior readable while still exercising real macOS classes, selectors, event handlers, and framework imports. A later SwiftUI version tests a harder language/runtime tier rather than defining initial success.

The visible app has digit entry, a base-ten integer display, add/subtract/multiply/divide buttons, equals, clear, sign change, and an error display. It must be a real interactive application, not only a command-line fixture. Separate UI state and formatting from a deterministic calculation core. Freeze 16–24 representative core routines, including at least eight nontrivial functions with branches, loops, structures, or multiple calls. Do not inflate scores with trivial getters. Specify repeated equals and consecutive-operator behavior, and verify 20 scripted UI journeys independently of decompiler quality.

Specify core semantics before coding: signed 64-bit integer operations for the first fixture, checked overflow, division-by-zero rejection, explicit handling of minimum-integer divided by minus one, truncation toward zero for integer division, and structured status results. Decimal/floating-point arithmetic is a later fixture with its own NaN, infinity, rounding, and formatting rules. A decimal-looking display must not imply floating-point arithmetic in the integer fixture.

Add small, individually callable fixtures for a switch dispatcher, bounded digit-parsing loop, history-array traversal, helper calls, signed/unsigned comparisons, and a function-pointer dispatch table. Do not overcomplicate the UI to exercise every instruction. Keep extended patterns in a test module linked into a dedicated corpus target.

### 8.2 Required build products

Keep source, tests, Xcode project, build settings, compiler version, SDK version, macOS deployment target, source revision, linker map, dSYM UUIDs, and binary hashes. Disable LTO initially. Disable fast math. Set `ENABLE_DEBUG_DYLIB=NO` for the baseline, or explicitly analyze the companion image as an additional variant.

Use two build configurations: `DebugAnalysis` with `-O0`, debug info, no LTO and no-inline fixtures; `ReleaseAnalysis` with `-O2`, debug info retained for evaluator-only artifacts, no LTO, and normal inlining. For a controlled subset, retain no-inline marker functions in both; score ordinary optimized/inlined code separately. Never claim a missing inlined source helper is a function-discovery failure.

Build arm64 and x86_64 thin products from the same source revision. From each link product create a symbol-preserving and a stripped analysis copy. Keep the unmodified link product and dSYM only in the evaluator store. Verify executable section bytes are unchanged by stripping; record metadata/signature changes separately. The exact strip command must be validated on the chosen Xcode toolchain rather than assumed portable.

| Optimization | Symbol state | Architectures | Purpose |
| --- | --- | --- | --- |
| O0 | Symbol-preserving | arm64, x86_64 | Establish discoverability and readable baseline. |
| O0 | Stripped | arm64, x86_64 | Test discovery and recovery without local function names. |
| O2 | Symbol-preserving | arm64, x86_64 | Test optimizer transformations with useful metadata. |
| O2 | Stripped | arm64, x86_64 | Main realistic static-analysis challenge. |

These are eight unique analysis cases. Add four universal-container parity cases by combining the matching arm64/x86_64 products. They test slice handling, not four new semantic programs. Build/run availability on Intel must be recorded; Apple-silicon static analysis of x86_64 does not require Rosetta. Execution under Rosetta is a separate translated-runtime test, not native Intel validation. [Apple universal binaries](https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary)

### 8.3 Future build and inspection recipe

The future project will provide an Xcode scheme with the settings above. The following illustrates the intended recorded build invocation, not a currently existing project:

```sh
xcodebuild -project CalculatorFixture.xcodeproj \
  -scheme CalculatorFixture -configuration DebugAnalysis \
  -derivedDataPath build/arm64-debug ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
  ENABLE_DEBUG_DYLIB=NO build
```

Repeat with the explicit architecture and configuration matrix. Before automation, inspect the expanded build settings and actual compiler/linker invocations, not only scheme names. Record the location of the real executable, each UUID, and each file hash.

Use `xcrun` to resolve the installed toolchain's `nm`, `otool`, `dwarfdump`, `lipo`, and `llvm-objdump` where available. Check each tool's supported flags. A reference assembly command on a compatible LLVM toolchain is:

```sh
llvm-objdump --macho --arch=arm64 --disassemble CalculatorFixture
```

LLVM exposes Mach-O-specific metadata options useful for independent checks, including function starts, Objective-C metadata, exports and fixups. Record exact versions because Apple-shipped LLVM may not match upstream documentation. [LLVM objdump](https://llvm.org/docs/CommandGuide/llvm-objdump.html)

### 8.4 Blind analysis and controlled assistance

Create physically separate evaluator and analyst workspaces. The analyst gets only the specified binary variant, allowed runtime metadata, and generic platform type information. It must not receive source, dSYMs, linker maps, symbol maps from another variant, evaluator expected-function lists, or caches from richer runs. Disable implicit debug-file/source discovery, network symbol lookup, and parent-directory traversal. Classify embedded names naturally present in the chosen binary as valid evidence.

Run three separately labeled conditions: binary-only; binary plus its permitted symbol table; explicitly source/dSYM-assisted diagnostic analysis. Never pool their scores. Freeze and hash the blind outputs before the evaluator opens the source mapping. If an analyst has already seen the ground truth, use a separate clean analyst context for qualitative interpretation.

### 8.5 Execution sequence

1. Approve the remaining specification and development scope, then pin the build environment and selected full Ghidra headless environment. The engine choice itself is already settled.
2. Implement and test the calculator source only after development authorization.
3. Demonstrate UI operations and record reference test outputs on the intended host.
4. Build the eight variants and four universal parity containers; produce a signed or hashed manifest, with no need for a public signing identity.
5. Run isolated full Ghidra headless analysis directly and retain raw evidence for functions discovered from that binary alone. Blind runs enumerate and decompile their own discovered functions; the evaluator maps its hidden whitelist only after output freeze. Source/dSYM-derived addresses or function lists supplied as query seeds make a run assisted and exclude it from blind discovery scores. When the optional REA comparison is in scope, run its verified Ghidra provider in a separate workspace on the same immutable inputs.
6. Once implemented in phase 2, run the new CLI's full headless path on those inputs and retain JSON, assembly, pseudocode and CFGs. Compare with the direct baseline; REA availability is not a prerequisite for this core validation.
7. Decode the same code ranges with LLVM and adjudicate instruction disagreements by bytes and ISA semantics.
8. Freeze analysis output; reveal source/dSYM/linker evidence only to the evaluator.
9. Compare original source, machine ranges and recovered pseudocode, including known compiler transformations and unresolved parts.
10. Run behavioral comparisons on the pure core subset; record all pseudocode-to-harness repairs and tested domains.
11. Publish a private evaluation report with pass/fail/unknown per criterion and a remediation backlog. Do not proceed to broad app claims if the baseline gate fails.

### 8.6 Comparison record

One record per target behavior contains source symbol and source range (evaluator only), binary/slice hash, machine address ranges, assembly, recovered pseudocode, direct/indirect calls, important constants and comparisons, expected behavior, test outcomes, manual repairs, and unresolved questions. Source-line alignment is useful but not a semantic oracle under optimization. Text similarity and variable-name similarity are diagnostic only.

## 9 Acceptance criteria and test corpus

All thresholds below are proposed engineering gates. They must be ratified after the initial baseline reveals toolchain behavior; changes require a documented reason and must not hide failures. Report denominators and exclusions. Quality on a small calculator is not evidence of equivalent quality on arbitrary apps.

### 9.1 Correctness gates

| Area | Proposed release gate |
| --- | --- |
| Full headless path | Demonstrate import, analysis, disassembly and pseudocode using the pinned full Ghidra distribution and Java bridge on each supported host profile. Missing/incompatible launcher, JDK, native decompiler or bridge produces a typed dependency failure, never backend substitution. The core passes without REA or PyGhidra. |
| Import identity | 100% correct hashes, selected architectures, image mappings and UUIDs on valid corpus; no silent slice substitution. |
| Parser safety | Every malformed fixture exits with a typed error or partial result within configured limits; no input mutation or execution. |
| Controlled function discovery | 100% precision and recall for retained no-inline calculator core routines at O0, across both architectures and symbol states. |
| Optimized discovery | At least 95% precision and recall for evaluator-confirmed surviving controlled routines at O2; report merged/inlined/eliminated routines separately. |
| Instruction fidelity | 100% agreement on byte ranges, instruction boundaries and branch targets for the controlled core after alias normalization and adjudication. |
| Pseudocode completion | 100% of controlled core routines at O0 and at least 95% of surviving controlled routines at O2 return inspectable pseudocode, with warnings preserved. |
| Core behavior | Every controlled routine is testable without semantic repairs and passes at least 100 directed boundary cases plus 10,000 seeded valid-domain inputs where applicable. Realistic O2 requires at least 90% testable function and instruction-byte coverage, with zero mismatches in testable outputs. |
| Direct calls and xrefs | 100% of annotated controlled direct calls/data references recovered in baseline fixtures; no fabricated resolved targets for indirect dispatch. |
| Universal parity | Match by slice hash, architecture and virtual address after canonical remapping of all artifact-derived analysis/function IDs and references; exclude container identity/offset fields. |
| Determinism | Three identical runs with pinned inputs/options produce identical normalized exports on the same validated host profile. |
| Annotation round trip | Names/comments/type hints persist, export/import without loss, and correctly invalidate affected cached output. |
| REA adapter, when enabled | Selected complete REA evidence retains origin, identity, available facets and limitations; no silent partial-evidence flattening. This gates the optional adapter, not the core full headless release. |

For function discovery, true positives require evaluator-approved entry and body mapping, not name matches. Precision is correct discovered controlled functions divided by discovered candidates in the controlled region; recall is correctly discovered controlled functions divided by actual surviving functions there. Report false-positive functions and overlap conflicts separately.

Pseudocode completion is availability, not correctness. A compiler-accepted reconstructed function can still be wrong. Require review of error paths, overflow checks, pointer operations, signedness, and externally visible side effects. Do not remove failing random inputs to improve the score.

Require at least 95% reference-core branch coverage plus stateful operation sequences. Compare values, statuses and observable state exactly for the integer fixture. Freeze a held-out variation before tuning the analyzer. An IR interpreter matching the binary does not alone test the correctness of the final pseudocode printer. Keep any manual semantic repair outside scored results.

### 9.2 Performance targets

On a declared reference Apple-silicon host with 16 GB RAM and local SSD, target metadata inspection under 2 seconds, cold analysis of the small calculator under 60 seconds, and warm selected-function pseudocode under 5 seconds at the 95th percentile over 20 runs. These are budgets for the small fixture, not universal promises. Record launcher/JVM/native-decompiler startup, import, analysis and per-function decompilation separately, together with end-to-end command latency. The warm pseudocode target applies to an already loaded worker or a valid cached result, with those cases reported separately; an MVP command that starts a new worker must include that startup cost in its end-to-end result. A completed on-disk project alone does not make a new JVM process warm. Provide a configurable startup default of 300 seconds, per-function default of 30 seconds, whole-job default of 600 seconds, and a 4 GB worker memory target. Make client transport deadlines long enough for the declared job deadline, or return a job ID for polling. If resource limits cannot be safely enforced by the chosen host mechanism, report the gap and limit supported workload size.

### 9.3 Expanded corpus

- C arithmetic, signed/unsigned width changes, comparisons, loops, recursion, switches, lookup tables, structs, arrays, globals, and function pointers.
- Objective-C classes, categories, selectors, properties, inheritance, message sends, blocks, and ARC-managed objects.
- C++ constructors, virtual dispatch, templates, exceptions and RTTI, with unsupported facets explicitly recorded.
- Swift names, structs/enums, protocols/generics, closures, async functions and SwiftUI examples as an exploratory tier, not MVP pass gates.
- O0/O1/O2/Os, later LTO, tail calls, inlining, dead stripping, thunks and split ranges.
- New/old supported linker fixup formats, unusual section layouts, Unicode paths, spaces in names, missing dSYM, no symbols, huge function bodies, and interrupted jobs.
- Truncated headers, out-of-bounds/overflowing offsets, overlapping ranges, inconsistent fat headers, bogus load-command sizes, unsupported CPU subtype, data masquerading as code, and malicious bundle symlinks.
- Binary diff cases with known changed constant, changed branch, added function, renamed symbol, and identical code with changed metadata.

Use only user-owned or appropriately licensed fixtures in the distributable corpus. Keep third-party proprietary apps and exports in a separate private data store. Fuzz parser entry points in an isolated worker with bounded time/memory and retain minimal reproducers that contain no private data.

## 10 Taskovsky reuse scenarios

The tool is independent of Taskovsky but must serve its analysis workflow. The relevant use case is understanding a macOS application's calendar and task behavior from symbols, function pseudocode, cross-references, and resources. A read-only review on 9 November 2026 of the private 8 November export found TickTick 8.2.20, 44 Mach-O images with arm64/x86_64 slices, LLVM gzip text inventories, REA JSON evidence, and shipped resources. The archived input is now an unpacked app snapshot. Main/framework hashes were checked against the historical analysis. These are historical workflow observations, not results from the proposed CLI. No proprietary binaries, assets, or recovered code are included here.

The prior investigation produced useful small-framework pseudocode but not a complete main-app decompilation, complete cross-reference database, or retained Hopper database. One main Hopper startup took 2 minutes 9 seconds, exceeding a 120-second REA connection default; a temporary 450-second connection helped with a smaller target. This motivates configurable stage deadlines and partial results, not a promise that Ghidra will have the same performance.

### 10.1 Calendar investigation workflow

Import the authorized app's main image and explicitly selected embedded images. Search raw and demangled names, Objective-C selectors, and strings for calendar, date, month, week, day, recurrence, event, and task-related terms. Record that string matches are leads, not conclusions. Disassemble and decompile selected candidate functions, follow bounded callers/callees and data xrefs, and distinguish UI handlers from scheduling/data-model logic.

Build a private report that answers: where month/week/day mode is selected; where date ranges and time zones are handled; which functions appear to load events/tasks; what evidence supports recurrence behavior; and which assets/resource names are associated with the relevant screens. Each claim must cite binary identity, architecture, function/address, and evidence. Unknown behavior remains a question for separately authorized observation.

### 10.2 Required reusable outputs

- A filterable function/symbol inventory with stable IDs within one analysis snapshot.
- Per-function pseudocode and assembly with no trial/demo truncation and explicit engine failure statuses.
- Typed incoming/outgoing references and bounded caller/callee traversal, including unresolved Objective-C dispatch.
- A resource manifest containing relative paths, types, sizes and hashes; copying assets is not the default.
- A private JSON/HTML investigation export that can be diffed after a source app update.
- An evidence-led behavioral description that Taskovsky developers can implement independently without copying recovered proprietary code or assets.

### 10.3 Acceptance for this workflow

Use a small user-approved set of calendar-related symbols/addresses from the existing private investigation, after validating that they refer to the exact current binary and architecture. For each, the tool must return a function result or a typed explanation of why it cannot; it must not silently omit hard functions. Require end-to-end search → function → pseudocode → xrefs → private export on that set. Do not require every Objective-C call target or UI behavior to be statically recoverable.

An existing Hopper/REA export may be an analyst aid, but it is not a trusted correctness oracle, a substitute for access to the matching binary, or proof of legal reuse rights. Keep third-party material outside the distributable repository. Validate calendar logic separately against dates, DST transitions, locales, recurrence exceptions, and UI observations only when those observations are authorized.

### 10.4 Concrete private regression scenarios

**Filter predicates:** analyze a small framework's AND/OR/NOT combinations and priority/type/tag conditions. Export selected-function pseudocode and CFGs. Keep unresolved condition codes explicit; compare known branch evidence without inventing business meanings.

**Task and list data:** inventory compiled Core Data `.mom` schemas and correlate task/list/tag entities and relationships with binary references. A field name or schema relationship is structural evidence, not proof of validation rules or runtime behavior. A bounded, data-only resource parser is a phase 3 addition, separate from machine-code decompilation; it must not instantiate arbitrary archived objects.

**Rich editor:** trace Objective-C selectors and callback registrations to candidate handlers; distinguish unresolved dispatch and missing Swift/generic/resilient metadata from an empty result. Preserve selector and method-implementation evidence separately.

**Calendar resources:** correlate `.nib` and `.strings` control names, outlets, actions and localized labels with candidate binary handlers. The earlier 40-nib subset contained 3,675 nodes and 1,769 edges; a broader pass hit a 64-document cap before reaching Calendar, and main metadata collection hit a 20,000-record cap. These prior counts demonstrate the need for explicit selection, pagination, resumable cursors, and a coverage manifest. They do not establish complete UI recovery.

For all four scenarios, test explicit framework/image selection, bounded per-function analysis, resumable collection, and private export. Every budgeted collection reports requested scope, observed count, known total if available, continuation token, truncation reason and unvisited items. An empty page after truncation must not be reported as complete coverage.

Import existing REA evidence without losing `evidence_id`, subject identity/digest/format/architecture, provider, profile, parameters, raw and normalized results, confidence fields, limitations, relationship coverage, locations and evidence links. Preserve an upstream confidence value as upstream metadata; do not claim it is a calibrated probability. New normalized records link back to the original evidence.

Prior session ownership and cleanup failures also require explicit job ownership tokens, a process registry scoped to this project, and recovery tests. Cancellation may stop only the owned worker/process group, never an unrelated Hopper, Ghidra, REA, Codex, or application session. Stale ownership must be verified before cleanup. A transport disconnection does not authorize killing another session.

## 11 Security and privacy

Treat every input as untrusted data. Static analysis does not make a parser safe. Launch analysis in a least-privilege child process or approved isolated environment, with no network by default, a read-only input snapshot, and a private writable output directory. Do not claim that a Java subprocess alone is a security sandbox. Document the actual isolation mechanism tested on each supported host.

No analyzed program is executed by `inspect`, `import`, `analyze`, `disasm`, `decompile`, or `export`. No user-provided scripts, project hooks, dynamic libraries, command substitutions, or tool plugins are loaded automatically. Pin and validate helper paths; do not search for a demangler in attacker-controlled working directories. Bound path lengths, input sizes, recursion, worker output, graph depth, collection pages, string scans, and timeouts.

Workspace input snapshots and private outputs default to owner-only access where supported. Escape HTML, DOT labels, terminal control characters, filenames, strings, and comments. Treat binary strings and imported reports as data, never instructions. A resource or symbol that contains a shell command must never cause it to run.

No automatic binary upload, telemetry, cloud symbol lookup, external LLM call, or public report publication. Logs may contain sensitive strings or code and need an explicit retention policy. Export manifests include a sensitivity warning and omit absolute personal paths by default. Do not bundle third-party binaries or proprietary recovered output with the open-source tool.

Dependency installation is a separate explicit step with pinned versions, official origins, hashes, and notices. Review relevant security advisories at each release. An active upstream advisory concerns Mach-O loader resource consumption, illustrating why malformed-input limits are mandatory. [Ghidra security advisories](https://github.com/NationalSecurityAgency/ghidra/security/advisories)

## 12 Delivery plan and decision gates

### Phase 0 Pin the selected headless environment

Keep the selected full Ghidra headless architecture fixed. Choose exact Ghidra/JDK/host versions, verify macOS native decompiler availability, define the Java bridge's supported headless invocations, and map the required CLI commands to Ghidra APIs. Confirm the intended REA project only for the optional integration. Review licensing, distribution, and the independent Git repository. Deliver a pinned dependency proposal and a list of genuine product gaps; do not reopen backend or PyGhidra selection as an automatic spike. No installation, calculator implementation, bridge implementation or CLI development starts before explicit development authorization.

### Phase 1 Build and measure the calculator baseline

After development authorization, create the UI calculator and test corpus; generate the build matrix; run the direct full Ghidra headless and LLVM baselines before writing a large wrapper. Add the isolated REA/Ghidra comparison when its optional integration scope is approved. Deliver the source-to-binary manifest, blind results, and quality report. Stop and reassess if baseline decompilation fails on the controlled core. This phase tests feasibility, not product completeness.

### Phase 2 Implement the narrow CLI

Implement the headless launcher/Java bridge contract and `doctor`, `inspect`, `project create`, `import`, `analyze`, `functions`, `disasm`, `decompile`, `xrefs`, `cfg`, `export`, and JSON schemas. Add input isolation, limits, cancellation, atomic storage, and end-to-end tests from the beginning. Deliver an installable local package and reproducible benchmark report. Gate on the controlled corpus, not screenshots.

### Phase 3 Make the tool reusable

Add annotations and type hints, Objective-C/Swift metadata views, search, bounded call traversal, bundle/resource inventories, REA evidence import, and the Taskovsky calendar report. Validate on a limited private real-app sample plus the public corpus. Keep privacy and authorization boundaries intact.

### Phase 4 Harden and broaden

Add packaging, signed distribution if desired, SBOM/notices, compatibility matrix, schema migration, fuzzing, regression dashboards, and tested newer engine releases. Investigate arm64e, broader Swift patterns, or advanced matching after a prioritized gap warrants them. A second backend or a PyGhidra integration would require a separate approved scope change; neither is part of this delivery plan.

Each phase ends with a reviewable artifact and explicit pass/fail/unknown status. Schedule and cost estimates should be set after phase 1; building a reliable decompiler from scratch would be a fundamentally larger research project and is not an alternative hidden within this plan.

## 13 Versions and licensing

### 13.1 Verified research snapshot

The following versions and license classifications were checked against official sources on 9 November 2026. They are candidate pins, not an installed or compatibility-tested environment. Check published security fixes again when implementation starts. The full Ghidra headless architecture is selected; exact release and runtime pins remain candidate choices pending compatibility validation. The candidate baseline is the full Ghidra 12.2 distribution with a compatible 64-bit JDK 25 and the project-owned Java bridge; Python 3.12 remains the proposed wrapper runtime. Entries for unselected engines are retained as research context, not installation requirements.

| Component | Verified candidate and license | Product decision |
| --- | --- | --- |
| Ghidra | 12.2, released 22 October 2026; Apache-2.0 with separately licensed distribution components | Selected full headless engine; validate this candidate release, then pin the full official distribution hash and notices. |
| Java runtime | Ghidra 12.2 requires 64-bit JDK 25 | Select an approved distribution and review its redistribution terms separately. |
| PyGhidra | Bundled 3.2.0; tagged Python range 3.9–3.15 | Not used by the selected Java/headless integration; no PyGhidra or JPype runtime dependency is added to the CLI. |
| REA | Repository package metadata 6.8.0; MIT | Optional provider/orchestration adapter; confirm installed identity and matching tag/integrity before selecting it. |
| radare2 and r2ghidra | Both 6.2.6; LGPLv3-family obligations and component exceptions | Not selected or required; r2ghidra is LGPL-3.0-only. |
| Rizin and rz-ghidra | Rizin 0.9.1; rz-ghidra 0.9.0 for Rizin 0.9.x, using Ghidra 12.1 code | Not selected or required; Rizin LGPL-3.0-only, rz-ghidra LGPLv3-or-later per project README. |
| RetDec | 5.0, released December 2022; main code MIT | Research context only; not selected or required. |
| angr | 10.0.5; BSD-2-Clause; Python 3.12 or later | Research option; CLE labels Mach-O support limited. |
| LLVM | 23.1.5 upstream; Apache-2.0 with LLVM exceptions | Optional reference tools; Apple toolchain version may differ. |
| Capstone | Stable 5.0.6; BSD-style terms | Optional decoder; do not accidentally choose 6.0 alpha via latest. |
| LIEF | Regular 1.0.0; Apache-2.0 | Optional fast metadata parser, not required for MVP. |

Ghidra's own macOS floor does not establish this product's supported OS floor: the selected JDK, Python distribution and actual native decompiler builds also constrain it. Validate native arm64 and x86_64 workers explicitly. Do not require Rosetta silently. Ghidra distributions include separately licensed components, so the entire archive must not be described as public-domain or uniformly Apache-licensed.

Regular LIEF does not provide every feature advertised under LIEF Extended. In particular, do not assume its advanced Objective-C, dyld shared-cache, DWARF, disassembly and assembly features are all part of the free/open-source dependency. This design relies on Ghidra and separately scoped metadata work instead. [LIEF Extended distinction](https://lief.re/doc/stable/extended/intro.html)

### 13.2 Distribution requirements

The implementation must use a lock manifest, not floating `latest` dependencies. Pin CLI dependencies, Ghidra distribution and checksum, Java major/patch, bridge build, optional REA version/revision and Node runtime, LLVM reference version, Xcode build number, SDK version, host OS, and CPU architecture. Store the effective analyzer options and compiler/language IDs per analysis.

Open source removes the paid Hopper dependency, not all maintenance, distribution, or legal obligations. Prefer an independently installed Ghidra dependency for the first release; it minimizes redistribution complexity. If bundling later, include upstream licenses, notices, third-party components, source obligations where applicable, and an SBOM. Separate-process integration is an engineering boundary, not a blanket legal exemption.

The new project's license is not selected by this specification. The owner should choose it before remote publication. Apache-2.0 is a reasonable proposal for the project-owned wrapper, subject to dependency review; do not relicense upstream code under the wrapper's license.

### 13.3 Official version and license sources

- [Ghidra 12.2 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build), [tagged installation requirements](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md), [LICENSE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/LICENSE), [NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/NOTICE).
- [PyGhidra tagged API](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/PyGhidra/src/main/py/README.md), [dependency constraints](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/PyGhidra/src/main/py/pyproject.toml).
- [REA package metadata](https://github.com/morluto/rea/blob/main/package.json), [native investigation guide](https://github.com/morluto/rea/blob/main/docs/guides/native/native-investigation.md), [MIT license](https://github.com/morluto/rea/blob/main/LICENSE).
- [radare2 6.2.6](https://github.com/radareorg/radare2/releases/tag/6.2.6), [license guide](https://github.com/radareorg/radare2/blob/6.2.6/COPYING.md), [r2ghidra usage](https://github.com/radareorg/r2ghidra), [component licenses](https://github.com/radareorg/r2ghidra/blob/6.2.6/LICENSE.md).
- [Rizin 0.9.1](https://github.com/rizinorg/rizin/releases/tag/v0.9.1), [rz-ghidra compatibility](https://github.com/rizinorg/rz-ghidra/releases/tag/v0.9.0), [rz-ghidra license](https://github.com/rizinorg/rz-ghidra#license).
- [RetDec capabilities and maintenance](https://github.com/avast/retdec), [5.0 changelog](https://github.com/avast/retdec/blob/v5.0/CHANGELOG.md), [license](https://github.com/avast/retdec/blob/master/LICENSE).
- [angr package](https://pypi.org/project/angr/), [decompiler stages](https://docs.angr.io/en/latest/analyses/decompiler.html), [CLE format limits](https://docs.angr.io/projects/cle/en/latest/quickstart.html).
- [LLVM 23.1.5](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.5), [license](https://github.com/llvm/llvm-project/blob/main/LICENSE.TXT), [Capstone 5.0.6](https://github.com/capstone-engine/capstone/releases/tag/5.0.6), [Capstone license](https://github.com/capstone-engine/capstone/blob/5.0.6/LICENSE.TXT).
- [LIEF 1.0.0](https://github.com/lief-project/LIEF/releases/tag/1.0.0), [regular project capabilities](https://github.com/lief-project/LIEF).
- [Apple x86_64 ABI](https://developer.apple.com/documentation/xcode/writing-64-bit-intel-code-for-apple-platforms), [build UUID guidance](https://developer.apple.com/documentation/technotes/tn3178-checking-for-and-resolving-build-uuid-problems), [build settings](https://developer.apple.com/documentation/xcode/build-settings-reference).
- [Ghidra decompiler workflow source](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/docmain.hh), [Swift ABI](https://github.com/swiftlang/swift/blob/main/docs/ABIStabilityManifesto.md), [Swift type metadata](https://github.com/swiftlang/swift/blob/main/docs/ABI/TypeMetadata.rst).

Version links are preferred to floating source branches for future implementation. Sources on `main` or `master` establish the research snapshot only; archive the selected revision in the dependency manifest before building. No dependency compatibility, redistribution legal opinion, or benchmark is implied by this review.

## 14 Known limitations and unresolved decisions

Compilation destroys information. Optimization folds constants, removes code, merges functions, changes loops, inlines calls, and specializes types. Stripped binaries often lose names and debug types. Static analysis cannot generally enumerate dynamically generated code, all indirect callees, runtime-swizzled Objective-C methods, or all data-dependent behavior. Decompiler output can be plausible and wrong.

The initial design assumes user-owned calculator inputs and authorized read-only inspection of other applications. The exact host toolchain must be confirmed before its implementation work. The private Taskovsky corpus and REA installation identity must be confirmed before their respective later workflows; the desired remote repository owner/visibility must be confirmed before publication. Unsupported inputs should produce usable metadata and explicit boundaries where safe, not false confidence.

**Settled architecture:** full Ghidra headless, with the headless launcher and proposed Java bridge as the MVP integration baseline. PyGhidra and alternative decompiler stacks are not pending MVP choices.

Open decisions: final tool name; exact Ghidra/JDK/Python pins after compatibility validation; chosen license; whether to bundle the full Ghidra distribution; supported macOS release matrix; exact optional REA release; selected private calendar test functions; and whether a separate public-safe fixture suite is needed for external contributors.

**Remaining approval:** review the detailed specification and phased calculator validation, then explicitly authorize development. The full Ghidra headless selection does not itself authorize implementation, dependency installation, or experiments. The separate repository is ready to hold that future work but currently contains no implementation.

## 15 Example end to end interface

This is proposed future syntax, not a runnable implementation. `FUNCTION_ID` and paths are placeholders returned or chosen during the session. The example uses binary-only analysis and does not give the analyzer source or dSYM files.

```sh
macscope doctor --json
macscope inspect CalculatorFixture.app --format json
macscope project create workspaces/calculator-arm64
macscope import CalculatorFixture.app \
  --project workspaces/calculator-arm64 --arch arm64
macscope analyze --project workspaces/calculator-arm64 \
  --profile baseline --timeout 600
macscope functions list --project workspaces/calculator-arm64 --format json
macscope decompile --project workspaces/calculator-arm64 \
  --function-id FUNCTION_ID --format json
macscope cfg --project workspaces/calculator-arm64 \
  --function-id FUNCTION_ID --format dot
macscope export --project workspaces/calculator-arm64 \
  --format json --output results/calculator-arm64.json
```

### 15.1 Minimum JSON envelope

All JSON responses use `schema_version`, `command`, `status`, `analysis_id`, `data`, `diagnostics`, and `coverage`. `analysis_id` may be null for pre-import inspection. `data` is command-specific; errors must not return fabricated successful data. The schema is published with the package and validated in CI. Additive optional fields are minor changes; removed/renamed fields or semantic changes require a new major schema version.

Collection `coverage` contains `scope`, `status` (`complete`, `partial`, or `unknown`), `returned_count`, `known_total` (nullable), `next_cursor` (nullable), and `truncation_reason` (nullable). Cursors bind to analysis identity, filters and ordering; stale or cross-project cursors are rejected. A collection can be complete for a requested image while the broader bundle remains unexamined.

Function `data` contains `function_id`, `image_id`, `arch`, `entry_va`, `body_ranges`, `names`, `signature`, `pseudocode`, `address_spans`, `facets`, and `origin`. `pseudocode` is null when unavailable, never an empty success surrogate. Each address span associates a text/token range with one or more machine ranges; exact line mapping is not promised where the engine cannot supply it. Store raw engine output separately from presentation changes.

### 15.2 Review checklist

- The selected core path uses the full Ghidra headless loader, analyzers and decompiler through the Java bridge, without a paid engine, remote model, REA or PyGhidra dependency.
- All supported commands have golden JSON/schema tests and documented failure behavior.
- The calculator is a real UI app with a separately testable core and no embedded answer corpus.
- Blind and assisted scores are separate, with immutable output frozen before ground truth is revealed.
- The Taskovsky regression sample covers frameworks, resources and metadata as well as the main executable.
- No partial, truncated, timed-out, unsupported, or inferred finding appears as a complete recovered fact.
- The repository remains independent, private to the selected workspace, and documentation-only until explicit development authorization.

