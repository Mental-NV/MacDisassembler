# Exact focused-selection preflight

Spec first. Add `decompile --from-import --preflight --address VA --project PROJECT`
as an engine-free preview of the existing exact-selection verifier. This addresses
an observed workflow gap: analyzed `functions show` cannot preview an import-only
selection, so a caller otherwise needs internal Python APIs or an expensive launch.
Do not change `functions show`, focused selection semantics or ordinary captures.

Require an exact unslid address and `--from-import`. JSON/text only; reject fresh,
all/name/function-ID/relative/runtime selectors, type/recovery hints and pseudocode
formats. Existing parser exclusivity and focused-selection errors stay intact.
No engine probe, trust prompt, worker, native decompiler, Ghidra Program check,
annotation lookup, job/receipt publication or fallback capture. Standard explicit
CLI output-file handling may write the requested output; project contents remain
unchanged. Native launch budgets and dependency paths are not evaluated by this
mode and do not establish launch readiness.

Select the image through existing project rules; verify the stored slice and run
`focused.select` unchanged. Return policy `macscope-focused-selection-preflight/1`,
project/image/architecture/slice identity, exact extent proof including offsets,
length/digest, selection policy and existing static boundary/tail-call/flow plans.
Label those plans as static preparation evidence, not applied native overrides or
verified recovered control flow. Do not emit the full selected binary payload or pseudocode; retain bounded
instruction bytes already required by the existing proof. No absolute host paths.
Success/exit0 means only that this byte-bound selection passed its verifier.
Include `native_readiness=not_checked`, `capture_performed=false` and explicit
limitations. No function record, signature, pseudocode, runtime reachability or
promise of successful later capture is implied. A later capture revalidates all
inputs and performs its normal separate Program/dependency/trust checks.

Acceptance: real owned Mach-O exact/nonentry/interior/terminal selections,
existing boundary and size/mapping refusal, tampered slice, ambiguous image,
invalid option combinations and error compatibility. Prove no engine/trust calls,
new jobs or changed project hashes; repeat installed entry-point JSON/text with
engine paths unavailable. Existing no-preflight behavior and full tests must pass;
independent spec/code review before publication. No native recapture required for
this pure existing-verifier projection; do not label offline checks native tests.

## Validation checkpoint

998 primary and 115 analysis tests passed in the cloud. Eight new tests cover
real owned Mach-O selection/refusal, terminal boundary proof, size limit, tampered
slice, image ambiguity, incompatible options, engine/trust non-invocation, ordinary
capture routing and protected output paths. Independent review caught the ordinary
decompile text renderer hiding preflight fields; a policy-specific text path and
substantive content assertions now preserve the proof and limitations.

The isolated installed wheel matched all 93 source package files. Three existing
owned Swift image selections ran twice in JSON and text: 12 exit0 invocations,
byte-identical repeats and unchanged project file hashes/job inventory, with
engine/JDK paths unavailable. Exact entry/end/length and explicit non-readiness
fields were checked. This is static saved-slice preflight, not native recapture,
a fresh Mac full-suite gate, decompiler correctness or a launch-readiness test.
No user application, private application artifact, system installation or
Taskovsky session is part of this checkpoint.
