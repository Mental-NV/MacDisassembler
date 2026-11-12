# Add evidence-backed Objective-C class index

Shared frozen artifact contract: accept/return plain JSON-compatible records, include schema_version=1, image identity (input hash, architecture, image identifier), coverage copied from input, explicit limitations. Never assert complete discovery. Preserve raw evidence by reference, never rewrite pseudocode. Use no new dependencies and only synthetic owned fixture records in committed tests. Do not publish TickTick artifacts. Keep your API independent of other queued jobs; integration into CLI/engine is a later reviewed job. No Rust, no Ghidra engine changes. Read docs/export-readability-roadmap.md and relevant existing metadata source/tests before coding.

Create pure class_index API over existing ObjC metadata records. Preserve image/slice and metadata address identity, duplicate class names, categories, +/- method kind, selectors, multiple owners and one raw-code reference. Expose unassigned and metadata-only entries, copied discovery caps and missing evidence. Deterministic near-linear algorithm, no CLI/bridge mutation. Tests must use actual existing metadata shapes and negative controls.

Create the requested test file with meaningful assertions and documentation. Report tests run, remaining native checks and limitations. Do not change shared CLI/bridge/top-level documents.
