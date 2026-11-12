# Add string reference sidecar builder

Shared frozen artifact contract: accept/return plain JSON-compatible records, include schema_version=1, image identity (input hash, architecture, image identifier), coverage copied from input, explicit limitations. Never assert complete discovery. Preserve raw evidence by reference, never rewrite pseudocode. Use no new dependencies and only synthetic owned fixture records in committed tests. Do not publish TickTick artifacts. Keep your API independent of other queued jobs; integration into CLI/engine is a later reviewed job. No Rust, no Ghidra engine changes. Read docs/export-readability-roadmap.md and relevant existing metadata source/tests before coding.

Create pure sidecar builder over existing string_evidence records and recorded reference sites, with image/function identity, exact text/encoding/address/verified bytes, absent/partial evidence and resource-vs-binary distinction. Never substitute hex values or mutate raw pseudocode. No extra scanner, CFString/Swift decoder or new evidence claims. Test malformed encodings, missing/limited references, duplicate text at distinct addresses and unresolved mapping.

Create the requested test file with meaningful assertions and documentation. Report tests run, remaining native checks and limitations. Do not change shared CLI/bridge/top-level documents.
