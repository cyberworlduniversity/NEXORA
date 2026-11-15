# NEXORA Evidence Model

## Purpose

NEXORA separates observations from interpretations. Static analyzers emit evidence records tied to the SHA-256 identity of the exact artifact bytes they inspected. A future finding or AI-generated explanation must reference one or more evidence IDs.

## Evidence record

Each record contains a schema version and deterministic evidence ID; artifact SHA-256; analyzer identity and evidence type; concise observation summary; confidence (observed, strongly inferred, or weakly inferred); authority (original artifact, local analyzer, external tool, or external service); optional byte location; and structured JSON payload.

Evidence IDs are SHA-256 digests of the normalized serialized observation identity. Identical observations generated with the same fields produce the same ID. This is an identity aid, not a digital signature.

## Coverage and limitations

An evidence bundle includes analyzed and total byte counts, analyzed categories, a partial-coverage flag, and explicit limitations. A report must not imply that an unimplemented analysis phase was performed. Current static reports explicitly state that sample code was not executed and that symbol/import/call-graph resolution and external-engine analysis are not yet included.

## Safety policy

The default policy caps input size at 512 MiB, bounds evidence/finding/printable-string output counts, disables external tools, and disables dynamic execution.

Dynamic analysis must not be enabled merely by changing a boolean in a production deployment. It requires a separately designed execution supervisor, disposable isolation boundary, resource enforcement, audit trail, and security review.

## Reproducibility

Reports retain the artifact digest, engine version, analysis mode, analyzer identity, structured evidence, coverage, and limitations. The current pipeline is deterministic for the same input bytes and engine version, subject to platform-independent serialization and future schema compatibility guarantees.

The current executable dependency parser extracts bounded ELF DT_NEEDED names, PE import-library names, and Mach-O dylib load-command names. It does not resolve individual imported symbols, relocation targets, or call graphs. A parser result is an observation about file metadata, not proof that a dependency is loaded at runtime.
