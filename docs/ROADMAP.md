# NEXORA Roadmap

## Milestone 0 — Repository foundation
- [x] Establish project identity and architecture direction
- [x] Document security boundaries and service choices
- [x] Add Rust workspace and CLI skeleton
- [x] Add formatting, linting, and CI workflow
- [ ] Add contribution and release conventions

## Milestone 1 — Artifact foundation
- [x] Safe regular-file ingestion with a hard byte limit
- [x] SHA-256 content addressing and duplicate storage avoidance
- [x] Magic-byte identification for common formats
- [x] JSONL artifact manifest with provenance fields
- [x] Unit tests for signatures, deduplication, and size limits
- [ ] Project workspace model and richer provenance schema
- [ ] Adversarial filesystem and race-condition tests

## Milestone 2 — Static analysis
- [x] Bounded read-only triage (SHA-256, entropy, printable strings)
- [ ] Analyzer interface and plugin registry
- [ ] ELF, PE, and Mach-O header and section parsing
- [ ] Dependency/import inspection
- [ ] Structured evidence output and report export

## Milestone 3 — Tool integrations
- [ ] Optional Ghidra integration
- [ ] Optional radare2 integration
- [ ] Optional JADX integration for authorized Android application analysis
- [ ] Tool version detection and capability declarations
- [ ] Reproducible integration tests

## Milestone 4 — Agent interoperability
- [ ] MCP server with a narrow tool surface
- [ ] REST API
- [ ] Authentication, project authorization, quotas, timeouts, and audit logs
- [ ] Agent compatibility tests

## Milestone 5 — Controlled dynamic analysis
- [ ] Disposable sandbox workers
- [ ] Network disabled by default
- [ ] CPU, memory, disk, and time limits
- [ ] Artifact and output isolation
- [ ] Threat model and sandbox escape review

## Milestone 6 — Product experience
- [ ] CLI analysis and project history
- [ ] Evidence-based report export
- [ ] Optional local dashboard
- [ ] Optional SQLite-backed indexing and search
- [ ] Optional managed database and object storage

## Release gate
A milestone is complete only when implementation, automated tests, security checks, and documented limitations are present. A passing build alone does not establish production readiness.
