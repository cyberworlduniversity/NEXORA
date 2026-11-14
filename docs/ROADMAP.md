# NEXORA Roadmap

## Milestone 0 — Repository foundation
- [x] Establish project identity and architecture direction
- [x] Document security boundaries and service choices
- [ ] Add Rust workspace and CLI skeleton
- [ ] Add formatting, linting, and CI
- [ ] Add contribution and release conventions

## Milestone 1 — Artifact foundation
- [ ] Project workspace model
- [ ] Safe file ingestion and size limits
- [ ] SHA-256 hashing and file-type identification
- [ ] Artifact manifest and provenance records
- [ ] Unit and adversarial input tests

## Milestone 2 — Static analysis
- [ ] Analyzer interface and plugin registry
- [ ] Executable metadata extraction
- [ ] ELF, PE, and Mach-O identification
- [ ] Dependency/import inspection
- [ ] Structured evidence output

## Milestone 3 — Tool integrations
- [ ] Ghidra integration (optional external installation)
- [ ] radare2 integration (optional external installation)
- [ ] JADX integration for authorized Android application analysis
- [ ] Tool version detection and capability declarations
- [ ] Reproducible integration tests

## Milestone 4 — Agent interoperability
- [ ] MCP server with a narrow tool surface
- [ ] REST API
- [ ] Authentication and project-level authorization
- [ ] Request quotas, timeouts, and audit logs
- [ ] Agent compatibility tests

## Milestone 5 — Controlled dynamic analysis
- [ ] Disposable sandbox workers
- [ ] Network disabled by default
- [ ] CPU, memory, disk, and time limits
- [ ] Artifact and output isolation
- [ ] Threat model and sandbox escape review

## Milestone 6 — Product experience
- [ ] CLI workflows
- [ ] Project and analysis history
- [ ] Evidence-based report export
- [ ] Web dashboard
- [ ] Optional managed database and object storage

## Release gate

A milestone is complete only when implementation, automated tests, security checks, and documented limitations are present. A passing build alone does not establish production readiness.
