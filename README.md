# NEXORA

**Advanced Reverse Engineering & Intelligence Platform**

NEXORA is a GitHub-first, local-first reverse-engineering platform. Its deterministic Rust engine owns artifact handling, analysis policy, evidence, and tool execution. External AI agents are optional clients connected through narrowly scoped MCP or REST interfaces; they are not the engine.

## Principles
- Evidence-first results with hashes and provenance.
- Safe by default: analyze only software and systems you own or are authorized to inspect.
- Never execute untrusted samples on the host.
- No mandatory Vercel, Supabase, Firebase, hosted database, or AI provider.
- Modular analyzers and optional external tool integrations.
- Experimental features are not described as production-ready.

## Implemented first slice
- Rust workspace and CLI.
- Local artifact ingestion with a hard byte limit.
- SHA-256 content addressing and duplicate storage avoidance.
- Magic-byte identification for ELF, PE, Mach-O, PDF, ZIP, PNG, JPEG, gzip, SQLite, and WebAssembly.
- Bounded read-only static triage with SHA-256, Shannon entropy, capped printable-string extraction, and structured analyzer findings.
- In-process analyzer trait and registry with a built-in binary-header analyzer; extensions are trusted Rust code, not dynamically loaded from samples.
- JSON Lines provenance manifest.
- Untrusted-by-default records; ingestion never executes input.
- GitHub Actions formatting, tests, and Clippy checks.

## Build and test
Requires stable Rust.

    cargo fmt --all -- --check
    cargo test --workspace --all-targets
    cargo clippy --workspace --all-targets -- -D warnings
    cargo build --release -p nexora-cli

## CLI
    cargo run -p nexora-cli -- version
    cargo run -p nexora-cli -- inspect ./sample.bin
    cargo run -p nexora-cli -- analyze ./sample.bin
    cargo run -p nexora-cli -- ingest ./sample.bin --workspace ./nexora-project

Artifacts are stored under artifacts/<sha256>; metadata is appended to manifest.jsonl. Input files are never executed.

## Not yet implemented
Python adapters, dependency/import analysis, MCP, REST, authentication, dashboard, and isolated dynamic analysis remain planned work. This repository is not yet a complete production reverse-engineering platform.

See docs/ARCHITECTURE.md, docs/ROADMAP.md, and SECURITY.md.


### Analyzer registry

`nexora_core::Analyzer` defines a read-only analyzer contract. `AnalyzerRegistry` runs registered trusted implementations over the bounded input buffer and adds structured `analyzer_findings` to analysis reports. The default registry includes `BinaryHeaderAnalyzer`. There is no dynamic library loading, and untrusted artifact bytes are never executed as code. The report schema version is 2.

### Binary header metadata

Static analysis extracts bounded ELF, PE, and Mach-O header metadata when the header is structurally valid. ELF section-table bounds and PE section-table bounds are checked before metadata is reported. This initial parser does not yet decode symbols, imports, relocations, or section contents. Malformed or unsupported headers produce `binary_metadata: null`; input files are never executed.
