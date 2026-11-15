# Analyzer Registry

NEXORA analyzers are trusted, in-process Rust implementations. They receive a byte slice that has already been read under the caller's configured size limit and return optional JSON findings.

## Contract

- Implement `nexora_core::Analyzer`.
- Return a stable analyzer name.
- Keep analysis deterministic, bounded, and read-only.
- Return `None` when the analyzer does not recognize or cannot safely parse the input.
- Never execute artifact bytes, load sample-provided code, or perform network access.

## Registry

Use `AnalyzerRegistry::new()` to create an empty registry and `register` to add trusted analyzer implementations. `AnalyzerRegistry::default()` includes the built-in `BinaryHeaderAnalyzer`.

The CLI's `analyze` command uses the default registry. Its JSON report includes `analyzer_findings`, an array of analyzer names and structured findings. The report schema version is 2.

Dynamic plugins, third-party binaries, and untrusted extension loading are deliberately out of scope. A future external-tool adapter must use an explicitly isolated worker and a separate security review.
