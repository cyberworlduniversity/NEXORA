# NEXORA

**Advanced Reverse Engineering & Intelligence Platform**

NEXORA is an extensible reverse-engineering platform designed to combine deterministic analysis tools with external AI agents. NEXORA owns the analysis engine, tool execution, permissions, evidence collection, and workflows. Connected agents provide reasoning and may invoke approved NEXORA capabilities through MCP or the REST API.

## Project principles

- Evidence-first: every finding should link to an artifact, location, tool output, or reproducible observation.
- Safe by default: analyze only software and systems the operator owns or is authorized to inspect.
- Sandboxed execution: untrusted samples must never execute on the host.
- Agent-independent: support multiple external agents without depending on one model provider.
- Modular: analysis capabilities are plugins with explicit input/output contracts.
- Honest status: experimental features must be labelled as experimental until validated.

## Planned capabilities

- File and binary identification
- Static metadata and structure analysis
- Disassembly/decompiler integrations
- Dependency and call-graph exploration
- Controlled dynamic analysis in isolated environments
- Architecture and behavior summaries
- Vulnerability triage with evidence
- MCP server and REST API for external agents
- CLI and web dashboard
- Extensible plugin/tool registry and audit history

## Initial architecture

- **Core engine:** Rust workspace
- **Agent and tool adapters:** Python where ecosystem integrations make it practical
- **API and MCP layer:** added after core contracts stabilize
- **Dashboard:** TypeScript frontend, deployed separately from analysis workers
- **Persistence:** local project workspace first; database added when multi-user requirements exist

See [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), and [Security Policy](SECURITY.md).

## Current status

NEXORA is at the repository initialization stage. The initial scaffold is not a production-ready reverse-engineering engine. Features will be marked complete only after implementation and tests.

## Development

The first milestone establishes the Rust workspace and documented interfaces. See the roadmap for the staged implementation plan.
