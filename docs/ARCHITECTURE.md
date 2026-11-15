# NEXORA Architecture

## 1. System boundary

NEXORA is the tool platform. External AI agents are clients, not the engine. Agents can request operations, but NEXORA validates permissions, executes approved tools, stores evidence, and returns structured results.

## 2. Logical components

1. **Core domain** — projects, artifacts, analysis jobs, findings, evidence, tool capabilities, and policy decisions.
2. **Ingestion** — validates file size/type, computes cryptographic hashes, detects formats, and stores immutable input metadata.
3. **Analysis engine** — coordinates static analysis and calls registered analyzers through stable interfaces.
4. **Execution supervisor** — runs dynamic tools only in disposable, resource-limited sandboxes.
5. **Tool/plugin registry** — records tool identity, version, capabilities, input schema, output schema, and trust level.
6. **Agent gateway** — exposes approved capabilities through MCP and REST; enforces authentication, authorization, quotas, and audit logging.
7. **Evidence store** — preserves raw tool output, normalized observations, artifact hashes, and provenance.
8. **User interface** — CLI first; web dashboard later.

## 3. Technology choices

- Rust for the security-sensitive core, file processing, job orchestration, and CLI.
- Python adapters for selected reverse-engineering ecosystems where mature bindings or scripts exist.
- TypeScript for a future dashboard and API client.
- MCP for agent-tool interoperability; REST for application and automation clients.
- SQLite/local project storage for the first single-user milestone. PostgreSQL can be introduced for multi-user deployments.
- Container isolation (Docker or Podman) for dynamic analysis. Containers are not a complete security boundary for hostile samples; stronger isolation may be required.

## 4. External services: staged, not mandatory

- **GitHub:** source control and CI; required for this repository workflow.
- **Vercel:** optional dashboard hosting only. Do not run heavy binary analysis or untrusted sample execution on Vercel functions.
- **Supabase:** optional later for managed PostgreSQL, authentication, and multi-user project metadata. Keep the core usable without it.
- **Firebase:** not selected. It would duplicate capabilities without a clear need.
- **Object storage:** consider Cloudflare R2 or an S3-compatible service only when remote artifact storage is required.

No cloud account is required to build or test the initial core.

## 5. Agent integration model

External agents connect through MCP or authenticated REST endpoints. The gateway exposes narrow, typed operations such as:

- inspect_artifact
- identify_file_format
- extract_metadata
- run_static_analyzer
- inspect_dependencies
- get_analysis_status
- retrieve_evidence
- export_report

An agent must not receive arbitrary host shell access. Each tool call is validated against project permissions, operation policy, resource limits, and audit requirements.

## 6. Data flow

1. User creates a project and submits an authorized artifact.
2. Ingestion validates the artifact and computes SHA-256.
3. The scheduler creates an analysis job.
4. Registered analyzers run with declared capabilities and limits.
5. Outputs are normalized into observations and evidence records.
6. Findings are generated only when supported by evidence.
7. An external agent may interpret the structured results and request additional approved tools.
8. The report records tool versions, artifact hashes, timestamps, and limitations.

## 7. Non-goals

- No autonomous execution of arbitrary commands on the host.
- No bypassing DRM, licensing, access controls, or authentication.
- No analysis of systems without authorization.
- No claim that AI-generated reconstruction is original source code or guaranteed correct.


## 8. Implemented core contracts

The current Rust core now contains:
- a bounded artifact-ingestion and static-triage foundation;
- an evidence schema with deterministic observation IDs, confidence, authority, coverage and limitations;
- a policy object that defaults to static-only operation and bounds input and output sizes;
- a static analysis pipeline that emits JSON reports;
- a project manifest model with safe relative-path validation;
- an analysis-job state machine with explicit legal transitions and audit events;
- a capability registry that rejects unverified tools and disallowed effects by default.

These contracts are metadata and in-process policy foundations. They do not yet provide a persistent job scheduler, a process sandbox, dynamic plugin loading, MCP server, REST server, authentication, or dashboard. Those remain separate milestones.
