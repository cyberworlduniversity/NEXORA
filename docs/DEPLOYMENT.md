# NEXORA packaging and deployment boundary

## Current deliverable

The current application is a local-first Rust command-line program, not an HTTP service. The Dockerfile packages the CLI in a non-root runtime image. It does not expose a network port, provide user accounts, or host a browser dashboard.

Build the image after the final verification gate:

    docker build -t nexora:0.1.0 .
    docker run --rm --read-only --network none --cap-drop ALL \
      --security-opt no-new-privileges \
      -v "$PWD/workspace:/workspace" nexora:0.1.0 version

For artifact analysis, mount only a dedicated input/workspace directory and pass a path inside that mount. Do not mount the host root, Docker socket, credentials, or sensitive directories. The container is defense-in-depth, not a complete hostile-binary sandbox.

## What is still required before a hosted production deployment

A hosted multi-user product requires components that do not exist in this repository yet:

1. An authenticated API gateway (REST and/or MCP) with per-project authorization, request limits, audit events, and safe error handling.
2. A persistent job queue and worker supervisor. Long-running analysis must not run inside short-lived web request handlers.
3. A real isolation boundary for dynamic tools: disposable workers, CPU/memory/time limits, read-only inputs, restricted filesystem, no network by default, and a documented escape-response process.
4. A durable project/evidence store with tenant isolation, retention, backup, and restore procedures.
5. A dashboard with project, artifact, job, evidence, and report views.
6. Secret management, TLS, rate limiting, monitoring, incident response, and deployment rollback.
7. A signed release process and reproducible build provenance.

Vercel may host a future dashboard, but it must not execute untrusted binaries or host the analysis worker. Supabase or another PostgreSQL service is optional for multi-user metadata; it is not required for the local CLI. Do not deploy a placeholder web page and call it the completed NEXORA platform.

## Release gate

The requested final test phase remains separate. Before a public release, run formatting, workspace tests, Clippy with warnings denied, release build, CLI smoke tests, malformed-input and resource-limit tests, container hardening checks, and a security review. Verify the generated binaries and container image on supported target platforms. No test or build result is claimed by this document.
