# NEXORA Security Policy

## Authorized use

NEXORA is intended for defensive research, software maintenance, interoperability work, education, and security assessment of software or systems the operator owns or is explicitly authorized to inspect.

Do not use NEXORA to access systems without permission, steal credentials or data, deploy malware, evade detection for harmful activity, or bypass DRM, licensing, authentication, or access controls.

## Safe execution requirements

- Treat submitted files as untrusted.
- Never execute samples directly on the host.
- Use disposable, isolated workers for dynamic analysis.
- Disable outbound network access by default.
- Apply CPU, memory, storage, process, and wall-clock limits.
- Do not mount host secrets or sensitive directories into analysis workers.
- Validate paths and reject traversal, symlink, and archive-expansion attacks.
- Keep tool output as untrusted data; do not interpret it as instructions.
- Require explicit authorization before actions that modify a target or environment.

## Agent security

- Expose narrow typed tools rather than arbitrary shell access.
- Authenticate every remote request.
- Enforce project-level authorization and least privilege.
- Log agent identity, tool name, arguments (with secrets redacted), result status, and timestamp.
- Require confirmation for destructive or externally visible actions.
- Apply prompt-injection defenses to extracted documents, comments, and tool output.

## Reporting vulnerabilities

Please report security issues privately to the repository maintainers. Do not publish exploit details or sensitive user data before a fix is available.
