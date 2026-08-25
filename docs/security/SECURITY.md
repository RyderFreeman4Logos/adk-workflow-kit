# Security Contract

Security checks are deterministic, local, and fail closed. Input validation happens at trust boundaries; typed diagnostics preserve the reason category without echoing payloads, advisory bodies, tenant identifiers, roles, hosts, ports, or secret markers.

## Dependency audit

`audit_dependencies(policy, lock)` parses a strict policy (`schema_version = 1`, `denied_crates`) and a Cargo lock fixture. `AuditDisposition` is deliberately three-way: `Clean` means no unresolved critical findings, `Critical` means a denied package was found, and `BoundaryMiss` means the policy or lock input was missing or invalid. A critical result never reports clean, and a boundary miss never reports that the audit ran.

`AuditReport` exposes only disposition and counts. `AuditError` exposes the stable code `workflow.audit.boundary_miss` plus typed disposition; it does not serialize policy bytes, lock bytes, or advisory bodies. The audit uses the crate names in the lock fixture and does not claim to fetch or interpret external advisories.

## Boundary rules

Strict Serde shapes use `deny_unknown_fields` where the contract requires it. Bounded inputs are rejected before dispatch. Canonical hashes and locks bind exact bytes. Foreign ADK implementation type markers are rejected by `workflow-adk`'s Verbatim boundary. Review, CLI, sandbox, Skill, and audit surfaces preserve typed failure diagnostics and redact untrusted values.

The repository's docs-contract integration test checks that these implemented names and boundary rules remain present in the published documents. It is a documentation consistency check, not a replacement for the crate tests that exercise the runtime behavior.
