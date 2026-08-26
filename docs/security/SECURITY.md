# Security Contract

Security checks are deterministic, local, and fail closed. Input validation happens at trust boundaries; typed diagnostics preserve the reason category without echoing payloads, advisory bodies, tenant identifiers, roles, hosts, ports, or secret markers.

## Dependency audit

`audit_dependencies(policy, lock)` parses the repository's cargo-deny policy and a Cargo lock fixture. An allow-list treats a missing package license as critical; compound SPDX expressions are never clean; and any advisory severity is critical because cargo-deny 0.19 enables vulnerability checking by default. `AuditDisposition` is deliberately three-way: `Clean` means no unresolved critical findings, `Critical` means a denied package/license, compound license, missing allowed license, or advisory was found, and `BoundaryMiss` means the policy or lock input was missing or invalid. A critical result never reports clean, and a boundary miss never reports that the audit ran.

`AuditReport` exposes only disposition and counts. `AuditError` exposes the stable code `workflow.audit.boundary_miss` plus typed disposition; it does not serialize policy bytes, lock bytes, or advisory bodies. The in-process fixture audit does not fetch advisories; the cargo-deny gate performs the external advisory-database check and fails closed on database or policy errors.

## Boundary rules

Strict Serde shapes use `deny_unknown_fields` where the contract requires it. Bounded inputs are rejected before dispatch. Canonical hashes and locks bind exact bytes. Foreign ADK implementation type markers are rejected by `workflow-adk`'s Verbatim boundary. Review, CLI, sandbox, Skill, and audit surfaces preserve typed failure diagnostics and redact untrusted values.

The frequent `just pre-commit-fast` and full `_quality-gates` paths run `cargo deny check licenses advisories`; a missing advisory database or invalid policy remains a non-clean failure. The repository's docs-contract integration test checks that these implemented names and boundary rules remain present in the published documents. It is a documentation consistency check, not a replacement for the crate tests that exercise the runtime behavior.
