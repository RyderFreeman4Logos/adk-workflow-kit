# Releasing adk-workflow-kit

## Scope

This document defines release governance and the v0.1 compatibility contract for release candidates. It does not publish crates, binaries, or migration guidance; those remain part of `RELEASE-003`.

## Compatibility and Migration Contract

v0.1 is the compatibility baseline for the documented workflow and review
wire contracts. Versioned top-level persisted artifacts carry explicit schema
versions; readers must reject an unknown or unsupported version rather than
silently reinterpret it. Boundary validation remains explicit, and failures
retain typed diagnostic codes instead of relying on rendered error text.

### Migration Guarantees

- A v0.1.x reader accepts artifacts produced by the corresponding v0.1.x
  writer without a migration step.
- A compatible patch release does not silently change the meaning of an
  accepted v0.1 artifact.
- A breaking contract change requires a new schema version and an explicit,
  separately reviewed migration path; unsupported input fails closed.
- Migration preserves validation, boundary checks, and typed failure
  diagnostics. It must not downgrade a failure into an accepted artifact.
- Published release artifacts and dogfood migration instructions are out of
  scope here and belong to `RELEASE-003`.

## v0.1 Release Checklist

Before proposing a v0.1 release candidate:

1. Confirm the candidate is on a feature branch based on `origin/main` and the tree
   is clean before and after verification.
2. Confirm `Cargo.lock` is committed and locked metadata resolves without
   rewriting the lockfile.
3. Run the repository's fast checks: formatting, locked workspace check,
   locked clippy, unit tests, integration/fixture tests, and local gate tests.
4. Verify unit and integration coverage for successful workflows, malformed
   input, unsupported versions, explicit boundary violations, and typed
   compiler/runtime/sandbox diagnostics.
5. Inspect the exact `origin/main...HEAD` diff for compatibility, migration, secret
   handling, and documentation scope; exclude publishing and dogfood work.
6. Record the candidate commit and its verification receipts, then require
   the repository's exact-tree gate and review before proposing a pull request.

## Release Candidate Workflow

1. Work on a feature branch; never work directly on `main`.
2. Install the repository hooks once with `just install-hooks`.
3. Run `just pre-commit-fast` before committing.
4. Commit the candidate and ensure the working tree is clean.
5. Run `just quality-gates` on the clean committed candidate.
6. Before pushing, require the exact-tree gate receipt and a passing review of `origin/main...HEAD`.
7. Open a pull request targeting `main`. Do not merge it automatically.

## Reproducible Dependencies

[ADR-0014](docs/architecture/adrs/ADR-0014.md) and [GOV-002](docs/architecture/GOV-002_ADK_RUST_BASELINE.md) define the dependency baseline. `Cargo.lock` is committed, and normal verification uses Cargo's `--locked` mode through the repository recipes.

Use a dedicated pull request for dependency upgrades. Run `just lock`, inspect the resolved metadata with `just metadata`, and then run the locked gates.

## Automation Boundary

The repository-local `just` recipes and Lefthook hooks are the project's CI-equivalent. This repository does not claim hosted GitHub CI.

## Deferred

- Hosted CI, including GitHub Actions
- Dependabot
- SaaS security scanners
- Automatic merging
- Release automation
- Tagging and publishing
- Live release execution
