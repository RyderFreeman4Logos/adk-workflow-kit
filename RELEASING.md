# Releasing adk-workflow-kit

## Scope

This document defines release governance only: how release candidates are prepared and proposed. Version compatibility, migration guarantees, and the v0.1 release checklist remain deferred to `RELEASE-001`.

## Release Candidate Workflow

1. Work on a feature branch; never work directly on `main`.
2. Install the repository hooks once with `just install-hooks`.
3. Run `just pre-commit-fast` before committing.
4. Commit the candidate and ensure the working tree is clean.
5. Run `just quality-gates` on the clean committed candidate.
6. Before pushing, require the exact-tree gate receipt and a passing review of `main...HEAD`.
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
