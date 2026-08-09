# Read First: Mission, Constraints, and Planning Protocol

**Research snapshot:** 2026-08-03  
**Audience:** the primary Hermes agent responsible for creating and planning a new repository, plus the subagents it delegates to.  
**Deliverable requested from Hermes:** create the repository, create a dependency-aware set of feature issues, prioritize them, and add the ready work to the primary agent's Todo list. Do not begin broad implementation until the planning gates in this pack have been satisfied.

## 1. Mission

Build an opinionated, Rust-first workflow engineering kit on top of the latest stable ADK-Rust. The kit should make it possible to create, test, debug, package, and maintain bounded LLM workflows with approximately the iteration speed normally associated with configuration-driven Python frameworks, without giving up Rust for the runtime, security boundaries, high-value validators, connectors, or production nodes.

The central product decision is:

> Declarative workflow definitions are a permanent orchestration layer, not merely prototypes that must later be rewritten. Individual nodes graduate to Rust when stronger typing, performance, transactionality, or security warrants it.

The first implementation must be driven by real workflows already present in CodeSeek and Verbatim. It must also study current independent adopters of ADK-Rust for reusable patterns, but it must not indiscriminately copy their scope.

## 2. Non-negotiable constraints

1. **Rust is the implementation language.** ADK-Rust is the execution substrate. Do not replace it with a Python framework.
2. **Upstream first.** Reuse ADK-Rust graph, agent, runner, tool, session, skill, sandbox, action, evaluation, authentication, telemetry, artifact, and plugin capabilities when they satisfy the requirement. Add a thin boundary or contribute upstream rather than recreating equivalent machinery.
3. **Pin an exact stable ADK-Rust 1.x release in deployable workspaces.** At the research snapshot, v1.0.0 is the latest stable release. Reverify immediately before repository creation and record the result in an ADR and lockfile policy.
4. **Every workflow run receives an independent work directory and an enforceable sandbox policy.** A directory alone is not a security boundary. The runtime must verify that the selected backend can enforce every requested capability or fail before execution.
5. **No unbounded retry, reflection, review, or graph cycle.** Every cycle has explicit visit, time, tool-call, byte, and cost limits. Exhaustion ends in a typed failure, incomplete result, or abstention.
6. **Deterministic validation remains authoritative.** A reviewer model cannot waive schema, provenance, access-control, path, budget, citation, compilation, or business-rule failures.
7. **Skills never grant permissions.** Effective capabilities are an intersection of runtime, workflow, skill, role, user, tenant, and sandbox policy.
8. **No arbitrary expression language in v0.1.** Use closed route operators and registered Rust predicates. Avoid creating a second programming language inside TOML.
9. **No generic host shell tool in the default runtime profile.** Skill scripts run only by declared script ID through a sandboxed executor and a companion runtime manifest.
10. **Preserve application domain boundaries.** ADK implementation types must not leak into CodeSeek or Verbatim durable/public domain schemas.

## 3. Required reading order

The primary agent should read this document, then delegate the remaining documents in parallel according to `16_SUBAGENT_RESEARCH_ASSIGNMENTS.md`.

Recommended synthesis order:

1. `01_EXECUTIVE_DECISION_AND_PRODUCT_THESIS.md`
2. `02_UPSTREAM_BASELINE_AND_REUSE_MATRIX.md`
3. `03_SCOPE_NON_GOALS_AND_DESIGN_PRINCIPLES.md`
4. `04_TARGET_ARCHITECTURE_AND_CRATE_LAYOUT.md`
5. `05_WORKFLOW_SPEC_IR_AND_COMPILER.md`
6. `06_SKILL_PACKAGE_DISCOVERY_AND_PROMOTION.md`
7. `07_PER_RUN_WORKDIR_SANDBOX_AND_SECURITY.md`
8. `08_REVIEW_REVISE_VALIDATE_RELIABILITY.md`
9. `09_PATTERN_CATALOG_FROM_CODESEEK_AND_VERBATIM.md`
10. `10_EXTERNAL_ADK_RUST_PROJECT_DISTILLATION.md`
11. `11_TESTING_EVAL_REPLAY_AND_OBSERVABILITY.md`
12. `12_CLI_DX_PACKAGING_AND_REPOSITORY_LAYOUT.md`
13. `13_DOGFOOD_MIGRATION_AND_UPSTREAM_STRATEGY.md`
14. `14_REPOSITORY_BOOTSTRAP_ISSUE_AND_TODO_PROTOCOL.md`
15. `15_PRIORITY_DEPENDENCY_ROADMAP_AND_DECISION_GATES.md`
16. `16_SUBAGENT_RESEARCH_ASSIGNMENTS.md`
17. `17_SOURCE_REGISTER.md`
18. `18_INITIAL_ARCHITECTURE_DECISIONS.md`
19. `19_GLOSSARY.md`
20. `20_FDE_OPERATING_MODEL_AND_CUSTOMER_LIFECYCLE.md`
21. `21_BUNDLE_MANIFEST.md`

The `examples/` directory contains proposed formats. They are design inputs, not stable public contracts.

## 4. Mandatory subagent workflow

The primary Hermes agent should delegate at least these workstreams:

- current ADK-Rust stable and `main` capability audit;
- CodeSeek extraction audit;
- Verbatim contract and pattern audit;
- declarative specification, canonical IR, and compiler design;
- Skill and Skill-script runtime design;
- per-run work directory, sandbox, and threat-model design;
- review/revise/validate reliability and evaluation design;
- independent adopter pattern study;
- repository, issue graph, milestones, labels, and Todo import planning.

Each subagent must return:

```text
1. Confirmed facts with source or code references
2. Proposed decisions
3. Rejected alternatives and why
4. Concrete issue candidates
5. Dependencies for each issue
6. Acceptance tests
7. Risks and unresolved questions
8. Upstream contribution candidates
```

No subagent may merely summarize its assigned document. It must inspect the referenced current source and identify any stale assumptions.

## 5. Primary-agent synthesis protocol

After all subagents report:

1. Reconcile conflicts into explicit ADRs.
2. Select a repository name and verify that it is available.
3. Create the repository with a minimal Rust workspace, license, README, security policy, contribution guide, rust-toolchain file, formatting/lint policy, and CI skeleton.
4. Create milestones and labels before feature issues.
5. Deduplicate issue candidates.
6. Build a dependency DAG. Reject circular dependencies or vague umbrella issues.
7. Assign priority using the method in document 15.
8. Create issues in dependency order, but do not confuse creation order with execution order.
9. Add only unblocked issues to the primary Hermes Todo list; retain blocked issues in the repository plan with explicit dependency links.
10. Produce a final planning report containing repository URL, issue table, dependency graph, critical path, initial Todo list, and deferred scope.

## 6. Repository defaults when no stronger evidence exists

These are planning defaults, not immutable requirements:

- provisional name: `adk-workflow-kit`;
- owner: the user's existing GitHub account or organization chosen by the primary agent after checking current access;
- visibility: public if no customer-confidential material is present, otherwise private until sanitized;
- license: Apache-2.0, matching the user's existing open-source preference and ADK-Rust compatibility;
- Rust MSRV: the exact MSRV required by the pinned ADK-Rust stable release;
- default branch protection: required CI, no direct pushes, squash merge preferred;
- all deployable examples commit `Cargo.lock`;
- initial release channel: `0.x`, with schema versioning independent from crate versioning.

## 7. Definition of planning completion

Planning is complete only when all of the following exist:

- a real repository;
- an approved crate boundary diagram;
- an explicit upstream reuse matrix;
- initial ADRs;
- a versioned proposed workflow specification and canonical IR direction;
- a sandbox capability model and threat model;
- a Skill runtime contract;
- a review-loop reliability contract;
- a parity/dogfood plan for CodeSeek and Verbatim;
- issue templates, labels, milestones, and dependency metadata conventions;
- a feature issue DAG with acceptance criteria;
- a priority-sorted ready queue in the Hermes Todo list;
- a list of deliberately deferred features.

Do not treat repository creation by itself as completion.
