# Bundle Manifest

## 1. Purpose

This archive is a planning and research handoff for a Hermes primary agent and its delegated subagents. It is designed to lead to a new Rust repository, a verified architecture plan, a dependency-aware feature issue graph, and an initial ready Todo queue.

Start with `00_READ_FIRST.md`.

## 2. Numbered documents

| File | Purpose |
|---|---|
| `00_READ_FIRST.md` | Mission, non-negotiable constraints, delegation and action protocol |
| `01_EXECUTIVE_DECISION_AND_PRODUCT_THESIS.md` | Strategic judgment and product thesis |
| `02_UPSTREAM_BASELINE_AND_REUSE_MATRIX.md` | ADK-Rust stable baseline and adopt/wrap/extend matrix |
| `03_SCOPE_NON_GOALS_AND_DESIGN_PRINCIPLES.md` | v0.1 boundaries and design rules |
| `04_TARGET_ARCHITECTURE_AND_CRATE_LAYOUT.md` | Target layers, crates, registries, and dependency direction |
| `05_WORKFLOW_SPEC_IR_AND_COMPILER.md` | TOML, canonical IR, compiler phases, routing, lockfile, diagnostics |
| `06_SKILL_PACKAGE_DISCOVERY_AND_PROMOTION.md` | Agent Skills integration, script/reference runtime, evidence and promotion |
| `07_PER_RUN_WORKDIR_SANDBOX_AND_SECURITY.md` | Independent workdir, capability model, backends, threats, conformance tests |
| `08_REVIEW_REVISE_VALIDATE_RELIABILITY.md` | Bounded producer/validator/reviewer/reviser contract and eval strategy |
| `09_PATTERN_CATALOG_FROM_CODESEEK_AND_VERBATIM.md` | Concrete extraction candidates and application-local boundaries |
| `10_EXTERNAL_ADK_RUST_PROJECT_DISTILLATION.md` | Patterns from current stable adopters and labeled pre-stable comparisons |
| `11_TESTING_EVAL_REPLAY_AND_OBSERVABILITY.md` | Test pyramid, scripted model, fault injection, replay, metrics, CI |
| `12_CLI_DX_PACKAGING_AND_REPOSITORY_LAYOUT.md` | `workflowctl`, scaffolds, packages, diagnostics, release structure |
| `13_DOGFOOD_MIGRATION_AND_UPSTREAM_STRATEGY.md` | Behavior-preserving extraction, parity gates, upgrade/upstream policy |
| `14_REPOSITORY_BOOTSTRAP_ISSUE_AND_TODO_PROTOCOL.md` | Exact repository, issue, milestone, dependency, and Todo procedure |
| `15_PRIORITY_DEPENDENCY_ROADMAP_AND_DECISION_GATES.md` | Epics, 84 seed issues, dependencies, milestones, and gates |
| `16_SUBAGENT_RESEARCH_ASSIGNMENTS.md` | Parallel subagent prompts, outputs, and cross-review protocol |
| `17_SOURCE_REGISTER.md` | Primary and independent sources with snapshot caveats |
| `18_INITIAL_ARCHITECTURE_DECISIONS.md` | Proposed ADR set for verification and adoption |
| `19_GLOSSARY.md` | Shared terminology |
| `20_FDE_OPERATING_MODEL_AND_CUSTOMER_LIFECYCLE.md` | Company-wide Hermes discovery, FDE compilation, pilots, governance, economics |
| `21_BUNDLE_MANIFEST.md` | This inventory and validation record |

## 3. Proposed format examples

The `examples/` directory contains design examples, not implemented stable schemas:

| File | Purpose |
|---|---|
| `01_code_investigation.workflow.toml` | CodeSeek-style producer/validator/reviewer/reviser graph |
| `02_grounded_answer.workflow.toml` | Verbatim grounded-answer topology with Rust validators |
| `03_skill.runtime.toml` | Companion Skill runtime and sandbox manifest |
| `04_workflow.lock.toml` | Reproducible model/resource/implementation lock example |
| `05_review.schema.json` | Typed review verdict and defect JSON Schema |
| `06_run_manifest.json` | Per-run identity, workdir, sandbox, and limit manifest |

## 4. Planning support files

| File | Purpose |
|---|---|
| `planning/01_FEATURE_ISSUE_TEMPLATE.md` | Feature issue form with upstream, security, tests, dependencies |
| `planning/02_EPIC_TEMPLATE.md` | Epic structure and completion evidence |
| `planning/03_HERMES_TODO_TEMPLATE.md` | Ready-only Todo queue format |
| `planning/04_PLANNING_REPORT_TEMPLATE.md` | Final repository and issue-planning report |
| `planning/05_seed_issues.csv` | Machine-readable seed backlog |
| `planning/06_seed_issues.toml` | Machine-readable seed backlog with dependency arrays |
| `planning/07_seed_dependency_graph.mmd` | Mermaid dependency graph generated from the seed backlog |
| `planning/08_ISSUE_CREATION_CHECKLIST.md` | Preflight before GitHub issue creation |

## 5. Validation performed

The bundle generation process checked:

- all proposed TOML files parse successfully;
- all JSON files parse successfully;
- the review schema is valid Draft 2020-12 JSON Schema;
- the seed CSV and TOML contain the same 84 issue records;
- all issue dependency IDs resolve;
- the seed dependency graph is acyclic;
- only two initial seed issues have no dependencies: repository scaffold and upstream baseline verification;
- Markdown code fences are balanced;
- numbered English documents are present in sequence from 00 through 21;
- referenced local bundle files exist;
- a SHA-256 manifest is included as `SHA256SUMS`.

## 6. Research caveats

- The source snapshot date is 2026-08-03.
- ADK-Rust v1.0.0 was the latest stable release at verification time; the planning agent must recheck before pinning.
- Upstream `main` may contain unreleased 2.0 work and must not be confused with stable APIs.
- Entheai, Cowork Forge, Velocia, and ADK Gateway provide current 1.0-line pattern evidence.
- Portail currently pins ADK-Rust 0.9.1 and is included only as a near-current pre-stable comparison.
- External project patterns require source, test, license, and security review before code reuse.
- Reviewer/reviser designs improve a bounded system only when paired with objective validation, limits, and abstention; they are not a correctness proof.
- The TOML/IR/lock formats in this bundle are proposals to be refined by the implementation-planning agents.

## 7. Expected next action

Unpack the archive, give the complete directory to the primary Hermes agent, and instruct it to follow `00_READ_FIRST.md` exactly. The expected result is an executed repository-and-issue planning workflow, not another prose-only summary.
