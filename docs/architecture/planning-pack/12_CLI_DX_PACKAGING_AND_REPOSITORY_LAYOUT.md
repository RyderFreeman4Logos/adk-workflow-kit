# CLI, Developer Experience, Packaging, and Repository Layout

## 1. Goal

Make the safe common path fast enough that an FDE or coding agent can create a new workflow mostly by editing TOML, prompts, Skills, schemas, fixtures, and small Rust validators/connectors.

Rust agility comes from eliminating repeated decisions and boilerplate, not from removing types or shifting arbitrary code into configuration.

## 2. Proposed CLI

Binary name in this pack: `workflowctl`.

```bash
workflowctl new workflow <name> --pattern <pattern>
workflowctl validate <workflow.toml>
workflowctl lock <workflow.toml>
workflowctl graph <workflow.toml> --format mermaid
workflowctl run <workflow.toml> --input <input.json>
workflowctl run <workflow.toml> --locked --json
workflowctl test <workflow.toml> --cases <dir>
workflowctl eval <workflow.toml> --profile <profile>
workflowctl replay <run-bundle>
workflowctl explain-run <run-id-or-bundle>
workflowctl package <workflow-dir>
workflowctl inspect-package <archive>
workflowctl skill lint <skill-dir>
workflowctl skill test <skill-dir>
workflowctl skill promote <evidence-package>
workflowctl sandbox check <profile>
workflowctl registry list <kind>
workflowctl doctor
```

All commands should support machine-readable JSON output and stable diagnostic codes.

## 3. Fast development loop

```bash
workflowctl new workflow invoice-review --pattern retrieve-extract-validate
cd invoice-review
workflowctl validate workflow.toml
workflowctl test workflow.toml --cases evals
workflowctl run workflow.toml --input fixtures/sample.json
workflowctl explain-run .runs/<id>
```

`validate` must not require a model endpoint. `test` should default to scripted models/fake tools unless a live profile is requested.

## 4. Scaffolded workflow package

```text
invoice-review/
├── workflow.toml
├── workflow.lock.toml
├── prompts/
│   ├── extract.md
│   └── review.md
├── schemas/
│   ├── input.json
│   ├── state.json
│   ├── output.json
│   └── review.json
├── skills/
├── evals/
│   ├── cases/
│   └── fixtures/
├── src/
│   ├── lib.rs
│   ├── validators.rs
│   └── connectors.rs
├── tests/
├── Cargo.toml
└── README.md
```

A pure declarative workflow may omit `src/` and `Cargo.toml` if all capabilities come from an installed registry package. Customer deployments should still lock the runtime and registries.

## 5. Pattern templates

Initial templates:

- `retrieve-extract-validate`;
- `draft-review-revise`;
- `code-investigate-review`;
- `grounded-answer`;
- `decompose-fanout-cover-merge`;
- `read-decide-approve-write`;
- `webhook-dedupe-enrich-sync`;
- `scheduled-spec-check`.

A template contains graph, schemas, fake tools, scripted model responses, failure tests, Skill skeleton, security defaults, and documentation.

## 6. Diagnostics UX

Human example:

```text
E0412 unbounded cycle
  workflow.toml:87:1
  cycle: review -> revise -> validate -> review
  no node in this component declares max_visits and no review.max_revisions exists
  fix: add [review].max_revisions or a bounded registered predicate
```

JSON output includes the same code, location, related nodes, and remediation.

## 7. Graph visualization

`workflowctl graph` should render:

- node ID and kind;
- model role;
- read/write/side-effect badges;
- validators and approval gates;
- cycle bounds;
- terminal statuses;
- subworkflow boundaries.

Mermaid and DOT output are sufficient for v0.1. Visual editing is deferred.

## 8. Package format

A workflow package archive contains:

```text
manifest.toml
workflow.toml
workflow.lock.toml
prompts/
schemas/
skills/ or immutable Skill references
evals/ optional
licenses/
SBOM or dependency manifest optional initially
signature/attestation later
```

Packaging verifies hashes, path containment, no undeclared executable, no secret-like files, and lock consistency.

## 9. Local registry and configuration

Separate:

- workflow package content;
- operator endpoint/model profiles;
- secret references;
- tenant policy;
- installed tool/node/validator implementations.

A package should say `model = "worker"`, while operator config maps `worker` to a specific endpoint/model. The lock records the resolved identity for a run or deployment profile.

## 10. Hot reload

Development-only hot reload may watch workflow, prompt, Skill, and schema files, then revalidate and create a new immutable package version. It must never mutate the semantics of an in-flight run.

Production reload requires:

- successful validation;
- new package identity;
- optional eval gate;
- atomic activation for new runs;
- retention of old package for resume/rollback.

## 11. Repository layout and contribution workflow

Shared repository:

```text
crates/              platform implementation
patterns/            reusable packages/templates
examples/             runnable demonstrations
conformance/          backend/provider/registry suites
docs/                 ADRs and specifications
.github/              CI, issue forms, dependency automation
```

Every pull request should state:

- affected public contracts;
- schema/lock migration impact;
- security capability impact;
- dogfood workflow impact;
- tests and benchmarks;
- upstream overlap.

## 12. Developer Skills

Ship repository Skills such as:

```text
workflow-author
registered-node-author
validator-author
connector-author
skill-author
sandbox-reviewer
eval-author
migration-author
adk-upgrade-auditor
issue-planner
```

They should encode the repository's mandatory tests and boundaries. Production copies are read-only; updates occur through pull requests.

## 13. Build and release

- Rust toolchain pinned to ADK stable MSRV.
- Cargo workspace dependency table owns versions.
- release binaries through cargo-dist or equivalent after initial stability.
- `cargo-binstall` metadata when releases exist.
- checksums and provenance attestations.
- semantic versions for crates, separate schema versions for workflow/lock/Skill runtime formats.

## 14. Avoiding CLI bloat

Keep `workflowctl` thin. Library APIs must implement parsing, compilation, execution, packaging, and testing. This enables embedding in CodeSeek, Verbatim, servers, and future GUIs without shelling out.
