# Subagent Research Assignments

## 1. Coordination rule

The primary Hermes agent should dispatch these assignments in parallel. Each subagent must inspect current sources rather than relying only on this pack. Reports should use the common format in `00_READ_FIRST.md` and include concrete issue candidates with dependencies and acceptance tests.

## 2. Assignment A — ADK-Rust upstream capability and stability audit

### Objective

Verify the exact latest stable release, MSRV, feature tiers, graph/workflow schema, action nodes, Skills, sandbox/code execution, sessions, plugins, evaluation, server YAML configuration, and current `main` gaps.

### Required sources

- upstream release notes and tag;
- crate docs/source for graph, action, skill, sandbox, code, runner, session, eval, plugin;
- open issues/PRs relevant to registry-based graph compilation and Skill execution;
- ADK Studio interchange/codegen source.

### Required output

- adopt/wrap/extend/upstream/reject matrix;
- exact dependency recommendation;
- API gaps with minimal reproductions;
- upstream contribution candidates;
- stale assumptions in this pack.

## 3. Assignment B — CodeSeek extraction audit

### Objective

Inspect the current default branch and open issues/PRs. Identify exactly which lifecycle, model adapter, tool envelope, artifact, session, reviewer, test, and workdir concepts can move to the shared platform without moving CodeSeek domain behavior.

### Required output

- file/type/function inventory;
- characterization test gaps;
- extraction sequence;
- dependency inversion plan;
- paired parity metrics;
- issues for CodeSeek and the new repository;
- risks from dirty-worktree/snapshot semantics.

## 4. Assignment C — Verbatim contract and pattern audit

### Objective

Inspect current grounded-answer, multi-hop research, ADK integration, public SDK, evidence, storage, and ACL boundaries. Determine the minimum platform interfaces needed without leaking ADK types or replacing Verbatim source truth.

### Required output

- adapter and validator map;
- state/terminal mapping;
- domain contracts that must remain local;
- declarative topology prototypes;
- parity fixtures;
- issue candidates and dependencies.

## 5. Assignment D — Workflow specification, canonical IR, and compiler

### Objective

Design a narrow v1 external TOML schema and canonical IR that can express the three dogfood workflows. Study upstream `WorkflowSchema`, action nodes, YAML agent loader, and ADK Studio interchange.

### Required output

- proposed Rust types;
- closed node/route set;
- parse/normalize/resolve/lock/compile phases;
- diagnostics design;
- cycle/state/security analyses;
- version/migration policy;
- prototype TOML for all three workflows;
- what is deliberately impossible in v1.

## 6. Assignment E — Skills, references, scripts, and promotion

### Objective

Integrate Agent Skills and `adk-skill`; design the companion runtime manifest, progressive resource tools, script execution contract, evidence packages, and promotion lifecycle.

### Required output

- compatibility matrix with Agent Skills specification;
- Skill runtime schema;
- path and integrity rules;
- effective permission algorithm;
- sandbox input/output protocol;
- Skill selection policy;
- promotion/evidence schema;
- issues and tests.

## 7. Assignment F — Per-run workdir, sandbox, and security

### Objective

Design independent workdir lifecycle and enforceable sandbox backends. Evaluate ADK sandbox/code, bubblewrap, rootless Podman/OCI, WASM, embedded JS, and platform portability.

### Required output

- threat model;
- capability model;
- backend comparison;
- Linux v0.1 recommendation;
- directory/mount/network/secret policy;
- common conformance suite;
- cleanup/retention design;
- security issues ordered by dependency.

This subagent must explicitly distinguish “process wrapper,” “container,” and “security boundary.”

## 8. Assignment G — Review/revise/validate and evaluation

### Objective

Design the bounded reliability pattern and determine when small/inexpensive models are viable. Review relevant self-correction, self-bias, judge consistency, and workflow-to-Skill research.

### Required output

- typed review/defect schemas;
- deterministic-versus-semantic responsibility split;
- same/different model policy;
- no-progress/oscillation algorithms;
- eval matrix and metrics;
- task eligibility rubric;
- recommended default revision count based on proposed experiments;
- issues and tests.

## 9. Assignment H — Independent adopter pattern study

### Objective

Inspect current projects using stable/latest ADK-Rust, including Entheai, Cowork Forge, Velocia, ADK Gateway, and any stronger current examples discovered. Inspect Portail only as an explicitly labeled pre-1.0 comparison; do not count it as current-stable adoption evidence.

### Required output

For each project:

```text
current commit/version
license and maintenance signal
pattern observed
evidence in source/tests
adopt now / later / reject
security or quality caveats
issue candidate, if any
```

Prioritize patterns that appear independently in more than one project.

## 10. Assignment I — Repository, issue DAG, and Hermes Todo planner

### Objective

Using all reports, create the concrete repository plan, issue hierarchy, dependencies, labels, milestones, and ready queue.

### Required output before actions

- proposed repository name/visibility/license;
- issue table with IDs, priorities, sizes, milestones, dependencies;
- Mermaid dependency graph;
- cycle check;
- critical path;
- first Todo frontier.

After primary-agent approval/synthesis, this workstream may execute repository and issue creation.

## 11. Optional Assignment J — Naming, packaging, and ecosystem check

### Objective

Check repository/crate/CLI naming availability, likely collisions, discoverability, and whether the project should publish one umbrella crate or multiple internal crates first.

### Output

- naming shortlist;
- package publication strategy;
- compatibility with cargo-binstall/cargo-dist;
- recommendation with reasons.

## 12. Cross-review protocol

Before synthesis:

- A reviews D for upstream reinvention.
- F reviews E and D for sandbox/path/permission gaps.
- G reviews B/C/D for unbounded or model-authoritative correctness claims.
- B and C review D for expressiveness against real workflows.
- I reviews every report for issue-sized actionable work.

Conflicts are recorded, not silently averaged. The primary agent decides through ADRs.

## 13. Report naming

Suggested files in the planning branch:

```text
research/01-upstream-audit.md
research/02-codeseek-extraction.md
research/03-verbatim-contracts.md
research/04-spec-ir-compiler.md
research/05-skills-runtime.md
research/06-sandbox-security.md
research/07-review-eval.md
research/08-external-patterns.md
research/09-issue-dag.md
```

These reports should remain in the repository as design provenance.
