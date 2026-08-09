# Scope, Non-Goals, and Design Principles

## 1. Product scope for v0.1

The first release should support a bounded subset sufficient to reproduce three real workflows:

1. CodeSeek investigation with typed read-only tools and optional reviewer/repair.
2. Verbatim grounded answer with deterministic claim/citation validation and abstention.
3. Verbatim multi-hop research with parallel retrieval, coverage evaluation, bounded corrective rounds, merge, and incomplete outcomes.

Required platform functionality:

- TOML workflow package parsing;
- canonical normalized IR;
- schema-aware state keys;
- direct edges and closed conditional routing;
- agent, action, validator, registered Rust, approval, and terminal nodes;
- bounded loops;
- model/tool/node/validator/predicate/Skill registries;
- run limits and cancellation;
- independent sessions by role;
- independent per-run work directories;
- sandbox capability negotiation;
- Skill activation, reference reading, and declared script execution;
- artifacts and progressive reads;
- structured traces and call ledgers;
- deterministic validation and typed abstention;
- test, replay, and lockfile commands.

## 2. Deliberate non-goals for v0.1

- a general-purpose distributed workflow engine;
- arbitrary user-authored expression evaluation;
- a visual editor;
- a SaaS control plane;
- a universal connector abstraction for every enterprise product;
- dynamic native plugin ABI loading;
- arbitrary shell commands exposed to the model;
- automatic production publication of a Skill after one successful trace;
- cross-tenant shared mutable workspaces;
- unrestricted runtime graph mutation by an LLM;
- full replacement of Temporal, Dagster, Airflow, n8n, or Kubernetes;
- high-risk autonomous actions without approval and idempotency controls;
- a claim that reviewer loops guarantee correctness.

Deferred features must still appear as labeled issues or roadmap entries when strategically useful, but they must not block the critical path.

## 3. Design principles

### 3.1 Upstream-first, boundary-conscious

Use ADK-Rust for general execution primitives while keeping application domain contracts independent. A wrapper should translate, not duplicate.

### 3.2 Configuration describes topology; Rust supplies capability

TOML should state which registered capability to use and how nodes connect. It should not contain arbitrary executable business logic. Complex conditions become registered predicates; high-value deterministic work becomes validators or Rust nodes.

### 3.3 Fail closed

Unknown node types, unresolved registries, unsupported sandbox controls, invalid schemas, missing references, budget exhaustion, and illegal transitions stop or abstain. They never silently downgrade to a less secure mode.

### 3.4 Least privilege by construction

The model sees only tools required by the active node and Skill. Reviewer roles are read-only unless an explicit reviewed design proves otherwise. Secrets are brokered and scoped rather than copied into work directories.

### 3.5 Every cycle is bounded

Static validation rejects unbounded cycles. Runtime limits are independent from model prompts. A model cannot request more iterations by editing state.

### 3.6 Determinism around uncertainty

Use models only where semantic interpretation is actually needed. Use ordinary Rust for parsing, validation, routing, citation rendering, hashes, access control, and side effects.

### 3.7 Reproducible execution

A run records the exact normalized workflow hash, prompts, Skill hashes, references, schemas, model identity, tool schemas, runtime version, and policy snapshot. Replaying with mocks should reproduce control flow even when a live model cannot reproduce text exactly.

### 3.8 Explicit incomplete states

`incomplete`, `abstained`, `cancelled`, `timed_out`, `limit_exceeded`, and `failed` are first-class terminal outcomes. Do not compress all failures into an empty string or a fabricated final answer.

### 3.9 Evidence is not instruction

Retrieved documents, repository code, user files, and external results are untrusted evidence. They cannot modify the workflow, grant tools, or override system/Skill policy.

### 3.10 Extraction requires two callers

Except for foundational invariants such as identity, limits, audit, errors, workdirs, and policy, shared abstractions should have at least two real callers before stabilization.

## 4. Compatibility principles

- Workflow schema version is independent from crate version.
- Unknown schema versions fail with a migration diagnostic.
- Compiler normalization produces a canonical representation suitable for hashing.
- Node IDs and state keys are durable once runs may be resumed.
- A workflow update creates a new immutable package identity.
- In-flight runs remain bound to their original package and implementation lock.
- Package migrations are explicit tools, not automatic reinterpretation.

## 5. Security principles

- A container is not automatically a sandbox.
- A work directory is not automatically isolated.
- Network is denied by default.
- Host home directories, Docker sockets, SSH agents, D-Bus, and cloud metadata endpoints are unavailable by default.
- Read-only mounts are preferred to copied secrets or source trees.
- Symlinks are resolved and checked before exposure.
- All child processes inherit the sandbox and resource limits.
- Output bytes, file count, disk usage, PIDs, CPU time, and wall time are bounded.
- Sandbox backends publish enforceable capability descriptors.

## 6. Reliability principles

- Reviewers emit defect objects, not vague prose.
- Same-model review is allowed only as one signal.
- Objective validators run before and after semantic review.
- No-progress detection is mandatory for repair loops.
- A revised answer cannot cite evidence outside the current authorized evidence set.
- Side effects occur after validation and, where required, approval.
- Retrying a side effect requires an idempotency key.

## 7. Developer-experience principles

The common path should require the developer to supply only:

1. state/input/output schemas;
2. graph topology;
3. prompts and Skills;
4. registered connectors or tools;
5. deterministic validators;
6. fixtures and acceptance evals.

The framework supplies lifecycle, isolation, artifacts, limits, tracing, retry policy, packaging, replay, and CI scaffolding.

Diagnostics must include file, path, node ID, state key, expected type, actual type, and suggested remediation. A fast `validate` command is more important than a rich UI in v0.1.

## 8. Decision rule for adding a feature

Add a capability to the framework only when at least one is true:

- two independent workflows need it;
- it enforces a cross-cutting invariant;
- it eliminates a repeated security risk;
- it materially reduces test or debugging cost;
- it is necessary to remain compatible with an upstream standard.

Reject or defer it when it merely anticipates hypothetical flexibility.
