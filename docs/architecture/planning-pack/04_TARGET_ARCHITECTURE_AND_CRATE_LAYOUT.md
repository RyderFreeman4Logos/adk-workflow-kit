# Target Architecture and Crate Layout

## 1. System architecture

```text
                   Workflow Package
     workflow.toml / prompts / schemas / Skills / evals
                           │
                           ▼
                Parse + Validate + Normalize
                           │
                           ▼
                  Canonical Workflow IR
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
       Static policy checks        workflow.lock
             │
             ▼
                 ADK-Rust Graph Compiler
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
    Agent Registry    Tool/Node Registry  Skill Runtime
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                    Execution Runtime
       limits / sessions / workdir / sandbox / artifacts
       policy / callbacks / trace / checkpoint / review
                           │
                           ▼
                     Typed Run Result
```

## 2. Proposed workspace

```text
adk-workflow-kit/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── crates/
│   ├── workflow-spec/
│   ├── workflow-ir/
│   ├── workflow-compiler/
│   ├── workflow-adk/
│   ├── workflow-runtime/
│   ├── workflow-policy/
│   ├── workflow-tools/
│   ├── workflow-artifacts/
│   ├── workflow-workdir/
│   ├── workflow-sandbox/
│   ├── workflow-skills/
│   ├── workflow-review/
│   ├── workflow-testkit/
│   └── workflowctl/
├── patterns/
├── examples/
├── schemas/
├── docs/
└── tests/
```

The planning agent may merge crates during the first implementation to reduce compile overhead. The boundaries matter more than the initial package count. Split only when APIs and callers justify it.

## 3. Crate responsibilities

### 3.1 `workflow-spec`

- Serde types for the external TOML format.
- Source-span and path-aware diagnostics.
- No ADK dependency.
- Strict unknown-field policy by default, with explicit extension namespaces.
- Schema version dispatch.

### 3.2 `workflow-ir`

- Canonical normalized graph representation.
- Stable node and route enums.
- Resolved resource identities.
- Hashing and canonical serialization.
- No live model, tool, filesystem, or network behavior.

### 3.3 `workflow-compiler`

- Registry resolution.
- Graph structural validation.
- Closed route compilation.
- Cycle and terminal analysis.
- State contract checks.
- Security/policy preflight.
- Compilation diagnostics.

### 3.4 `workflow-adk`

- Concentrates direct ADK-Rust integration.
- Translates canonical IR into ADK graph, agent, tool, session, plugin, and artifact types.
- Owns compatibility shims for the exact pinned ADK version.
- Prevents ADK types from becoming public durable package formats.

### 3.5 `workflow-runtime`

- Run identity and lifecycle.
- Limits, cancellation, statuses, timers, progress tracking.
- Session creation and role isolation.
- Node visit ledger.
- Checkpoint hooks.
- Terminal result assembly.

### 3.6 `workflow-policy`

- Effective capability intersection.
- User, tenant, role, Skill, workflow, and node policies.
- Data classification and network destination rules.
- Approval requirements.
- Redaction policy.
- Does not replace domain-specific ACL enforcement.

### 3.7 `workflow-tools`

- Generic typed tool registration helpers.
- `ToolEnvelope<T>` and `ToolFailure`.
- Provenance, pagination, artifact handles, and output budgets.
- Read-only/concurrency-safe/idempotent metadata.
- Capability descriptors.

### 3.8 `workflow-artifacts`

- ArtifactStore trait.
- Content-addressed IDs.
- Page/range reads.
- Retention and pinning.
- Hash verification.
- In-memory and local filesystem implementations first.

### 3.9 `workflow-workdir`

- Per-run directory allocation.
- Immutable input snapshots.
- Mount plan generation.
- Quota accounting.
- cleanup/retention lifecycle.
- run manifest persistence.

### 3.10 `workflow-sandbox`

- Required capability model.
- Backend adapters for ADK sandbox/code execution.
- Linux bubblewrap backend first if conformance passes.
- rootless OCI/Podman backend for stricter or customer-compatible isolation.
- WASM/embedded-JS path for pure transforms.
- Network and filesystem policy enforcement.

### 3.11 `workflow-skills`

- Integrates `adk-skill`.
- Resolves explicit and query-selected Skills.
- Reads references through bounded resource tools.
- Executes declared scripts through the sandbox.
- Verifies Skill/runtime manifests and hashes.
- Produces Skill Evidence Packages and promotion metadata.

### 3.12 `workflow-review`

- Typed review verdicts and defect model.
- Compiler helpers for producer/reviewer/reviser patterns.
- no-progress, repeated-defect, repeated-output, and oscillation detectors.
- model-role isolation.
- bounded repair policy.

### 3.13 `workflow-testkit`

- Scripted LLM.
- Fake Tool and Registry.
- record/replay fixtures.
- fault injection.
- sandbox conformance harness.
- graph and trace assertions.
- adapters to `adk-eval`.

### 3.14 `workflowctl`

- Thin CLI over library crates.
- No business logic unique to the CLI.
- Human-readable and JSON diagnostics.

## 4. Central registry model

```rust
pub trait ModelRegistry { /* resolve immutable model profiles */ }
pub trait ToolRegistry { /* resolve typed tools by versioned ID */ }
pub trait NodeRegistry { /* resolve registered Rust nodes */ }
pub trait ValidatorRegistry { /* resolve deterministic validators */ }
pub trait PredicateRegistry { /* resolve complex route predicates */ }
pub trait SkillRegistry { /* resolve local or approved remote Skills */ }
```

A registry returns both an implementation and metadata:

- semantic version;
- schema hash;
- capability requirements;
- side-effect classification;
- idempotency support;
- read/write/network behavior;
- data-classification ceiling;
- source/build provenance.

The compiler binds these into the lockfile. Runtime lookup must match the locked identity or reject the run.

## 5. Core run contracts

Proposed application-neutral identities:

```rust
RunContext {
    run_id,
    workflow_id,
    workflow_version,
    package_hash,
    tenant_id,
    actor_id,
    role,
    scopes,
    data_classification,
    deadline,
    budget,
    idempotency_root,
    trace_id,
}
```

Proposed terminal statuses:

```text
completed
abstained
incomplete
failed
cancelled
timed_out
limit_exceeded
policy_denied
```

Each terminal result includes diagnostics, artifact references, cost/usage, validation reports, and the exact lock identity.

## 6. Dependency direction

```text
spec → ir → compiler → adk/runtime
                │         │
                ├─ policy │
                ├─ skills │
                └─ review │

workdir ← sandbox ← runtime
artifacts ← tools ← runtime
```

`workflow-spec` and `workflow-ir` should remain lightweight and testable without a model or sandbox. Application workflows depend on public platform crates, never on private internals.

## 7. Customer repository model

Shared platform and customer code should normally use separate repositories:

```text
shared platform repo
  └─ versioned crates and CLI

customer workflow repo
  ├─ workflow packages
  ├─ customer connectors
  ├─ customer validators
  ├─ private Skills and references
  └─ sanitized eval fixtures
```

This avoids accidental cross-customer data leakage and permits independent access controls. Cargo `[patch]` may point to a local platform checkout during development; releases pin a published or Git-revisioned platform version under an explicit policy.

## 8. Multi-tenancy boundary

The runtime may serve multiple tenants, but no mutable runtime state is implicitly shared. Every run has:

- tenant-scoped registries/policies;
- a unique workdir;
- independent session IDs;
- isolated artifact namespaces;
- scoped credentials;
- explicit model endpoint policy;
- audit identity.

Caches may be shared only when their keys include all security-relevant inputs and their content is permitted across the sharing boundary.
