# Upstream Baseline and Reuse Matrix

## 1. Verified release baseline

As of 2026-08-03, ADK-Rust v1.0.0 is the latest stable release listed by the upstream repository. The release declares a SemVer-stable 1.x line and Rust 1.94 MSRV. Its published capability set includes graph workflows with durable/resumable execution and HITL, multiple session backends, A2A, MCP, plugins, Skills, evaluation, authentication, telemetry, artifacts, server scheduling, and model providers.

The planning agent must verify this again immediately before pinning dependencies. Upstream `main` may contain post-release changes and should be researched for future contributions, but production implementation must target a released version unless an explicit ADR justifies a temporary commit pin.

## 2. Upstream capabilities that should be reused

| Need | Upstream component | Default disposition |
|---|---|---|
| Agent/tool-call loop | `adk-agent` | Adopt |
| Events and core contracts | `adk-core` | Adopt behind application boundary |
| Execution and session orchestration | `adk-runner`, `adk-session` | Adopt/wrap |
| Graph, cycles, interrupts, checkpointing | `adk-graph` | Adopt |
| Deterministic action nodes | `adk-action` | Adopt selectively |
| Typed function tools and registries | `adk-tool`, core registries | Adopt |
| Agent Skills parsing/matching/injection | `adk-skill` | Adopt and extend |
| Retry/reflect plugin | `adk-retry-reflect` | Evaluate; do not duplicate |
| Tool/model lifecycle hooks | `adk-plugin` and callbacks | Adopt |
| Evaluation and trajectory checks | `adk-eval` | Adopt and wrap in testkit |
| Artifacts | `adk-artifact` | Wrap; do not replace application evidence stores |
| Authentication and RBAC plumbing | `adk-auth` | Wrap; do not replace domain ACLs |
| Telemetry | `adk-telemetry` | Adopt through standard spans/events |
| Sandbox abstraction | `adk-sandbox` | Adopt after capability conformance tests |
| Code execution pipelines | `adk-code` | Adopt selectively |
| YAML agent loading | `adk-server` YAML loader | Study/reuse pieces; not the workflow language itself |
| Visual interchange/code generation | `adk-studio` | Compatibility target later, not v0.1 dependency |
| A2A/ACP/MCP transports | upstream crates | Adopt only when a workflow requires them |

## 3. Existing upstream declarative building blocks

### 3.1 Serializable workflow graph

`adk-graph` v1 contains a serializable `WorkflowSchema` with edges, conditions, action-node configurations, and agent-node identifiers. It can build a graph from action nodes and edges. This is evidence that a configuration-to-graph path is aligned with upstream architecture.

However, the current stable builder does not by itself resolve arbitrary agent nodes, application validators, predicates, Skills, or tool profiles. The proposed compiler should add registries and static checks above this schema, not fork the graph executor.

### 3.2 Action nodes

`adk-action` and the graph executor provide deterministic node families such as set, transform, switch, loop, merge, wait, file, HTTP, database, notification, and code-related nodes. They already carry common timeout, condition, retry, continue, and fallback behavior.

The platform must still restrict them. For example, the upstream file node can write and delete, while the default platform profile should expose only capabilities explicitly approved by policy. Upstream availability is not equivalent to default authorization.

### 3.3 YAML agent configuration

The server-side YAML loader already models provider/model configuration, instructions, named tools, subagents, plugins, sessions, memory backends, and environment interpolation. This should inform the proposed configuration model. It is not sufficient as the complete workflow compiler: stable source currently treats MCP references as unresolved during ordinary load, and it is centered on agent construction rather than cross-node state contracts, lockfiles, Skill script policies, and per-run workspaces.

### 3.4 Skills

`adk-skill` implements Agent Skills discovery, frontmatter parsing, indexing, lexical selection, allowed-tool validation, and prompt injection. It does not currently execute Skill scripts or provide a full reference-resource execution layer. It also does not provide the proposed promotion registry, package lock, remote catalog, or semantic retrieval layer.

The framework should integrate this crate and contribute generally useful missing hooks upstream where appropriate.

### 3.5 Sandbox and code execution

`adk-sandbox` distinguishes backend capabilities. Its process backend is useful but does not enforce all network, filesystem, or memory constraints by itself. WASM and platform-specific enforcers provide stronger controls. `adk-code` adds Rust, embedded JavaScript, container, and Docker execution paths and validates whether a requested policy can be enforced.

The platform must preserve this honesty: requested controls are requirements, not advisory flags. A backend mismatch is a preflight failure.

## 4. Capabilities the new platform should add

The following are the main justified additions:

1. versioned TOML front-end and canonical workflow IR;
2. compiler with model/tool/node/validator/predicate/Skill registries;
3. restricted route operators and cycle analysis;
4. package and lockfile format;
5. per-run work directory manager;
6. sandbox policy and backend capability negotiation;
7. Skill resource and declared-script execution layer;
8. effective permission intersection;
9. producer/reviewer/reviser compiler pattern;
10. no-progress and oscillation detection;
11. uniform typed tool envelope and progressive artifacts;
12. application-neutral lifecycle limits, statuses, and traces;
13. record/replay and fault-injection testkit;
14. scaffolding and CLI optimized for FDE delivery;
15. Skill Evidence Package and promotion workflow.

## 5. Explicitly prohibited reinvention

Do not create a parallel implementation of:

- an LLM provider abstraction merely to avoid ADK model types;
- a generic agent loop;
- a graph scheduler;
- an MCP client/server stack;
- a generic session database;
- an unrelated evaluation framework;
- a second Agent Skills parser;
- a home-grown telemetry protocol;
- a generic RBAC system;
- arbitrary code compilation when `adk-code` already supports the requirement.

A stable application boundary is still necessary. The distinction is between wrapping upstream behavior and recreating it.

## 6. Proposed version policy

- Exact pin of all direct `adk-*` dependencies in the workspace root.
- Commit `Cargo.lock` for CLI, server, examples, and conformance binaries.
- One compatibility crate owns direct ADK imports where practical.
- ADK upgrades occur in dedicated pull requests.
- Every upgrade runs graph, tool, sandbox, Skill, replay, CodeSeek parity, and Verbatim parity suites.
- No customer workflow depends directly on an ADK internal struct in its durable schema.
- Preserve old workflow package execution when possible through compiler/schema versioning, not by silently changing semantics.

## 7. Candidate upstream contributions

Subagents should verify whether these gaps still exist on current `main`:

1. `WorkflowSchema::build_graph_with_registries` or equivalent agent/custom-node binding.
2. Resource access hooks for Agent Skills.
3. Standard Skill script declaration and execution adapter interfaces, without imposing an unsafe universal shell.
4. Stronger workflow schema validation diagnostics.
5. Exported session-service access or a documented wrapper pattern.
6. Sandbox conformance fixtures.
7. Workflow schema/codegen round-trip compatibility with ADK Studio.

Do not plan upstream work until a minimal local proof demonstrates the gap.
