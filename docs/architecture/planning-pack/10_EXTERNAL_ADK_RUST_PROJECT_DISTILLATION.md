# External ADK-Rust Project Distillation

## 1. Method

Study independent projects that currently use ADK-Rust 1.0/current stable, plus clearly labeled near-current pre-1.0 comparison projects. Extract patterns, not code by default. Verify license, maintenance state, tests, and source freshness before reuse. Inclusion here is not an endorsement of overall project quality or security.

## 2. Entheai: migrate by adapting boundaries, not rewriting domains

Current Entheai source pins `adk-rust = 1.0.0` and Rust 1.94. Its migration design and implementation show several useful patterns:

- replace a hand-written agent/provider loop with an ADK-backed wrapper;
- keep existing application tools and adapt them to ADK Tool;
- move permission checks into lifecycle callbacks;
- invoke application memory through before/after callbacks;
- retain existing config conventions through a model resolver;
- hold the session service beside Runner when runtime access is needed;
- create a fresh session for each run and seed history explicitly when required;
- port behavioral parity tests before removing the old loop;
- preserve max-iteration cost/safety guards.

### Adopt now

- wrapper/adapter migration strategy;
- callbacks for cross-cutting concerns;
- behavioral parity tests;
- fresh session identity;
- explicit history seeding tests;
- preserving application tool/domain implementations.

### Do not copy blindly

- a big-bang cutover without a feature flag may be inappropriate for CodeSeek/Verbatim;
- application-specific memory and event choices;
- any accepted provider timeout/retry gap.

## 3. Cowork Forge: data-driven flows, actor-critic stages, and human gates

Cowork Forge currently pins ADK-Rust 1.0.0 crates. Its public source defines versioned, serializable flow definitions with ordered stage references, per-stage overrides, success/failure routing, global hooks, total execution limits, interrupt-state persistence, and configuration-driven built-in presets. Its documented development lifecycle combines specialized roles, actor-critic refinement, artifacts, Todo tracking, and human confirmation at critical stages.

### Adopt as patterns

- keep flow definitions versioned and serializable;
- separate stage definitions from flow topology;
- support per-stage overrides without mutating shared stage definitions;
- treat global hooks as cross-cutting policy/telemetry integration points;
- persist artifacts and explicit project/Todo state rather than relying only on conversation history;
- place human confirmation at high-value transition points;
- represent success and failure routing explicitly.

### Important cautions

- actor-critic wording does not prove review reliability; retain deterministic validators and bounded loops;
- its free-form condition field should not be copied into v0.1 without a closed expression/predicate design;
- its end-to-end product scope is much broader than the proposed workflow kit.

## 4. Portail: a near-current pre-1.0 comparison, not a latest-stable adopter


Portail currently pins ADK-Rust 0.9.1 because of its workspace MSRV, so it must not be counted as evidence about exact 1.0 APIs. It is retained only as a close pre-stable pattern comparison. It wraps a deterministic TOML golden-spec route comparison in an ADK CustomAgent and emits a typed report. It also schedules fresh-session CI agents with one Tokio task per schedule and skips missed ticks.

### Adopt now

- deterministic node/agent as a valid workflow participant;
- typed report emitted as an event/artifact;
- schedule-trigger pattern as a later generic trigger;
- fresh invocation/session per scheduled execution;
- keep direct deterministic entry point for tests and non-agent callers.

### Design implication

The platform should not force every node to be an LLM node. A registered deterministic validator/action should be easier to author and test than an agent.

## 5. Velocia: configuration factory and remote-agent tools

Velocia documents a YAML-driven `AgentFactory`, A2A JSON-RPC/SSE service, remote agents exposed as tools, optional persistent sessions, telemetry, JWT, and container-first per-agent deployment.

### Adopt as patterns

- configuration compiles into an agent/server factory;
- remote agents are explicit versioned tools with AgentCard discovery;
- thin client-only feature separate from the full runtime;
- container image per independently deployed agent/workflow;
- A2A examples as later interoperability tests.

### Defer

- making every workflow its own network service in v0.1;
- distributed orchestration before local compiler/runtime parity;
- a hard dependency on DynamoDB or any single session backend.

## 6. ADK Gateway: operational controls around agent execution

ADK Gateway demonstrates production-oriented patterns around current ADK-Rust:

- model fallback chains;
- runtime specialist agents;
- per-user independent sessions;
- graph workflows;
- scheduled tasks;
- interactive tool approval;
- runaway-loop rate limiting;
- health monitoring;
- hot-reloaded validated config;
- cancellation;
- graceful drain/restart;
- multiple session backends;
- progress events.

### Adopt or plan early

- cancellation and progress surfaces;
- tool approval as a graph/HITL gate;
- validated config reload for development;
- rate/loop limits independent of prompts;
- health/conformance commands;
- graceful shutdown before accepting server deployment.

### Defer

- multi-channel gateway UI;
- broad tool catalog;
- memory/RAG implementation unrelated to the workflow platform;
- channel-specific identity systems.

## 7. ADK Studio: interchange and code-generation compatibility

ADK Studio uses graph/action concepts, visual workflow editing, and Rust code generation. It is strategically relevant because the platform's canonical IR may later import/export a compatible subset.

### Adopt as a compatibility target

- stable node identity and graph interchange;
- action-node schema reuse where semantics match;
- compiler-generated dependency manifests;
- preflight warning when a sandbox cannot enforce requested controls.

### Defer

- UI integration;
- arbitrary action-node exposure;
- generated Rust as the only production path;
- visual editor-specific metadata in the core IR.

## 8. Upstream examples and crates

The upstream repository itself provides useful patterns:

- Retry & Reflect plugin with per-tool/global limits and structured tracing;
- YAML agent definitions with environment interpolation and plugin/session/memory references;
- graph workflow schema and action-node round trips;
- A2A/ACP/MCP adapters;
- sandbox/code capability separation;
- `cargo-adk` scaffolding and addon templates.

The framework should extend these patterns through composition and upstream contributions rather than forking.

## 9. Pattern adoption matrix

| Pattern | v0.1 | Later | Reject/default-off |
|---|:---:|:---:|:---:|
| Thin ADK compatibility wrapper | Yes | | |
| Existing tool adapters | Yes | | |
| Callback-based policy/telemetry/memory | Yes | | |
| Behavior parity tests | Yes | | |
| Fresh sessions per role/run | Yes | | |
| Deterministic CustomAgent/node | Yes | | |
| Config-to-runtime factory | Yes | | |
| Per-run container/workdir | Yes | | |
| A2A remote agent as tool | | Yes | |
| Scheduled triggers | | Yes | |
| Model fallback chains | | Yes | |
| Hot reload | Dev only | Yes | |
| Visual editor | | Yes | |
| Multi-channel gateway | | | Yes |
| Hundreds of default tools | | | Yes |
| Arbitrary host shell | | | Yes |

## 10. Continuing distillation process

Create a recurring research task for each ADK-Rust stable release:

1. search GitHub and crates.io for current-version adopters;
2. rank by recent commits, tests, source completeness, and production relevance;
3. inspect architecture, failure handling, configuration, sessions, tools, sandbox, and deployment;
4. add candidate patterns to a research registry;
5. require two independent examples or one compelling dogfood need before framework adoption;
6. record rejected patterns and reasons to avoid rediscovery;
7. upstream generic fixes when possible.

The research registry should store source commit, access date, license, pattern, evidence, confidence, and disposition.
