# Source Register

## 1. Purpose and caveat

This register records sources used for the planning pack. It is a research snapshot dated 2026-08-03. The implementation agent must verify current stable releases, current default-branch source, licenses, and active issues/PRs before creating final implementation issues.

Primary source is preferred. Independent projects are pattern evidence, not authoritative documentation for ADK-Rust.

## 2. ADK-Rust upstream

### Release and repository

- ADK-Rust releases: <https://github.com/zavora-ai/adk-rust/releases>
- v1.0.0 release tag: <https://github.com/zavora-ai/adk-rust/releases/tag/v1.0.0>
- Repository: <https://github.com/zavora-ai/adk-rust>
- Stability policy: <https://github.com/zavora-ai/adk-rust/blob/main/STABILITY.md>
- Roadmap: <https://github.com/zavora-ai/adk-rust/blob/main/ROADMAP.md>

Snapshot finding: v1.0.0 was listed as latest stable; release notes describe SemVer stability, Rust 1.94 MSRV, durable/resumable Graph workflows, HITL, sessions, A2A, MCP, functional graph, server scheduling, and the broader stable crate set.

### Core crates and source

- `adk-agent`: <https://docs.rs/adk-agent/1.0.0/adk_agent/>
- `adk-graph`: <https://docs.rs/adk-graph/1.0.0/adk_graph/>
- Workflow schema source: <https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-graph/src/workflow.rs>
- Graph node/AgentNode source: <https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-graph/src/node.rs>
- `adk-action`: <https://docs.rs/adk-action/1.0.0/adk_action/>
- Action executor source: <https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-graph/src/action/mod.rs>
- File action source: <https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-graph/src/action/file.rs>
- Code action source: <https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-graph/src/action/code.rs>
- `adk-skill`: <https://docs.rs/adk-skill/1.0.0/adk_skill/>
- `adk-sandbox`: <https://docs.rs/adk-sandbox/1.0.0/adk_sandbox/>
- `adk-code`: <https://docs.rs/adk-code/1.0.0/adk_code/>
- Retry/Reflect: <https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-retry-reflect/README.md>
- YAML agent schema: <https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-server/src/yaml_agent/schema.rs>
- YAML loader: <https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-server/src/yaml_agent/loader.rs>
- `cargo-adk`: <https://github.com/zavora-ai/adk-rust/tree/v1.0.0/cargo-adk>

### ADK Studio

- Repository: <https://github.com/zavora-ai/adk-studio>
- README: <https://github.com/zavora-ai/adk-studio/blob/main/README.md>
- Code generation: <https://github.com/zavora-ai/adk-studio/tree/main/src/codegen>

Pattern relevance: graph/action interchange, visual editing, production Rust code generation, and backend capability preflight. It is a later compatibility target rather than a v0.1 dependency.

## 3. Agent Skills

- Specification: <https://agentskills.io/specification>
- Client implementation guidance: <https://agentskills.io/client-implementation/adding-skills-support>
- Script authoring guidance: <https://agentskills.io/skill-creation/using-scripts>

Snapshot findings: a Skill contains `SKILL.md` and optional `scripts/`, `references/`, and `assets/`; progressive disclosure and relative references are part of the design; `allowed-tools` is experimental and must not be treated as an authorization grant.

## 4. Sandbox and operating-system primitives

- Bubblewrap repository and security notes: <https://github.com/containers/bubblewrap>
- Podman run documentation: <https://docs.podman.io/en/latest/markdown/podman-run.1.html>
- Linux Landlock documentation: <https://docs.kernel.org/userspace-api/landlock.html>

Snapshot finding: bubblewrap supplies low-level namespace/mount primitives and explicitly leaves policy construction to the caller. Therefore platform conformance tests are mandatory.

## 5. User repositories

### CodeSeek

- Repository: <https://github.com/RyderFreeman4Logos/codeseek>
- ADK module: `rust-core/src/workflow_adk/`
- Key files at snapshot:
  - `mod.rs`
  - `lifecycle.rs`
  - `pipeline.rs`
  - `toolset.rs`
  - `openai_compat.rs`
- Cargo manifest: `rust-core/Cargo.toml`

Pattern evidence: exact ADK feature pinning, narrow boundary, typed read-only tools, lifecycle limits, redacted tracing, progressive artifacts, isolated reviewer/repair, deterministic evidence validation, and retrieval artifact reuse.

### Verbatim

- Repository: <https://github.com/RyderFreeman4Logos/verbatim>
- ADK architecture: `docs/architecture/adk-rust-integration.md`
- ADK contract code: `crates/verbatim-core/src/adk_integration/`
- Grounded answer: `crates/verbatim-core/src/grounded_answer/`
- Multi-hop research: `crates/verbatim-core/src/multi_hop_research/`

Pattern evidence: explicit adopt/wrap boundaries, no ADK domain leakage, fail-closed state machines, grounded publication, deterministic citation rendering, bounded revision, coverage-driven corrective rounds, and incomplete outcomes.

## 6. Independent ADK-Rust adopters

### Entheai

- Repository: <https://github.com/entropy-om/entheai>
- ADK migration design: <https://github.com/entropy-om/entheai/blob/main/docs/superpowers/specs/2026-07-22-adk-rust-core-migration-design.md>
- Current workspace manifest: <https://github.com/entropy-om/entheai/blob/main/Cargo.toml>
- Agent wrapper: <https://github.com/entropy-om/entheai/blob/main/crates/core/src/entheai_agent.rs>

Pattern evidence: application wrapper around ADK, old Tool adapters, callback-based permissions/memory, fresh sessions, history seeding, and behavioral parity tests.

### Cowork Forge

- Repository: <https://github.com/sopaco/cowork-forge>
- Workspace manifest: <https://github.com/sopaco/cowork-forge/blob/main/Cargo.toml>
- Flow definition source: <https://github.com/sopaco/cowork-forge/blob/main/crates/cowork-core/src/config_definition/flow_definition.rs>

Snapshot finding: the project pins ADK-Rust 1.0.0 crates and uses versioned serializable flow/stage configuration, hooks, success/failure routing, execution limits, artifacts, human gates, and actor-critic-style stages. Review claims still require independent evaluation.

### Portail (pre-1.0 comparison)

- Repository: <https://github.com/peterlodri-sec/portail>
- Deterministic spec verifier: <https://github.com/peterlodri-sec/portail/blob/main/crates/portail-agents/src/ci/spec_verify.rs>
- Scheduled CI runner: <https://github.com/peterlodri-sec/portail/blob/main/crates/portail-agents/src/ci/runner.rs>

Version caveat: its current agent crate pins ADK-Rust 0.9.1, not 1.0.0. Use it only as a near-current pattern comparison. Pattern evidence: deterministic checks wrapped as ADK CustomAgents, typed report events, fresh invocation sessions, and schedule behavior.

### Velocia

- Docs: <https://docs.rs/crate/velocia/latest>

Pattern evidence: YAML AgentFactory, A2A JSON-RPC/SSE, remote agents as tools, optional persistent sessions/telemetry/JWT, and container-first per-agent deployment.

### ADK Gateway

- Docs: <https://docs.rs/crate/adk-gateway/1.0.0>
- Repository identified by docs: <https://github.com/zavora-ai/adk-gateway>

Pattern evidence: fallback chains, multi-user sessions, graph workflows, schedules, tool approvals, rate limiting, health monitoring, cancellation, hot reload, graceful restart, and multiple session backends.

## 7. Reliability and workflow research

- Workflow-to-Skill: <https://arxiv.org/abs/2606.06893>
- SKILL-DISCO: <https://arxiv.org/abs/2606.26669>
- FlowEvo: <https://arxiv.org/abs/2607.21596>
- DeCRIM, structured critique: <https://aclanthology.org/2024.findings-emnlp.458/>
- Self-bias and self-refinement study: <https://aclanthology.org/2024.acl-long.826/>
- LLM-as-judge consistency: <https://aclanthology.org/2025.findings-emnlp.1361/>
- Checklist-decomposed judging (CheckEval): <https://aclanthology.org/2025.emnlp-main.796/>
- Adversarial persuasion of judges: <https://aclanthology.org/2025.findings-emnlp.790/>
- Survey/evidence on self-correction: <https://aclanthology.org/2024.tacl-1.78/>

Use these papers to motivate experiments and failure controls, not as proof that a specific model/runtime configuration is reliable for customer data.

## 8. Source-quality rules for subagents

1. Prefer release tags and official docs over blogs.
2. Inspect source for behavior that security or correctness depends on.
3. Record exact commit/tag and access date.
4. Treat README claims as claims until tests/source support them.
5. Do not infer production security from the word “sandbox” or “container.”
6. Check license before copying code.
7. Verify that an independent project actually uses the claimed ADK version.
8. Separate current stable behavior from unreleased `main` behavior.
