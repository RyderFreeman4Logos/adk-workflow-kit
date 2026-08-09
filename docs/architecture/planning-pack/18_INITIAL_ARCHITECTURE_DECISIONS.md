# Initial Architecture Decision Set

These are proposed ADRs. The primary Hermes agent must verify sources, resolve conflicts, assign final ADR numbers, and commit accepted versions to the new repository.

## ADR A — Build above ADK-Rust rather than another agent framework

**Decision:** use the latest stable ADK-Rust 1.x as the substrate.  
**Reason:** Rust requirement, broad stable primitives, existing use in CodeSeek/Verbatim, and avoidance of hand-written agent/runtime machinery.  
**Consequence:** direct ADK imports are concentrated in a compatibility layer; upgrades require parity suites.

## ADR B — Declarative workflows are production artifacts

**Decision:** TOML packages compile to production execution and are not assumed to be throwaway prototypes.  
**Reason:** topology, policies, prompts, Skills, and model roles benefit from reviewable data; individual nodes can graduate to Rust.  
**Consequence:** package/IR/lock versioning becomes a durable compatibility responsibility.

## ADR C — TOML is the first authoring format; canonical IR is authoritative

**Decision:** parse TOML into a format-neutral IR.  
**Reason:** Rust ecosystem fit and future JSON/YAML/visual compatibility.  
**Consequence:** runtime never executes TOML directly; normalization and hashing are mandatory.

## ADR D — Closed node and route sets

**Decision:** v0.1 supports enumerated node kinds and route operators plus versioned registered Rust predicates.  
**Reason:** avoid an unsafe, weakly typed second language.  
**Consequence:** unsupported logic must be a registered node/predicate or remain handwritten ADK graph code.

## ADR E — Per-run workdir and verified sandbox

**Decision:** each run has an independent directory and a backend whose enforceable capabilities satisfy the workflow policy.  
**Reason:** reproducibility, cleanup, customer isolation, and safe Skill scripts.  
**Consequence:** backend mismatch is a preflight error; local process execution is not automatically production-safe.

## ADR F — Network denied by default

**Decision:** no egress unless a workflow/node policy names an approved network profile.  
**Reason:** Skill scripts and model-generated actions must not exfiltrate data or fetch uncontrolled dependencies.  
**Consequence:** connectors should often run as registered brokered tools outside the script sandbox.

## ADR G — Skills are instructions and resources, not authority

**Decision:** integrate Agent Skills but compute permissions by intersection.  
**Reason:** `allowed-tools` is descriptive/experimental and a Skill may be untrusted or customer-authored.  
**Consequence:** activation cannot expand the compiled capability set.

## ADR H — Skill scripts are declared by ID

**Decision:** execute only scripts listed in a locked runtime manifest through a sandbox.  
**Reason:** preserve agility without exposing arbitrary shell.  
**Consequence:** script path/hash/runtime/schema/capabilities are package metadata; stable scripts should graduate to Rust.

## ADR I — Objective validators outrank model reviewers

**Decision:** deterministic checks are authoritative, run before publish and after repair.  
**Reason:** model reviewers are probabilistic, self-biased, and inconsistent.  
**Consequence:** a reviewer `pass` cannot waive a failed validator.

## ADR J — All review and correction cycles are bounded

**Decision:** explicit max revisions plus global limits and no-progress detectors.  
**Reason:** prevent infinite loops, cost surprises, and oscillation.  
**Consequence:** exhaustion returns typed abstention/incomplete/failure.

## ADR K — Producer and reviewer sessions are isolated

**Decision:** independent session IDs and read-only reviewer tools by default.  
**Reason:** reduce context contamination and privilege.  
**Consequence:** necessary context is passed as explicit artifacts/inputs.

## ADR L — Large stage outputs become artifacts

**Decision:** use handles and paginated reads rather than copying large values through state/model context.  
**Reason:** token cost, memory, provenance, and reuse.  
**Consequence:** artifact identity and retention are core runtime contracts.

## ADR M — Domain source truth remains in applications

**Decision:** platform artifacts, sessions, auth, and RAG do not replace CodeSeek/Verbatim authoritative stores or ACLs.  
**Reason:** preserve security and product semantics.  
**Consequence:** application adapters validate every crossing.

## ADR N — Exact stable dependency pins and committed lockfiles

**Decision:** deployable workspaces use exact ADK 1.x pins and commit `Cargo.lock`.  
**Reason:** reproducible agent behavior and controlled upgrades.  
**Consequence:** upgrades are dedicated PRs with parity and conformance tests.

## ADR O — Extract with characterization tests

**Decision:** generic CodeSeek behavior is characterized before movement; Verbatim contracts are tested before adapter integration.  
**Reason:** avoid silently changing security, cost, or failure semantics.  
**Consequence:** framework API freeze waits for three dogfood workflows.

## ADR P — CLI is thin over libraries

**Decision:** parsing, compilation, execution, testing, and packaging live in reusable crates.  
**Reason:** CodeSeek, Verbatim, servers, and future GUI need embedding.  
**Consequence:** no important behavior exists only in shell command handlers.

## ADR Q — Upstream contributions preferred to long-lived fork

**Decision:** patch locally only with a removal plan and upstream issue/PR.  
**Reason:** reduce maintenance and benefit the ecosystem.  
**Consequence:** source audits precede general feature issues.

## ADR R — No hidden chain-of-thought persistence

**Decision:** store observable events, actions, artifacts, usage, and digests, not private reasoning text.  
**Reason:** privacy, security, and unnecessary dependency on hidden model internals.  
**Consequence:** replay is structural and artifact-based.

## ADR S — Explicit incomplete and abstained terminal states

**Decision:** uncertainty and insufficient evidence are typed outcomes.  
**Reason:** reliable systems must not fabricate success.  
**Consequence:** callers and UIs handle non-success states explicitly.

## ADR T — Visual editing is deferred, interchange is preserved

**Decision:** design IR IDs and graph semantics so ADK Studio compatibility is possible later, but do not block v0.1 on a GUI.  
**Reason:** validation, testkit, and dogfood produce greater immediate value.  
**Consequence:** avoid embedding editor-specific layout metadata in core semantics.
