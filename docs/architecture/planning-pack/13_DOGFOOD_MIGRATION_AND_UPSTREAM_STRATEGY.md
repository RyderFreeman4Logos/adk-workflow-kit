# Dogfood Migration and Upstream Strategy

## 1. Goal

Build the platform by extracting proven behavior from CodeSeek and then proving that the same substrate can express Verbatim's stronger domain contracts. Avoid a long framework-only phase with no real caller.

## 2. Migration rule

The first migration is behavior-preserving extraction, not a redesign. New declarative behavior is introduced only after characterization tests make regressions visible.

```text
characterize current behavior
  → extract neutral primitive
  → point original application to primitive
  → prove parity
  → add declarative compiler representation
  → prove parity again
  → generalize only with second/third caller
```

## 3. CodeSeek extraction workstream

### 3.1 Establish baseline

Record the exact CodeSeek commit, Cargo feature set, ADK versions, local model profile, and test commands. Add or confirm characterization tests for:

- typed Tool Call success and failure;
- empty versus failed results;
- per-run and per-role session isolation;
- model/tool/output/time limits;
- cancellation;
- artifact paging;
- structured finish;
- provider request extensions;
- retrieval artifact reuse;
- investigator output validation;
- reviewer repair and revalidation;
- evidence freshness/overlay behavior;
- redacted call ledger.

### 3.2 Extract in low-risk order

1. generic content digest and artifact-page utilities;
2. generic typed tool envelope and failure taxonomy;
3. generic run limits, counters, statuses, and trace events;
4. generic OpenAI-compatible adapter pieces only where upstream is insufficient;
5. session-role helper;
6. reviewer/reviser contract;
7. per-run workdir and sandbox wrappers;
8. declarative compiler integration.

After each step, CodeSeek remains green.

### 3.3 Maintain application boundaries

CodeSeek keeps:

- Broker and security implementation;
- code graph and retrieval pipeline;
- source snapshot/overlay logic;
- benchmark arms and schemas;
- evidence validation;
- MCP/CLI product interface.

The shared platform receives only application-neutral contracts.

### 3.4 Declarative parity workflow

Create a workflow package that compiles to the same logical sequence:

```text
preflight
→ shared retrieval binding
→ investigator
→ deterministic output/evidence validation
→ optional reviewer
→ repaired-output validation
→ artifact persistence
→ terminal result
```

Run paired fixtures through handwritten and declarative implementations. Compare structural behavior, not exact free-form wording.

## 4. Verbatim dogfood workstream

### 4.1 Keep domain types authoritative

Verbatim's source, chunk, evidence, context, ACL, and public SDK types remain Verbatim types. The platform invokes registered Verbatim nodes and validators through stable adapters.

### 4.2 Grounded answer package

Implement topology declaratively while retaining Rust validators for:

- claim support;
- quotation correctness;
- evidence authorization;
- citation bindings;
- publication eligibility;
- deterministic citation rendering.

The workflow must produce typed `Published`, `Abstained`, or `Disabled`-equivalent application results.

### 4.3 Multi-hop research package

Implement declaratively:

- decomposition agent/node;
- parallel retrieval;
- coverage validator/predicate;
- bounded correction;
- attributed merge;
- complete/incomplete terminal mapping.

The budget and coverage decisions remain deterministic Rust contracts.

## 5. Third-pattern requirement

Before freezing v0.1, add one materially different example from the external pattern study, preferably:

- scheduled deterministic spec drift check; or
- webhook-dedupe-enrich-sync with an idempotent fake side effect.

This prevents the platform from becoming specific only to retrieval/review workloads.

## 6. Feature-flag rollout

For CodeSeek and Verbatim:

- keep the platform integration behind a Cargo feature until parity gates pass;
- support paired benchmark/test execution;
- retain a fast rollback path during initial releases;
- do not allow both engines to mutate the same external side effect in one paired test;
- remove the old path only after a separate issue records evidence and rollback criteria.

## 7. Upstream-first review before every issue

Every issue that adds general ADK behavior must answer:

1. Does stable ADK-Rust already provide it?
2. Does current upstream `main` provide it?
3. Is an upstream issue or PR already active?
4. Can a thin adapter satisfy the need?
5. Is the requirement platform-specific enough to remain local?
6. If local now, what interface would allow later upstream replacement?

Record the result in the issue body.

## 8. Candidate upstream contributions

### High-value candidates

- workflow schema construction with agent/custom-node registries;
- better source-aware graph schema diagnostics;
- standardized hooks for Skill resources and declared script execution;
- sandbox conformance API/fixtures;
- documented role/session isolation helpers;
- workflow schema import/export compatibility with ADK Studio;
- provider request extension hooks if stable adapters lack them.

### Contribution sequence

1. reproduce the gap in a minimal upstream-compatible test;
2. discuss or open an issue upstream;
3. implement a local adapter without forking where possible;
4. submit a focused upstream PR;
5. retain compatibility until a released upstream version is available;
6. remove the local workaround in a dedicated upgrade PR.

## 9. Fork policy

Do not maintain a long-lived ADK-Rust fork by default. A temporary patch branch is acceptable only for:

- a confirmed release-blocking bug;
- a minimal, reviewable patch;
- an upstream issue/PR;
- a documented removal condition;
- CI against both patched and next upstream versions where feasible.

## 10. Release upgrade protocol

For each ADK-Rust stable release:

1. update the source register;
2. review release notes and changed public APIs;
3. run upstream capability-diff subagent;
4. update exact pins in one PR;
5. run all compiler, registry, Skill, sandbox, replay, CodeSeek, and Verbatim suites;
6. compare latency, memory, and event traces;
7. test old locked workflow packages;
8. update compatibility ADR and matrix;
9. publish only after dogfood deployments pass.

## 11. Extraction success criteria

- CodeSeek no longer owns duplicate generic lifecycle/tool/artifact/review helpers;
- CodeSeek behavior is equal or stricter;
- Verbatim uses the same platform without importing ADK types into durable/public domain schemas;
- three pattern packages compile through one IR;
- adding the third workflow requires new registered capabilities, not compiler surgery;
- upstream overlap is documented and minimized.
