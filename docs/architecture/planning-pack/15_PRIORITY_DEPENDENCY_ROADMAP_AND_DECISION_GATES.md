# Priority, Dependency Roadmap, Seed Backlog, and Decision Gates

## 1. Purpose

This is a **seed backlog**, not an instruction to create every issue unchanged. Subagents must verify, merge, split, rename, or reject candidates. The primary agent must preserve the dependency logic and acceptance intent.

## 2. Epic map

```text
E0 Governance and Upstream Baseline
E1 Specification, IR, and Compiler
E2 Runtime, Artifacts, Workdirs, and Sandbox
E3 Tools, Policy, and Skills
E4 Review, Reliability, and Evaluation
E5 CLI, Packaging, and Developer Experience
E6 CodeSeek Dogfood
E7 Verbatim Dogfood
E8 Release, Documentation, and Upstream Contributions
```

## 3. Critical path

```text
E0 baseline/ADRs
  → repository + CI
  → external spec + canonical IR
  → registries + compiler walking skeleton
  → runtime limits + workdir + fake sandbox
  → ADK graph compilation
  → tool/artifact contracts
  → Skill activation/resources
  → bounded review
  → CodeSeek declarative parity
  → Verbatim grounded-answer parity
  → Verbatim multi-hop parity
  → v0.1 release gate
```

Linux production sandbox can develop in parallel after the capability contract, but v0.1 production claims must wait for conformance.

## 4. Seed issue table

### E0 — Governance and Upstream Baseline

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| GOV-001 | P0 | Create repository, license, workspace, branch protection, and baseline CI | — | Empty workspace builds and protected CI is active |
| GOV-002 | P0 | Verify latest stable ADK-Rust, MSRV, crate feature matrix, and exact pin policy | — | Source-linked report and exact workspace pin |
| GOV-003 | P0 | Adopt initial ADR set and architecture boundary | GOV-002 | ADRs accepted; ADK/domain leakage rules explicit |
| GOV-004 | P1 | Establish security, contribution, release, and dependency policies | GOV-001 | Policy files and CI checks exist |
| GOV-005 | P1 | Create recurring external-adopter distillation process | GOV-002 | Research registry schema and scheduled issue/template |
| GOV-006 | P2 | Define upstream issue/PR tracking workflow | GOV-003 | Label/template and compatibility removal rules |

### E1 — Specification, IR, and Compiler

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| SPEC-001 | P0 | Define source-aware external workflow specification v1 skeleton | GOV-003 | TOML parses with path-aware diagnostics |
| IR-001 | P0 | Define canonical Workflow IR and stable identifiers | SPEC-001 | Canonical serialization and hash tests pass |
| DIAG-001 | P0 | Implement stable compiler diagnostic codes and JSON output | SPEC-001 | Human/JSON snapshots pass |
| REG-001 | P0 | Define model/tool/node/validator/predicate/Skill registry contracts | GOV-003 | Fake registries resolve versioned metadata |
| COMP-001 | P0 | Implement parse→normalize→resolve compiler pipeline | IR-001, REG-001, DIAG-001 | Minimal plan compiles to locked executable plan |
| COMP-002 | P0 | Implement graph reachability, terminal, and cycle analysis | IR-001 | Invalid graphs fail with exact diagnostics |
| COMP-003 | P0 | Implement closed route operators | IR-001 | Operator unit/property tests pass |
| COMP-004 | P1 | Implement registered Rust predicate routing | REG-001, COMP-003 | Versioned predicate fixture routes correctly |
| STATE-001 | P1 | Define state key/schema contracts and artifact-handle convention | IR-001 | Missing/incompatible state caught preflight where possible |
| LOCK-001 | P0 | Define and generate workflow lockfile v1 | COMP-001 | All semantic resource hashes recorded |
| MIGRATE-001 | P2 | Define explicit workflow/lock schema migration API | LOCK-001 | Old fixture migration tested |
| SUBWF-001 | P2 | Evaluate typed subworkflow invocation | COMP-001, STATE-001 | ADR accepts or defers with prototype evidence |

### E2 — Runtime, Artifacts, Workdirs, and Sandbox

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| RUN-001 | P0 | Define run context, statuses, limits, and typed terminal result | GOV-003 | Pure contract tests and serialization pass |
| RUN-002 | P0 | Implement host-enforced counters, wall/idle/tool limits, and cancellation | RUN-001 | Runaway fixture terminates and cleans up |
| SESSION-001 | P0 | Implement per-run/per-role ADK session isolation helpers | GOV-002, RUN-001 | Producer/reviewer IDs differ; history tests pass |
| ART-001 | P0 | Define ArtifactStore, content IDs, pagination, and retention interfaces | RUN-001 | In-memory store conformance passes |
| ART-002 | P1 | Implement local filesystem ArtifactStore | ART-001, WORKDIR-001 | Hash, atomic write, paging, cleanup tests pass |
| WORKDIR-001 | P0 | Implement independent per-run workdir manager and manifest | RUN-001 | Parallel runs cannot see each other's mutable files |
| WORKDIR-002 | P1 | Implement immutable input/package/Skill/reference materialization | WORKDIR-001, LOCK-001 | Hash and read-only plans verified |
| SBOX-001 | P0 | Define sandbox requested-capability and backend-capability contracts | GOV-003 | Unsatisfied required control fails preflight |
| SBOX-002 | P0 | Implement fake sandbox backend and common conformance suite | SBOX-001, WORKDIR-001 | Suite can validate allow/deny fixtures |
| SBOX-003 | P1 | Implement Linux bubblewrap backend | SBOX-002, WORKDIR-002 | Full Linux conformance suite passes |
| SBOX-004 | P1 | Integrate WASM/embedded-JS pure-transform backend | SBOX-001 | No-host-access transform fixtures pass |
| SBOX-005 | P2 | Implement rootless OCI/Podman backend | SBOX-002 | Image-digest and isolation conformance passes |
| CHECK-001 | P2 | Integrate external durable checkpoint backend | RUN-002, LOCK-001 | Kill/resume fixture avoids duplicate side effect |

### E3 — Tools, Policy, and Skills

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| TOOL-001 | P0 | Extract generic typed ToolEnvelope, ToolFailure, provenance, and metadata | REG-001, ART-001 | CodeSeek-compatible fixtures pass |
| TOOL-002 | P0 | Build typed FunctionTool registration helper | TOOL-001, GOV-002 | Input/output schema and flags generated correctly |
| TOOL-003 | P1 | Implement structured terminal/output tool helper | TOOL-002, RUN-001 | Valid output terminates; invalid output does not |
| POLICY-001 | P0 | Implement effective capability intersection | REG-001, SBOX-001 | Property tests prove no privilege expansion |
| POLICY-002 | P1 | Add role, tenant, data classification, and network profile policy | POLICY-001 | Denial and redaction fixtures pass |
| APPROVAL-001 | P1 | Compile approval/HITL node with timeout and denial semantics | RUN-002, POLICY-001 | Approval grant/deny/expire tests pass |
| SKILL-001 | P0 | Integrate `adk-skill` discovery, parse, and explicit activation | REG-001, GOV-002 | Valid/invalid Agent Skills fixtures pass |
| SKILL-002 | P0 | Implement bounded Skill resource listing/read tools | SKILL-001, ART-001, POLICY-001 | Traversal/symlink/size tests pass |
| SKILL-003 | P0 | Define `skill.runtime.toml` schema and integrity lock | SKILL-001, LOCK-001, SBOX-001 | Declared scripts/resources lock deterministically |
| SKILL-004 | P1 | Implement declared Skill script execution by ID | SKILL-003, SBOX-002, WORKDIR-002 | No arbitrary path/command; schema tests pass |
| SKILL-005 | P1 | Define Skill Evidence Package and promotion metadata | SKILL-001, RUN-001 | Redacted evidence fixture validates |
| SKILL-006 | P2 | Add semantic Skill candidate retrieval adapter | SKILL-001, POLICY-001 | Relevance cannot alter capability set |
| SECRET-001 | P2 | Define brokered secret/credential interface | POLICY-002, SBOX-001 | Secrets absent from state/workdir/trace fixtures |

### E4 — Review, Reliability, and Evaluation

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| REVIEW-001 | P0 | Define typed ReviewVerdict and Defect contracts | RUN-001, STATE-001 | Schema and serialization tests pass |
| REVIEW-002 | P0 | Compile producer→validator→reviewer→reviser pattern | REVIEW-001, SESSION-001, COMP-003 | Scripted model graph reaches all routes |
| REVIEW-003 | P0 | Implement repeated-output, repeated-defect, and two-cycle detection | REVIEW-001, RUN-002 | Non-progress fixtures abstain within bounds |
| REVIEW-004 | P1 | Enforce repaired-output deterministic revalidation | REVIEW-002 | Reviewer cannot bypass validator |
| REVIEW-005 | P1 | Add multi-reviewer disagreement policy prototype | REVIEW-002 | ADR and eval fixture accept/defer default |
| TESTKIT-001 | P0 | Implement scripted LLM and fake Tool/Registry harness | REG-001, RUN-001 | Deterministic tool loop fixture passes |
| TESTKIT-002 | P0 | Implement record/replay bundle format | TESTKIT-001, LOCK-001, ART-001 | Replay reproduces structural trace |
| TESTKIT-003 | P1 | Implement fault-injection utilities | TESTKIT-001, RUN-002 | Timeout/rate/invalid/output flood fixtures pass |
| EVAL-001 | P1 | Integrate `adk-eval` behind platform test API | TESTKIT-001, GOV-002 | One trajectory and rubric fixture runs |
| OBS-001 | P1 | Define redacted event, call-ledger, and OTel mapping | RUN-001, TOOL-001 | No chain-of-thought/raw secret snapshots |
| BENCH-001 | P2 | Add compiler/runtime/sandbox benchmark suite | COMP-001, SBOX-003 | Baseline report generated |

### E5 — CLI, Packaging, and Developer Experience

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| CLI-001 | P0 | Scaffold thin `workflowctl` with human/JSON diagnostics | DIAG-001, GOV-001 | Help and JSON error fixtures pass |
| CLI-002 | P0 | Implement `validate`, `graph`, and `lock` | COMP-001, COMP-002, LOCK-001, CLI-001 | Example package validates and renders graph |
| CLI-003 | P1 | Implement `run` and `explain-run` | RUN-002, WORKDIR-001, CLI-001 | Scripted example runs and explains artifacts |
| CLI-004 | P1 | Implement `test`, `eval`, and `replay` | TESTKIT-002, EVAL-001, CLI-001 | Local CI workflow uses commands |
| CLI-005 | P1 | Implement Skill lint/test commands | SKILL-003, SKILL-004, CLI-001 | Invalid manifests/scripts fail clearly |
| PKG-001 | P1 | Define workflow package manifest/archive validation | LOCK-001, WORKDIR-002 | Path/hash/secret-scan fixtures pass |
| TEMPLATE-001 | P1 | Add initial pattern scaffolds and Developer Skills | CLI-002, TESTKIT-001 | New workflow passes offline tests immediately |
| HOTRELOAD-001 | P2 | Add development-only immutable hot reload | CLI-003, LOCK-001 | In-flight run remains on old package |

### E6 — CodeSeek Dogfood

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| CS-001 | P0 | Pin CodeSeek characterization commit and inventory generic candidates | GOV-003 | Source-linked extraction report |
| CS-002 | P0 | Add/confirm lifecycle and ToolEnvelope characterization tests | CS-001 | Existing behavior captured |
| CS-003 | P1 | Migrate generic tool/artifact contracts to platform | TOOL-001, ART-001, CS-002 | CodeSeek tests unchanged in intent |
| CS-004 | P1 | Migrate lifecycle/session/trace helpers | RUN-002, SESSION-001, OBS-001, CS-002 | Limit and isolation parity passes |
| CS-005 | P1 | Express CodeSeek investigator workflow declaratively | CLI-003, TOOL-003, CS-003, CS-004 | Paired fixture structural parity |
| CS-006 | P1 | Express isolated reviewer/repair declaratively | REVIEW-004, CS-005 | Revalidation and session parity |
| CS-007 | P1 | Integrate per-run workdir/sandbox into CodeSeek workflow | SBOX-003, CS-005 | Repository access constrained; parity passes |
| CS-008 | P2 | Decide old workflow path removal | CS-006, CS-007 | ADR with benchmark and rollback evidence |

### E7 — Verbatim Dogfood

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| VB-001 | P0 | Pin Verbatim contract commit and map adapters/validators | GOV-003 | Domain-boundary report |
| VB-002 | P1 | Implement Verbatim platform adapter without ADK type leakage | REG-001, VB-001 | Boundary tests reject leakage |
| VB-003 | P1 | Compile grounded-answer workflow package | REVIEW-004, TOOL-003, VB-002 | Publish/abstain transition parity |
| VB-004 | P1 | Bind deterministic claim/citation validators | VB-003 | Unsupported claim never publishes |
| VB-005 | P1 | Compile multi-hop decomposition/fanout/coverage workflow | COMP-004, VB-002, TESTKIT-001 | Complete/corrective/incomplete fixtures pass |
| VB-006 | P1 | Bind budgets, coverage predicate, and attributed merge | VB-005 | Bounded corrective parity |
| VB-007 | P2 | Add production sandbox/workdir profile for Verbatim workflows | SBOX-003, VB-003, VB-005 | Source truth/ACL boundaries remain intact |

### E8 — Release and Upstream

| ID | Pri | Issue | Blocked by | Completion signal |
|---|---|---|---|---|
| DOC-001 | P1 | Publish architecture, spec, Skill, sandbox, and security docs | CS-006, VB-006, PKG-001, SBOX-003, SKILL-004 | Docs match implemented contracts |
| UP-001 | P2 | Prototype upstream graph builder with registries | COMP-001, GOV-006 | Minimal patch/issue or explicit rejection |
| UP-002 | P2 | Propose upstream Skill resource/script hooks | SKILL-004, GOV-006 | Minimal upstream design submitted |
| RELEASE-001 | P1 | Define v0.1 compatibility and release checklist | CS-006, VB-006, PKG-001 | Checklist and migration guarantees accepted |
| RELEASE-002 | P1 | Run security review and dependency audit | SBOX-003, POLICY-002, SKILL-004 | No unresolved critical findings |
| RELEASE-003 | P1 | Publish v0.1 crates/binary and dogfood migration guidance | RELEASE-001, RELEASE-002, DOC-001 | Reproducible signed release |

## 5. Recommended initial ready queue

After repository creation and exact dependency verification, likely ready items are:

```text
GOV-002  Verify upstream baseline
GOV-001  Create workspace and CI
GOV-003  Accept initial ADRs (after GOV-002)
CS-001   Pin and inventory CodeSeek
VB-001   Pin and inventory Verbatim
SPEC-001 External specification skeleton (after GOV-003)
RUN-001  Run contracts (after GOV-003)
SBOX-001 Sandbox capability contract (after GOV-003)
```

The primary agent must calculate the actual queue rather than copying this list mechanically.

## 6. Parallel groups

After ADRs:

- spec/IR/compiler contracts;
- runtime/status/limits;
- workdir/sandbox capability model;
- CodeSeek characterization;
- Verbatim adapter inventory;
- testkit scripted model;

can proceed in parallel with shared review checkpoints.

## 7. Decision gates

### Gate M0: Architecture ready

- upstream baseline verified;
- ADRs accepted;
- repository/CI active;
- CodeSeek and Verbatim baseline commits pinned;
- issue DAG has no cycles.

### Gate M1: Walking skeleton

- minimal TOML parses to IR;
- registry resolves fake capabilities;
- graph executes through ADK;
- run gets independent workdir;
- limits/cancellation work;
- offline test passes.

### Gate M2: Isolated Skill execution

- Skills activate progressively;
- resources are path-safe and paginated;
- declared script runs only in conforming sandbox;
- capability intersection passes property tests.

### Gate M3: Reliability

- deterministic validator and typed review loop;
- repaired output revalidated;
- no-progress detector terminates;
- record/replay and fault injection work.

### Gate M4: CodeSeek parity

- declarative workflow meets characterization suite;
- no extra high-cost retrieval calls;
- sandbox profile works;
- rollback evidence exists.

### Gate M5: Verbatim parity

- grounded-answer and multi-hop contracts pass;
- ADK does not become source truth or ACL;
- incomplete/abstain behavior preserved.

### Gate M6: v0.1

- security review;
- documentation;
- package/lock stability statement;
- reproducible release;
- dogfood adoption guidance.

## 8. Deferred backlog

- remote package/Skill registry;
- signed organization package attestations;
- visual editor/import-export with ADK Studio;
- A2A remote subworkflows;
- distributed worker scheduler;
- Postgres/Redis production checkpoint implementations;
- model fallback/router marketplace;
- advanced semantic Skill retrieval;
- customer admin UI;
- full workflow debugger;
- dynamic plugin ABI;
- arbitrary expression language, likely permanently rejected.
