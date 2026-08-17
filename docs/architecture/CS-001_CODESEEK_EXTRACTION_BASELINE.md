# CS-001 CodeSeek Extraction Baseline

Revalidated: 2026-08-17T11:14:45Z

This report is an offline characterization baseline for one frozen CodeSeek
commit. It records extraction candidates only: it adds no runtime behavior and
does not import ADK into this kit.

## Verified upstream commit

- Default branch: `main`.
- Commit: [`88a14f3d94d9ed3b161de8bc13304941efc428ef`](https://github.com/RyderFreeman4Logos/codeseek/commit/88a14f3d94d9ed3b161de8bc13304941efc428ef).
- Committer date: `2026-08-11T18:27:58Z`.
- Subject: `test(security): use writable hidden temp outside broker root (#328)`.
- Revalidation: `env -u GH_CONFIG_DIR gh api repos/RyderFreeman4Logos/codeseek/commits/HEAD` returned this SHA at the timestamp above.

All repository-relative source references below resolve inside that exact commit.

## Pin inventory

| Field | Pinned value and source |
|---|---|
| Access/revalidation date | `2026-08-17T11:14:45Z` UTC. |
| Cargo feature set | `default = ["workflow-adk"]`; that feature enables optional `adk-agent`, `adk-core`, `adk-runner`, `adk-session`, `adk-tool`, and `schemars`. [rust-core/Cargo.toml:12-21](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/Cargo.toml#L12-L21) |
| ADK versions | Each enabled ADK dependency is `=1.0.0` with `default-features = false`; the manifest declares Rust `1.94`. [rust-core/Cargo.toml:1-5](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/Cargo.toml#L1-L5), [rust-core/Cargo.toml:40-47](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/Cargo.toml#L40-L47) |
| Workspace pins | No repository-root `Cargo.toml` exists at this pin; no additional workspace pin was found. |
| Local model profile | Versioned local profile: `qwen3.6-27b-decensored`, `Qwen/Qwen3.6-27B`, revision `main`, `NVFP4`, 262144-token context, OpenAI tool-call parser, vLLM reference serving engine, and thinking disabled with a versioned mechanism. [benchmarks/three-arm/v1/configs/local-model-provider.toml:11-42](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/benchmarks/three-arm/v1/configs/local-model-provider.toml#L11-L42) |
| Test commands | Documented only; not executed for CS-001: `just pre-commit-fast`, `just acceptance-gates`, `just test-workflow-adk-all`, and `just test-retrieval-only`. [justfile:18-47](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/justfile#L18-L47), [justfile:206-262](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/justfile#L206-L262) |

## Candidate inventory

| ID | Extraction intent | Evidence at the pinned commit |
|---|---|---|
| 2.1 | Preserve the optional, exact-version ADK adapter boundary while keeping core retrieval and broker types outside it. | [rust-core/Cargo.toml:12-21](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/Cargo.toml#L12-L21), [rust-core/src/workflow_adk/mod.rs:1-14](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/mod.rs#L1-L14) |
| 2.2 | Characterize reusable run limits, counters, cancellation, and terminal statuses. | [rust-core/src/workflow_adk/lifecycle.rs:3-6](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/lifecycle.rs#L3-L6), [rust-core/src/workflow_adk/lifecycle.rs:40-65](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/lifecycle.rs#L40-L65), [rust-core/src/workflow_adk/lifecycle.rs:96-116](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/lifecycle.rs#L96-L116) |
| 2.3 | Characterize a redacted model/tool trace and call-ledger contract. | [rust-core/src/workflow_adk/lifecycle.rs:121-152](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/lifecycle.rs#L121-L152) |
| 2.4 | Characterize the typed envelope for success, empty, failure, provenance, paging, artifact handle, and data. | [rust-core/src/workflow_adk/toolset.rs:42-80](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/toolset.rs#L42-L80) |
| 2.5 | Characterize content-addressed stage artifacts and bounded offset/limit reads. | [rust-core/src/workflow_adk/toolset.rs:82-109](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/toolset.rs#L82-L109), [rust-core/src/workflow_adk/toolset.rs:812-867](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/toolset.rs#L812-L867) |
| 2.6 | Characterize structured final-output validation and ADK-native termination. | [rust-core/src/workflow_adk/toolset.rs:359-363](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/toolset.rs#L359-L363), [rust-core/src/workflow_adk/toolset.rs:870-924](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/toolset.rs#L870-L924) |
| 2.7 | Characterize provider request extensions only where upstream adapters cannot meet the local-model contract. | [rust-core/src/workflow_adk/openai_compat.rs:290-353](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/openai_compat.rs#L290-L353) |
| 2.8 | Characterize immutable shared retrieval artifacts and ledger reuse across paired runs. | [rust-core/src/workflow_adk/pipeline.rs:319-371](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/pipeline.rs#L319-L371), [rust-core/src/workflow_adk/pipeline.rs:1063-1069](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/pipeline.rs#L1063-L1069) |
| 2.9 | Characterize isolated investigator/reviewer sessions and evidence-plus-schema revalidation of repairs. | [rust-core/src/workflow_adk/pipeline.rs:393-505](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/pipeline.rs#L393-L505) |
| 2.10 | Characterize snapshot identity and evidence-freshness metadata while retaining CodeSeek's overlay implementation. | [rust-core/src/workflow_adk/toolset.rs:42-50](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/toolset.rs#L42-L50), [rust-core/src/workflow_adk/pipeline.rs:271-279](https://github.com/RyderFreeman4Logos/codeseek/blob/88a14f3d94d9ed3b161de8bc13304941efc428ef/rust-core/src/workflow_adk/pipeline.rs#L271-L279) |

## Stays local to CodeSeek

- PetCodeGraph and language-specific graph queries.
- Benchmark arm identities and teacher/reference exclusions.
- CodeSeek evidence/ranking schemas.
- Repository snapshot and dirty-overlay implementation.
- Exact search/reranker pipeline.
- Source-path semantics.
- CLI/MCP commands unique to CodeSeek.

## Deferred and excluded

- CS-002+ characterization tests and migrations.
- Live CodeSeek execution and index rebuild.
- ADK dispatch and any ADK import into this kit.
- Network activity other than the one permitted pin revalidation.
- Public API freeze.

## Authority boundary

`AGENTS.md` rule 080 abandons CodeSeek as a live locator in favor of `pbi`.
This report does not supersede CS-001: it is the one-time, offline pin that
ADR-0015 still requires.
