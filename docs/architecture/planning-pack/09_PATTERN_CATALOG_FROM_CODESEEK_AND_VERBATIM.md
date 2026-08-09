# Pattern Catalog from CodeSeek and Verbatim

## 1. Purpose

The first framework abstractions must be extracted from real implementations rather than invented for hypothetical customers. CodeSeek is the primary runtime source. Verbatim is the primary source of domain contracts, fail-closed semantics, and reusable workflow shapes.

## 2. CodeSeek patterns to extract

### 2.1 Narrow ADK boundary

CodeSeek feature-gates exact ADK-Rust dependencies and keeps core retrieval and broker types independent of ADK. The framework should preserve this pattern: application domain code depends on stable platform contracts; only the adapter/compiler layer imports ADK types broadly.

### 2.2 Lifecycle limits

CodeSeek already models:

- maximum model iterations;
- maximum total tool calls;
- maximum calls per tool;
- wall timeout;
- idle timeout;
- tool timeout;
- maximum cumulative tool-output bytes;
- cancellation;
- explicit terminal statuses.

Extract these into application-neutral `RunLimits`, counters, and status types. Keep CodeSeek-specific benchmark status conversion in CodeSeek.

### 2.3 Redacted trace and call ledger

CodeSeek records model and tool events using digests, usage, latency, and status without persisting hidden chain-of-thought. Extract the general event/ledger contract and retain application-specific cost aggregation separately.

### 2.4 Typed tool envelope

CodeSeek's read-only tools return a common envelope distinguishing:

- success;
- successful empty result;
- typed failure;
- provenance;
- pagination;
- artifact handle;
- bounded inline data.

This is one of the strongest shared abstractions. Generalize it with typed payload support while retaining JSON compatibility.

### 2.5 Progressive artifacts

Large tool results become content-addressed stage artifacts read by offset/limit. Extract the ArtifactStore and paging mechanics. Do not assume in-memory storage in production.

### 2.6 Typed structured termination

`finish_investigation` validates a final output, records it in runtime state, and signals ADK-native termination. Generalize this into an output/terminal tool builder or agent-output contract.

### 2.7 Provider request extensions

CodeSeek carries provider-specific request extensions, including thinking controls, into actual production chat calls and records model identity. Extract the OpenAI-compatible adapter only if upstream stable does not fully satisfy the local model requirements. Prefer upstream model adapters when equivalent.

### 2.8 Reuse retrieval artifacts

CodeSeek's ADK arm can reuse a shared retrieval artifact and ledger instead of repeating embedding/reranking. Generalize immutable stage artifact reuse and cost attribution.

### 2.9 Isolated reviewer and revalidation

Investigator and reviewer receive independent sessions. Reviewer-repaired output is revalidated against shared evidence and schema. Extract this as the initial `workflow-review` pattern.

### 2.10 Hermetic snapshot and dirty overlay awareness

CodeSeek distinguishes committed indexed evidence from current worktree changes and validates freshness. Generalize source snapshot identity and evidence freshness metadata, but leave Git/code-specific overlay logic in CodeSeek.

## 3. CodeSeek-specific elements that should remain local

- PetCodeGraph and language-specific graph queries;
- benchmark arm identities and teacher/reference exclusions;
- CodeSeek evidence/ranking schemas;
- repository snapshot and dirty overlay implementation;
- exact search/reranker pipeline;
- source path semantics;
- CLI/MCP commands unique to CodeSeek.

## 4. Verbatim grounded-answer pattern

```text
query plan
  → retrieve EvidencePack
  → assemble ContextPack
  → create answer plan/draft
  → verify claims
  → deterministic citation rendering
  → publish / bounded revise / abstain
```

Reusable elements:

- legal stage-transition contract;
- typed published, abstained, and disabled outcomes;
- fail-closed conversion of model/verification errors;
- claim-level support reports;
- deterministic rendering after semantic generation;
- content hashes binding plans, context, and output;
- mandatory validation before publication.

Application-local elements:

- Verbatim EvidencePack and ContextPack schemas;
- source/chunk ACL enforcement;
- citation styles and source identifiers;
- retrieval/storage implementation;
- claim-support policy.

## 5. Verbatim multi-hop research pattern

```text
decompose question
  → parallel retrieval batch
  → evaluate coverage/conflict
  → bounded corrective round if budget allows
  → merge attributed evidence
  → complete / incomplete / disabled
```

Reusable elements:

- budget dimensions and usage accounting;
- coverage decision enum;
- bounded corrective cycle;
- explicit incomplete outcome;
- parallel fanout/aggregate pattern;
- attributed merge;
- evidence-origin guardrails.

Application-local elements:

- retrieval providers;
- graph-relation evidence policy;
- coverage schema and thresholds;
- source truth and ACLs.

## 6. General pattern pack seeded by both repositories

### `retrieve-investigate-validate`

Fast retrieval creates an evidence pack; an agent reads progressively; a deterministic validator checks source alignment.

### `draft-review-revise`

Producer, objective validator, isolated semantic reviewer, bounded repair, and publish/abstain.

### `grounded-generate-publish`

Retrieve and assemble authorized context, generate, verify claims, render deterministic citations, publish only supported content.

### `decompose-fanout-cover-correct-merge`

Create subquestions, parallel retrieve, measure coverage, perform bounded correction, merge with attribution.

### `read-decide-approve-write`

Read-only investigation and validation precede an approval and idempotent side effect.

### `progressive-artifact-read`

Keep default model context small; expose large stage results through stable handles and pages.

### `snapshot-plus-overlay`

Bind execution to an immutable source snapshot while detecting current local changes that may invalidate evidence.

## 7. Extraction sequence

1. Add characterization tests around CodeSeek lifecycle, tools, artifacts, sessions, and reviewer behavior.
2. Move application-neutral types/helpers to the new repository without semantic changes.
3. Point CodeSeek to the new crates through a temporary Git/path dependency.
4. Re-run all existing tests and paired benchmark fixtures.
5. Implement the declarative CodeSeek workflow with the same tools and validators.
6. Compare event traces, limits, output schema, evidence identity, and failure behavior.
7. Only then stabilize public APIs.
8. Add Verbatim grounded-answer and multi-hop packages as second and third callers.

## 8. Parity requirements

For CodeSeek:

- exact tool allowlist;
- no generic shell/write tool;
- same or stricter limits;
- same independent-session behavior;
- same evidence artifact identity;
- same deterministic postvalidation;
- same fail/abstain semantics;
- no extra embedding/reranker calls;
- equivalent redacted tracing.

For Verbatim:

- illegal transitions fail;
- unsupported claims never publish;
- citations remain deterministic;
- corrective rounds remain bounded;
- insufficient coverage returns incomplete;
- ADK artifacts/sessions do not become Verbatim source truth or ACLs.

## 9. Abstraction freeze gate

Do not declare v0.1 public APIs stable until all three workflows compile and pass parity/eval suites. Before that point, internal crate restructuring is acceptable.
