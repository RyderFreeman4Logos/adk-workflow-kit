# Review, Revise, Validate, and Reliability Contract

## 1. Objective

Use inexpensive tool-calling models in bounded workflows while obtaining reliability from graph structure, deterministic checks, evidence constraints, independent sessions, and explicit failure semantics. The framework must never equate additional model calls with proof of correctness.

## 2. Standard pattern

```text
inputs/evidence
      │
      ▼
producer or investigator
      │
      ▼
deterministic validator
  ├── objective failure ──► reviser with typed defects
  └── objective pass
             │
             ▼
      semantic reviewer
       ├── pass ───────────► final deterministic validation ─► publish
       ├── revise ─────────► reviser ─► deterministic validation
       └── abstain ────────► typed abstention
```

The review node is optional for workflows whose deterministic acceptance contract is already complete.

## 3. Typed review contract

```json
{
  "verdict": "pass | revise | abstain",
  "summary": "short explanation",
  "defects": [
    {
      "code": "unsupported_claim",
      "severity": "error",
      "location": "/claims/2",
      "evidence_refs": ["artifact:..."],
      "message": "Claim is not supported by the authorized evidence set",
      "suggested_action": "remove or retrieve supporting evidence"
    }
  ],
  "confidence": 0.81
}
```

The reviewer output is schema-validated. `pass` is ignored if mandatory deterministic checks fail.

## 4. Deterministic validator responsibilities

Depending on the workflow:

- JSON/schema validity;
- required fields and enum values;
- citation/evidence IDs exist and are authorized;
- quoted spans match sources;
- paths stay inside allowed roots;
- compile, format, lint, unit tests, and static analysis;
- numeric/date/business invariants;
- deduplication;
- budget and size limits;
- tool and scope compliance;
- side-effect plan and idempotency;
- policy and approval requirements;
- no secret or restricted content in output;
- task-specific correctness checks that can be encoded reliably.

These checks should return structured defects in the same general defect format as semantic review.

## 5. Semantic reviewer responsibilities

- whether the output addresses the user/task intent;
- whether important evidence or constraints were omitted;
- whether reasoning visible in the deliverable contradicts evidence;
- whether the proposed action is coherent and complete;
- whether ambiguities require abstention or human input;
- whether a repair instruction can be made concrete.

The reviewer should not reproduce the task from scratch unless the workflow explicitly uses a competing-solution pattern.

## 6. Independent context and roles

Producer, reviewer, and reviser should use independent ADK sessions by default. The reviewer receives:

- task and acceptance contract;
- candidate output;
- validator report;
- authorized evidence or handles;
- a read-only toolset;
- no hidden producer reasoning.

This reduces anchoring and prevents the reviewer from inheriting irrelevant tool history. Different model profiles may be selected for each role.

## 7. Same-model and different-model policies

Reliability preference:

1. deterministic validator plus different reviewer model;
2. deterministic validator plus same model in isolated session with distinct role prompt;
3. multiple sampled reviewers with aggregation for high-value ambiguous cases;
4. same-session self-reflection only as a low-cost fallback.

Research shows self-review can exhibit self-preference, LLM judges can be inconsistent across repeated ratings, and persuasive text can bias judges even on objectively scored tasks. Checklist-style decomposed judgments can improve interpretability and agreement, which supports typed defect/checklist outputs rather than one opaque scalar score. Reviewer outputs remain evidence, not authority.

## 8. Bounded repair policy

Example configuration:

```toml
[review]
max_revisions = 2
max_same_defect_rounds = 1
stop_on_repeated_output_hash = true
stop_on_two_cycle = true
require_new_evidence_for_repeated_grounding_defect = true
on_exhausted = "abstain"
```

Also enforce global model-turn, tool-call, wall-time, byte, and cost budgets.

## 9. No-progress detection

Stop when any configured condition occurs:

- candidate output hash repeats;
- defect fingerprint repeats without severity reduction;
- output alternates A→B→A;
- reviewer introduces new defects while old objective defects remain unchanged;
- no new evidence was gathered for a repeated evidence defect;
- deterministic score regresses beyond policy;
- remaining budget cannot complete another full validate/review cycle.

Record the reason as a typed terminal diagnostic.

## 10. Reviewer disagreement

For workflows using multiple reviewers:

- deterministic failure always wins;
- any critical security defect forces failure or human review;
- aggregate structured defect codes, not only scalar scores;
- use a tie-breaker model only when the expected value justifies the cost;
- preserve disagreement in the run artifact;
- do not average contradictory safety verdicts into a pass.

## 11. Evidence binding

The candidate and reviewer operate on an authorized evidence set identified by immutable artifact IDs and content hashes. A revision cannot introduce a new citation unless the workflow explicitly executes a retrieval node that adds it to the evidence set.

Reviewer tools should normally be read-only. A reviewer that discovers missing evidence requests a route to retrieval; it does not silently browse arbitrary sources.

## 12. Side effects

Separate planning from execution:

```text
model proposes side-effect plan
      → deterministic validation
      → semantic/policy review
      → human approval where required
      → idempotent registered tool executes
      → postcondition verification
```

Never place an irreversible side effect inside an unconstrained revise loop.

## 13. Task eligibility

High suitability:

- classification and extraction with schemas;
- evidence-based summarization;
- code investigation with source validation;
- draft/review/revise documents;
- deterministic reconciliation with semantic exception handling;
- support triage and response drafts;
- policy checks with traceable sources;
- test-driven code changes in a sandbox.

Lower suitability without stronger human control:

- novel strategic judgment with no objective acceptance criteria;
- irreversible finance, legal, employment, or access decisions;
- tasks where evidence cannot be exposed to a reviewer;
- outputs whose correctness is primarily aesthetic preference;
- open-ended autonomous exploration with unbounded external effects.

## 14. Cost-aware routing

A workflow may route based on objective confidence/coverage:

```text
high confidence + complete deterministic checks → skip semantic reviewer
moderate confidence → one reviewer
low confidence or high value → stronger/different reviewer or human gate
insufficient evidence → retrieve or abstain
```

The routing rule itself must be deterministic and evaluated in benchmarks. It should not merely ask the producer whether review is needed.

## 15. Evaluation metrics

- task success;
- objective validation pass rate;
- false-pass rate;
- false-abstain rate;
- reviewer defect precision/recall where labels exist;
- repair success by round;
- regressions introduced by review;
- no-progress termination rate;
- tool calls, tokens, wall time, and cost;
- human correction minutes;
- unauthorized side effects: target zero.

The most important metric is false-pass rate on high-impact errors, not average reviewer confidence.

## 16. Recommended initial experiments

For each dogfood workflow, compare:

1. producer only;
2. producer + deterministic validator;
3. producer + validator + same-model reviewer;
4. producer + validator + different-model reviewer;
5. producer + validator + reviewer + one repair;
6. same with two repairs.

Use paired fixtures and report cost-adjusted success. Do not select the maximum number of rounds by intuition.
