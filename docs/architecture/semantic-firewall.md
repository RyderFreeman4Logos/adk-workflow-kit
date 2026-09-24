# Semantic Firewall v1 — offline integration milestone (#239)

## Opt-in boundary

`FirewallInvocation::with_semantic(SemanticFirewall::new(...))` binds four
independent judgments to the existing validator entry gate. Construct the binding
first, put its resulting `identity()` into the source `firewall` contract, then
use `compile_str` and `AdkGraphTranslator::translate_with_firewall`. The existing
specification → IR → compiler identity path rejects missing or stale bindings.
Hard-only callers retain their original identity and behavior.

`SemanticFirewall::new` requires exactly one explicit `ModelBinding` for each
`JudgeKind`, a `SemanticFacts` value, an ambiguity-escalation boolean, and a positive
per-pass timeout no greater than 120 seconds. It performs no provider/credential
discovery. Start with escalation disabled. No tools, conversation history, raw
retrieved documents, outer graph state, checkpoints, or approval grants enter a
judge. Each ADK function node makes its own stateless bounded model invocation.
ADK-Rust 2.1.0 `GraphAgent` owns parallel dispatch; its executor uses
`buffer_unordered`. This does not assert any particular provider throughput.

`SemanticFacts` is **trusted host input**, not a place to copy attacker prose or
an unchecked model summary. The embedding application must independently construct
canonical goal/action/scope/destination/argument summaries and classify provenance,
data class and impact for the exact proposal. Text fields are nonempty, at most
512 UTF-8 bytes each, with control characters and known synthetic-secret markers
rejected. Types exclude raw-content fields; each judge receives only its projection.
The binding identity includes these facts, all prompt/schema/model/provider/
tokenizer identities, model runtime settings, impact, budgets and timeout.

## Decisions and budgets

1. Evaluate the immutable #238 hard gate. Deny **and** pending approval return before
   any judge invocation. This feature cannot authorize a hard-denied operation.
2. Run task alignment, privilege/scope, destination trust/surprise and data-flow
   judgments in parallel with low inference effort. Each has a separately named
   v1 schema over the shared compact `TypedOutput` Firewall envelope, at most 384
   output bytes and a 96-token request budget, zero format retries.
3. Only explicit `rha` ambiguity may trigger one configured x-high pass for that
   judge. Errors/timeouts/malformed output never trigger a second pass. There is no
   automatic cloud route; escalation uses the same explicitly bound model.
4. Missing, duplicate or invalid judgments deny. Four allows allow. Any denial
   denies at low impact; mixed denial/non-denial at high impact requires human
   approval. Four denials deny. Remaining ambiguity requires human approval.
   No vote averaging or confidence threshold exists.

The graph does not perform approved execution or accept resume. Issue #240 owns
fresh-target authorization and execution-ledger integration. Calling the reducer
or serializing a report does not create an executor permit.

## Telemetry and evidence

Observed gate events carry the ordinary compact Firewall report and an optional
`structured_output.semantic_firewall` v1 report. Each judge has ordered pass records:
`invocation_identity`, `inference_effort`, `elapsed_ms`, `canonical_output_bytes`,
and `status` (`valid`, `invalid_or_failed`, `timeout`). The final per-judge decision
is closed-code or null on failure. No raw input, model prose, secret, or chain of
thought is retained. Timing is measured; canonical byte length is **not** token usage
or billed cost. Timing never enters deterministic decision/cache identity.

## Local checks and exclusions

Run `mise exec -- just issue-239-runtime`, `mise exec -- just issue-239-adk`,
`mise exec -- just issue-238-adk`, and `mise exec -- just issue-238-concurrent`.
Fixtures use explicit provider-free fake models and exercise public compilation,
translation, ordinary invocation and observed invocation. Wire tests reject duplicate
keys before generic JSON decoding can collapse them.

**Live-model semantic coverage, measured benign utility, actual token cost and
SuperQwen/cloud comparisons are unverified. Issue #239 remains open.** To run a live
acceptance campaign, supply an authorized registered binding/profile version,
nonsecret model/provider/tokenizer identity, approved route and budgets, and opaque
credential handle; do not discover credentials or silently substitute providers.
