# Sentinel bounded probes (#232 milestone)

**Offline execution verified; live semantic quality remains unverified.** The v1
`nodes.untrusted_text` spec, canonical IR v11, compiler admission and observed ADK
terminal retain source descriptors and execute bounded semantic probes using the
profile's worker binding. No new authored configuration or dependency is introduced.
Direct translated graphs can supply `with_sentinel_model`;
without it they report `model_unavailable`. The terminal remains the closed
`UntrustedTextReport`: semantic evidence does not authorize graph continuation or
any tool/action. Descriptors alone are never model evidence.

Read `node_completed.payload.structured_output.preparation.probes.artifact_id`
through the existing protected artifact store. Artifact commitment verifies its
SHA-256 and emits the usual content-free observation. `version` and `bytes` accompany
the handle; no source or decoded text is copied into events, descriptors or Debug.
Handles and digests remain correlation-sensitive. Earlier invalid preparation
paths have no probe artifact. Unsupported/unattributed language is retained as the
explicit `language_gate`, never resolved by chunking or decoding.

## Descriptor schema v1

The report contains `schema_version`, `version` (`sentinel-source-probes-v2`),
`original_artifact_id`, `normalized_sha256`, `trust_domain` (`untrusted_content`),
`language_gate`, `causal_attribution` (`not_measured`), `budget`, and four ordered
`branches`. Each branch has a closed `kind`, `reason`, and `views` array:

- `ordered`: the complete normalized view, not replaced by shuffled chunks.
- `shuffled`: UTF-8-safe windows up to 256 bytes with 61–64 bytes overlap. Before
  a hard split, prefer the last newline, then whitespace, in the window's second
  half. This is line/whitespace awareness, not a markup/programming parser.
  Sort chunk ordinals by SHA-256(version || SHA-256(normalized bytes) || ordinal
  as big-endian u64), breaking ties by ordinal. Rotate an identity permutation
  once when there is more than one chunk. This is reproducible, not random security.
- `decoded`: nonempty views from the existing bounded carrier analysis. `candidate`
  identifies its deterministic preorder candidate, preserving nested reconstruction.
- `task_alignment`: the ordered normalized view when a host goal is bound, otherwise
  no views and `trusted_goal_unavailable`. Attacker-supplied goals cannot enable it.

Each view records half-open `start`/`end` in normalized bytes (ordered/shuffled)
or decoded bytes (decoded), `sha256`, `candidate` (null outside decoded), and the
existing original-artifact covering `source` span. Covers may include stripped
controls or whole encoding quanta; they are not exact semantic citation spans.
Reconstruct using the retained original and pinned preparation versions; a digest
is not the view text or a claim that a model consumed it.

`semantic_not_run` describes the source-only descriptor phase; consult the separate
semantic report for actual execution. `empty_view`, `no_decoded_view`,
`budget_exhausted`, and `trusted_goal_unavailable` abstain. None proves safety;
`no_decoded_view` also covers malformed/empty candidates. Descriptors never claim
causal security attribution, branch agreement, task alignment or semantic intent.

## Host goal and task-alignment evidence

The embedding application may call
`graph.with_sentinel_trusted_goal(authenticated_goal, host_revision)?` before
`invoke_observed`. The application MUST authenticate and authorize both values out
of band. This API is the host capability boundary, not cryptographic authentication:
it cannot make an attacker-derived string trustworthy. Do not wire it to issue-body
fields, model output, input JSON or graph State. A goal is bound once per graph;
rebinding and non-Sentinel graphs fail. Use a new graph for a different task. Blank
goals/revisions, goals above 4,096 UTF-8 bytes and revisions above 128 bytes fail
without echoing text. Revision can bind the host's task/authorization version.
`ExecutionBackend::run` and `workflowctl` do not yet accept authenticated goals:
their task branch still abstains. The byte ingress remains exactly two fields;
a sibling `trusted_goal` makes it invalid, while embedded claims remain untrusted.

Only the task request receives the goal, not source classifier siblings. Its fixed
schema enumerates four alternative one-object choices, each containing `schema_version: 1`,
`relation`, the ordered original `source` cover, `goal_identity` and fixed
`trust_origin: authenticated_host_api_v1`. Relations are `redirects_goal`,
`benign_discussion`, `aligned_intent`, and `uncertain`; no free text, rationale or
model-supplied authority is allowed. Raw parsing rejects duplicate/unknown keys;
exact enum membership binds source, goal, origin and version. The reducer rechecks
those bindings, then maps redirects to `inj`, uncertainty to `sus`, and benign/aligned
to non-authoritative `cln` for the existing unanimity check. Any disagreement or
invalid task evidence drops all findings and decisions. A valid relation is model
evidence, not semantic truth, action permission, or authenticated model output.

Goal and revision text are transient and never persisted in reports/events or Debug
for the goal holder. Only digests/fixed codes may be published; digests remain
correlation-sensitive and are not secret-hiding encryption. The configured model
necessarily receives the goal: the embedding host must authorize that disclosure.

## Bounds and identity

The fixed typed budget is 32 views / 65,536 represented bytes per branch, with a
32,768-byte serialized report ceiling. A branch exceeding its budget discards its
entire view list with `budget_exhausted`; other branches survive. An overall report
excess discards all populated lists with that reason. Existing carrier/segmentation
ceilings apply first. These are offline construction bounds, not model-token or
wall-time guarantees. No unbounded task text or semantic prose is serialized.

Adapter identity is `sentinel-workflow-preparation-v5`; the preparation key binds
both probe versions and fixed budgets, retaining raw-byte, workflow/IR, language
policy and preparation identities. A host goal additionally binds its domain-separated
SHA-256 identity (goal bytes, host revision, fixed `authenticated_host_api_v1` origin,
`sentinel-task-alignment-v1`), and the fixed 4,096-byte goal ceiling. Goal/revision
changes invalidate preparation and all semantic invocation identities; goal data is
not serialized into the preparation report. Each semantic invocation additionally binds
that key, source view, branch task/schema, prompt, model/provider/tokenizer route,
trust salt and output budgets through `ModelInvocationSpec`. The reported invocation
identity additionally fingerprints the non-secret runtime policy (sampling, inner
timeout and provider extensions), following the semantic Firewall identity contract;
raw runtime policy is never published. No semantic cache is
read or written. The preparation key alone is **not** a semantic cache key.

## Executed semantic report v2

Read `preparation.semantics.artifact_id` from the same completion event. This
content-addressed report has `schema_version`, `version`
(`sentinel-semantic-probes-v2`), a closed `reason`, `task_alignment`
(`trusted_goal_unavailable`, `not_completed`, or a validated relation below),
`causal_attribution` (`not_measured`), `findings`, and
`decision` (shared Sentinel `TypedOutput` or null).

After the unchanged language gate, a fresh ADK graph superstep executes one
stateless model request per ordered/shuffled/decoded/task-alignment view. All branches have
independent two-message contexts, no session history, no tools, no inherited
outer state and no checkpoints. Canonical length-framed common data is explicitly
untrusted; fixed policy/task/schema and, only in the task branch, the separately
length-framed authenticated host goal occupy the trusted policy channel. View
text stays transient and never reaches report/event text. Chunk requests do not
inherit the full ordered view. The host binds each schema to precisely its supplied
original source cover and permits only complete `inj`/`sus`/`cln` envelopes with no
rationale (the task branch uses its closed relation schema below). The shared invocation boundary rejects nontext parts, provider failure
or interruption, missing final complete Stop, over-budget output and malformed raw wire;
strict Sentinel parsing rejects duplicate/unknown fields before Value decoding.

The fixed ceiling is **8 requests total**, **128 requested output tokens / 512
response bytes per request**, **30 seconds for the model superstep**, no retries or
escalation, and **32,768 report bytes**. Any missing ordered/shuffled view, exhausted
descriptor branch or total above eight denies all model entry (`view_budget`), not
partial coverage. A bound goal consumes one slot in this same ceiling, not an extra
budget: eight source views plus a task view denies all nine. No decoded candidate
needs no extra request. Invalid/unsupported/
unattributed preparation is not upgraded by semantic inference (`language_gate`).
The deadline excludes synchronous normalization, schema construction and artifact IO.

An invocation-local failure signal cancels pending sibling requests/streams without
waiting for ADK's deferred error collection. Cancellation of the owning observed
invocation also drops all probe streams. No branch artifacts/events are published;
only a complete aggregate or content-free abstention report is committed after
joining. Previously retained original/envelope/descriptor artifacts remain on failure.

Reduction is canonical ordered → shuffled order → decoded order → task alignment,
never completion order. It requires every expected source-bound typed finding and unanimous non-Clean
judgment. `agreement` retains findings (branch, descriptor, invocation/schema hashes,
typed output) and uses the ordered finding as the conservative decision cover.
`invalid_or_failed`, `deadline`, `conflict`, `clean_not_authoritative`, `language_gate`,
`view_budget`, and `model_unavailable` publish **no findings and no decision**. A
unanimous model Clean is deliberately insufficient: deterministic/behavioral security
acceptance is not implemented. Semantic `inj`/`sus` remains fallible model evidence,
not a causal attack proof or Firewall authorization. Terminal preparation stays
pending/null. Absent goals abstain; present-but-uncompleted task branches report
`not_completed`. On unanimous Clean the validated relation may be reported, but
findings and decision remain absent.

Fixed policy/tool ordering is stable. Branch-specific schemas precede data in the
existing prompt protocol, limiting cross-branch exact-prefix sharing. Provider cache
reuse, shared-prefix latency, usage/cost telemetry and semantic quality are not measured.
Existing `model_request_started` agent-loop events do not cover these private probes;
accepted invocation provenance is in this protected aggregate, not an agent-loop log.

Verify offline with `just issue-232-semantics` (also shared prompt-protocol regressions),
`just issue-232-adk`, `just issue-231-adk`, `just issue-231-compiler`, and
`just issue-231-runtime`. The semantic fixtures use scripted responses and an injected
fake ADK `Llm`, including a real response-stream barrier and cancellation drop guards.
They prove wiring, concurrent requests, source isolation, validation and publication
behavior—not semantic accuracy. The descriptor fixtures continue to test replay,
overlap, normalized offsets, ambiguity and atomic exhaustion.

Remaining #232 acceptance: authenticated end-to-end CLI/service goal integration,
live calibrated task alignment, calibrated final Clean/security routing, more than eight-view
scheduling, multilingual/decoded-language quality, precise offending spans,
shared-prefix/cache measurements, live security hard negatives and chunk-boundary
accuracy, causal experiments and shared benchmark integration. **Leave #232 OPEN.**
