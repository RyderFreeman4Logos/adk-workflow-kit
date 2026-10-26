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

Adapter identity is `sentinel-workflow-preparation-v7`; the preparation key binds
both probe versions and fixed budgets, retaining raw-byte, workflow/IR, language
policy and preparation identities. It also binds `sentinel-reduction-policy-v1`.
The existing eight-field framing remains `WORKFLOW_ID`, `WORKFLOW_VERSION`,
`NODE_ID`, `NODE_VERSION`, `INVOCATION_IDENTITY`, `INPUT_ARTIFACT_HASHES`,
`REQUEST_INPUT_DIGEST`, and `POLICY_DIGEST`; the reducer version belongs inside
the policy digest. A host goal additionally binds its domain-separated
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

## Executed semantic report v5

Read `preparation.semantics.artifact_id` from the same completion event. This
content-addressed report has `schema_version`, `version`
(`sentinel-semantic-probes-v5`, schema version 5), a closed `reason`, `task_alignment`
(`trusted_goal_unavailable`, `not_completed`, or a validated relation below),
`causal_attribution` (`not_measured`), `findings`, `observations`, `failure`, and
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
accepted model-text bytes per request**, **30 seconds for the model superstep**, no retries or
escalation, and **32,768 report bytes**. Any missing ordered/shuffled view, exhausted
descriptor branch or total above eight denies all model entry (`view_budget`), not
partial coverage. A bound goal consumes one slot in this same ceiling, not an extra
budget: eight source views plus a task view denies all nine. No decoded candidate
needs no extra request. Invalid/unsupported/
unattributed preparation is not upgraded by semantic inference (`language_gate`).
The deadline excludes synchronous normalization, schema construction and artifact IO.
The text limit does not bound the raw HTTP response body or provider metadata.

An invocation-local failure signal cancels pending sibling requests/streams without
waiting for ADK's deferred error collection. Cancellation of the owning observed
invocation also drops all probe streams. No branch artifacts/events are published;
only a complete aggregate or content-free abstention report is committed after
joining. Previously retained original/envelope/descriptor artifacts remain on failure.

`failure` is null except for `invalid_or_failed`. Its host-created `stage` is
`invocation`, `graph_execution`, `missing_completed`, `invalid_completed`,
`task_alignment`, `typed_output`, `reducer_admission`, or `consensus`. Per-probe
stages carry a zero-based `probe` ordinal in canonical request order. An invocation
failure retains only the existing closed `kind`, `model_error`, and `output_error`
classes, optional actual `upstream_status_code`, and validation `attempts`. Schema
paths/indices, provider messages, prompts, responses, credentials and endpoints are
excluded. A capacity-one signal retains the first observed failure; concurrent
observation order is not a complete error inventory or a deterministic global root
cause. Pending siblings remain cancelled and incomplete accounting remains null.
These diagnostics do not enable retries, grant quality or establish wire-send counts.

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

### Deterministic reduction receipt

Only complete non-Clean `agreement` carries the optional `reduction` object:
`policy_version` (`sentinel-reduction-policy-v1`), `policy_digest`, and `identity`.
Both digests are canonical lowercase `sha256:` values. The closed object is at
most 512 serialized bytes within the unchanged 32,768-byte report ceiling.
Every other reason omits the field; an explicit null is invalid. Strict benchmark
consumers accept only the paired semantic-v5/schema-5 contract, reject duplicate
or unknown fields, and reconstruct the receipt from the protected preparation,
original bytes, ordered findings and invocation/schema provenance before projecting
`protected-semantic-artifact-v5` calls. The same validator serves execution and
public measurement reconstruction.

The pure runtime reducer takes ordinary evidence, never an execution approval.
It validates all supplied bindings before precedence: InvalidInput, then
UnsupportedLanguage, admitted semantic Injection, genuine behavioral tripwire,
semantic Suspicious, exact-report observer weak evidence, then evidence-free
Suspicious. It never emits Clean or promotes simulation/observer evidence to causal
Injection. It retains one dominant bounded envelope rather than concatenating facts.
The source cover addresses the entire retained original byte extent; normalized
character or byte length cannot replace it. Identity binds policy, preparation,
cover, terminal, exact semantic output and producer, report bytes, observation bytes,
and explicit absences. Determinism means identical genuine inputs, including run IDs;
independent simulations keep their existing run identities.

The ADK adapter invokes this reducer only after its existing complete schema, source,
task-alignment and unanimous non-Clean admission. Model and behavioral paths remain
mutually exclusive. This first unit does not provide replay/escalation policy,
calibrated Clean, mixed-host scheduling, causal experiments or live quality acceptance.

| Reason | Meaning for consumers |
| --- | --- |
| `invalid_or_failed`, `deadline`, `conflict` | Typed uncertainty/abstention: classification unavailable; never a semantic-quality success, authority, or automatic retry/escalation. |
| `language_gate`, `view_budget`, `model_unavailable` | No complete semantic coverage; preparation and capability boundaries remain unchanged. |
| `clean_not_authoritative` | Complete unanimous model Clean evidence, deliberately discarded as insufficient for authorization. |
| `agreement` | Complete unanimous non-Clean findings; fallible evidence, never permission. |

`observations` is independent of `findings`. After the private superstep completes,
it contains at most eight host-created records in the same canonical branch/view
order, binding each call to its descriptor and invocation/schema hashes. Each `usage`
is null when provider counters are unavailable, otherwise it contains six optional
raw counters: `input_tokens`, `output_tokens`, `total_tokens`, `cache_read_tokens`,
`cache_write_tokens`, and `reasoning_tokens`. Missing counters stay null; genuine zero
stays zero. The latest valid provider snapshot replaces earlier snapshots; counters
are not merged, summed, inferred, or normalized from SDK defaults. Clean and Conflict
discard findings while preserving these completed-call observations. If the superstep
fails or is cancelled before complete aggregation, observations are null: accounting
is unavailable, not zero cost or proof that no request ran. Validation attempts are
not HTTP-send counts, and these records do not establish billing or physical KV hits.

Fixed policy/tool ordering is stable. Non-task probes share the source-schema family
ID; for an identical view, ordered/shuffled messages share the complete system and
common-data prefix up to the branch task suffix. Different source covers retain
different strict enum schemas; different text/view descriptors retain different
common-data identities. The task branch alone receives the authenticated goal and
keeps its dedicated policy/schema. Branch suffixes and invocation hashes remain
distinct. This message-prefix property does not guarantee equal HTTP bodies or
provider cache keys. Provider cache reuse, shared-prefix latency, actual cost and
semantic quality require separate measurement.
Existing `model_request_started` agent-loop events do not cover these private probes;
accepted invocation provenance is in this protected aggregate, not an agent-loop log.

Verify offline with `just issue-232-semantics` (also shared prompt-protocol regressions),
`just issue-232-adk`, `just issue-231-adk`, `just issue-231-compiler`, and
`just issue-231-runtime`. The semantic fixtures use scripted responses and an injected
fake ADK `Llm`, including a real response-stream barrier and cancellation drop guards.
They prove wiring, concurrent requests, source isolation, validation and publication
behavior—not semantic accuracy. The descriptor fixtures continue to test replay,
overlap, normalized offsets, ambiguity and atomic exhaustion.

The shared benchmark now verifies protected private-call observations and the finite
preparation contract through the shipped no-goal package. Remaining #232 acceptance
is a separately frozen finite live table covering benign quotation/security discussion, goal
redirection, decoded material and adjacent overlapping chunks through the existing
authenticated host-goal API. Scripted fixtures and prefix equality do not establish
those model-quality results or physical cache benefits. Final Clean authorization,
new goal ingress, expanded scheduling and causal experiments are separate contracts.
