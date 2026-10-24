# Benchmark harness status

The harness supports scripted workflow execution and an explicitly authorized
provider-measurement path through the same runtime. Scripted adapters and local HTTP
fixtures remain distinct from the bounded provider acceptance recorded below.
[Issue #230](https://github.com/RyderFreeman4Logos/adk-workflow-kit/issues/230)
tracks delivery status and remaining evaluation obligations.

## Commands and evidence

With `TMPDIR` set to an admitted SSD scratch directory:

- `just issue-230-smoke` invokes `bench-230 scripted`. It discovers all immediate
  workflow packages under `examples/` and `templates/`, verifies the known packages
  are present, and durably admits each run before compilation through
  `ExecutionBackend::run_admitted` (the existing ADK-Rust graph/runtime boundary).
- `just issue-230-fixture` invokes `bench-230 fixture`. This preserves the original
  three-case deterministic golden report. All its tokens, timing, quality, cost,
  and cache values are **synthetic**, including the simulated warm prefix hit.
- `just issue-230-test` runs fixture/report and public execution integration tests.
  `just issue-230-resume` runs real process kill/recovery, admission-failure, identity,
  completion-integrity and writer-lock checks. `just issue-230-execution-unit`
  exercises unsupported and source-mismatch paths.

The scripted command executes all **five** known packages and requires a successful
runtime receipt for each. Every input/profile remains part of the recorded identity:

| Package | Adapter |
|---|---|
| code-investigation | Shipped fake profile and canonical host input; real read-only tools and selected-answer/citation validation |
| runtime-smoke | Shipped fake profile and input; real ADK execution |
| downstream-consumer | Shipped fake profile, data input and scripted echo connector; real ADK/Skill/tool execution, not a downstream dependency-pin rebuild |
| minimal-template | Declared versioned `minimal-worker` binding; the runtime-smoke fake model is explicitly bound to this identity and receives a distinct case input |
| sentinel-preparation | Shipped 81-byte English note, two source-bound fake probe replies, and the same durable preparation validator used by measurement reconstruction |

The minimal template declares its binding in the source. A mismatched profile is
still rejected as `MissingBinding`, with no fabricated receipt or provider measurements.
Code-investigation checks Snapshot facts before run admission and uses the existing
M3-07 validator against the actual selected draft/revise, completed reads, checkpoint
and terminal generation. A graph-success label alone does not pass this semantic check.
Configured private output-directory symlinks retain their paths and targets; both
names share one validated regular-file lock. Unsafe ancestry or lock objects fail closed.

A newly discovered package without
an admitted adapter is a typed `unsupported` case, never silently skipped. Missing
known packages and symlinked package directories are errors. A failed/unsupported
case is a hard suite failure. The public CLI rejects unknown/extra arguments.

The execution report has `schema_version=2`,
`evidence_kind="scripted_execution"`, and `live_executed=false`. Each executed case
contains the **unaltered typed ExecutionReceipt**, its event-stream SHA-256, and
`elapsed_ns` measured by a monotonic clock around the executor call. That duration
includes executor compilation/setup/persistence, not merely inference. Receipt
cache dispositions/event counts come from runtime observations; `model_turns`
counts scripted model completion events, not billable provider usage. The command
does not infer a KV-cache hit from a result-cache disposition or invent zeroes for
unavailable metrics: token classes, prefill/decode time, cost, prefix hit, retries,
escalation, HITL and quality scores are absent.

Each case manifest binds the observed Git HEAD and committed tree, a sorted
length-framed digest of current tracked and nonignored untracked source-file
contents, executable digest, exact workflow bytes, canonical assembled profile,
scripted worker/reviewer model descriptions (including replies), and input JSON.
Source content is checked again after execution. These are observed source and
binary identities, not a reproducible-build attestation. Runtime plan/resume
identities additionally bind runtime resources. Model providers must be `fake`
before profile parsing/execution; no credentials or live profiles are loaded.

`output_directory` contains immutable `suite.json`, `admission-N.json`, atomic
`case-N.json` completions and runtime `runs/` artifacts. Use `bench-230 scripted
--output DIR` to select a fresh private directory; `bench-230 resume DIR` validates
all source/config/input/model/binary identities and existing completions before
running only unstarted cases. A process-scoped exclusive file lock prevents two
harness writers. Keep the directory private; this is not a signed evidence store.

`ExecutionBackend::run_admitted` calls the journal before compilation, run artifact
creation or graph invocation. Its callback must fsync admission before returning.
Completed cases retain their original run IDs, measured durations and receipts;
resume never substitutes a new timing or a simulated cache hit. Pending temporary
files are not completion evidence. Old report-only directories cannot be resumed.

This is **not exactly-once execution**. If admission exists without a completion,
resume fails closed rather than invoking the workflow or runtime resume again.
A successful admission may have no runtime directory (crash before materialization)
or may already have performed effects (crash before completion publication).
After verifying the original process and any effect-producing children are stopped,
run `./target/debug/bench-230 abandon DIR CASE_ID RUN_ID` using the exact admission
identities. It atomically records a **failed** case with `effects unknown`, absent
receipt/timing, and the original admitted run ID. It neither calls runtime resume
nor replays, undoes, or asserts completion of effects. `abandon` exits 0 when that
journal operation succeeds; the subsequent `resume DIR` report still exits 1 for
this failed case. Wrong IDs, changed identity, existing completions, concurrent
writers and malformed records fail closed. Orphan runtime artifacts are preserved.

Resume checks receipt fields against runtime inspection and checks event bytes.
The receipt's `node_cache` inventory is a historical snapshot of a shared cache;
inspection recomputes its current inventory. Resume therefore retains that original
snapshot, compares all other durable receipt fields, and does not rewrite history.
No journal signature, adversarial shared-directory protection or elapsed-time/ETA
reconstruction is claimed. Completed-case files supply durable progress counts;
this milestone does not introduce hot reload or automatic retries.

## Measured offline suite policies

`bench-230 init SPLIT.json CAMPAIGN` freezes a private campaign on the current
source/config/input/model/executable identity. `CAMPAIGN` must be a fresh directory
under the admitted scratch root. The version-1 split must partition **every**
discovered workflow exactly once; empty groups, duplicate/unknown/omitted IDs and
shared input digests across groups are rejected. For example:

```json
{"schema_version":1,"tuning":["downstream-consumer","runtime-smoke"],"holdout":["code-investigation","minimal-template","sentinel-preparation"]}
```

Run the built `./target/debug/bench-230` locally:

- `regression CAMPAIGN`: executes all tuning cases once, in sorted case-ID order.
- `adaptive CAMPAIGN elapsed_ns COUNT`: executes the slowest `COUNT` tuning cases
  from the latest complete regression operation, descending measured executor wall
  time then ascending case ID for ties. Every baseline case must have a successful
  measured receipt. The baseline ordinal and digest of its actual case records are
  frozen in admission; resume revalidates the same evidence. No user-supplied score,
  synthetic fixture, other campaign, adaptive/soak or holdout result is a baseline.
- `soak CAMPAIGN REPEATS`: executes the entire tuning partition for `REPEATS` cycles,
  with distinct `case#cycle` and runtime run IDs. Counts are bounded to 1..100;
  adaptive count also cannot exceed tuning size. Repetitions exercise the real
  executor, not copies of receipts. They do not imply cold/warm/pressure or KV hits.
- `sealed-final CAMPAIGN`: fsyncs a one-shot irreversible final admission **before**
  any holdout effects, then executes the entire holdout once. Admission blocks all
  subsequent new operations, including another final attempt, even after failure
  or process death. Every selected workflow must retain a successful measured
  receipt; unsupported adapters remain hard failures in either partition.

`campaign.json` binds the sorted partitions and complete registry identities.
`operation-N.json` binds mode, campaign digest/path, ordinal, selected base IDs,
repeat count and any adaptive baseline. The selected execution uses the existing
admission/completion journal in `operation-N/`; journal schema is now 2. Resume
validates the selection against the frozen partition, not just a mode label. Use
`resume CAMPAIGN/operation-N` and, for ambiguous admissions, the existing exact-ID
`abandon` command. A campaign lock serializes commands/resume/abandon; an unfinished
operation blocks new operations. A crash after operation admission but before
`suite.json` publication conservatively consumes that operation and has no automatic
recovery command. Never delete the seal to retry. Schema-1 journals are not migrated.

Policy failures emit JSON `error.kind` (`invalid_policy`, `identity_mismatch`,
`missing_measurement`, `unsupported_metric`, `invalid_evidence`, `sealed`) and exit 1.
Only `elapsed_ns` is eligible for selection. Token/cost/security/quality metrics are
unsupported, not zero. Hard execution failures remain separate from any optional
performance target. The strict paired elapsed-time comparison below is separate
from semantic quality/security evaluation. Correlated scripted repetitions do not
establish revision-attributed accuracy/security intervals. Fixture intervals remain
synthetic utilities, not evidence for these operations.

The seal is enforced **within this private campaign**, not an OS access-control
boundary or a claim that public example inputs were previously unseen. Standalone
`scripted`, a new campaign, manual file edits or external runs are outside its
history. No global holdout-use ledger, secret dataset store, signed evidence or
independent semantic-quality evaluator exists. Elapsed time and historical cache
inventory remain trusted observations; durable receipt fields and event hashes
are checked, but wall time is not independently attested. Source revisions cannot
be changed within a campaign. A statistically valid final model benchmark still
requires an authorized pinned private dataset and evaluator integration.

`just issue-230-modes` exercises public CLI policy boundaries, measured selection,
foreign-history rejection, real repeated executions and a killed final process.
The separate `fixture` command and its golden bytes are unchanged.

## Strict cross-revision elapsed-time comparisons

This bounded contract compares **two complete regression operation reports**, each
containing the full tuning partition. It is not an all-workflow final evaluation.
Both private campaigns must have exactly one regression and no adaptive, soak or
holdout history. Holdout is never read as a measurement or used to set a threshold.

1. Preserve a baseline campaign with one complete regression from a clean committed
   source revision, including all runtime artifacts. Do not recreate old sources.
2. On a distinct committed revision, initialize a fresh candidate using the same
   split. Run `bench-230 compare-plan BASELINE CANDIDATE MAX_REGRESSION_BPS` **before**
   any candidate execution. The unsigned nonnegative integer is the maximum allowed
   elapsed-time increase per case in basis points (100 = 1%). This one-shot command
   freezes the threshold, both campaign identities and baseline case-record digest
   in `CANDIDATE/comparison.json`. It rejects an existing plan or started candidate.
3. Run `bench-230 regression CANDIDATE`. Admission binds the plan digest before any
   effects. A planned campaign admits only this one regression; resume validates
   the same plan and original observations, never new timings.
4. Run `bench-230 compare CANDIDATE`. This reads and revalidates both complete
   journals and runtime evidence, without executing a workflow or mutating source.

Comparison validates full literal committed object IDs, commit-to-tree identity,
length-framed source bytes against Git blobs (including symlink bytes), registered
workflow source, and committed scripted config/model/input digests. Dirty source
snapshots, same-revision runs, differing case sets/splits/workflow bytes/configs/
models/inputs, overlapping split inputs, missing/failed/unsupported cases, borrowed
admissions, changed durable receipts/events, duplicate run IDs and changed plans
fail closed with `error.kind=invalid_comparison`, `hard_invariant_failed=true`, exit 1.
Both commit objects must remain locally available. Only Git object reads are used;
no checkout, worktree, clone or old-source execution is performed. Workflow/config
changes are ineligible in the default source-revision mode: this isolates source
implementation revisions while holding the scripted workload constant. The explicit
config-only mode below holds source and executable fixed instead.

The deterministic version-1 `paired_scripted_execution` report binds campaign,
plan and case digests plus both source revisions. Each sorted row includes both
complete manifests (source/tree/file/executable/workflow/config/model/input digests), original
run IDs, baseline/candidate `elapsed_ns`, signed `delta_ns`, integer `delta_bps`
(truncated toward zero), and a separate `performance_target_failed`. Threshold
failure uses exact integer cross multiplication, not rounded displayed basis
points: equality passes and any strict excess fails. Values that cannot fit the
signed report fields fail closed. A valid report has `hard_invariant_failed=false`;
a target miss alone exits 1 with `performance_target_failed=true`. Repeated compare
returns the same bytes while evidence is unchanged. No aggregate hides a bad case.

`uncertainty_interval=null` explicitly reports unavailable independent repeated
sampling: there is one observation per revision/case, so **no confidence or causal
performance claim** is justified. No token, cost, cache-class or semantic-quality
measurements are synthesized. These are scripted executor wall times including
setup and persistence, not inference benchmarks. Elapsed times and executable
identities are trusted observations, not independently attested or reproducibly
built binaries. Private journal hashes detect inconsistent edits, not coordinated
forgery by their owner. This is campaign-local leakage prevention, not a global
holdout-use ledger or proof that public examples were unseen elsewhere.

`just issue-230-comparison` runs public CLI negatives with real runtime artifacts
and explicitly labeled policy/source identity fixtures for exact threshold, control
mismatch, source-object and plan-admission checks. Fixture revisions do not count
as cross-revision execution evidence. A real two-revision smoke requires preserved
baseline artifacts and a clean committed candidate, not relabeling a fixture.

### Controlled config-only pairs

`bench-230 init-config SPLIT.json CONFIG.json CAMPAIGN` snapshots an explicit,
versioned config into the private campaign. It never loads operational settings.
The file is limited to 64 KiB and accepts only this schema:

```json
{"schema_version":1,"loop_policy":{"schema_version":1,"max_model_iterations":20,"max_total_tool_calls":20,"max_tool_calls_per_tool":20,"wall_time_ms":60000,"idle_time_ms":30000,"tool_time_ms":10000,"max_tool_output_bytes":65536}}
```

The existing executor validates and applies the loop policy to each supported
scripted profile. No model, tool, sandbox, trust-domain, input or workflow override
is admitted. Config identity is the canonical assembled-profile digest, not a file
name or caller-supplied revision label. Editing the original config file after init
does not change the snapshot. Editing the saved snapshot invalidates its registry,
operation and comparison identities; resume retains the original observed samples.

Initialize two fresh campaigns on the **same clean committed source and executable**,
using the same split but different explicit loop budgets. Run baseline regression,
then `bench-230 compare-plan BASELINE CANDIDATE MAX_REGRESSION_BPS config-only`
before candidate regression. Finally run `bench-230 compare CANDIDATE`. The plan's
`config_only=true` is admission-bound; the report includes that flag and both full
per-case manifests. Missing/identical configs, mixed source/config changes, changed
binary/workflow/model/input/split and post-admission plan edits fail closed. The
existing exact per-case regression threshold and hard-evidence gate remain separate.

This is one measured pair, **not independent repeated sampling**. Each campaign
uses a fresh runtime directory, but process/OS filesystem caches, host scheduling
and ordered runs are not experimentally isolated. Soak repetitions or copied/resumed
observations are ineligible for comparison; no sample-count option or confidence
interval is provided. A deterministic interval formula cannot repair unproven
independence. Zero observed catastrophic events would not imply zero true risk;
these timing reports do not evaluate security events at all and must not be used
as a security pass. The separately tested fixture Hoeffding bound below assumes
independent Bernoulli trials and is not applied to these timings. Changing execution
budgets can change failure/security behavior; successful scripted execution is not
evidence of semantic equivalence or improved quality, safety, cache use or cost.

## Measured offline content-cache experiment

`bench-230 cache-experiment DIR` runs 18 real ADK executions of the shipped
`runtime-smoke` single-agent workflow. `DIR` must be fresh and private. The model
and echo responses remain scripted; this is **result-cache**, not provider KV or
prefix-cache evidence. `just issue-230-cache` exercises the public process path.

The version-1 plan freezes four isolated cache namespaces:

| Arm | Request order | Perturbation |
|---|---|---|
| unbounded-grouped | A A B B A | No capacity pruning; cold/warm and changed-key controls |
| capacity-one-grouped | A A B B A | Retain at most one entry after each execution |
| capacity-one-interleaved | A B A B A | Same inputs/counts/capacity, changed dispatch order |
| explicit-invalidation | A A A | Purge entries before the third execution |

A is the unchanged shipped input. B replaces only `request` with a fixed declared
cache-key negative control, so A and B are **not** asserted semantically equivalent.
Comparisons pair the same variant and occurrence across arms, with identical
source/workflow/profile/model/input manifests and distinct admitted runtime IDs.
No result is copied into another execution. The scheduling experiment changes
sequential client dispatch order, **not** the ADK graph scheduler or concurrency.
Pressure uses the existing `NodeResultCache::gc` digest-order retention (not LRU),
not host-memory/GPU pressure. Capacity is enforced at run boundaries, not during a
run. A null or unchanged scheduling effect is an honest outcome, not a failure.

`content_cache_class` is derived from the real agent's node completion disposition
and checked against durable receipt fields and actual model-completion events:
`recorded` with model work is `cold`; `reused` with zero model work is `warm`;
`reexecuted` with model work is `reexecuted`. Unknown, inconsistent, unsuccessful,
or multi-agent outcomes fail closed. Declared cold/warm/invalidation controls are
hard assertions, never the source of the observed labels. Warm hits are **not** KV
hits. `kv_cache_hit=null` and its reason explicitly state that provider telemetry
is unavailable. Token/cost/quality/security measurements are not manufactured.

The report contains unmodified runtime receipts, measured executor elapsed times,
cache-state digests, observed removal counts, and ten same-input paired elapsed
changes. No aggregate masks a case. Intervals remain null: ordered scripted runs
are correlated and cannot establish causal speedup, semantic quality, or safety.
Elapsed timing includes executor persistence/setup and pre-run explicit purge;
post-run GC and harness source hashing are outside that timing.

`experiment.json` binds source HEAD/tree/current-file digest, executable bytes,
workflow/profile/model/input digests, runtime prompt/cache schema versions, the
runtime trusted-goal cache salt, order and retention policy. Source is checked at
each unit boundary. Dirty snapshots are observable but not clean-source attestations;
use a clean committed tree for retained measurements. Runtime keys additionally
bind invocation, policy, tool/schema and request provenance through the existing
executor. No separate provider integration or runtime cache implementation is added.

`admission-N.json` is fsynced before runtime artifacts/effects **and before purge**;
`observation-N.json` is atomically published after execution and post-run GC.
`progress.json` is a disposable completed/total/generation-elapsed projection with
unavailable ETA. `cache-resume DIR` validates the complete prefix, original evidence,
plan, event digests and latest cache-state digest for every started arm before
executing unstarted units. Original measured rows and run IDs are retained, so a
complete resume returns byte-identical report JSON. Concurrent writers, edited
plans/receipts, foreign identities, journal gaps and changed cache state are errors.
Historical cache inventories/removals remain trusted observations linked by hashes,
not independently attested telemetry or protection against coordinated owner forgery.

An admitted unit without completion is ambiguous, including a crash after a cache
write or GC but before publication. Resume refuses to replay or relabel it warm.
Keep the directory for investigation and start a **new** experiment directory;
`abandon` belongs to suite journals and does not apply here. Runtime failure evidence
is retained in the original runtime directory even if no observation was published.
Crash-before-plan/root publication and automatic effect reconciliation are not
implemented. This experiment is separate from private sealed campaigns, and public
example inputs are not an unseen holdout dataset. It does not complete #230.

## Explicit-input runtime measurement

`bench-230 measure BINDING.json DIR` runs one registered workflow through the
existing compiler, IR, ADK model binding and `ExecutionBackend::run_admitted`.
`DIR` must be fresh and private. This command admits only `local_wire_test` with
literal `http://127.0.0.1:PORT/v1` endpoints. Use it with a test-owned scripted HTTP
server, not synthetic benchmark reports. It is not a network sandbox: the selected
runtime transport retains its normal proxy/redirect behavior. Tests clear proxy
settings in the child and serve a single bounded loopback exchange (two for retry).

`bench-230 measure-live BINDING.json DIR` is a separate explicit provider-I/O
opt-in requiring `origin="live_provider"`. There is **no default endpoint, model,
credential value or price**, and no discovery of local configuration. Supply an
authorized public binding with this version-1 shape:

- `schema_version`: `1`;
- `origin`: `local_wire_test` or `live_provider` matching the command;
- `workflow_source`: exact registered repository-relative workflow path;
- `profile`: the existing `ExecutionProfileV1` JSON, with explicitly versioned
  model bindings and `provider="openai-compatible"` (worker/reviewer as needed);
- `input`: the exact public case input JSON.

The profile's existing credential **handle** is resolved only by the runtime
broker during execution. Do not put credential values in the binding. Unknown
binding fields/versions, fake profiles, remote endpoints in test mode, and model/
message/stream overrides in provider extensions are rejected before admission.
The existing ADK OpenAI extension channel admits only typed `reasoning_effort`,
`return_token_ids` (boolean), and `cache_salt` here. The salt is a caller-designated
public trust-domain name: 1–128 ASCII letters, digits, `_`, `.`, `/`, or `-`; never
put a credential in it. The harness derives the actual wire salt from that domain,
the role, stable effective profile (excluding salt operands), and workflow identity.
It adds no random entropy. Equal configurations retain the same salt, while distinct
domains/configurations/roles are isolated. The effective profile/model digests bind
the derived value. These request capabilities do not establish cache hits or token
ID availability; only actual response observations can do so. Omitted reasoning
effort remains unknown/default, never the cache policy's hardcoded medium effort.
The minimal template uses its declared versioned binding. Bindings are regular
files bounded to 1 MiB.

The telemetry target also checks one fixed minimal semantic case through real SDK
loopback requests: sorting `[7,2,7,1]` and summing to `17`. The admitted input digest,
actual user message, completed nodes, full terminal event prefix and public SQLite
checkpoint bind the predicate. A fully finished response with sum `18` is rejected
semantically. `semantic-check.json` retains that separate verdict with source,
executable/config/input and run identities; runtime success alone is insufficient.
The ignored `minimal_semantic_live_pair_from_explicit_binding` test uses this same
predicate only with explicitly supplied private binding/output paths. It performs
at most two sequential fresh invocations, proceeding to the second only after the
first satisfies semantic, token and supported-cache checks. Default tests never
execute it; an ignored test is not live acceptance. The invocation requires an
independently admitted 180-second outer process fence. It does not restart services
or establish KV-hit, coldness, provider billing or model-weight attestation.

Host `ModelBinding` stamps one terminal response per successful invocation with
version-1 typed telemetry, overwriting any provider lookalike. The ADK event mapper
retains it under `payload.model_telemetry`, even on tool-call events. Report rows
carry the exact event ID, sequence and node. The schema exposes:

- resolved **client** route/profile version and actual requested wire model;
- explicit request reasoning mode; missing mode is null;
- response-owned `input_tokens` / `output_tokens` and optional `cached_input_count` /
  `reasoning_count`, preserving absent versus observed zero. Count names avoid
  weakening the shared runtime's secret-key redactor;
- actual successful-invocation host retry count (ADK internal retries are disabled);
- runtime result-cache dispositions and exact approval-event identities.

`output_tokens` is the provider completion count, not inferred visible output.
`visible_output_count`, prefill/decode clocks, billing cost, KV hit, wire-prefix
hash, escalation and human-intervention status remain null with reasons.
`reported_cost_usd` remains null; see [source labels and KV intent](BENCHMARK_TELEMETRY.md).
Failed invocations can lack telemetry; missing rows do not prove no provider work.
Usage counters are independently optional. An absent or invalid raw counter stays
null without discarding other valid counters or failing a semantic completion.
The non-streaming wire control preserves negative input as null, output as 1 and
total as 0 independently. Streaming usage-only coverage is not claimed by this
measured executor path.

Origin is caller-declared, not remotely attested. Local wire reports have
`evidence_kind="local_wire_execution"`, `live_executed=false`. Provider opt-in
reports have `evidence_kind="opt_in_provider_execution"`, `live_opt_in=true`, and
`live_executed=null`: this runtime cannot attest whether a supplied endpoint runs
real inference. `completed_model_observed` reports only actual completed event
coverage. Neither model alias nor profile version proves a weights/tokenizer
revision. The authorized provider acceptance below does not change those attestation
limits.

The plan binds source HEAD/tree/current-file and executable digests, workflow
bytes, canonical profile/model/input identities and the exact binding-file digest.
Admission is fsynced before effects. Source is rechecked after execution. Private
`execution.json` retains the original runtime receipt; `measurement.json` is a
payload-free projection (no prompts, outputs, endpoints or credential handles).
The underlying runtime artifacts remain private and may retain workflow data;
the public report is not a sanitizer for that directory. Do not publish it wholesale.

`bench-230 measure-report DIR` validates the plan/admission, original receipt,
event-byte digest and typed event sequence/integrity, then recomputes the original
projection and requires exact equality. It never calls a provider. Changed metrics, origins,
plans, receipts or event bytes fail closed. These are consistency hashes, not
signed provenance or protection against coordinated owner forgery. Missing
completion after admission is ambiguous; preserve evidence and use a new directory,
not replay/resume. This one-case path is not a sealed holdout campaign.

The `measured` schema-version-1 row is derived after those checks. For the exact
minimal sorting request used below, the production report reads the selected
`node:start` output through the public checkpoint API, verifies its completed
terminal event generation, and recomputes predicate
`sort-7-2-7-1-and-sum-exact-v1`. It binds the output digest, run, input, selected
node, checkpoint sequence, events and producer source. External `passed` or
quality sidecars are not authority. A wrong but complete answer has quality 0;
the exact answer has quality 1000. Tasks without a finite host predicate have null quality rather than an
invented judge. Raw counts from one response remain optional; multiple-response
runs retain their individual `model_calls` without inventing one combined count.
Security failures and their confidence bound remain null without a security
observation. Provider completion is a distinct dimension from visible output.
The checkpoint reader requires existing compatible data and never initializes or
repairs its database, schema, metadata or manifest. It reads committed WAL frames;
SQLite may still coordinate through derived SHM files. Close readers before sealing
evidence; read-only checkpoint data does not imply zero directory I/O.

For `examples/03-sentinel-preparation/workflow.toml`, the same finite validator
runs after execution, while building the measurement, and during report-only
reconstruction. It binds the input, latest checkpoint/event generation, identical
`node:prepare` and `terminal`, closed terminal report, and bounded protected
original/envelope/probe/semantic artifacts with exact commit references. Predicate
`sentinel-preparation-contract-v1` covers four fixed benign English, Simplified
Chinese, Traditional Chinese and Japanese inputs and existing invalid, unsupported
and unattributed controls. Unknown inputs have no quality label. Positive cases
require their exact language label, unchanged envelope bytes and complete source
covers; `PendingClassification`, null decisions or supported language alone cannot
pass. Explicit preparation-contract violations fail execution and reconstruction.
The model's `semantic_reason` is separate fallible evidence, never quality authority
or a final security decision. Existing optional sorting-quality behavior is unchanged.

Sentinel's private calls are reported separately in `sentinel_probe_calls`, sourced
from the protected version-four semantic artifact, with branch, view, invocation
identity, schema hash and six optional raw usage counters. They remain available
when clean or conflicting findings are discarded. Null accounting is unknown or
incomplete; an empty list means verified preparation denial before model entry,
including invalid input or language-policy denial, and does not identify the denial
reason. A null per-call usage value means missing usage, while reported zero remains
zero. These calls never become agent
`model_calls` or a synthetic single-response total. A positive run without any
completed model call fails the measurement wiring check even when preparation
passes. KV intent is refused before admission for this package. No wire count,
physical KV benefit, billing or final Clean decision is inferred from the report.

`bench-230 measure-compare LEFT_DIR RIGHT_DIR` revalidates both measurements and
pairs distinct runs of the same case, workflow and canonical input. Its row
retains each side's fixture/provider origin, opt-in assertion and binding digest,
each source/config identity, and explicitly lists changed source/config
fields. It shares the fixture Pareto dominance arithmetic, maximizing observed
host-predicate quality and minimizing **provider completion count**. Missing
quality/count points are excluded with a reason. Token deltas use exact signed
decimal strings. Safety deltas and single-pair confidence intervals are null;
neither a frontier nor a null safety observation is a security acceptance or a
causal performance claim. Legacy fixture reports keep their existing visible-token
and mandatory-observation contracts.

`bench-230 measure-aggregate SAMPLING.json DIR...` verifies declared trials.
`measure`/`measure-live` bindings accept host-only
`sampling: {"manifest": ..., "trial_id": ...}`. Digest and durable admission seal it
before provider/effects; it is never model-visible or admitted posthoc.

The strict version-1 manifest requires `name`, `independence`
(`assumed_independent` or `correlated`), `confidence_percent` (1 through 99),
`security_rule` (null or `selected_output_public_canary_v1`), and 1–128 `trials`.
Each trial has a unique `trial_id` and SHA-256 `input_digest` of canonical JSON
execution input. Names/trial IDs allow 1–64 ASCII letters, digits, `_` or `-`.
Intake requires exact manifests, distinct original run IDs and the full trial set.
Rows retain the verified-report identities above; sidecars are not authority.

The rule requires minimal input containing **public synthetic** marker
`BENCH230_SYNTHETIC_CANARY_V1`, never real secrets. It binds rule/trial/input/output/
checkpoint/events and counts marker presence in verified output. Counts/bounds
describe only this sample/rule, not overall security.
Other workflows, absent rules or missing evidence remain null, never inferred zero.

Complete labels for at least two distinct inputs under assumed independence use
the existing one-sided Hoeffding bound, rounded upward to millionths: zero events
still give a nonzero bound. Correlation, repeated inputs or incomplete labels give
null bounds. Independence is assumed, not attested. Quality uses the finite sorting
and Sentinel host predicates above; unknown inputs have no quality label, and
independent quality intervals remain null.
Raw metrics stay optional; Pareto excludes unknown dimensions, inventing no visible
tokens, bills, KV or safety passes.
Canary violations fail hard; wrong sorting answers fail the optional quality target.

`just issue-230-telemetry` exercises the public binary against a real local HTTP
script, verifies wire model/effort and runtime-event usage provenance, missing usage,
reported zero, missing details, HTTP 429 retry, invalid-counter omission, privacy, tampering,
origin/route admission and mismatched binding denial. It is deliberately
separate from `fixture` and from offline fake-model cache/suite execution.

## Recorded bounded acceptance

These observations bind source revision `ad19edb50e294197a642b16fab0a6c9080d4be12`
and bench executable SHA-256
`2c366769951205333e4cec4cbbfa09164079bd1d483355db9c9c9867ba8436d2`.

A subsequent report-only analysis used independent byte copies of those retained
public checkpoints. The measured bridge revalidated both selected outputs at
sequence 7 with the versioned host predicate, producing quality 1000 for each
and preserving the original 151/193 provider completion counts. The derived
output bindings are separate from the unchanged original semantic proofs. This
is analysis of historical execution evidence, not a new provider invocation or
live acceptance on the later analyzer source.
They bind observed client source/binary identities and results, not remote model weights.

- One `just issue-230-smoke` command successfully executed all four registered
  workflows in 45.134 seconds of measured monotonic command time. These are
  scripted-model runtime results, not live-provider quality measurements.
- Two distinct config-only campaigns used loop iteration budgets 20 and 21 on that
  same source/executable. Both tuning cases succeeded in each regression. The
  comparison's pre-frozen 0-basis-point target **failed**: `compare` exited 1 with
  `performance_target_failed=true` and `hard_invariant_failed=false`. Exact
  arithmetic and exit classification were verified; this is not a performance pass,
  independent repeated sampling or evidence of a causal improvement.
- Two authorized sequential provider invocations passed the same input-bound
  sorting/sum predicate described above. Each used one completed model invocation;
  route/profile version and requested wire model matched the authorized binding,
  with explicit `low` reasoning. The pair settled naturally within the admitted
  180-second outer budget. Response-owned observations were:

| Invocation | Input tokens | Output tokens | Reasoning count | Cached input count | Host retries |
|---|---:|---:|---:|---:|---:|
| First | 99 | 151 | 127 | 0 | 0 |
| Second | 99 | 193 | 169 | 0 | 0 |

An observed cached count of zero is valid response evidence, not a KV-hit or warm
cache claim. Physical HTTP attempts were not independently observed; completed
host telemetry records two completed invocations and zero retries, below the
predeclared maximum of four HTTP attempts.
KV/prefix, prefill/decode, visible-output counts and provider billing remain
unavailable. Under the user's local-service policy, marginal API cost is zero,
excluding hardware, electricity and labor; this is not observed provider billing.
No all-workflow live-quality or shared-service pressure claim follows from this pair.

## Fixture reporting utilities

The separate `CaseEnvelope` requires `evidence_kind`: `synthetic_fixture`,
`provided_observation`, or `wire_fixture`. Caller-supplied observations are not
independently verified execution. The old `registered_workflows`, `run_mode`, and
`run_scripted_smoke` APIs remain **frozen fixture utilities**, not the execution
registry. Use `execution230::scripted_workflows` / `run_registered_smoke` for the
production adapter.

`aggregate_report` rejects empty/duplicate cases, missing version bindings,
invalid quality/token ranges and overflowing security counts, and sorts by case
id. Security hard failures and optional accuracy/output-token targets are
independent. The one-sided Hoeffding bound assumes independent Bernoulli trials,
counts affected cases and rounds upward to millionths. Empty/invalid-confidence
samples return 1. Zero observed events never imply zero risk; correlated scripted
repetitions are not calibrated safety evidence.

Paired comparison requires matching nonempty unique case sets, workflow, dataset,
and cache class. It compares only accuracy and security. `resume_suite` is an
in-memory fixture filter, not persistent recovery. These fixture suite-mode enums
and threshold/holdout splitting do not enforce policy; the campaign commands above
are the measured execution path.

## Scope limits and further evaluation

- Offline cold/warm/pressure and AABBA/ABABA request-order controls measure result
  caching, not provider KV behavior or a host-resource scheduler. The provider pair
  retains supported cached-input counts. Host request-prefix observations and
  pre-admitted KV intent are distinct from unavailable server KV state; see
  [the telemetry contract](BENCHMARK_TELEMETRY.md). No shared-service reset or
  full live pressure campaign is implied.
- Automatic checkpoint/effect reconciliation remains deliberately unsupported.
  Completed-case resume and explicit fail-closed abandonment are implemented.
- Extend measured host predicates, safety observations and authorized private holdout data;
  offline regression/adaptive/soak/sealed-final execution policy is implemented,
  but the public scripted examples are not unseen semantic holdout evidence.
- Extend beyond the finite host predicates and declared security-sampling bound
  with appropriate independent accuracy samples and optional cost/cache dimensions. Single-pair source
  revision and explicit loop-budget config-only elapsed-time thresholds are
  implemented. Those elapsed-time threshold commands do not support arbitrary
  or joint source/config changes; descriptive measured-pair comparisons do not
  expand that performance-admission policy.
