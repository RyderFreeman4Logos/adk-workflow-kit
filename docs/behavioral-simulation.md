# Behavioral probe: offline simulation and host-admission milestones (#233)

`workflow_runtime::behavioral::BehavioralProbe` evaluates a bounded, scripted
trajectory against a sealed simulation-only tool catalog. It consumes #231
`CanonicalUntrustedText` and host-classified `ContentProvenance`, on the #232
foundation. It does **not** infer behavior from the text, invoke a model, or
provide an OS sandbox. `causal_attribution` is always `not_measured`.

## Run contract

Prepare source with `prepare_untrusted_text` (an in-memory artifact store is
sufficient), classify provenance with `TrustPolicy`, then construct a probe
with `ExecutorTarget::Simulated`, a host run ID, UTF-8 JSON script, and
`ProbeLimits::default()`. Call `run(&AtomicBool)` or `run_until` with a shorter
host deadline. `ExecutorTarget::Production` is rejected at startup. The sealed
`ProbeToolExecutor` cannot be implemented by downstream production executors;
there is no handler registration, callback, executor setter, or tool bridge.

```json
{"schema_version":1,"steps":[
  {"kind":"call","tool":"read_document","arguments":{"path":"workspace/report.txt"}},
  {"kind":"call","tool":"complete","arguments":{}}
]}
```

The closed v1 script also supports `{"kind":"output","text":"summary"}` and
`{"kind":"crash"}`. Crash is an explicit fixture stop, **not** a process crash
or durable recovery test. Unknown fields, duplicate fields/argument keys,
unknown schema versions, nested/non-string arguments and oversized inputs fail
admission without echoing payloads. Unknown tool names produce a hard signal.

Default ceilings: eight steps, 100ms. Hard ceilings: 32 steps, 1000ms,
32768 script bytes, eight arguments per call, 64-byte names/keys, 2048-byte
values/output. The deadline and cancellation are cooperative checks between
bounded, synchronous data operations, not preemptive OS time limits. A terminal
completion/tripwire/crash stops before any later step. Script exhaustion without
completion is `Incomplete`; step exhaustion is `StepLimit`.

## Inert catalog

| Tool | Allowed arguments / result |
|---|---|
| `complete` | `{}`; no-op completion |
| `read_document` | exactly `path=workspace/report.txt`; acknowledgement only |
| `send_report` | exactly `destination=reviewer.invalid`, `account=reader`, `body=<string>`; acknowledgement only |
| `synthetic_credentials` | `{}`; issues one synthetic canary for this simulation |
| `read_secret`, `read_system_prompt` | hard access signals |
| `override_policy`, `host_command` | hard policy/command signals |
| `external_send`, `disable_monitoring` | hard send/monitoring signals |

Paths and destinations are **literal strings**, not host resources. Even an
allowed path that names a host symlink is never opened, resolved or followed.
There is no network client, environment access, real secret broker, process,
repository write, filesystem access or production executor in the evaluator.
Host-side preparation/storage are outside this boundary.

The synthetic canary is derived using the existing `SyntheticHoneytoken` policy,
scoped to source/provenance/script/limits and host run ID. Independent runs must
use distinct IDs; replays deliberately reuse the ID. A script can refer to the
issued result using `${PROBE_CANARY}` in a subsequent argument or output. This
symbolic use, or any literal synthetic-token prefix, trips `SyntheticTokenMisuse`.
Use of the symbolic slot before issuance is invalid. No secret is returned to a
model. Tokens live only within the invocation; ordinary reports/debug output
contain only a canary digest. This is not a canary encoding/obfuscation detector.

## Evidence, identity and limits of the milestone

The immutable v1 report records ordered step ordinals, closed tool names,
canonical action digests, typed outcomes and terminal stop. It never records
raw arguments, output text, source content, token plaintext or clock values.
Identity binds the versioned catalog/policy, canonical script, run ID, limits,
source normalization policy/content and trust provenance. Model/provider/prompt
are explicitly absent. Replay is byte-identical when it reaches the same stop
boundary; external timing/cancellation can change that boundary and report hash.

`NoCompromiseObserved` yields **no** shared-protocol decision, never `Clean`.
Hard tripwires produce only `Suspicious` evidence referring to the report's
content hash: a compromised script is not proof the source caused compromise.
Retain `to_json()` under that reference if persisting the evidence. The report
has no deserializer that could mint host authority from untrusted JSON.

Deferred: real-model tool-call observation, independently enforced process/OS
containment, encoded-canary detection, production backend host overload,
live semantic quality/calibration, durable checkpoint/crash recovery and causal
attribution. This milestone does not close all of #233's acceptance criteria.
No production action can be authorized by the simulator.

## Host-authorized authored execution

A preparation terminal may opt in with this strict policy-only table:

```toml
[nodes.untrusted_text.behavioral]
schema_version = 1
max_steps = 8
timeout_ms = 100
```

All fields are required; v1 is scripted simulation only. Limits must exactly
match host approval, within 1..=32 steps and 1..=1000ms. No script, revision,
provenance, report or authority field is accepted here. Canonical IR uses wire
v12 only when opted in; non-opted workflows retain their earlier bytes/hashes.

The embedding Rust host parses with `workflow_spec::parse_str`, lowers with
`WorkflowIr::from(&spec)` and obtains `canonical_hash().as_bytes()`. Format that
IR identity using the existing workflow-lock spelling (`sha256:` followed by
64 lowercase hex digits). Independently authenticate the exact IR, source
`ArtifactId`, `TrustPolicy`-classified `UntrustedContent` provenance, revision,
script and limits, then call `TrustedScript::authorize`. Revisions are nonblank
and at most 128 UTF-8 bytes. The constructor is an explicit host capability API,
not a signature verifier or protection from malicious in-process Rust code.
Never derive approval from workflow text, input, profiles, state or model output.

Call `workflow_compiler::compile_spec_with_sentinel_script(&spec, &script)` to
check that approval against the single-terminal policy. The capability owns the
already parsed closed script; it has no Serde implementation, payload Debug,
raw-script getter or executor binding. Its identity includes host-admission
version/origin, approved IR/source/provenance, revision, canonical script, limits
and versioned catalog. The compiled plan exposes only
`sentinel_script_identity()`: copying or persisting it grants no authority.
All ordinary string/file/predicate compile entries and `GraphBuilder` reject
behavioral opt-in without authority, before registry resolution. The CLI has no
host-authority channel and rejects opt-in. Approval on non-opted workflows and
mismatched IR/schema/limits are rejected, never silently ignored or clamped.

Consume that same capability with `AdkGraphTranslator::new().with_sentinel_trusted_script(&compiled, script)` before `translate(&compiled)`. Translation without live authority still rejects behavioral opt-in, including direct/resolved IR. Different compiled approval, IR, duplicate binding, profile adapters, model bindings and checkpoint continuation fail closed.

Call `graph.invoke_observed_with_sentinel_script(state, config, mapper, artifacts, cancelled, deadline).await` with explicit host cancellation and an absolute deadline. `config.thread_id` must equal the fresh mapper's host run ID. Ordinary `invoke`/`invoke_observed` cannot execute this mode. Actual source identity is checked before retention; prepared normalization telemetry, host provenance/approval and run ID bind the sealed probe and preparation cache identity. Preparation skips semantic/model work. The existing authored terminal consumes its probe once, using invocation-local typed state rather than graph JSON, and returns `(State, ProbeReport)` only after report retention. Events reference that report's digest and optional Suspicious evidence, never Clean or causal attribution.

The embedding-host route is implemented; `ExecutionBackend` and CLI still have no host-script channel and reject opt-in during ordinary compilation. Profile execution and durable resume remain unsupported. No result cache, approval serialization, new executor registry or production IO was added. Cancellation/deadlines cover preparation/queue time cooperatively; host artifact-store IO is outside the inert reducer, not preemptively bounded. This is not full #233 acceptance.

## Public ADK path

`workflow_adk::behavioral::run_simulation(probe, cancelled, deadline).await`
executes the same admitted probe in a fresh ADK `GraphAgent` superstep. Only a
typed in-memory report channel leaves the node; caller-writable graph state
cannot fabricate a `ProbeReport`. No provider, production `ExecutionBackend`,
artifact observer, checkpoint or inherited state is bound. The host deadline
includes graph setup/queue time; the runtime still clamps its own ceiling.
The direct runtime API is a deterministic data reducer, not a second agent loop.

## Verification

Run `just issue-233-runtime`, `just issue-233-adk` (including authored execution and public default denial), and `just issue-233-doc` with the repository's safe
SSD temp setup. Tests cover every honeytool, benign completion, parameter traps,
network/filesystem/symlink/process-shaped requests, production-binding refusal,
canary lifecycle, resource limits, cancellation, expired deadlines and replay.
Compile-fail examples prove that real executors cannot implement/bind the sealed
trait and that `TrustedScript` cannot be serialized, deserialized or forged by a
struct literal. `just issue-231-compiler` also covers strict behavioral policy,
canonical IR roundtrip/hash stability and public compile admission. Run
`just conformance-contract 'workflow-compiler --test graph_builder behavioral_policy_cannot_bypass_host_admission_through_graph_builder'`
and
`just conformance-contract 'workflowctl --test cli_contracts behavioral_opt_in_has_no_cli_authority_channel'`
for sibling/CLI default denial. These are API capability tests, not evidence of
an OS security boundary.
