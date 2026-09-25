# Offline canonical trajectory observer (#234)

`workflow_runtime::behavioral::trajectory` is an **offline partial milestone**,
not a provider CoT monitor. Ordinary workflow execution remains unchanged.
`ObserverMode::default()` is `Disabled`; only an explicit Rust host call enables
`OfflineSummary`. Authored workflows require both the policy below and an explicit
host capability. No profile/CLI authority channel, model calls, tool registry,
raw-CoT capture, raw storage or second agent loop is introduced.

## Host API and data boundary

1. Obtain an immutable `ProbeReport` from #233's inert simulation (including the
   existing ADK execution receipt). The report cannot be deserialized from JSON.
2. Authenticate a trusted task independently, then call
   `TrustedObserverTask::authorize(&report, task)`. Never use workflow text,
   issue/comment content, profiles or model output as authority. The task must
   be nonblank and at most 2048 UTF-8 bytes. Approval binds the exact report
   bytes, including run/source/policy identity and actual stop boundary.
3. Call `observe(mode, &task, &report, optional_summary_bytes)`.

`task.canonical_input(&report)` exposes an ephemeral versioned observer view:
trusted task text, report digest, at most 32 existing ordered `ProbeEvent`s and
terminal stop. Events contain closed tool names, action digests and typed
outcomes/policy tripwires. They contain no original source, argument values,
output text, canary plaintext or raw CoT. Unknown tool names are not copied.
No semantic inference over the trusted task is claimed by this deterministic
observer. Richer argument/destination classes and bounded excerpts are deferred;
this milestone reuses existing safe event features rather than reconstructing
information that the report intentionally discarded.

## Compact fixture, not raw reasoning

The optional fixture is a UTF-8 JSON object, bounded to 1024 bytes:

```json
{"schema_version":1,"goal_override":false,"secret_seeking":false,"tool_manipulation":false,"claims_no_tools":true}
```

All fields are required. Arrays, unknown/duplicate fields, non-booleans, unknown
versions, invalid UTF-8/JSON and oversized input produce `Malformed` without
retaining bytes. No fixture produces `Unavailable`; disabled mode does not
parse submitted bytes. `Present` describes only this compact fixture, **never
provider reasoning availability**. The report separates `summary_status` from
`raw_reasoning`, which is always `disabled` or `unavailable` in this milestone.
There is no raw-reasoning adapter.

The first three flags map to typed weak hints. `claims_no_tools` conflicts with
any observed call (including an unknown tool). This narrow syntactic consistency
check is not a detector of natural-language deception or unfaithful reasoning.
All-false, absent, disabled and malformed fixtures have zero exculpatory weight.

`TrajectoryObservation::evidence()` returns the exact existing hard-tripwire
evidence first. Otherwise weak hints can produce only shared-protocol
`Suspicious`, with the retained observation's content-addressed artifact reference.
No hints produce `None`, never `Clean`, `Allow` or side-effect authorization.
The report keeps typed weak hints separate from the hard stop.

## Retention, identity and deferred acceptance

For published weak evidence, retain `TrajectoryObservation::to_json()`. For
returned hard-tripwire evidence, preserve the original `ProbeReport::to_json()`
artifact it references; retaining only the observation is insufficient. Both
artifacts omit task text, raw fixtures, attacker arguments and CoT. Never retain
the task-bearing canonical input as ordinary telemetry. There is deliberately
no raw artifact API, retention timer or purported access-control guarantee.
Raw reasoning capture requires a separately verified storage/access/retention
policy and provider authorization before implementation.

Identity binds the versioned input (including exact report and trusted task),
mode, availability and canonical parsed claims. Invalid fixture bytes are neither
retained nor hashed. Provider/model are explicitly absent from this offline
identity; changing fixture key order/whitespace is immaterial. Existing #233
report bytes and non-opted workflow cache identities are unchanged.

## Authored host-only execution

Add this table to a #233 behavioral terminal to request the offline observer:

```toml
[nodes.untrusted_text.behavioral.trajectory]
schema_version = 1
```

V1 fixes the existing 2048-byte task, 1024-byte compact fixture and 32-event
ceilings. Unknown/duplicate fields and missing versions are rejected. It accepts
no task, summary, report, raw reasoning or authority. Omission disables the
observer and preserves existing v12 IR, script identity, report and preparation
cache bytes. Opt-in uses canonical IR v13; the observer version and canonical
fixture status/claims plus task digest participate in host approval identity.
Malformed fixture bytes are discarded, never hashed or stored.

Authenticate the exact authored IR/source/script as described in
[behavioral simulation](behavioral-simulation.md#host-authorized-authored-execution),
then consume that `TrustedScript` using
`script.with_trajectory_observer(trusted_task, optional_summary_bytes)` before
compilation. Authenticate the task independently; this is a host capability API,
not authentication of arbitrary strings or protection against hostile in-process
Rust code. Rebinding, missing host task, missing policy and unknown policy versions
fail closed. Do not call this API with workflow/input/state/model-derived tasks.

The existing `compile_spec_with_sentinel_script`, authorized ADK translator and
`ExecutionBackend::run_with_sentinel_script` execute the observer without another
registry or provider adapter. Source/run/IR/host approval bind the sealed probe;
`probe.observe_trajectory(&report)` rejects foreign reports before authorizing the
exact report bytes. Task/summary authority and reports never travel in caller JSON
or checkpoints. Only validated compact claims, not raw fixture bytes, are retained
ephemerally inside the host capability.

Observed invocation retains the original behavioral report, then the content-free
trajectory observation before publishing node/workflow completion. The
`sentinel-trajectory` artifact event and `preparation.trajectory` reference the
observation; weak evidence references it, hard evidence still references the
original report. Artifact-store failure returns an error, not success; previously
retained preparation/report artifacts are not rolled back. Host storage remains
outside the inert reducer, with no new raw-CoT retention/access-control claim.

Run `just issue-234-authored`, `just issue-234-runtime`, `just issue-231-compiler`,
`just issue-233-adk` and `just issue-233-doc` for offline contracts.
Live-provider availability, semantic quality, token/decode overhead measurement,
raw-artifact access/retention tests and independent OS isolation
remain deferred. This milestone does not close #234 or #233.
