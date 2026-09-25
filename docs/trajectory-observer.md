# Offline canonical trajectory observer (#234)

`workflow_runtime::behavioral::trajectory` is an **offline partial milestone**,
not a provider CoT monitor. Ordinary workflow execution remains unchanged.
`ObserverMode::default()` is `Disabled`; only an explicit Rust host call enables
`OfflineSummary`. No new workflow/profile/CLI opt-in, model calls, tool registry,
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

Run `just issue-234-runtime` and `just issue-233-doc` for offline contracts.
Live-provider availability, semantic quality, token/decode overhead measurement,
raw-artifact access/retention tests and authored spec/IR/compiler integration
remain deferred. This milestone does not close #234 or #233.
