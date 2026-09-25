# Versioned Sentinel preparation workflow

This is a bounded #231 milestone, not semantic classification (#232). Workflow
schema v1 accepts `nodes.untrusted_text` only on the sole terminal node, with no
edges or routes. Compiler admission rejects unsupported policy versions,
unknown/missing/mistyped fields, and byte limits above 65,536. Zero denies input.
Canonical IR wire v10 binds every policy field; workflows without this contract
keep their previous canonical wire.

```toml
schema_version = 1
edges = []
[workflow]
id = "sentinel-preparation"
version = "1"
entry = "prepare"
[[nodes]]
id = "prepare"
kind = "terminal"
[nodes.untrusted_text]
schema_version = 1
max_input_bytes = 65536
en = true
zh = true
ja = true
```

## Execution and byte identity

Run the fixture `crates/workflow-adk/tests/fixtures/sentinel.workflow.toml` through
`ExecutionBackend::run` (or the normal `workflowctl run` boundary). Its input is
exactly `{"schema_version":1,"bytes":[80,108,101,97,115,101]}`: an explicit array
of integer bytes in 0..255. Unknown fields, wrong types and unsupported payload
versions produce `invalid_input / invalid_byte_payload`. Arbitrary JSON values
and JSON strings are never converted into text implicitly.

**Original bytes mean the declared byte sequence, not the JSON transport's source
bytes.** The existing `Value` API has already lost JSON whitespace, escape spelling
and duplicate keys. Transport-byte conservation is not claimed. The normal run
boundary also retains its existing 64-KiB serialized-JSON admission limit, so the
maximum usable byte-array length depends on the values. Rejection at that outer
boundary creates no run artifact; the caller owns retention.

The observed ADK execution entry point persists nonempty admitted bytes before
calling `prepare_untrusted_text`, `analyze_carriers(Decode)`, `segment_language`,
and `assess_language`. It retains these bytes even when `max_input_bytes` denies
them. Empty input yields `invalid_input / empty_input`, with no original artifact:
`ArtifactStore` rejects empty content. Invalid byte payloads and lower-level arrays
above the hard admission ceiling have no admitted original byte stream/artifact.
No alternate storage location or synthetic original handle is used.

A normalized length-framed envelope is a separate immutable artifact, not a
trusted prompt. Raw and envelope SHA-256 handles are checked after each write.
Both emit `artifact_committed` observations with protected artifact references;
`node_completed.payload.structured_output.preparation` contains diagnostic outcome,
versions, policy/cache digests, counts and artifact handles, not a reducer decision.
Source maps and decoded views remain transient library values; the original
artifact plus exact versions supports reconstruction, but this milestone does not
persist a full decoded-view/source-map report.

The compiler restriction makes preparation the only operation. Preparation occurs
before ADK streaming because graph closures cannot borrow the observer's artifact
store; ADK still owns terminal-node execution and checkpoint delivery. Input state
is replaced by the host-created report before the stream starts, preventing
caller-injected state from minting a preparation result. Unobserved `invoke` and
checkpoint-resume invocations fail closed for this contract. Existing model/tool
and WASM workflows without `untrusted_text` are unchanged.

## Typed terminal output and limits

The terminal is a closed v1 `UntrustedTextReport`, separate from stage telemetry.
Its five required fields are `schema_version`, `state`, `reason`,
`original_artifact_id` (handle or null), and `decision` (envelope or null).
`UntrustedTextState` is `invalid_input`, `unsupported_language`, `unattributed`,
or `pending_classification`. Only the first two have a `decision`: a shared
`TypedOutput` Sentinel envelope (`inv` / `uns`, complete, no rationale), admitted
through `admit_for_reducer`. It references the retained original artifact when one
exists; no precise offending span is claimed. Feed **`terminal.decision`**, not the
metadata/report, to `parse_typed_output`. Null means no classification, never Clean.

`UntrustedTextReport::parse` rejects reports over 4,096 bytes, unknown versions,
missing/duplicate/unknown report fields, unknown reasons/states, mismatched rejection
codes/references, truncated decisions and any decision attached to abstention.
It validates consistency, not origin authenticity; provenance still comes from
host execution and retained artifacts. Reasons are closed preparation subcodes;
invalid payload and empty input have no original, all other results retain one.
A successful run means preparation completed, never semantic approval, model
invocation or graph continuation. Han-only Chinese remains unattributed. Adapter
identity `sentinel-workflow-preparation-v3` binds the output contract and the
additional [source-only probe descriptor artifact](sentinel-probes.md); it supplies
no semantic verdict or trusted task-alignment goal.

Normalization uses the authored input ceiling and the runtime's default output/work
limits. Carriers use bounded Decode defaults; segmentation uses its default 16,384
bytes / 4,096 segments. Stage resource/delimiter failures produce `invalid_input`
with a typed reason and `failed_stage`. Language en/zh/ja flags are explicit and
independent; zh is reserved pending genuine attribution, as described in
[sentinel-envelope.md](sentinel-envelope.md).

The existing `NodeCacheKey` binds raw-byte digest, artifact identity, canonical IR,
workflow/node identity, every preparation stage and compact-output schema version,
Unicode/security/trust versions, all used limits, decode mode and language policy.
Repeated runs have the
same key; policy, workflow or raw-byte changes miss that identity. This milestone
emits the key but deliberately does not reuse cached preparation results: it always
persists/verifies the current run's artifacts. It does not bind unused model or
provider settings or pretend an issue-body author identity for generic bytes.

Verify with `just issue-231-compiler`, `just issue-231-adk` and
`just issue-231-runtime`. Full #231 acceptance remains incomplete: general graph
routing, resumable preparation, durable cache reuse, complete language/carrier
coverage and #230 benchmark integration remain; #232 owns semantic classification.
