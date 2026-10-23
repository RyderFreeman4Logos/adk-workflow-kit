# Measured request and cache evidence

This supplements [the harness measurement contract](BENCHMARK_HARNESS.md#explicit-input-runtime-measurement).
It adds no model call, service reset, streaming transport or cache-hit inference.

## Field sources and units

`measure`, `measure-live` and `measure-report` share the same verification path.
Their derived `measured.field_sources` names each counter's exact raw response
path and unit. A valid reported zero is observed; missing, null or malformed
counts stay null. With multiple completed model calls, single-response summary
fields stay null; individual `model_calls` retain their own observations.

| Field | Source and meaning |
|---|---|
| `input_count`, `total_count` | `provider_usage.prompt_tokens`, `total_tokens` |
| `provider_completion_count` | `provider_usage.completion_tokens`, including reasoning |
| `cached_input_count`, `cache_write_count` | `prompt_tokens_details.cached_tokens`, `cache_write_tokens` |
| `reasoning_count` | `completion_tokens_details.reasoning_tokens` |
| `sdk_estimated_cost_usd` | Optional finite, nonnegative `UsageMetadata.cost`, an SDK estimate |
| `elapsed_ns` | Host workflow duration; not provider prefill or decode time |
| `retries` | Host binding retry count, separate from successful model calls |

Visible output is not completion minus reasoning. Prefill/decode clocks, provider
billing and KV hit remain unavailable on the selected SDK path. An SDK estimate
is not billing. The user's zero marginal local API cost is a separate policy,
excluding hardware, electricity and labor. Arbitrary usage fields do not become
metrics merely because a provider returned them.

## Actual host request prefix

The model binding hashes the actual post-runtime `LlmRequest`: ordered leading
`system` contents, explicitly serialized tool declarations, response schema and
host model. Canonical JSON sorts object/tool keys, preserving array/system order.
It excludes user/tool/history suffixes, continuation IDs, transport extensions
and cache salt. The tag is
`host_actual_llm_request.leading_system_tools_schema_model.v1`.

`host_prefix_hash` is this host stable view, not SDK final wire bytes, token IDs,
server weights, server prefix or a cache hit. No authored system content is
invented when an agent has none. The digest is not redaction or secret detection;
original prompts and request bodies are not added to telemetry. Separately,
`request_cache_salt_hash` hashes the actual salt passed to the SDK.
Historical events without these fields remain readable and do not acquire an
observation retroactively.

## Pre-admitted KV request intent

An optional host-only binding declaration uses the existing measurement path:

```json
{"kv_intent":{"schema_version":1,"schedule":"pair-v1",
 "namespace":"public-isolated-namespace","arm":"cold_namespace","order":0}}
```

Every configured model role must already designate a public `cache_salt` trust
domain in its allowed OpenAI extensions. The namespace binds that domain; the
existing salt owner additionally binds configuration, workflow and role. Salt is
never injected into model messages. Defaults without `kv_intent` are unchanged.

A repeat declares `arm: "warm_repeat"`, `order: 1` and `predecessor` pointing to
the completed first measurement directory. Further repeats increment order,
up to 16. The schedule/namespace, complete source/tree/files/executable/workflow/
configuration/model/input manifest, origin and role/salt identities must match.
Distinct model roles need distinct public profile identities. Missing, failed,
changed or ambiguous predecessor executions are rejected before creating the new
output directory or admitting provider/effect work. Reusing an existing output
directory remains denied; this is not automatic replay of ambiguous work.

The durable plan/admission seals the declaration and identity before execution.
Completed telemetry must match admitted role salts. Repeat validation also
requires the same actual host prefix sets per node/role. Report-only revalidation
uses the original receipt/checkpoint/event evidence and recursively verifies the
strictly decreasing, bounded predecessor chain. It never invokes the provider.

`kv_intent` records requested arm/order/namespace and predecessor run; it does
not certify physical coldness, warmth, eviction or hit. Arm/order/run ID do not
enter the stable salt/prefix. Loopback controls verify both real wire salts and
request order. Provider cached-token observations and runtime result-cache
outcomes remain separate. There is no physical reset, global cache clearing,
shared-service pressure or new resource scheduler.
