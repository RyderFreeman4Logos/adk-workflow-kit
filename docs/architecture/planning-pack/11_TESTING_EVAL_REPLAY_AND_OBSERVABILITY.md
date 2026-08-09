# Testing, Evaluation, Replay, and Observability

## 1. Testing philosophy

The framework's value depends on repeatability. Most tests must run without a live model, external API, container registry, or customer system. Live-model evals are an additional layer, not the foundation.

## 2. Test pyramid

### Layer 1: pure unit tests

- TOML parsing and diagnostics;
- normalization and canonical hashing;
- route operators;
- cycle analysis;
- state contract checks;
- permission intersections;
- workdir path rules;
- defect fingerprints and no-progress detection;
- artifact paging and hashes;
- lockfile comparison.

### Layer 2: property tests

- parse/serialize round trips;
- canonical IR stability under map ordering;
- graph invariants;
- route totality;
- no unauthorized capability after arbitrary policy intersections;
- path containment under generated traversal/symlink cases;
- bounded cycle termination;
- artifact ID collision resistance assumptions.

### Layer 3: component tests

- registry resolution;
- ADK compiler adapter;
- scripted model Tool Calls;
- tool envelope handling;
- Skill activation/resource reads;
- script schema validation;
- session isolation;
- callbacks/plugins;
- cancellation.

### Layer 4: sandbox conformance

Run the common suite against every backend and target OS. Backend support is a tested claim, not documentation text.

### Layer 5: workflow integration

Use fake connectors and scripted LLMs to execute complete graphs. Assert node order, routes, state, artifacts, limits, and terminal outcome.

### Layer 6: record/replay

Replay recorded model/tool events with content digests and fixture payloads. Re-run old traces after compiler/runtime upgrades.

### Layer 7: live model evals

Run representative fixtures across configured worker/reviewer models. Track quality and cost regressions. Do not make ordinary CI depend on an unstable external provider.

### Layer 8: dogfood parity

Compare declarative CodeSeek and Verbatim workflows against current implementations.

## 3. Scripted model

The testkit should support a deterministic sequence:

```text
expect model request matching predicate
return text/tool calls/usage/error/delay
expect tool result
return next model response
```

It must simulate:

- valid Tool Call;
- malformed JSON arguments;
- unknown tool;
- repeated Tool Call ID;
- empty response;
- text plus Tool Call;
- provider timeout;
- partial stream;
- rate limit;
- invalid structured final output;
- runaway loop.

## 4. Fake tools and connectors

A fake registered tool should configure:

- input/output schemas;
- read/write/network metadata;
- delay;
- payload size;
- deterministic success/empty/failure;
- idempotency behavior;
- side-effect ledger;
- cancellation behavior.

Connector contract tests should use local fake servers and verify pagination, retries, authentication refresh, timeouts, and idempotency headers.

## 5. Fault injection matrix

Every production pattern should test:

```text
invalid input
missing registry entry
model malformed output
tool timeout
tool rate limit
tool output too large
artifact missing/corrupt
sandbox unavailable
network denied
permission denied
approval denied/expired
duplicate delivery
partial side effect
process kill and resume
budget exhausted
reviewer disagreement
repeated defect/no progress
cross-tenant access attempt
```

## 6. Replay format

A replay bundle should contain:

- workflow lock identity;
- initial state/input digest;
- ordered node events;
- model request/response fixtures or redacted references;
- tool arguments/results or fixture references;
- artifacts by content hash;
- policy decisions;
- terminal result;
- expected structural assertions.

Raw hidden reasoning is neither required nor desirable. Preserve observable inputs, outputs, actions, and decisions.

## 7. Deterministic trace assertions

Examples:

- node `retrieve` executed once;
- reviewer session differs from producer session;
- no write tool was exposed to reviewer;
- total tool calls ≤ configured limit;
- every published citation belongs to evidence set;
- repaired output passed validator after review;
- approval preceded side effect;
- workdir was cleaned and no child process survived;
- final result used the locked Skill hash.

## 8. Integration with `adk-eval`

Use upstream evaluation for trajectory and model-oriented scoring where applicable. Wrap it in platform commands and retain application-specific validators. Do not make an LLM judge the sole source of pass/fail for deterministic properties.

## 9. Live eval dataset design

Each workflow should include:

- normal cases;
- difficult but valid cases;
- ambiguous cases expected to abstain;
- adversarial prompt-injection evidence;
- missing-data cases;
- stale/contradictory evidence;
- low-frequency safety-critical exceptions;
- multilingual inputs where relevant;
- model Tool Call formatting variations.

Split development and held-out cases. Version eval datasets and record changes.

## 10. Review-loop evaluation

Measure each stage independently:

- producer baseline;
- validator catch rate;
- reviewer defect accuracy;
- repair success per round;
- errors introduced by revision;
- false pass;
- false abstain;
- no-progress detection;
- incremental token/tool/time cost.

The selected default review policy should maximize expected task value, not raw pass rate.

## 11. Observability schema

Recommended event dimensions:

```text
run_id
workflow/package/lock identity
tenant and actor pseudonymous IDs
node ID/kind/visit
role and session ID
model provider/resolved ID
Tool/script ID and implementation version
status and diagnostic code
input/output content digests
artifact IDs
latency
input/output tokens
bytes
retry/revision count
policy/approval decision IDs
sandbox backend/profile
```

Content logging is disabled by default. Emit OpenTelemetry-compatible spans where upstream support applies.

## 12. Metrics

- runs by terminal status;
- success/abstain/failure by workflow version;
- p50/p95/p99 latency;
- model/tool/script calls and cost;
- validator defect codes;
- review rounds and repair rate;
- sandbox failures;
- policy denials;
- artifact bytes and retention;
- cancellation cleanup time;
- cache/artifact reuse;
- human approval latency.

## 13. CI gates

Initial required gates:

```text
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
schema/fixture validation
compiler property tests
sandbox conformance on Linux
examples validate --locked
CodeSeek characterization suite
Verbatim contract suite
cargo deny/audit policy
```

Live-model evals may run on a scheduled or manually approved workflow with stored regression reports.

## 14. Performance benchmarks

Benchmark:

- parse/normalize/compile latency;
- cold and warm runtime startup;
- workdir allocation;
- sandbox startup by backend;
- graph overhead without model calls;
- artifact paging;
- concurrent runs and memory;
- cancellation and cleanup;
- record/replay throughput.

Do not optimize model latency by weakening isolation or validation without an explicit measured tradeoff.
