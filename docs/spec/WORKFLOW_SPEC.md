# Workflow Specification

`workflow-spec` supports only `WORKFLOW_SCHEMA_VERSION_V1` (`schema_version = 1`). `parse_str` and `parse_file` decode strict TOML into `WorkflowSpec`; parsing preserves `SourcePath`, structural `FieldPath`, and an optional byte span for diagnostics.

## v1 shape

A document contains workflow metadata (`id`, `version`, `entry`), source-order `nodes` and `edges`, optional registered-predicate `routes`, and optional state. `NodeKind` is closed: `agent`, `action`, `validator`, `registered`, `approval`, and `terminal`. A node may carry `timeout_ms` only when it is an approval node, and approval timeouts must be non-zero.

Route operators are closed and represented by `RouteOperator`: `equals`, `not_equals`, `is_true`, `is_false`, `exists`, `is_empty`, `enum_case`, `numeric_range`, and `status_class`. Unknown operators produce `UnsupportedRouteOperator` rather than being accepted as free text.

## Compilation contract

`workflow-compiler` turns a parsed specification into validated `WorkflowIr`. It checks graph endpoints, canonical graph structure, state declarations, approval timeout rules, and exact predicate registry bindings. A workflow containing routes cannot compile without the required registry. Failures are categorized by `CompileError` (`Parse`, `Graph`, `State`, `PredicateRegistryRequired`, or `Registry`).

Source input is bounded. Unknown fields, malformed values, unsupported schema versions, invalid identifiers, and invalid structural combinations fail closed. The spec parser does not execute nodes or invoke predicates.

Validator entry nodes may declare a versioned `firewall` invocation identity. The compiler and ADK translator require the exact trusted binding and never fall back to an ordinary validator. See [FIREWALL.md](FIREWALL.md).

See [NODE_RESULT_CACHE.md](NODE_RESULT_CACHE.md) for the production node-result cache identity and replay dispositions.

## Authored agent sessions

An explicit `session = "isolated"` gives each node visit a fresh model conversation. An explicit `session = "shared"` grants access to the workflow run's previously accepted Shared turns: each turn contains only that node's mapped input and validated public output. Previous instructions, schemas, tool calls/results, and Isolated reviewer conversations are excluded. Current instructions and schemas remain local to each invocation. Uncontracted nodes keep their existing behavior.

Shared visits serialize within their run; unrelated Isolated nodes and separate run identities retain their concurrency. Re-entering a node prepares its new mapped input once while preserving cumulative model/tool budgets and effect replay. Request/cache identity includes the effective history. The existing loop ledger binds accepted order and pending visit ownership to the checkpoint generation; supported execution-backend resume rebuilds the ADK session from that exact generation before effects. Reusing a run ID for a new graph invocation does not inherit an earlier invocation's history.

Shared requires recoverable raw history. Profiles that redact raw loop history because they contain Skill packages are rejected before model/tool effects, rather than silently running Isolated. Generic caller-provided SDK checkpointers do not contain the Kit's accepted-turn ledger and are unsupported for Shared; use the execution backend for durable resume. SDK tool-confirmation events are never accepted Shared turns. Kit does not expose SDK confirmation pause/resume as an approval API: injected agents that request it fail the graph without executing the guarded tool. This is separate from the supported call-scoped ToolBridge/Firewall approval and durable-receipt contract.
