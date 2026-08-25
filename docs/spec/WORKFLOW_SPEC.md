# Workflow Specification

`workflow-spec` supports only `WORKFLOW_SCHEMA_VERSION_V1` (`schema_version = 1`). `parse_str` and `parse_file` decode strict TOML into `WorkflowSpec`; parsing preserves `SourcePath`, structural `FieldPath`, and an optional byte span for diagnostics.

## v1 shape

A document contains workflow metadata (`id`, `version`, `entry`), source-order `nodes` and `edges`, optional registered-predicate `routes`, and optional state. `NodeKind` is closed: `agent`, `action`, `validator`, `registered`, `approval`, and `terminal`. A node may carry `timeout_ms` only when it is an approval node, and approval timeouts must be non-zero.

Route operators are closed and represented by `RouteOperator`: `equals`, `not_equals`, `is_true`, `is_false`, `exists`, `is_empty`, `enum_case`, `numeric_range`, and `status_class`. Unknown operators produce `UnsupportedRouteOperator` rather than being accepted as free text.

## Compilation contract

`workflow-compiler` turns a parsed specification into validated `WorkflowIr`. It checks graph endpoints, canonical graph structure, state declarations, approval timeout rules, and exact predicate registry bindings. A workflow containing routes cannot compile without the required registry. Failures are categorized by `CompileError` (`Parse`, `Graph`, `State`, `PredicateRegistryRequired`, or `Registry`).

Source input is bounded. Unknown fields, malformed values, unsupported schema versions, invalid identifiers, and invalid structural combinations fail closed. The spec parser does not execute nodes or invoke predicates.
