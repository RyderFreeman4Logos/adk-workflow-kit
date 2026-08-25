# Architecture

This repository is a headless Rust workflow platform. The workspace is split into small contracts: `workflow-spec` decodes source text, `workflow-ir` holds the canonical graph, `workflow-compiler` validates and binds it, `workflow-runtime` evaluates execution policy, `workflow-review` carries typed review results, and `workflow-adk` is the domain-neutral platform boundary for ADK-Rust calls.

## Data flow

1. `workflow-spec` parses version 1 TOML with source-aware locations, closed enums, and strict unknown-field handling.
2. `workflow-ir` represents the normalized workflow graph without performing IO.
3. `workflow-compiler` validates graph, state, approval, and predicate-registry requirements, then exposes a `CompiledPlan` and deterministic Mermaid rendering.
4. `workflow-runtime` applies capability and contextual policy before execution. A policy denial is typed and privacy-safe.
5. `workflow-review` serializes typed verdicts, defects, grounded-answer and multi-hop outcomes; it is a wire model, not an execution engine.
6. `workflow-adk` accepts only a bounded opaque `VerbatimRequest`. It rejects invalid shape/size and foreign ADK type markers before dispatch.

## Boundaries and diagnostics

Core crates do not import UI code. Filesystem and platform effects are kept at explicit boundaries. Public failures use typed enums or structs rather than ambiguous success values. Boundary misses must not be rendered as successful validation, and diagnostics expose lengths, categories, or stable codes instead of untrusted payloads.

The `workflowctl` binary is the CLI composition layer. It maps compiler, skill, runtime, replay, evaluation, and audit failures to stable diagnostics and keeps command-specific IO out of the headless contracts.

## Compatibility

The workspace pins `adk-rust = 1.0.0` and enables its `agents`, `models`, `graph`, `guardrail`, and `telemetry` features. `workflow-adk` intentionally does not re-export ADK implementation types: its contract is the validated Verbatim boundary.
