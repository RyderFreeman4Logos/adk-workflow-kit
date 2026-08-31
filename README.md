# adk-workflow-kit

> An opinionated, Rust-first workflow engineering kit built on stable **ADK-Rust**.

## Overview

`adk-workflow-kit` compiles declarative `workflow.toml` files to a canonical IR and runs them through ADK-Rust with bounded workdirs, sandbox capabilities, durable checkpoints, and replayable evidence.

## Five-minute quickstart

The quickstart uses the implemented ADK execution path without provider credentials: use the `fake` profile shown below, then replace it with a real profile kept outside the repository.

```toml
# workflow.toml
schema_version = 1

[workflow]
id = "quickstart"
version = "1"
entry = "agent"

[[nodes]]
id = "agent"
kind = "agent"
model = { role = "worker", id = "quickstart", version = "1" }
tool = { id = "echo", version = "1" }

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "agent"
to = "done"
```

```json
// profile.json
{"schema_version":1,"model":{"provider":"fake","name":"quickstart","version":"1","model":"fake","responses":["done"]},"tool":{"name":"echo","result":{"ok":true},"required_capabilities":[]},"sandbox":{"capabilities":[]}}
```

```sh
cargo run -p workflowctl -- run workflow.toml --profile profile.json --input '{"request":"public"}' --workdir .workflow-runs
cargo run -p workflowctl -- inspect --run-id RUN_ID --workdir .workflow-runs
cargo run -p workflowctl -- resume --run-id RUN_ID --workdir .workflow-runs
```

`run` prints `RUN_ID`; `inspect` and `resume` read its durable checkpoint and receipt from the same workdir. Keep profiles and workdirs outside source-controlled directories. Do not place API keys or other secrets in a workflow, fixture, replay bundle, or checked-in profile.

## CLI

```sh
workflowctl validate workflow.toml
workflowctl graph workflow.toml --format mermaid
workflowctl lock workflow.toml
workflowctl run workflow.toml --profile profile.json --input '{"request":"public"}' --workdir .workflow-runs
workflowctl resume --run-id RUN_ID --workdir .workflow-runs
workflowctl inspect --run-id RUN_ID --workdir .workflow-runs
workflowctl replay replay.json
workflowctl skill lint skill-dir
workflowctl skill test skill-dir
```

Use `--profile` for ADK-backed execution. `--module` is the bounded pure-transform path. The sandbox is deny-by-default: profiles declare only needed capabilities, and an unauthorized capability fails before backend work. Checkpoints, events, and artifacts are stored beneath the selected workdir; replay validates a redacted replay bundle rather than contacting a provider.

## Maturity

| Area | Status | Notes |
| --- | --- | --- |
| Workflow validation, graphing, locking, and CLI contracts | implemented | Stable local commands with typed diagnostics. |
| ADK profile execution, workdir receipts, checkpoint, resume, inspect, and replay | implemented | The quickstart exercises the real ADK path with a fake model. |
| Sandbox capability policy and secret-free fixtures | implemented | Inputs fail closed at the boundary. |
| Development hot reload | experimental | Development-only; production bindings reject reload. |
| Additional provider adapters and richer workflow nodes | planned | No compatibility promise before implementation. |
| Remote execution and distributed replay storage | deferred | Not part of the local security boundary. |

## Architecture

- `crates/workflow-spec`: Serde types and path-aware TOML diagnostics.
- `crates/workflow-ir`: Canonical normalized graph representation and enums.
- `crates/workflow-compiler`: Pipeline for graph validation, reachability, and compilation.
- `crates/workflow-adk`: ADK-Rust integration shim and graph translation.
- `crates/workflow-runtime`: Workdir isolation, limits, session management, sandbox interfaces, and checkpoints.
- `crates/workflowctl`: Thin CLI over reusable libraries.

## Planning documentation

Full design and architecture specifications are under [`docs/architecture/planning-pack/`](docs/architecture/planning-pack/).

## License

Licensed under [Apache License, Version 2.0](LICENSE-APACHE).
