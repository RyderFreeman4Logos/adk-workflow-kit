# adk-workflow-kit

> An opinionated, Rust-first workflow engineering kit built on top of stable **ADK-Rust**.

## Overview

`adk-workflow-kit` provides a declarative workflow specification (`workflow.toml`), a canonical intermediate representation (IR), a workflow compiler, and isolation runtimes to create, evaluate, test, and debug LLM workflows in Rust with high developer velocity.

## Architecture

- `crates/workflow-spec`: Serde types and path-aware TOML diagnostics.
- `crates/workflow-ir`: Canonical normalized graph representation and enums.
- `crates/workflow-compiler`: Pipeline for graph validation, reachability, and compilation.
- `crates/workflow-adk`: ADK-Rust integration shim and graph translation.
- `crates/workflow-runtime`: Workdir isolation, limits, session management, and sandbox interfaces.
- `crates/workflowctl`: CLI tool for validation, compilation, replay, and evaluation.

## Planning Documentation

Full design and architecture specifications can be found under [`docs/architecture/planning-pack/`](docs/architecture/planning-pack/).

## License

Licensed under [Apache License, Version 2.0](LICENSE-APACHE).
