# GOV-002 ADK-Rust Dependency Baseline

Revalidated: 2026-08-09T16:24:20Z

This report fixes the dependency-governance baseline only. It does not add ADK imports, APIs, providers, adapters, exporters, examples, or runtime behavior.

## Verified upstream release

- The [latest stable release API](https://api.github.com/repos/zavora-ai/adk-rust/releases/latest) returned `v1.0.0`, published at `2026-06-07T20:29:54Z`, with `draft=false` and `prerelease=false`.
- The [`v1.0.0` tag ref](https://api.github.com/repos/zavora-ai/adk-rust/git/ref/tags/v1.0.0) resolves directly to commit [`a6c79b6f97a338de58d2c0fbf33cac00eaae0f13`](https://github.com/zavora-ai/adk-rust/commit/a6c79b6f97a338de58d2c0fbf33cac00eaae0f13).
- The tagged [workspace manifest](https://github.com/zavora-ai/adk-rust/blob/v1.0.0/Cargo.toml) declares version `1.0.0`, Rust `1.94.0`, and Apache-2.0. Its tagged [toolchain file](https://github.com/zavora-ai/adk-rust/blob/v1.0.0/rust-toolchain.toml) also pins Rust `1.94.0`.
- Crates.io reports the resolved [`adk-rust`](https://crates.io/api/v1/crates/adk-rust/1.0.0), [`adk-core`](https://crates.io/api/v1/crates/adk-core/1.0.0), [`adk-agent`](https://crates.io/api/v1/crates/adk-agent/1.0.0), [`adk-model`](https://crates.io/api/v1/crates/adk-model/1.0.0), [`adk-graph`](https://crates.io/api/v1/crates/adk-graph/1.0.0), [`adk-guardrail`](https://crates.io/api/v1/crates/adk-guardrail/1.0.0), and [`adk-telemetry`](https://crates.io/api/v1/crates/adk-telemetry/1.0.0) packages as version `1.0.0`, unyanked, Apache-2.0, and Rust `1.94.0`.

## Pin and MSRV policy

The root workspace dependency is intentionally exact:

```toml
adk-rust = { version = "=1.0.0", default-features = false, features = ["agents", "models", "graph", "guardrail", "telemetry"] }
```

Cargo's [exact requirement syntax](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html) makes `=1.0.0` prevent compatible-version drift. `Cargo.lock` is committed and normal metadata, check, Clippy, and test routes use `--locked`. Dependency updates are explicit: refresh the lock mechanically with `just lock`, inspect resolver output with `just metadata`, then rerun the locked gates.

The repository pins `rust-toolchain.toml` to `1.94.0`, declares `workspace.package.rust-version = "1.94.0"`, and makes every workspace package inherit that declaration. The active compiler and Cargo-declared MSRV are separate checks.

## Selected feature matrix

The tagged [meta-crate manifest](https://github.com/zavora-ai/adk-rust/blob/v1.0.0/adk-rust/Cargo.toml) maps the selected features as follows:

| Meta feature | Direct package | Boundary selected for |
|---|---|---|
| `agents` | `adk-agent` | Agent primitives |
| `models` | `adk-model` | Provider-neutral model traits |
| `graph` | `adk-graph` | Graph primitives |
| `guardrail` | `adk-guardrail` | Guardrail primitives |
| `telemetry` | `adk-telemetry` | Telemetry primitives |

Disabling the meta-crate defaults is required because its tagged `default = ["minimal"]` path includes Gemini. The tagged root manifest sets `default-features = false` for both `adk-agent` and `adk-model`; the published [dependency metadata](https://crates.io/api/v1/crates/adk-rust/1.0.0/dependencies) confirms those two edges retain that setting. Therefore selecting bare `models` does not activate `adk-model`'s default Gemini feature. Resolver metadata must continue to show exactly the five meta features above, no `adk-model` provider feature, and no provider package.

## Deferred and excluded

GOV-002 does not select:

- provider features or crates, including Gemini, OpenAI, Anthropic, DeepSeek, Groq, Ollama, OpenRouter, Bedrock, Azure AI, Mistral, or other `adk-model` providers;
- meta bundles such as `minimal`, `standard`, `full`, or the default feature set;
- tools, sessions, artifacts, runner, memory, evaluation, plugin, authentication, skill, server/CLI, RAG, realtime, audio, code, sandbox, managed-runtime, or enterprise crates/features;
- graph actions, persistence/cache integrations, telemetry OTLP exporters, or payload recording;
- provider/model configuration, adapters, Runner/session/artifact backends, graph execution, telemetry export, model calls, workflow behavior, API/schema changes, examples, or future scaffolding.

The `workflow-adk` compatibility crate consumes the workspace dependency only to materialize and compile this boundary. It exposes no new imports or APIs.

## Documentation drift warning

The rendered [docs.rs page for `adk-rust` 1.0.0](https://docs.rs/adk-rust/1.0.0/adk_rust/) currently contains stale `0.8.2` installation text and a `labs` feature that is absent from the tagged 1.0.0 manifest. Version, MSRV, feature, and provider decisions must use the release/tag, tagged Cargo manifests, Cargo resolver metadata, and crates.io metadata instead of rendered docs prose.
