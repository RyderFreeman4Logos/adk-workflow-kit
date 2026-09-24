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

The runtime adapter currently rejects this contract with `MissingNodeBackend`;
it must never silently execute the legacy `true` terminal placeholder. Executable
artifact-backed preparation is the next milestone. Neither compilation nor
preparation means Clean. General graph routing and semantic branches remain out
of this restricted contract.
