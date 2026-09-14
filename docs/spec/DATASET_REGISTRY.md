# Dataset registry

Pinned evaluation datasets live in [`config/datasets.toml`](../../config/datasets.toml).
The repository stores manifests and adapters, not third-party dumps.

`workflow-runtime::prepare_dataset` is the fetch/verify boundary. It does not
call a live model.

## Contract

- Schema version `1`.
- Each dataset pins `revision`, SHA-256 (`sha256:` + hex), adapter version, and
  derivation recipe.
- `distribution = "fetch"` may read a `ByteSource`. `distribution = "manual"`
  requires an operator-supplied path.
- `license_acceptance_required = true` cannot be fetched silently.
- Formal/regression suites reject unpinned moving branches (`main`, `master`,
  `HEAD`, `latest`, `trunk`, `develop`, `origin/*`).
- Cache layout: `<cache>/<id>/<revision>/artifact`. Partial fetches resume from
  `artifact.partial`. Offline hits reuse a verified artifact and keep the same
  adapter/derivation hash.
- Reports list source revision, checksum, adapter version, and derivation hash.
- Case IDs are `{id}/{family}/{language}/0000`.

## Smoke path

Prepare `smoke-fixture` with a local `ByteSource` that yields the 24-byte
synthetic payload matching the pinned checksum. No AgentDojo/LongMemEval dump
is required.
