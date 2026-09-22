# Dataset registry

Pinned evaluation datasets live in [`config/datasets.toml`](../../config/datasets.toml).
The repository stores manifests and adapters, not third-party dumps.

`workflow-runtime::prepare_dataset` is the fetch/verify boundary. It does not
call a live model.

## Contract

- Schema version `1`.
- Formal and regression fetch entries use a full 40- or 64-hex immutable object
  ID for `revision`; moving labels are not a pin.
- `distribution = "fetch"` reads a `ByteSource` whose resolved identity must
  exactly match the requested origin and revision before publication or report.
  This is a trusted provider boundary, not cryptographic authentication of an
  arbitrary in-process source implementation.
- `memory://` sources are local fixtures and report a SHA-256 content identity,
  not upstream-commit provenance. `distribution = "manual"` likewise requires
  an operator path and reports a content-addressed manual identity.
- `license_acceptance_required = true` cannot be fetched silently.
- Cache layout: `<cache>/<id>/<revision>/artifact`. Partial fetches resume from
  `artifact.partial`; sibling identity metadata binds provenance kind, origin,
  and revision/content digest. Entries without matching metadata are cache
  misses and cannot be promoted into source provenance. Offline hits reuse only
  the same verified identity and keep the same adapter/derivation hash. Warm
  reuse and writes also require current-user-owned, non-group-writable
  id/revision directories; world-writable directories are allowed only when
  sticky. The configured cache-root symlink remains supported.
- Reports list the resolved source identity, checksum, adapter version, and
  derivation hash.
- Case IDs are `{id}/{family}/{language}/0000`.

## Smoke path

Prepare `smoke-fixture` with a local `ByteSource` that yields the 24-byte
synthetic payload matching the pinned checksum. No AgentDojo/LongMemEval dump
is required. This local fixture smoke does not execute an external upstream
fetch path.
