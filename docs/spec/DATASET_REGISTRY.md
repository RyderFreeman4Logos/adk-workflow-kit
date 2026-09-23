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
  sticky. The configured cache-root symlink remains supported. The committed
  `memory://` fixture is pinned by its SHA-256 and `LocalFixture` identity for
  Regression; its semantic revision label is not treated as an upstream
  immutable object ID. Moving upstream revisions remain ineligible.
- Reports list the resolved source identity, checksum, adapter version, and
  derivation hash.
- Case IDs are `{id}/{family}/{language}/0000`.

## Smoke path

The synthetic `smoke-fixture` remains a local `ByteSource` check, not a public
fetch. For the pinned public FutureHouse ether0-benchmark test Parquet subset:

```sh
mise exec -- just issue-229-product "$HOME/tmp/ether0-r1" accept-cc-by-4.0 online 3
mise exec -- just issue-229-product "$HOME/tmp/ether0-r1" accept-cc-by-4.0 offline 3
```

Read `$HOME/tmp/ether0-r1/ether0-report.json` after either command. Omit the
explicit CC BY 4.0 acceptance and the command fails before network or cache
access, including on warm cache. Use a private, safe cache root; the report is
atomically replaced there. The URL is pinned to FutureHouse ©2025
`ether0-benchmark` revision `c7d5e59960087f360bc32a5006bb994324b38c35`,
SHA-256 `c53213a37ef319aa7f733751b93748db960cce33355c1d44124108e7f15c5bbc`.
Original dataset license: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Our bounded first-physical-row adapter and control-character normalization
modify the source presentation. The report contains an existing deterministic
trajectory-fixture evaluation acknowledgement for each case, **not** a model
answer, answer-quality score, or the full #230 benchmark metrics harness.
