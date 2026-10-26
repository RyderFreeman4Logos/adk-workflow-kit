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
- `PreparedDataset::case_ids()` yields a singleton placeholder shaped
  `{id}/{family}/{language}/0000`. The Parquet adapter/report preserve upstream
  row IDs as `cases[].case_id`; family/language are `dataset.family` and
  `dataset.language`, not part of each product case ID.

## Smoke path

The synthetic `smoke-fixture` remains a local `ByteSource` check, not a public
fetch. For the pinned public FutureHouse ether0-benchmark test Parquet subset:

```sh
mise exec -- just issue-229-product "$HOME/tmp/ether0-r1" accept-cc-by-4.0 online 3
mise exec -- just issue-229-product "$HOME/tmp/ether0-r1" accept-cc-by-4.0 offline 3
```

Read `$HOME/tmp/ether0-r1/ether0-report.json` after either command. Omit the
explicit CC BY 4.0 acceptance and the command fails before network or cache
access, including on warm cache. The CLI accepts only direct children of
`~/tmp`, including existing cache-root directory links admitted by the shared
owner/mode/link-chain validator. Dangling or unsafe links fail without being
replaced. Use a private, safe cache root; the report is atomically replaced
there. `mise exec -- just issue-229-cli-links` opts into a public pinned-fixture
check of the shipping binary's offline linked-cache path. The URL is pinned to FutureHouse ©2025
`ether0-benchmark` revision `c7d5e59960087f360bc32a5006bb994324b38c35`,
SHA-256 `c53213a37ef319aa7f733751b93748db960cce33355c1d44124108e7f15c5bbc`.
Original dataset license: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Our bounded first-physical-row adapter and control-character normalization
modify the source presentation. The report contains an existing deterministic
trajectory-fixture evaluation acknowledgement for each case, **not** a model
answer, answer-quality score, or the full #230 benchmark metrics harness.

## Sentinel four-source native goldens (#236 first unit)

`prepare_sentinel_goldens(manifest, cache, source_dir, license_accepted)` is the
reusable offline runtime boundary. It requires the fifteen fixed `sentinel-*`
entries in this registry: ten native source/data artifacts and five complete
license/NOTICE artifacts. Explicit acceptance and exact manifest agreement precede
path access. `Some(source_dir)` imports the documented fixed local filenames;
`None` requires cache-only reuse. Configured directory links use the existing
owner/mode/ancestry validator and retain their storage layout.

The byte provenance is **Manual**, with content-digest identity. The pinned
upstream URLs/revisions remain declared lineage; a local import does not mint
Upstream provenance. Each canonical source/notice component contains the real
`DatasetReport` source identity, checksum, adapter version and derivation hash.
`SentinelDatasetCase::canonical_json` sorts object keys, preserves array order,
and excludes local paths, wall clocks and cache-hit flags. `canonical_sha256`
hashes those complete bytes. The committed derived goldens preserve their prior
plan hashes; adding actual report bindings intentionally changes the canonical
hash. The adjacent ether0 `DatasetCase` and product acknowledgment stay unchanged.

The fixed selections are AgentDojo v1 banking UserTask0 + InjectionTask0 +
injection_bill_text + DirectAttack; InjecAgent dh attacker/user/base row 0;
BIPIA test Language Translation[0] with a project-authored synthetic email;
and NotInject_one row 0, unchanged. The first three labels are attack **attempts**,
with no success measurement. NotInject has no native row label: its benign
hard-negative authority is publisher documentation tied to the exact source
identity. Source categories such as Multilingual do not establish zh/ja coverage.

AgentDojo uses eight exact pinned source slices: four assignment literals, the
DirectAttack name/template, YAML insertion-vector key/description, and the
read_file/file_path ground-truth context. The derived fixture records UTF-8 byte
offsets, physical lines, raw file and slice hashes, and whitespace rules. The four
assignment slices exclude exactly four leading spaces and final LF; the added
physical-line slices preserve indentation, trailing spaces and final LF. Literal
projection resolves one named IBAN constant and one goal placeholder, then retains
the bill utility line. No Python/YAML code, upstream utility/security function,
real banking tool or benchmark agent executes.

BIPIA reads both attack maps to keep all ten Language Translation entries in one
family across upstream train/test, before any derived split assignment. The
bounded license decision uses the publisher's default MIT scope with its named
third-party exceptions for **attack maps plus synthetic carrier only**; this is
an interpretation, not an upstream per-file license declaration. Preserve the
Microsoft copyright and complete pinned LICENSE/NOTICE. No third-party context
rows enter this unit. AgentDojo, InjecAgent and PIGuard retain their complete
pinned MIT copyright/license texts as separate admitted cache artifacts. Their
exact immutable URLs and digests are registry entries; those full notices must
accompany redistributed derivatives.
The checked-in derived fixture ships the [complete pinned notices and scope
statement](../../crates/workflow-runtime/tests/fixtures/issue_236/README.md).
Its bundle test checks the five full notice files against those same registry
digests; upstream copyright/permission text is not replaced with URL metadata.

`validate_sentinel_splits` checks fixed source-parent and canonical-family identity
before comparing split assignments. Upstream split prefixes cannot disguise a
shared family. A transformed/language-changed descendant cannot retain original
source review authority. SourceDocumentedOriginal is not human translation review;
the adapter does not create translations, a final/adaptive holdout, or a runtime
Sentinel verdict.

Focused controls and explicit real-source acceptance run locally:

```sh
mise exec -- just issue-236-runtime
mise exec -- just issue-236-offline "$HOME/tmp/adk-takeover-20261012/236-primary-source-r1" "$HOME/tmp/issue-236-r1"
```

The ignored acceptance test imports the fifteen pre-acquired files into a fresh
owned cache child, verifies the four actual canonical goldens, then performs two
cache-only reruns and negative checksum/notice/license controls. It records a
local acceptance artifact and passes the text through the existing untrusted
input envelope without assigning model verdicts. Normal workspace tests do not
replace this explicit ignored-test invocation. No download or live model runs.
The acceptance cache container is validated before any existing directory or
configured link is used, preserving its mode and link identity. A missing leaf
is created exclusively with mode 0700. Just passes each whole path parameter as
shell-quoted data; literal dollar signs, quotes, backticks and command-substitution
text are covered at the actual command argv/environment boundary.

The native/parser and post-admission cache readers cap each artifact at 1 MiB.
For Sentinel, shared manual acquisition and warm-cache verification read at most
1 MiB plus one lookahead byte, rejecting oversize before checksum validation or
publication even if an operator file grows after metadata inspection. Identity
verification reads at most its expected encoding length plus one byte. Ordinary
`prepare_dataset` callers retain their existing artifact-size policy.
Publisher documentation body
snapshots missing from the prepared bundle are not invented: the goldens retain
the verified source-preparation receipt and exact authority URLs.

This milestone leaves #236 open: complete four-source coverage, grouped en/zh/ja
and other transformations, stratified human translation review, cross-source and
adaptive-holdout isolation, and live semantic acceptance remain separate work.
An agent is not a human reviewer, and the evaluated model cannot be the sole
labeler of its final holdout.
