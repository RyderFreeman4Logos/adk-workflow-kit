# Sentinel canonical untrusted-data preparation

Status: **partial implementation of #231**, not a completed Sentinel or language
policy. `workflow_runtime::prepare_untrusted_text` is the explicit artifact IO
boundary; the internal normalizer is deterministic and performs no IO. Callers
inject the existing `ArtifactStore`. No model, provider, executor, or ADK agent is
constructed by this data transformation.

## Contract

`SentinelPreparation::Prepared(CanonicalUntrustedText)` means only that the
bounded analysis view was produced. It is **not `SentinelVerdict::Clean`** and
must not authorize a tool, action, or reducer decision. `Invalid` contains a
stable subcode and maps to the shared `SentinelVerdict::InvalidInput` (`inv`).
There is deliberately no Boolean safety API. A future language-policy stage
must distinguish `UnsupportedLanguage` from eligible input before #232 consumes
the view. This milestone does not supply that stage.

The store retains exact original bytes before UTF-8 validation. Failed UTF-8 is
never replaced with U+FFFD. Empty input, invalid policy, and oversized input are
rejected before storage, with no artifact handle; ingress owns retention of
rejected bytes. Store failures are ordinary `ArtifactError`s, not security
verdicts. Evidence handles are checked against the raw SHA-256.

The view removes annotated U+00AD, U+034F, U+180E, U+200B, U+2060, U+FEFF;
U+061C, U+200E–200F, U+202A–202E, U+2066–2069; and Unicode controls other than
TAB, LF, CR. Joiners U+200C–200D and variation selectors U+FE00–FE0F /
U+E0100–E01EF are annotated but remain intact to preserve emoji and orthography. This is an explicit carrier list, **not complete Unicode
format-character detection**. No NFC/NFKC folding or transliteration occurs.
Each retained scalar maps its normalized half-open UTF-8 byte interval to an
existing `SourceSpan` in the original artifact. Removed scalars retain their
source spans in annotations. Input text is not included in `Debug` output.

The v1 envelope has a fixed prefix and `CONTENT_BYTES:<decimal>` header, one
blank line, then exactly that many UTF-8 bytes. It has no closing delimiter for
attacker text to terminate. Consumers must parse the byte count, not search for
sentinel text, and keep the whole envelope in an untrusted data role. Framing
prevents structural ambiguity; it does not make models obey instructions.

## Limits

`NormalizationLimits` is caller-owned policy, never extracted from input text.
Unknown JSON fields are rejected. Defaults: 65,536 input bytes, 262,144 output
bytes, 1,048,576 work units. Hard ceilings: 1,048,576 input bytes, 4,194,304
output bytes, 16,777,216 work units. Zero denies the corresponding resource.
A work unit is one byte admitted to a normalization pass. The current single
pass charges the input size before walking scalars. Validation, hashing and
artifact IO add a bounded number of linear passes; store latency is external.
There is no claim of a wall-clock deadline. Limit exhaustion returns no partial
prepared view. Maps/annotations have at most one entry per input scalar.

## Cache and telemetry

`CanonicalUntrustedText::bind_cache_key` consumes existing `NodeCacheKeyMaterial`
and trusted `ContentProvenance`, returning an actual `NodeCacheKey` for
`NodeResultCache`. It binds original artifact bytes by digest even when two
inputs normalize identically; normalized bytes; all limits; normalizer, envelope,
compact-output, security-model and Rust Unicode-data versions; and provenance
including scope, author and trust-policy classification. The analysis domain
remains untrusted even for allowlisted authors. Existing outer request/policy
identities are combined, never discarded. Model/provider/prompt/tool/dataset
versions remain the caller's responsibility in `invocation_identity`.

`telemetry()` returns deterministic v1 JSON with state `prepared`, content
hashes/handles, resource counts and policy identity. It contains no input text,
timestamps, or random values. Treat hashes as correlation-sensitive metadata;
this is not permission to expose artifact contents. It is ready for a benchmark
consumer but is not yet wired into a workflow event producer.

## Acceptance ledger and runnable checks

Run `just issue-231-runtime` (offline, no credentials).

| #231 requirement | Evidence/status |
| --- | --- |
| Immutable original bytes and fixed envelope | `retained_bytes_and_length_framed_envelope_are_exact` |
| Typed invalid states, no lossy UTF-8 | `invalid_paths_are_typed_without_lossy_conversion` |
| Mapped zero-width/bidi/control carriers | `unicode_controls_have_golden_original_byte_mappings` (explicit list only) |
| Deterministic resource bounds | `output_and_work_exhaustion_never_return_partial_prepared_text` |
| Cache identity and structured telemetry | `cache_consumes_canonical_policy_raw_bytes_and_trust_provenance`, `telemetry_is_versioned_deterministic_and_does_not_echo_text` |
| en/zh/ja versus material unsupported spans | Pending; script presence is not language identification |
| Code/URL/identifier/emoji/math/data segmentation | Pending; no unsupported-language claims made |
| Hidden HTML/Markdown, escaping, Base64, hex, nested decoding | Pending |
| Unicode mapping/resource property corpus | `deterministic_unicode_property_corpus_has_total_source_coverage` (512 deterministic cases), joiner/variation-selector fixture |
| Multilingual/hard-negative/nested-encoding fuzz fixtures | Pending |
| Spec/IR/compiler runtime routing | Pending design of the language-policy binding; existing artifact runtime integrated |
| Live semantic coverage | Not run; no authorized binding and no semantic model branch implemented |

Do not close #231 from this ledger. #232 remains responsible for model branches;
preparation alone cannot supply their final security judgment.
