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
There is deliberately no Boolean safety API. `segment_language` supplies bounded
lexical spans and Unicode script evidence, not language attribution. Its typed
`LanguageScreening::Unattributed` result must stop supported-language routing.
`NoNaturalLanguage` is only a lexical result, never safety `Clean`. A validated
language-policy stage is still required before #232 consumes the view.

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

## Conservative segmentation (partial language prerequisite)

`CanonicalUntrustedText::segment_language(SegmentationLimits)` returns an immutable
borrowed `SegmentedUntrustedText`; it never discards bytes from the envelope.
Every nonempty normalized span has a covering original `SourceSpan`. Covers may
include removed controls between retained scalars; use the canonical scalar map
for exact per-scalar evidence. The ranges partition the entire normalized view.

Recognized exclusions are explicit backtick/tilde code delimiters; HTTP(S), FTP
and `www.` URL runs; underscore-bearing identifiers; Unicode emoji runs including
joiners/marks; explicit `$`, `$$`, `\(`, `\[` math delimiters and Unicode math
symbols; numeric, lowercase Boolean and null literals. Quoted prose is not
silently treated as a data literal. Bare code, camelCase/dotted identifiers,
HTML, nested/escaped delimiters and arbitrary structured data are **not parsed**;
possible prose in them remains unattributed. Unclosed recognized delimiters fail
atomically. Delimited payloads are still untrusted and still reach safety analysis.

Each possible-prose token records Latin, Han, kana and other-script evidence.
Script_Extensions and character categories come from the already-locked
`regex-syntax = 0.8.11` Unicode 16.0.0 generated tables (MIT/Apache-2.0 package;
Unicode data license included). This direct dependency adds no new locked package.
See [the upstream Unicode support contract](https://docs.rs/regex-syntax/0.8.11/regex_syntax/)
and [Unicode Script Extensions](https://www.unicode.org/reports/tr24/).
The fixed property parser runs once; range membership uses binary search. No
user-supplied regular expression or hand-written partial script table is used.
Bump `SENTINEL_SCRIPT_DATA_VERSION` with any data dependency change.

Defaults are 16,384 normalized bytes and 4,096 segments; hard ceilings are 65,536
bytes and 16,384 segments. Unknown policy fields and above-ceiling values fail.
Zero denies a nonempty corresponding resource. Each token is consumed once,
including malformed numeric runs; source mapping is one forward scalar walk.
Fixed property lookups and a bounded number of scans per token give linear work
in admitted text size with fixed Unicode tables. No wall-time guarantee is made.
Limit or delimiter errors return no partial segment list. Empty normalized views
can have zero spans (original bytes/annotations remain in the preparation).

**Language attribution blocker:** Latin is not English, and Han is shared by
Chinese and Japanese. Simplified and Traditional Chinese both retain Han evidence;
Han+kana retains both, including supplementary-plane characters. Mixed scripts
are not flattened into a dominant-language guess. All material possible prose,
including English and Chinese examples, currently returns `Unattributed` rather
than claiming en/zh/ja support. There is no configurable supported-language
allowlist until attribution can be validated. `whatlang 0.18.0` was evaluated but
not added: its `detect_lang_base_on_mandarin_script` assigns Han-only input Cmn
with confidence 1.0, which cannot resolve the required ambiguity. A future
classifier needs pinned model/version identity, reliable abstention and measured
multilingual hard-negative coverage before enabling supported-language routing.

## Bounded carrier analysis (recognized syntax only)

`CanonicalUntrustedText::analyze_carriers(mode, limits)` is an explicit optional
stage, not part of normalization or language attribution. `AnnotateOnly` records
root candidates without decoding; `Decode` also produces separate immutable
UTF-8 analysis views and recursively searches those views. Neither mode changes
the retained artifact, canonical text, envelope, author provenance or untrusted
analysis domain. A candidate is not proof of Injection; no candidates is not Clean.
Decoded text must stay in an untrusted data role, just like the original envelope.

The v2 subset recognizes literal `<!--...-->`, `[//]: # (...)`, standalone runs
of `%HH`, `\xHH` and `\uHHHH`, and explicitly labeled `base64:` / `hex:` tokens.
The comment patterns are candidates, not claims about actual rendered visibility.
Backtick/tilde-delimited literals and HTTP(S)/FTP/www URL runs are not decoded.
Unclosed literal delimiters consume the remaining literal region. Bare Base64,
hex digests, numeric literals, ordinary percent signs and normal backslash escapes
are not guessed to be encoded instructions. This is **not an HTML, Markdown,
JSON, CSS, or programming-language parser**. Hidden elements/attributes/styles,
entities, arbitrary reference-comment forms, unlabeled encodings, mixed literal
and escaped strings, URL encodings inside URLs, and surrogate-pair escapes remain
unsupported. All original text still reaches the complete canonical envelope.

Base64 uses the already-locked `base64 = 0.22.1` strict standard alphabet and
canonical padding; URL-safe and unpadded variants are not silently accepted.
Invalid encoding, malformed comment delimiters, or non-UTF-8 output retain an
`InvalidEncoding` candidate with original evidence and no decoded view. Invalid
encoding does not manufacture replacement characters or a security verdict.
Each decoded scalar has an original-artifact covering `SourceSpan`; byte escapes
compose exact spans, and Base64 conservatively covers its entire source quantum.
Nested spans compose these covers, including any removed controls between them.
Candidates form a deterministic preorder list with parent indices and root depth
one. Decoded `Debug` output is content-free.

Default limits are 65,536 input bytes, 256 candidates, depth 3, 65,536 aggregate
expanded bytes and 1,048,576 work units. Hard ceilings are respectively 65,536,
4,096, 8, 262,144 and 16,777,216. Caller policy rejects unknown fields and excessive
values. Work units charge bytes admitted to each scan, decoder and output-mapping
pass; fixed recognition checks, bounded binary searches for source spans and
UTF-8 validation add constant-factor work under these hard ceilings. This is not
a wall-clock guarantee. Expanded bytes include intermediate and attempted invalid
output, not just final leaves. Allocation checks precede each decoded chunk.
Limits are aggregate across siblings and nested transformations. Exceeding any
limit, including discovery of a candidate beyond the depth ceiling, returns an
atomic `ResourceLimit` error with no partial analysis. Annotation-only never
claims nested coverage. Decoded controls are retained verbatim, not recursively
normalized or assigned language/safety labels.

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
Segmentation and pinned script-data versions also participate in this consumed
cache path. For segmented results use `SegmentedUntrustedText::bind_cache_key`,
which additionally binds both segmentation limits and the unattributed stage.
Prepared-only keys cannot hit segmented results, and changing either limit
misses the durable cache in the integration fixture.
Carrier recognition/decoder identity (`sentinel-carriers-v2`) also participates
in preparation keys and telemetry. Cache optional carrier results only with
`CarrierAnalysis::bind_cache_key`: it binds the analysis stage, annotation/decode
mode, all five limits and the decoder version while preserving outer request,
policy and original provenance identities. The durable-cache fixture independently
reconstructs that versioned policy hash and proves version, mode, raw-byte, trust
and limit changes miss. `CarrierAnalysis::telemetry` adds content-free stage,
mode, candidate count and aggregate resource usage; it never echoes decoded text.

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
| en/zh/ja versus material unsupported spans | Blocked on validated attribution; `Unattributed` explicitly stops supported-language routing; no language allowlist claimed |
| Code/URL/identifier/emoji/math/data segmentation | Bounded recognized-syntax subset, mapped spans; `segmentation::*` focused fixtures; exclusions are lexical, not safety approval |
| Hidden HTML/Markdown, escaping, Base64, hex, nested decoding | Bounded explicit candidate subset, optional decoded views and composed maps; `carriers::*`; arbitrary hidden markup remains pending |
| Unicode mapping/resource property corpus | `deterministic_unicode_property_corpus_has_total_source_coverage` (512 deterministic cases), joiner/variation-selector fixture |
| Multilingual/hard-negative/nested-encoding fuzz fixtures | Carrier subset: 256 seeded nested UTF-8 mapping cases, 512 seeded malformed-input cases, quantum golden maps and code/URL/data negatives; complete language/markup coverage remains pending |
| Spec/IR/compiler runtime routing | Pending design of the language-policy binding; existing artifact runtime integrated |
| Live semantic coverage | Not run; no authorized binding and no semantic model branch implemented |

Do not close #231 from this ledger. #232 remains responsible for model branches;
preparation alone cannot supply their final security judgment.
