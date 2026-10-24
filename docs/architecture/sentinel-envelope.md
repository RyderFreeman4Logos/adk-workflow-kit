# Sentinel canonical untrusted-data preparation

This document defines the **bounded #231 preparation contract**, not a completed Sentinel or general
language detector. `workflow_runtime::prepare_untrusted_text` is the explicit artifact IO
boundary; emitted text/maps are deterministic and normalization performs no IO. Callers
inject the existing `ArtifactStore`. No model, provider, executor, or ADK agent is
constructed by this data transformation.

Callers record one `Instant` before ingress and pass it to `prepare_untrusted_text`.
Its fixed 1,000 ms cooperative budget follows the canonical value through scanning,
decoding, source mapping, segmentation and attribution. It is never reset between
stages. Expiry yields typed `DeadlineExceeded`, never a partial successful view.
Future start times are invalid policy. Checks cannot interrupt blocking IO or
provide an OS scheduling bound; semantic model execution has its separate budget.

## Contract

`SentinelPreparation::Prepared(CanonicalUntrustedText)` means only that the
bounded analysis view was produced. It is **not `SentinelVerdict::Clean`** and
must not authorize a tool, action, or reducer decision. `Invalid` contains a
stable subcode and maps to the shared `SentinelVerdict::InvalidInput` (`inv`).
There is deliberately no Boolean safety API. `segment_language` supplies bounded
lexical spans and Unicode script evidence, not language attribution. Its typed
`LanguageScreening::Unattributed` result must stop supported-language routing.
`NoNaturalLanguage` is only a lexical result, never safety `Clean`. The optional
`assess_language(LanguagePolicy)` stage supplies a conservative attribution subset;
#232 must still perform semantic security analysis of the complete view.

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
artifact IO add a bounded number of linear passes; blocking store latency can only
be checked after return. There is no hard wall-clock guarantee. Exhaustion returns no partial
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
they retain possible-prose tokens. Attribution does not prove that those tokens
were prose rather than code or data. Unclosed recognized delimiters fail atomically. Delimited payloads are still untrusted and still reach safety analysis.

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

## Language attribution and material-region policy

`SegmentedUntrustedText::assess_language(LanguagePolicy)` assesses the actual
mapped possible-prose tokens. `LanguageAssessment::evidence()` returns those
`TextSegment` references. `CarrierAnalysis::assess_language(policy, limits)` also
assesses every decoded view, using its composed original map and the original
preparation deadline; it does not normalize again or fabricate a new artifact.
Language attribution, lexical screening and a Sentinel safety verdict remain
separate. Excluded syntax is retained in the envelope and safety probes.

Whitespace within a line, commas and apostrophes can join prose tokens into one
material region. Newlines (including Unicode line/paragraph separators), sentence
endings, excluded syntax and other gaps end
a region. No sentence is invented across code, URLs, math or identifiers. Mixed
incompatible scripts in one region remain unresolved; independent sentences and
lines are assessed separately, including the second line of an input. Han and
kana can coexist in a Japanese region. There is no whole-document majority vote.
Bare `base64:` and `hex:` data use the same exact labeled carrier grammar as the
decoder, without excluding ordinary words such as `base64word` or `hexagon`.

The existing complete English grammar remains a narrow deterministic fast path:
`(this|that) (is|was) (a|the) NOUN`, `please VERB (the|this|that) NOUN`, or
`(we|they|you) (will|must|should|can) VERB (the|this|that) NOUN`, case-insensitive.
NOUN is `message|request|document|instruction|instructions|test`; VERB is
`read|check|review|follow|ignore`. The Japanese fast path still requires at least
four base letters, including two actual Hiragana/Katakana `Lo` letters, and only
Han/kana letters or marks. Extenders do not supply kana evidence. Neither fast
path is presented as broad language support.

General Latin and Han material uses the pinned reference `fasttext = 0.7.8`
engine and packaged `lid.176.ftz` model. All 176 labels compete before applying
the en/zh/ja allowlist. The top rank must be at least 0.8 and exceed the next rank
by at least 0.2; these are engineering cutoffs, not calibrated accuracy claims.
Latin regions need twelve base letters and two words of at least three base
letters. Han-only regions need six base letters, irrespective of spaces. The
model can attribute Simplified and Traditional Chinese to `Zh`, but shared-Han
names remain semantically ambiguous even if the model emits a high-ranked label.
Such names receive no accuracy credit in the qualification corpus. Short Han,
mark/extender-only runs, and opaque/private/unassigned evidence remain unresolved.
The existing single-script Cyrillic/Arabic/Hangul rule rejects material with
twelve base letters and two words of at least three base letters. Shorter material
with that same two-word evidence can use the same statistical model to corroborate
rejection. Only a foreign prediction meeting the fixed rank cutoffs rejects;
a supported label contradicting the validated nonshared script remains unresolved.
This route cannot grant supported-language admission, and errors propagate.

The model is 938,013 bytes, SHA-256
`8f3472cfe8738a7b6099e8e999c3cbfae0dcd15696aac7d7738a8039db603e83`.
Its [source and separate CC BY-SA 3.0 license](../../crates/workflow-runtime/assets/README.md)
are packaged with the bytes. Loading verifies the digest and uses the existing
sealed-memory-file primitive; an immutable `OnceLock` shares the reference engine.
Installed code needs no source checkout, model path, network or fallback model.
An unavailable or mismatched asset fails atomically as `language_model_unavailable`.
Prediction checks the shared cooperative deadline before and after native work;
this does not bound OS scheduling or supersede semantic model timeouts.

`LanguagePolicy { en, zh, ja }` defaults to all enabled; all three Boolean fields
are required, and an empty allowlist is valid. A positively identified disabled
language or material foreign language becomes `UnsupportedLanguage`. Changing
policy never resolves unknown evidence. Aggregation gives unsupported material
priority, then unresolved material, then the one positive label or `MixedSupported`.
Any raw or decoded unsupported/unresolved region stops every semantic dispatch.
Absent prose is neutral for attribution and still requires complete safety analysis.
`LanguageAssessment::rejection_verdict()` returns `uns` only for unsupported
language; `None` is never Clean. An English injection instruction is still untrusted.

The frozen engineering corpus covers ordinary en/zh-Hans/zh-Hant/ja, short Japanese,
unsupported languages, short/ambiguous evidence, all eight masks and raw/decoded
transport. Its correlated masks/transports are not independent accuracy samples;
held-out multilingual calibration and the #230 live quality/cost gates remain
separate acceptance requirements. Unicode, byte, segment, carrier expansion and
work ceilings remain unchanged; deadline/limit failure returns no partial result.

## Bounded carrier analysis (recognized syntax only)

`CanonicalUntrustedText::analyze_carriers(mode, limits)` is an explicit optional
stage, not part of normalization or language attribution. `AnnotateOnly` records
root candidates without decoding; `Decode` also produces separate immutable
UTF-8 analysis views and recursively searches those views. Neither mode changes
the retained artifact, canonical text, envelope, author provenance or untrusted
analysis domain. A candidate is not proof of Injection; no candidates is not Clean.
Decoded text must stay in an untrusted data role, just like the original envelope.

The v3 subset recognizes literal `<!--...-->`, `[//]: # (...)`, `%HH`, `\xHH`,
`\uHHHH` (including paired surrogates), and labeled `base64:` / `hex:` tokens.
Literal text can surround and mix byte escapes and entities in a token. Entities
are strict Unicode decimal/hex references and `amp`, `lt`, `gt`, `quot`, `apos`,
`nbsp`; other named references are invalid encoding, never silently expanded.
HTML attribute values have separate mapped views. Element bodies marked `hidden`,
`aria-hidden=true`, or literal inline `display:none` / `visibility:hidden` have
additional views; quoted delimiters and nested same-name elements are tracked.
Unsupported opener syntax or carrier labels in tag/attribute names decline the
HTML projection and leave those bytes to the ordinary carrier scanner; lookahead
remains charged and stops at the next unquoted `<`.
The comment patterns are candidates, not claims about actual rendered visibility.
Backtick/tilde-delimited literals and HTTP(S)/FTP/www URL runs are not decoded.
Unclosed literal delimiters consume the remaining literal region. Bare Base64,
hex digests, numeric literals, ordinary percent signs and normal backslash escapes
are not guessed to be encoded instructions. This is **not an HTML, Markdown,
JSON, CSS, or programming-language parser**. CSS cascade/computed visibility,
arbitrary reference comments, unlabeled encodings and URL encodings inside URLs
remain unsupported. All original text still reaches the complete canonical envelope.

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
values. Work units charge bytes admitted to each scan, HTML lookahead, decoder and output-mapping
pass; fixed recognition checks, bounded binary searches for source spans and
UTF-8 validation add constant-factor work under these hard ceilings. This is not
a wall-clock guarantee. Expanded bytes include intermediate and attempted invalid
output, not just final leaves. Allocation checks precede each decoded chunk.
Limits are aggregate across siblings and nested transformations. Exceeding any
limit, including discovery of a candidate beyond the depth ceiling, returns an
atomic `ResourceLimit` error with no partial analysis. Deadline expiry similarly
returns atomic `DeadlineExceeded`. Annotation-only never
claims nested coverage. Decoded controls are retained verbatim, not recursively
normalized or assigned language/safety labels.

## Cache and telemetry

`CanonicalUntrustedText::bind_cache_key` consumes existing `NodeCacheKeyMaterial`
and trusted `ContentProvenance`, returning an actual `NodeCacheKey` for
`NodeResultCache`. It binds original artifact bytes by digest even when two
inputs normalize identically; normalized bytes; all limits; normalizer, envelope,
compact-output, security-model and Rust Unicode-data versions, the fixed preparation
budget (never the process-local Instant); and provenance
including scope, author and trust-policy classification. The analysis domain
remains untrusted even for allowlisted authors. Existing outer request/policy
identities are combined, never discarded. Model/provider/prompt/tool/dataset
versions remain the caller's responsibility in `invocation_identity`.
Segmentation and pinned script-data versions also participate in this consumed
cache path. For segmented results use `SegmentedUntrustedText::bind_cache_key`,
which additionally binds both segmentation limits and the unattributed stage.
Prepared-only keys cannot hit segmented results, and changing either limit
misses the durable cache in the integration fixture.
For attributed results use `LanguageAssessment::bind_cache_key`: it wraps that
segmented key with `sentinel-language-policy-v5`, the exact model/engine identity,
a distinct attribution-stage tag,
and the canonical en/zh/ja Boolean tuple. Bump the language version on any grammar,
materiality, aggregation or allowlist semantic change. The durable-cache fixture
independently reconstructs the framing, proves all eight policy combinations have
distinct identities, and checks stage/version/limits/raw/provenance/request misses.
No prepared-only or segmented-only key may cache attribution results. Aggregate
raw/decoded attribution additionally requires the carrier stage and its limits;
the ADK preparation key consumes all these identities. A carrier-only key cannot
cache the language aggregate.
Carrier recognition/decoder identity (`sentinel-carriers-v3`) also participates
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
this is not permission to expose artifact contents. The bounded
[single-terminal preparation workflow](sentinel-workflow.md) now emits it through
the existing event producer. The [shared benchmark harness](../spec/BENCHMARK_HARNESS.md)
validates a finite preparation oracle against retained input, artifacts, checkpoints
and events, including report reconstruction. Controlled HTTP fixtures exercise this
integration; the harness independently requires an observed completed model call.

## Acceptance ledger and runnable checks

The normalization, carrier and language foundation was delivered in
[PR #372](https://github.com/RyderFreeman4Logos/adk-workflow-kit/pull/372).
Run `just issue-231-runtime` and `just issue-231-compiler` offline, without credentials.
`just issue-231-adk` and `just issue-232-semantics` exercise observed preparation with
scripted semantic bindings; `just issue-230-telemetry sentinel` covers controlled
HTTP and retained-artifact reconstruction. These checks establish the finite
contracts below, not a current full-gate or live semantic-quality result.

| #231 requirement | Evidence/status |
| --- | --- |
| Immutable original bytes and fixed envelope | `retained_bytes_and_length_framed_envelope_are_exact` |
| Typed invalid states, no lossy UTF-8 | `invalid_paths_are_typed_without_lossy_conversion` |
| Mapped zero-width/bidi/control carriers | `unicode_controls_have_golden_original_byte_mappings` (explicit list only) |
| Deterministic resource bounds | `output_and_work_exhaustion_never_return_partial_prepared_text`, `resource_and_depth_limits_fail_atomically`; `elapsed_preparation_budget_is_not_reset_before_carrier_analysis` checks the shared 1,000-ms cooperative budget, not OS preemption |
| Cache identity and structured telemetry | `cache_consumes_canonical_policy_raw_bytes_and_trust_provenance`, `telemetry_is_versioned_deterministic_and_does_not_echo_text` |
| en/zh/ja versus material unsupported spans | Actual pinned statistical en/zh-Hans/zh-Hant/ja attribution plus conservative short-text paths; `frozen_language_ingress_table_covers_every_allowlist_and_transport` executed 1,280 unique raw/decoded and eight-allowlist combinations with zero mismatches: 908 denials with no semantic requests, 364 positive semantic-dispatch combinations and eight empty-normalized pending combinations with no semantic requests. Semantic bindings are controlled; these correlated engineering fixtures do not establish held-out accuracy |
| Code/URL/identifier/emoji/math/data segmentation | Bounded recognized-syntax subset, mapped spans; `segmentation::*` focused fixtures; exclusions are lexical, not safety approval |
| Hidden HTML/Markdown, escaping, Base64, hex, nested decoding | Finite subset above, optional decoded views and composed maps; `carriers::*`, `carrier_syntax::*`; arbitrary rendered markup is unsupported |
| Unicode mapping/resource property corpus | `deterministic_unicode_property_corpus_has_total_source_coverage` (512 deterministic cases), joiner/variation-selector fixture |
| Multilingual/hard-negative/nested-encoding fuzz fixtures | Carrier subset: 256 seeded nested UTF-8 mapping cases, 512 seeded malformed-input cases, quantum golden maps and code/URL/data negatives; language cases use the finite table above. Generalization beyond these model fixtures and recognized markup grammars is unmeasured |
| Spec/IR/compiler runtime routing | Explicit v1 single-terminal preparation contract, canonical IR v11 and observed ADK execution; `just issue-231-compiler` / `just issue-231-adk`; general routing, positive continuation and cache reuse are unsupported capabilities outside this one-shot contract |
| Shared benchmark compatibility | `sentinel_language_http_contract`, `sentinel_private_measurement_rebuilds_without_inventing_agent_calls_or_totals` and `sentinel_private_reconstruction_rejects_artifact_input_and_missing_checkpoint` exercise the production executor and protected-artifact oracle; preparation quality and completed-model wiring remain separate assertions |
| Conditional semantic coverage | [#232 semantic branches](sentinel-probes.md) are exercised with scripted bindings; the real-provider failure below does not establish live semantic quality |

Earlier qualification runs failed at 19/20 and 1,272/1,280; the later finite table
does not erase those results or prove held-out calibration. The bounded real-provider
table stopped at its first, 81-byte English case: preparation passed, but semantic
reason was `invalid_or_failed`, observations were null and
`completed_model_observed` was false. The table failed; the other three language
rows were unexecuted. The provider/schema cause and physical send count remain
unknown. The completed-model invariant still fails this run independently of the
preparation predicate; no failed wiring result is reclassified as PASS.

This ledger establishes a bounded preparation milestone for
[#231](https://github.com/RyderFreeman4Logos/adk-workflow-kit/issues/231), with
[#232](https://github.com/RyderFreeman4Logos/adk-workflow-kit/issues/232) providing
the dependent semantic-judgment work. It does not replace the
[OWNER's full issue acceptance requirements](https://github.com/RyderFreeman4Logos/adk-workflow-kit/issues/231#issuecomment-5832579820):
live-model semantic efficacy/calibration, benchmark acceptance, independently
enforced process/OS sandboxing, persistent replay/checkpoint/crash-resume, and full
issue acceptance. This milestone does not establish or waive those requirements.
Public Sentinel resume refuses before modifying completed history; that protection
does not establish positive continuation.

The historical failed canonical run is retained under
[#374](https://github.com/RyderFreeman4Logos/adk-workflow-kit/issues/374).
A clean exact-tree full gate, fresh whole-range review and verified merge are
necessary delivery gates; they are not sufficient for full issue acceptance.
