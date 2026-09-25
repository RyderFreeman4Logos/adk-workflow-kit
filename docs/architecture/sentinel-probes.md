# Sentinel source-only probes (#232 milestone)

**Incomplete; no semantic classifier or live acceptance.** The existing v1
`nodes.untrusted_text` spec, canonical IR v10, compiler admission and observed ADK
terminal now emit an additional immutable probe descriptor artifact. There is no
new authored configuration, dependency, model invocation or trusted-goal input.
The terminal remains the closed `UntrustedTextReport`; descriptors are not
`TypedOutput` decisions and cannot enter the security reducer as Clean/Injection.

Read `node_completed.payload.structured_output.preparation.probes.artifact_id`
through the existing protected artifact store. Artifact commitment verifies its
SHA-256 and emits the usual content-free observation. `version` and `bytes` accompany
the handle; no source or decoded text is copied into events, descriptors or Debug.
Handles and digests remain correlation-sensitive. Earlier invalid preparation
paths have no probe artifact. Unsupported/unattributed language is retained as the
explicit `language_gate`, never resolved by chunking or decoding.

## Descriptor schema v1

The report contains `schema_version`, `version` (`sentinel-source-probes-v1`),
`original_artifact_id`, `normalized_sha256`, `trust_domain` (`untrusted_content`),
`language_gate`, `causal_attribution` (`not_measured`), `budget`, and four ordered
`branches`. Each branch has a closed `kind`, `reason`, and `views` array:

- `ordered`: the complete normalized view, not replaced by shuffled chunks.
- `shuffled`: UTF-8-safe windows up to 256 bytes with 61–64 bytes overlap. Before
  a hard split, prefer the last newline, then whitespace, in the window's second
  half. This is line/whitespace awareness, not a markup/programming parser.
  Sort chunk ordinals by SHA-256(version || SHA-256(normalized bytes) || ordinal
  as big-endian u64), breaking ties by ordinal. Rotate an identity permutation
  once when there is more than one chunk. This is reproducible, not random security.
- `decoded`: nonempty views from the existing bounded carrier analysis. `candidate`
  identifies its deterministic preorder candidate, preserving nested reconstruction.
- `task_alignment`: no views, `trusted_goal_unavailable`. An attacker-supplied goal
  cannot become trusted. Comparison to a separately authenticated goal is pending.

Each view records half-open `start`/`end` in normalized bytes (ordered/shuffled)
or decoded bytes (decoded), `sha256`, `candidate` (null outside decoded), and the
existing original-artifact covering `source` span. Covers may include stripped
controls or whole encoding quanta; they are not exact semantic citation spans.
Reconstruct using the retained original and pinned preparation versions; a digest
is not the view text or a claim that a model consumed it.

`semantic_not_run` means only descriptors exist. `empty_view`, `no_decoded_view`,
`budget_exhausted`, and `trusted_goal_unavailable` all abstain. None proves safety;
`no_decoded_view` also covers malformed/empty candidates. The report never claims
causal security attribution, branch agreement, task alignment or semantic intent.

## Bounds and identity

The fixed typed budget is 32 views / 65,536 represented bytes per branch, with a
32,768-byte serialized report ceiling. A branch exceeding its budget discards its
entire view list with `budget_exhausted`; other branches survive. An overall report
excess discards all populated lists with that reason. Existing carrier/segmentation
ceilings apply first. These are offline construction bounds, not model-token or
wall-time guarantees. No unbounded task text or semantic prose is serialized.

Adapter identity is now `sentinel-workflow-preparation-v3`; the existing cache key
additionally binds probe version and all budget fields, retaining raw-byte,
workflow/IR, language policy and preparation identities. The envelope bytes and
prefix are unchanged. No cache reuse or provider prefix optimization is claimed.

Run `just issue-232-adk`, `just issue-231-adk`, `just issue-231-compiler`, and
`just issue-231-runtime`. Public-path fixtures use the existing fake profile but
assert that no model request occurs. They test replay, overlap, source offsets,
content-free evidence, mixed/Han ambiguity, quotation without judgment, and atomic
chunk exhaustion. The independent #231 cache oracle includes the new identities.

Remaining #232 acceptance: real ordered/shuffled/decoded semantic branches,
isolated sessions, ADK concurrency/cache-aware scheduling, typed response parsing
and malformed-output isolation, deterministic joining/agreement/disagreement,
separately trusted goal admission and calibrated task alignment, model output
budgets, provider shared-prefix measurements, live multilingual/security hard
negatives, causal experiments and shared benchmark integration. **Leave #232 OPEN.**
