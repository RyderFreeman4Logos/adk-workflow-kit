# VB-001 Verbatim Domain Boundary

Revalidated: 2026-08-17T12:30:38Z

This report fixes the normative ownership, adapter, and validator boundary for
Verbatim integration. It adds no runtime behavior, adapter implementation,
public API, dependency, test, or source characterization.

## Scope and evidence status

| Evidence class | Status | Consequence |
|---|---|---|
| Normative contract | Issue #34 and debate session `01M07TJES90KC2C77D7AJNXC0N` approve the boundary below. | The ownership, adapter, and validator requirements are binding design constraints for later work. |
| Verified current fact | The one permitted GitHub commit API request returned the approved immutable commit at the revalidation time above. | This report may identify that commit, but it does not infer its source layout or implementation. |
| Unknown and deferred | No Verbatim checkout or source file was read, and no Verbatim runtime was executed. | Concrete files, modules, Rust symbols, signatures, registrations, validator topology, and implementation status remain unknown. |

Planning targets are not implementation evidence. This report lists no
planning-pack path and makes no claim that a prospective path or contract
exists in the verified commit.

## Verified Verbatim commit and revalidation provenance

- Canonical repository: `RyderFreeman4Logos/verbatim`.
- Revalidation command: `env -u GH_CONFIG_DIR gh api repos/RyderFreeman4Logos/verbatim/commits/main`.
- Returned commit: [`defa830d5111f6fa3bb036e5108366f887f0ddc1`](https://github.com/RyderFreeman4Logos/verbatim/commit/defa830d5111f6fa3bb036e5108366f887f0ddc1).
- Revalidated at: `2026-08-17T12:30:38Z` UTC.

The response identified the exact canonical repository and a lowercase
40-character SHA equal to the approved pin. A later mutable-branch change does
not retarget this report; changing the pin requires a newly ratified baseline.
This report contains no Verbatim source link.

## Domain ownership

The following inventory is normative. It assigns domain authority; it does not
claim that a particular Rust type currently implements the responsibility.

| Domain concept | Required owner | Boundary requirement |
|---|---|---|
| Source | Verbatim | Verbatim defines source identity, content references, metadata, provenance, and lifecycle semantics. |
| Chunk | Verbatim | Verbatim defines chunk identity, content, metadata, ordering, and source association. |
| Evidence | Verbatim | Verbatim defines support records, quotations, provenance, authorization attributes, and citation associations. |
| Context | Verbatim | Verbatim defines the evidence context presented to domain validators and the rules for its valid composition. |
| ACL | Verbatim | Verbatim defines principals, scopes, policies, and authorization decisions for domain evidence. |
| Public SDK types | Verbatim | Verbatim owns the public domain inputs, outputs, validation results, and terminal outcome types. |

The platform may carry opaque Verbatim values, handles, and transport
envelopes. It must not duplicate these domain types, reinterpret their fields,
or become the authority for their semantics.

## Adapter boundary

The platform invokes registered Verbatim nodes and validators only through
stable adapters. Every application crossing is validated in both directions;
there is no unchecked side channel around the adapter.

| Crossing | Required contract |
|---|---|
| Platform to adapter | Validate the registration identity, request envelope, caller context, and applicable execution limits before dispatch. |
| Adapter to Verbatim | Construct or accept only validated Verbatim-owned SDK inputs, then delegate domain decisions to the registered Verbatim node or validator. |
| Verbatim to adapter | Validate the returned SDK outcome and reject malformed, unauthorized, or contract-inconsistent results before application use. |
| Adapter to platform | Expose only domain-neutral workflow status and validated opaque Verbatim results or references; do not re-adjudicate domain semantics. |
| ADK to platform | Confine every ADK import and translation to `workflow-adk`; the remaining platform core receives only domain-neutral contracts. |

The platform owns orchestration, registration, scheduling, cancellation, and
transport concerns. Verbatim owns domain validity. An adapter failure or an
invalid crossing fails closed and cannot produce a publishable result. The
platform core remains domain-neutral.

## Validator inventory

### Grounded answer

These are required validation responsibilities, not verified current symbol
names or implementation claims.

| Responsibility | Normative decision |
|---|---|
| Claim support | Every publishable claim must be supported by its bound, authorized evidence. Unsupported claims prevent publication. |
| Quotation correctness | Every quotation must match the authorized evidence span it represents; altered or unverifiable quotations are rejected. |
| Evidence authorization | The caller context and ACL decision must authorize every item of evidence used by the answer. |
| Citation bindings | Claims, citations, quotations, and evidence identities must form complete, unambiguous bindings. |
| Publication eligibility | Publication is eligible only after all required support, quotation, authorization, binding, and coverage checks pass. |
| Deterministic citation rendering | The same validated citation bindings and rendering policy must produce the same citation output. |
| Terminal outcome | The result must map to `Published`-, `Abstained`-, or `Disabled`-equivalent semantics without treating abstention or disabled validation as publication. |

`Published`-equivalent means all required publication checks passed.
`Abstained`-equivalent means support, authorization, bindings, or completeness
could not be established. `Disabled`-equivalent means the capability was
explicitly unavailable or disabled and must not become an implicit bypass.
These names describe required semantics only; they are not asserted Rust enum
variants.

### Multi-hop

| Responsibility | Normative decision |
|---|---|
| Coverage predicate | A deterministic predicate decides whether all required hop and evidence obligations are satisfied. |
| Bounded correction | Correction attempts are limited by an explicit deterministic bound; exhausting it produces an incomplete result. |
| Attributed merge | Merged contributions preserve their evidence, citation, and authorization attribution; ambiguous or unattributed contributions are rejected. |
| Complete/incomplete mapping | Coverage success maps to complete and coverage failure or exhausted correction maps to incomplete; incomplete output cannot be represented as complete. |
| Deterministic budget and coverage | Identical validated inputs and policy produce the same budget and coverage decisions; model discretion cannot silently extend a bound. |

## Normative boundary versus verified current implementation

This document is normative for ownership and application boundaries. The
domain inventory, crossing checks, validator responsibilities, and terminal
semantics state what later integrations must preserve.

The only verified current Verbatim fact in scope is the immutable commit
identity and its UTC revalidation provenance. Rust modules, traits, structs,
enums, functions, node registration APIs, validator implementations, and file
paths are unknown and deferred until a separately authorized characterization
can cite immutable source evidence at the approved commit. No planning target
may substitute for that evidence.

## Deferred and excluded

- Verbatim source-symbol characterization and immutable source-line evidence.
- Concrete adapter implementation and application-boundary leakage tests.
- Grounded-answer topology, terminal parity, and deterministic validator implementation.
- Multi-hop fan-out, concrete coverage predicates, budgets, correction flow, and attributed merge implementation.
- Production sandbox or working-directory integration.
- Public API freeze, pending the separately planned dogfood workflows.
- Rust, fixtures, Cargo or lockfile changes, scripts, planning-pack changes, and new dependencies.
- ADK imports anywhere outside `workflow-adk`.
- Verbatim repository edits, tests, branches, commits, pull requests, or local-checkout evidence.
- Live Verbatim or ADK execution and any additional network access.
