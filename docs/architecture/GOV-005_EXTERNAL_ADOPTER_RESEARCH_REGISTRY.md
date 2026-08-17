# GOV-005 External Adopter Research Registry

## Scope

This document defines a human-maintained governance schema for researching external ADK-Rust adopters. It is not a Rust API, compiler registry, or runtime registry. Maintainers record the research in issues created from the [external adopter distillation template](../../.github/ISSUE_TEMPLATE/external-adopter-distillation.md); no crawler, parser, monitor, or issue automation is implied.

Each record represents one candidate architectural or operational pattern from one immutable adopter snapshot. A record must not combine patterns or source commits. Record inspected candidates even when their disposition is `defer` or `reject` so that rejected ideas remain auditable.

## Cadence

For every newly published stable ADK-Rust release, a maintainer MUST manually open one external-adopter distillation issue from this template. File it after publication and before any dependency-upgrade or pattern-adoption decision for that release. Assign an owner and target completion date when filing. If no new stable release exists, no issue is due.

## Record schema

Every candidate-pattern record MUST contain all seven fields:

| Field | Contract |
|---|---|
| `source_commit` | Permanent repository commit URL containing the full commit OID for the immutable adopter snapshot. |
| `access_date` | UTC date in `YYYY-MM-DD` form. |
| `license` | SPDX expression, or `UNKNOWN`. Unknown licensing requires a `defer` or `reject` disposition. |
| `pattern` | One concise architectural or operational pattern. |
| `evidence` | One or more non-empty immutable source permalinks plus a concise observation. |
| `confidence` | `low`, `medium`, or `high`, followed by the rationale for that level. |
| `disposition` | `adopt`, `defer`, or `reject`, followed by the rationale for that decision. |

`source_commit` and every evidence permalink must identify immutable source. For GitHub repositories, use full-OID commit and blob permalinks. Example permalink shapes only, not registry evidence: `https://github.com/OWNER/REPOSITORY/commit/0123456789abcdef0123456789abcdef01234567` and `https://github.com/OWNER/REPOSITORY/blob/0123456789abcdef0123456789abcdef01234567/path/to/file.rs#L10-L20`.

## Research and decision policy

The release issue verifies that the triggering ADK-Rust release is stable, then records the search, ranking, and inspection of candidate adopters. Inspection must cover the adopter's relevant implementation path and its license at the recorded source commit.

Set `disposition` to `adopt` only when the pattern has either two independent examples or one compelling dogfood need. Independent examples must come from separate adopter projects, not forks or mirrors of the same implementation. A dogfood rationale must name the concrete repository need in the disposition rationale. Evidence quality and licensing still apply when the threshold is met.

The completed release issue must preserve rejected patterns and identify any possible upstream work, or explicitly state that no upstream work was found. A possible upstream proposal does not change a record's evidence, confidence, licensing, or adoption threshold.

## Exclusions

GOV-005 does not add scheduled jobs, GitHub Actions, automatic issue filing, live adopter monitoring, SaaS services, parsers, manifests, gate scripts, crates, or runtime/compiler registry behavior. Existing local gates remain unchanged. Review verifies that this document and the issue template contain the same seven schema fields.
