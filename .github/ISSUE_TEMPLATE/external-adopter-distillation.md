---
name: External adopter distillation
about: Distill adopter patterns after a stable ADK-Rust release
title: "GOV-005: Distill external adopters for ADK-Rust"
labels: ""
assignees: ""
---

# External adopter distillation

For every newly published stable ADK-Rust release, a maintainer MUST manually open one external-adopter distillation issue from this template. File it after publication and before any dependency-upgrade or pattern-adoption decision for that release. Assign an owner and target completion date when filing. If no new stable release exists, no issue is due.

## Release

- Release tag:
- Release URL:
- Publication date (UTC, `YYYY-MM-DD`):
- Owner:
- Target completion date (UTC, `YYYY-MM-DD`):

## Stable-release verification

- [ ] The release is published, not a draft, and not a prerelease.
- [ ] The release tag and release URL identify the same stable release.
- [ ] The publication date is recorded in UTC.
- [ ] This issue was opened after publication and before any dependency-upgrade or pattern-adoption decision for this release.

## Adopter research checklist

### Search

- [ ] Search for external repositories that depend on or implement against this stable release.
- [ ] Exclude upstream-owned examples, forks, mirrors, generated repositories, and repositories without inspectable source.
- [ ] Keep every plausible adopter long enough to rank it; do not select only confirmatory examples.

### Rank

- [ ] Rank candidates by verified use of ADK-Rust, relevance to this kit, source inspectability, and maintenance evidence.
- [ ] Prefer candidates whose relevant implementation and license can be pinned to one immutable commit.
- [ ] Record why any high-ranked candidate could not be inspected.

### Inspect

- [ ] Pin the full source commit before drawing conclusions.
- [ ] Inspect the relevant implementation path and supporting tests or documentation.
- [ ] Verify licensing at the pinned snapshot; use `UNKNOWN` when it cannot be established.
- [ ] Create one record below for each candidate pattern from each immutable adopter snapshot, including deferred and rejected patterns.

## Candidate pattern records

<!-- Copy this entire seven-field block for each candidate pattern. Do not combine patterns or source commits. -->

### Candidate pattern record 1

- `source_commit`: <!-- Required permanent repository commit URL with the full commit OID. Example GitHub permalink shape only: https://github.com/OWNER/REPOSITORY/commit/0123456789abcdef0123456789abcdef01234567 -->
- `access_date`: <!-- Required UTC date: YYYY-MM-DD -->
- `license`: <!-- Required SPDX expression or UNKNOWN. UNKNOWN requires defer or reject. -->
- `pattern`: <!-- Required: one concise architectural or operational pattern. -->
- `evidence`:
  - Permalink(s): <!-- Required and immutable. Example GitHub permalink shape only: https://github.com/OWNER/REPOSITORY/blob/0123456789abcdef0123456789abcdef01234567/path/to/file.rs#L10-L20 -->
  - Observation: <!-- Required and concise. -->
- `confidence`: <!-- Required: low, medium, or high, followed by rationale. -->
- `disposition`: <!-- Required: adopt, defer, or reject, followed by rationale. Adopt requires two independent examples or one compelling dogfood need. -->

<!-- Repeat the block above as Candidate pattern record 2, 3, and so on. -->

## Decision check

- [ ] Every `adopt` disposition is supported by two independent examples or one compelling dogfood need.
- [ ] Independent examples come from separate adopter projects, not forks or mirrors of one implementation.
- [ ] Every `UNKNOWN` license has a `defer` or `reject` disposition.
- [ ] Confidence and disposition include rationales grounded in the recorded evidence.

## Rejected patterns and possible upstream work

- [ ] Every inspected pattern that was not adopted is preserved above with a `defer` or `reject` disposition and rationale.
- Rejected-pattern summary:
- Possible upstream work: <!-- Write none, or describe the proposal, evidence, and intended upstream repository. -->

## Completion

- [ ] All seven fields are complete in every candidate-pattern record.
- [ ] Rejected patterns and possible upstream work are explicitly recorded.
- [ ] The owner has recorded the final dependency-upgrade and pattern-adoption recommendation for this release.

Final recommendation:
