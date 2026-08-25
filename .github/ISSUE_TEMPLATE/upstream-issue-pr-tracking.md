---
name: Upstream issue and PR tracking
about: Track one relevant upstream ADK-Rust issue or pull request
title: "GOV-006: Track upstream ADK-Rust issue or PR"
labels: ""
assignees: ""
---

# Upstream issue or PR tracking

Use this template for one relevant upstream ADK-Rust issue or pull request. Filing and review are manual. The body is authoritative; labels are routing metadata only.

## Upstream item

- Repository:
- Item type: `issue` or `pull request`
- Number:
- Title:
- URL:
- Immutable commit or diff reference, when available:
- Current upstream state:
- Last reviewed (UTC, `YYYY-MM-DD`):

## Fork context

- Affected fork version, branch, or behavior:
- Owner:
- Next review date (UTC, `YYYY-MM-DD`):
- Evidence links:

## Review checklist

- [ ] The item is relevant to this fork's supported behavior, dependency surface, or planned adoption.
- [ ] The item is not an upstream-owned example, fork, mirror, generated artifact, duplicate, or unrelated discussion.
- [ ] The upstream state and last-reviewed date are recorded.
- [ ] Compatibility impact and the explicit next action are recorded.

## Labels

Apply the existing `upstream` and `governance` labels when available. Apply exactly one type label: `upstream-issue` or `upstream-pr`. Do not create labels automatically, rename labels, or rely on labels for correctness. If a required label is unavailable, record that fact here and keep the classification in this title and body.

- Labels applied or unavailable:

## Compatibility removal

Compatibility code or documentation MUST NOT be removed while this item is only proposed, open, unreleased, or unverified. Removal is allowed only after the fork verifies the exact supported version, commit, or release that provides the replacement and confirms supported callers no longer need the compatibility path.

- [ ] The upstream item is available in the fork's supported baseline.
- [ ] The exact version, commit, or release providing the replacement is recorded.
- [ ] Supported callers no longer need the compatibility path.
- [ ] A separate removal commit or pull request is identified.
- Compatibility removal reference:
- If removal is not allowed, reason:

## Disposition

Choose one and explain it: `watch`, `adopt`, `defer`, `reject`, or `superseded`.

- Disposition:
- Rationale:
- Next action:

## Completion

- [ ] The disposition and rationale are complete.
- [ ] The owner has recorded the next action and next review date.
- [ ] Closing this issue does not imply compatibility removal unless the removal evidence above is complete.
