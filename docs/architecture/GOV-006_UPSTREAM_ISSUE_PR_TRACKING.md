# GOV-006 Upstream Issue and PR Tracking

## Scope

This document defines the human-maintained workflow for tracking upstream ADK-Rust issues and pull requests that affect this fork. It is a governance record, not a Rust API, dependency manager, crawler, monitor, or issue automation system. Each tracking issue covers one upstream issue or pull request and records the decision that this fork must make.

## Intake and cadence

A maintainer MUST manually open one tracking issue when an upstream ADK-Rust issue or pull request is relevant to this fork's supported behavior, dependency surface, or planned adoption. The issue MUST identify the upstream URL, immutable reference when one exists, owner, and next review date. Do not create a tracking issue for unrelated discussion, duplicate reports, forks, mirrors, or generated artifacts.

Review the issue when the upstream item changes state, a release or dependency update makes it actionable, or the next review date arrives. Record the observed upstream state and the fork decision in the tracking issue; do not infer completion from silence.

## Record requirements

Every tracking issue MUST contain:

- the upstream repository and issue or pull request URL;
- the upstream number, title, current state, and last-reviewed UTC date;
- the relevant fork version, branch, or behavior;
- an owner and next review date;
- evidence links, including an immutable commit or diff reference when available;
- the fork disposition: `watch`, `adopt`, `defer`, `reject`, or `superseded`;
- the compatibility impact and the explicit next action.

A pull request being merged upstream does not by itself require adoption. The maintainer must verify compatibility with this fork and record the evidence for the chosen disposition.

## Label rules

Tracking issues MUST use the existing repository labels `upstream` and `governance` when those labels are available. Add `upstream-pr` for a pull request and `upstream-issue` for an issue; use exactly one of those two type labels. Do not create labels automatically, rename labels, or depend on a label for correctness. If a required label is unavailable, record that fact in the issue and preserve the same classification in its title and checklist.

The title MUST begin with `GOV-006:` and include the upstream repository and item number. Labels are routing metadata only; the issue body is the authoritative record.

## Compatibility removal rules

Compatibility code or documentation MAY be removed only after the tracked upstream item is verified as available in the fork's supported baseline and the issue records the exact version, commit, or release providing it. The maintainer MUST first confirm that supported callers no longer need the compatibility path, update affected documentation and tests where applicable, and record the removal commit or pull request.

Do not remove compatibility for an upstream proposal, an open pull request, an unreleased change, or an unverified backport. If the upstream item is abandoned, reverted, or incompatible, keep the compatibility path and change the disposition to `defer`, `reject`, or `superseded` with a reason. Removal is a separate change from tracking and must not be implied by closing the issue.

## Exclusions

GOV-006 does not add scheduled jobs, GitHub Actions, Dependabot, automatic issue filing, live crawling, SaaS services, Rust APIs, planning-pack changes, or product runtime behavior. All filing, review, labeling, and compatibility decisions remain manual and auditable.
