---
name: Feature
about: Versioned, testable implementation work
labels: ["type:feature"]
---

# <Area ID>: <Imperative title>

## Context

Explain the user/repository need. Link the parent epic, ADRs, source code, upstream stable/main evidence, and related dogfood workflow.

## Scope

- Exact behavior to implement.
- Public versus internal contracts.
- Files/crates expected to change.

## Non-goals

- Explicitly excluded adjacent work.

## Proposed contract

Describe types, traits, commands, schemas, package fields, or events. Mark illustrative names that still require implementation discovery.

## Security and failure semantics

- Required capabilities.
- Fail-closed behavior.
- Limits and cancellation.
- Data classification and secret handling.
- Side effects, idempotency, and approvals.

## Acceptance criteria

- [ ] Observable behavior 1
- [ ] Observable behavior 2
- [ ] Invalid/denied behavior fails with a stable diagnostic
- [ ] Documentation and examples updated

## Required tests

- [ ] Unit
- [ ] Property
- [ ] Integration
- [ ] Sandbox/provider conformance, if applicable
- [ ] CodeSeek/Verbatim parity, if applicable
- [ ] Benchmark, if applicable

## Dependencies

- Blocked by: #
- Blocks: #
- Parent epic: #

## Upstream analysis

- Stable ADK-Rust behavior:
- Current `main` behavior:
- Existing upstream issue/PR:
- Local versus upstream decision:
- Removal condition for any compatibility shim:

## Risks and rollback

State compatibility, migration, security, cost, and operational risks. Explain how to disable or revert safely.

```yaml
planning:
  id: AREA-000
  priority: P1
  milestone: M1
  blocked_by: []
  blocks: []
  parallel_group: example
  estimated_size: M
```
