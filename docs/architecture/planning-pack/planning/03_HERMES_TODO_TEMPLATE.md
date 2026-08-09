# Hermes Ready Todo Queue

Only include issues with no unresolved `blocked_by` dependency.

| Order | Priority | Issue | Parent epic | Why ready | Definition of done | Required test command |
|---:|---|---|---|---|---|---|
| 1 | P0 | #... | #... | Dependencies complete | ... | `cargo test ...` |

## Queue update rules

1. Recompute after every merged dependency.
2. Remove or pause work that becomes blocked by new evidence.
3. Keep one or more parallel groups only when their file/API overlap is manageable.
4. Do not place an epic in the implementation queue as a substitute for a leaf issue.
5. Record issue URL and acceptance criteria in each Todo item.
6. Mark completed only after repository issue acceptance tests pass.
