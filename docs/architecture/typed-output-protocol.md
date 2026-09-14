# Compact typed-output protocol

Model nodes return compact v1 envelopes. Renderers produce Markdown/JSON from
reason codes and source/artifact references. Free-form rationale is off by
default and is stored only on an explicit research path.

## Baseline output-token budgets

Whitespace-token estimates used as node output ceilings. Truncation is an
explicit continuation record; truncated envelopes are rejected before reducer
or action use.

| Node | Budget |
| --- | ---: |
| Sentinel | 128 |
| Firewall | 96 |
| CompactState | 192 |
| IssueCard | 160 |
| Dependency | 96 |
| Escalation | 80 |

## Reason codes

Sentinel: `inj` injection, `sus` suspicious, `uns` unsupported language, `inv` invalid input, `cln` clean.

Firewall: `alw` allow, `den` deny, `rha` require human approval.

Dependency: `blk` blocks, `dep` depends on, `unr` unrelated.

Escalation: `cld` cloud, `hitl` human.

Issue-card status: `open`, `blocked`, `done`. Compact-state ops: `add`, `set`, `del`.

Unknown schema versions and codes fail closed. There is no silent `_` fallback.
