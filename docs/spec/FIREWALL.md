# Deterministic Firewall v1

`workflow_runtime::firewall` evaluates a canonical tool proposal against an
application-owned `TrustedGoal`, `FirewallPolicy`, and target snapshot. It has no
model, network, filesystem, environment, approval-grant, or executor dependency.
The same values produce the same decision and identity.

## Trust boundary

- Load policy and goal from trusted application configuration, not graph state,
  an issue body, a tool response, or a model's claimed permissions.
- The only request is `ToolProposal`: versioned `ToolIntent`, bounded scalar
  arguments, and digest/trust-domain provenance. There is no document, issue-body,
  rationale, model-reasoning, or approval field. Unknown fields are rejected.
- Use `ToolProposal::decode` at a byte boundary (16 KiB ceiling). Argument strings
  are 1–256-byte ASCII tokens using letters, digits, `._-/:@#`; arrays, objects,
  nulls, floats, duplicate argument keys, and unrestricted prose are rejected.
  `ToolProposal::schema()` generates the versioned Draft 2020-12 shape. Schema
  validation alone does **not** authorize an action.
- `source_digest` is a lowercase 64-digit SHA-256 content reference. Provenance
  does not authenticate a model or promote its authority, even when its recorded
  trust domain is `trusted_goal`. The application supplies the actual trusted goal.
  No artifact or issue content is fetched by the Firewall.

## Injected policy

`FirewallPolicy` and `TrustedGoal` have `schema_version = 1` and an explicit
application version. The policy's `tools` map is the exact permitted tool registry;
there is no wildcard or fallback entry. Each `ToolRule` specifies:

- Exact tool version and a closed `SandboxCapability` set. Proposal capabilities
  must equal the registered set and be a subset of goal authority.
- Exact scope and destination allowlists, intersected with the trusted goal.
  These are canonical application identifiers, not URL/path prefix matches.
- Required argument names with integer ranges, booleans, bounded tokens, or
  closed string choices. Missing/extra names and wrong types/ranges deny.
- `scope`, `destination`, and `resource` bindings, each either a registration-owned
  literal or a scalar argument name. The proposal's metadata must agree with the
  actual argument values. A claimed allowed repository cannot conceal a different
  repository in the tool arguments.
- A closed side-effect class (`none`, `read`, `write`, `destructive`) and admission
  mode (`low_risk`, `human_approval`). No mode is inferred from model text.

For example, a GitHub issue-close registration uses `network`, effect `write`,
`human_approval`, repository-token and positive issue-number arguments, and a
`state` choice containing only `closed`. Scope binds to `repository`, resource
binds to `issue`, and destination is the trusted literal `github`. A fake no-op
registration can use empty capabilities, effect `none`, literal local bindings,
and explicitly configured `low_risk` admission. Both are executable fixtures in
`crates/workflow-runtime/tests/issue_238_firewall.rs`; no GitHub service is called.

`targets` is a set of exact `(scope, destination, resource, TargetVersion)`
snapshots. Missing, ambiguous, empty, unsupported, or unequal revisions deny.
The application must acquire a fresh snapshot independently of the proposal.
Revision equality is not an online freshness oracle or protection against a later
write race: an eventual executor must re-read/compare-and-set before effects.

Secrets fail closed on the shared secret-like key/fixture policy, the synthetic
honeytoken prefix anywhere in proposal metadata/arguments, and configured
`forbidden_markers`. Markers are matched as literal substrings of decoded strings,
not logged. This is not a claim to recognize every possible credential encoding;
the embedding application must supply prohibited values and constrain tool schemas.
Never load real credentials into test fixtures.

## Decisions, identities, and rendering

Every hard violation produces `Deny`; there is no override input. Only an explicitly
configured `low_risk` registration with `none` or `read` effects can produce
`Allow`. Other hard-policy-clean proposals produce `RequireHumanApproval`.
A write/destructive registration marked `low_risk` is a hard denial, not an allow.

`ToolDecision::typed_output`, `render_json`, and `render_markdown` use the shared
compact protocol and its 96-token budget. The v1 `policy` stamp carries a closed
reason code and deterministic identity; it is a report, **not** an execution permit.
No raw arguments, goal text, source document, marker, or unrestricted rationale is
emitted. `firewall_decisions()` exposes the same typed reports to offline harnesses.

Reason codes: `sch` schema, `pol` policy, `prv` provenance, `gol` goal identity,
`tol` tool/version, `cap` capability, `scp` scope, `dst` destination, `arg` arguments,
`sec` secret, `eff` side effect, `stl` stale/unknown target, `low` low-risk allow,
`hum` human approval required. The first failure in deterministic check order wins;
all later checks remain mandatory before any non-denial.

Canonical argument JSON sorts keys and uses exact scalar JSON spellings (no float
or Unicode normalization). Its digest uses the existing `argument_fingerprint`
contract. The decision identity binds the full policy/goal/proposal, their versions,
source/argument digests, target snapshot, reason, and hard-policy/security/secret
implementation versions. `FirewallInvocation::identity` binds the evaluation input;
that digest is included in canonical workflow IR. Policy/schema changes therefore
invalidate workflow cache/checkpoint identity. Future approval records must bind
this same identity, not just a tool name or arguments hash.

## Production workflow integration

Declare a deterministic validator **entry** gate:

```toml
[[nodes]]
id = "gate"
kind = "validator"
firewall = { schema_version = 1, identity = "<FirewallInvocation::identity() hex>" }
```

The application constructs `FirewallInvocation::new(policy, goal, proposal)`, writes
its exact identity into the specification, compiles normally, then calls
`AdkGraphTranslator::translate_with_firewall(&plan, invocation, &agents)`. Existing
specification, IR (canonical wire v10), compiler, and ADK `node_fn` boundaries are
used. The compiler rejects misplaced gates and incoming edges/routes to the gate.
Default/profile/resolved translators reject a Firewall contract without an exact
injected binding; there is no silent no-op or WASM fallback. The CLI can validate
such a spec but does not load trusted Firewall bindings from a live profile.

The gate ignores mutable graph state. Forged `approved` or `node:gate` values cannot
change admission. On `Deny` **or** `RequireHumanApproval`, graph execution stops
before downstream judges, approval nodes, or actions. `AdkGraphError::AuthorizationDenied`
is the execution stop; inspect the typed decision for the distinct outcome/reason.
An allow writes the compact envelope to `node:gate` before continuing. Explicit
checkpoint resume is rejected before execution; a stopped graph cannot be resumed
past its hard gate. Gate records belong to the invocation future, independent of
checkpoint thread IDs; concurrent runs do not clear, consume, or replay each other's
reports. `firewall_decisions()` is a last-completed-invocation snapshot (including
errors): rejected resume publishes an empty snapshot, while cancellation leaves the
previous completed snapshot unchanged. Use each invocation's mapper for concurrent
attribution, not that shared snapshot.
The observed execution path emits exactly one `ToolAuthorized`, `ToolDenied`, or
`ApprovalRequested` with the compact envelope under
`payload.structured_output.firewall`, without emitting a model request.

## Scope and local verification

This is an opt-in Firewall workflow boundary, not a retroactive global replacement
for every existing `ToolBridge` caller. `Allow` proves hard policy only: semantic
task alignment is #239. Human-grant verification, single-use approvals, actual
GitHub execution, target compare-and-set, and durable execution/approval ledger are
#240. In this release no human grant advances a stopped Firewall graph. Live model
coverage is inapplicable because the gate has no semantic-model behavior.

```sh
mise exec -- just issue-238-runtime
mise exec -- just issue-238-adk
mise exec -- just issue-238-concurrent
mise exec -- just issue-228-runtime
mise exec -- just m1-15-translation
```

Tests include the complete binary tool/scope/destination/secret/effect/schema/target
matrix, canonical JSON/digest goldens, malformed and future-version requests, exact
GitHub/no-op representations, explicit low-risk allow, immutable binding checks,
forged-state denial, downstream panic-judge non-invocation, and typed telemetry.
