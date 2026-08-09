# Workflow Specification, Canonical IR, and Compiler

## 1. Compiler model

```text
workflow.toml
   │ parse with source spans
   ▼
external AST
   │ interpolate permitted variables; resolve relative files
   ▼
normalized canonical IR
   │ static validation and registry resolution
   ▼
locked executable plan
   │ compile
   ▼
ADK-Rust graph + runtime plan
```

TOML is the initial authoring format. The canonical IR is the semantic authority. JSON, YAML, or a future visual editor may target the same IR without changing runtime semantics.

## 2. Why TOML first

- already common in Rust projects;
- clear distinction between values and multiline prompt files;
- deterministic parsing;
- good Serde support;
- easy review in Git;
- less indentation-sensitive than YAML;
- suitable for explicit, bounded configuration.

Prompts, Skills, references, and schemas should remain separate files rather than becoming enormous inline TOML strings.

## 3. Proposed top-level concepts

```text
schema_version
workflow identity
state schemas
input/output contracts
models
Skills
limits
sandbox/workdir policy
nodes
edges
routes
terminal requirements
artifacts
telemetry
evaluation profiles
```

The sample in `examples/01_code_investigation.workflow.toml` is illustrative and must be revised after the compiler subagent studies upstream source.

## 4. Closed node kinds for v0.1

### `agent`

An ADK LLM agent bound to a model profile, prompt, scoped tool set, Skills, input mapping, and output schema.

### `action`

A selectively exposed upstream action node. The platform compiler applies policy and feature checks.

### `validator`

A deterministic registered validator that returns a typed report and route verdict.

### `registered`

An application-provided Rust node implementing the platform node contract.

### `approval`

A HITL interrupt/approval gate with identity, timeout, and denial semantics.

### `subworkflow`

A separately versioned workflow package invoked with typed input/output. This may be deferred if it complicates v0.1.

### `terminal`

Produces a typed terminal status and selects published artifacts.

No arbitrary `eval`, shell, or dynamically compiled Rust node belongs in the default specification.

## 5. State and schemas

The graph state may be represented internally as JSON-like values because ADK graph state is dynamic, but every public node boundary should declare schemas or registered Rust types.

The compiler should verify:

- required keys exist before a node;
- output keys do not conflict unless a reducer is explicit;
- route source paths are defined;
- terminal outputs conform to the workflow output schema;
- secrets are never serialized into ordinary state;
- large values are converted to artifact handles rather than copied through every node.

For the first release, conservative validation is preferable to complex global type inference. Registered nodes can provide declared input/output JSON Schemas and optional Rust type IDs.

## 6. Routing

Use closed operators for simple cases:

```text
equals
not_equals
is_true
is_false
exists
is_empty
enum_case
numeric_range
status_class
```

Complex routing references a registered predicate:

```toml
[[routes]]
from = "coverage"
predicate = "verbatim.coverage-decision-v1"

[routes.targets]
complete = "merge"
corrective = "retrieve-more"
incomplete = "stop-incomplete"
```

Do not parse arbitrary boolean source code. Predicate implementations are versioned, tested Rust capabilities.

## 7. Cycles and bounded execution

Static graph analysis must identify strongly connected components. Every cyclic component requires at least one of:

- per-node `max_visits`;
- a loop node with an explicit iteration bound;
- a review policy with explicit max revisions;
- a global recursion/visit bound that is sufficiently tight and accepted by policy.

The compiler should also require:

- a path from every cycle to a terminal or fail node;
- side-effect nodes in cycles to be idempotent or compensating;
- no approval node to be silently revisited after approval without an explicit policy;
- a maximum total model-turn and tool-call budget independent of node visits.

## 8. Static validation rules

At minimum:

1. supported schema version;
2. valid workflow and node identifiers;
3. unique node IDs;
4. valid entry node;
5. all edge and route targets exist;
6. no unreachable nodes unless marked library-only;
7. at least one terminal;
8. every non-terminal path can terminate under a bounded policy;
9. all registry references resolve;
10. all referenced files remain inside the package root;
11. all Skill names resolve and declared resources exist;
12. all model roles have profiles;
13. tool schemas are compatible with the selected provider adapter;
14. reviewer nodes cannot receive unauthorized write tools;
15. success terminals require named validators when policy demands them;
16. side effects declare idempotency and approval class;
17. sandbox backend can enforce requested capabilities;
18. budget values are positive and internally consistent;
19. prompt/Skill/reference hashes can be computed;
20. package lock matches the current normalized plan when `--locked` is used.

## 9. Compiler phases

### Phase A: parse

Produce source-aware errors for invalid TOML and unknown fields.

### Phase B: resolve files

Canonicalize relative paths without following an escaping symlink. Read metadata and hash immutable resources.

### Phase C: normalize

Apply defaults and convert author-friendly aliases into a single IR. Sort maps where semantic order is irrelevant.

### Phase D: resolve registries

Bind versioned implementations and collect capability descriptors.

### Phase E: analyze graph

Reachability, cycles, state requirements, terminals, side effects, and approvals.

### Phase F: evaluate policy

Compute effective tools, data access, network destinations, and sandbox requirements.

### Phase G: lock

Write an immutable plan identity containing every semantically relevant dependency.

### Phase H: compile

Construct ADK agents, graph nodes, routes, callbacks/plugins, sessions, artifacts, and checkpointer configuration.

## 10. Lockfile

The lockfile should record:

- workflow schema and package hash;
- compiler/runtime version;
- exact ADK crate versions;
- normalized IR hash;
- model requested alias and resolved provider/model/revision;
- prompt, schema, Skill, reference, and script hashes;
- tool/node/validator/predicate implementation versions and schema hashes;
- sandbox backend and capability profile;
- policy snapshot ID;
- optional container image digests.

Do not store API tokens or raw secrets.

## 11. Extension namespace

Future-compatible configuration can allow namespaced metadata:

```toml
[extensions."com.librevectis.experimental"]
feature = "value"
```

Unknown unnamespaced fields should fail. Unknown namespaced extensions may be preserved in the AST but must not affect execution unless a registered compiler extension handles them.

## 12. Diagnostics

Every diagnostic should include:

```text
code
severity
file
line/column or TOML path
workflow/node/route ID
explanation
suggested remediation
related locations
```

Machine-readable JSON diagnostics are mandatory for agent-driven development.

## 13. Do not over-generalize the IR

The canonical IR exists to make semantics stable and testable, not to represent every possible program. A Rust node is the sanctioned escape hatch. When configuration becomes more complex than direct Rust, use Rust.
