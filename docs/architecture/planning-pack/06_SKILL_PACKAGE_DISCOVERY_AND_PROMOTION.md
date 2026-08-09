# Skill Package, Discovery, Execution, and Promotion

## 1. Skill roles

The platform should distinguish three classes of Skill.

### Discovery Skill

Created or refined from real employee use in Hermes. It captures procedures, corrections, examples, terminology, and exceptions. It is evidence and a hypothesis about a workflow, not automatically a production specification.

### Developer Skill

Guides FDEs and development agents in authoring workflows, connectors, validators, evals, migrations, security reviews, and upstream contributions. These Skills live in the platform repository and are reviewed like code.

### Runtime Skill

A thin user-facing interface for a production workflow. It decides applicability, gathers missing parameters, invokes a versioned workflow, explains status, and escalates failures. It should not duplicate the entire business process in prose after the process has been compiled.

## 2. Agent Skills compatibility

Use the Agent Skills directory convention:

```text
skill-name/
├── SKILL.md
├── scripts/
├── references/
├── assets/
└── skill.runtime.toml
```

`SKILL.md`, `scripts/`, `references/`, and `assets/` follow the public Agent Skills specification. `skill.runtime.toml` is a platform extension containing execution, sandbox, schema, integrity, and promotion metadata that the base specification does not define.

Integrate `adk-skill` for discovery, parsing, indexing, selection, allowed-tool validation, and prompt injection. Do not write a competing parser.

## 3. Proposed companion runtime manifest

```toml
schema_version = 1

[skill]
id = "code-investigation"
version = "0.3.0"
stage = "validated"

[execution]
backend = "linux-bwrap"
network = "none"
timeout_ms = 30000
memory_mb = 256
max_output_bytes = 262144

[resources]
read = ["references/**", "assets/**"]
write = ["$RUN_WORK/**", "$RUN_OUT/**"]

[[scripts]]
id = "normalize-query"
path = "scripts/normalize.py"
runtime = "python3"
sha256 = "..."
input_schema = "schemas/normalize-input.json"
output_schema = "schemas/normalize-output.json"
idempotent = true
```

A script is invoked by ID. The model never supplies a host command line or arbitrary script path.

## 4. Progressive disclosure

The runtime should expose:

1. Skill name and description during discovery;
2. full `SKILL.md` only after activation;
3. resource names and metadata without loading bodies;
4. references by explicit paginated request;
5. scripts by declared ID and typed input;
6. large outputs as artifact handles.

This reduces context cost and limits accidental exposure of irrelevant confidential data.

## 5. Dedicated Skill tools

Recommended platform tools:

```text
activate_skill
list_skill_resources
read_skill_resource
run_skill_script
```

Their parameter schemas should use enumerated active Skill/resource/script IDs generated for the run where practical. They must enforce path containment, hash checks, byte budgets, and capability policy.

## 6. Resource security

`read_skill_resource` must:

- reject absolute paths;
- reject `..` traversal;
- resolve symlinks and verify the final path remains in the Skill root;
- enforce an allowed glob from the runtime manifest;
- enforce file type, size, and total-read budgets;
- return provenance and content hash;
- paginate large files;
- avoid rendering binary content directly into model context unless an approved converter exists.

Skill assets and references should normally be mounted read-only in the per-run sandbox.

## 7. Script security

A Skill script must be:

- declared in `skill.runtime.toml`;
- content-hash locked;
- noninteractive;
- passed typed input through stdin or a generated input file;
- executed in the run sandbox;
- denied network unless explicitly allowed;
- denied host paths outside declared mounts;
- bounded by time, memory, PIDs, disk, and output;
- required to emit structured output when declared;
- validated against its output schema;
- traced without leaking secrets.

Prefer, in order:

1. registered Rust node/tool for stable critical logic;
2. WASM or embedded JavaScript for pure transformations;
3. sandboxed Python or command execution for compatibility and discovery-stage agility.

## 8. Effective permission intersection

The executable capability set is:

```text
compiled runtime capabilities
∩ workflow-declared tools
∩ active node tools
∩ Skill allowed tools
∩ actor scopes
∩ tenant policy
∩ role policy
∩ sandbox capabilities
```

Any empty or denied intersection fails closed. A Skill cannot request a tool the workflow did not include. Semantic relevance never grants authorization.

## 9. Skill selection

Initial selection should support:

- explicit Skill ID;
- required Skills listed by a workflow node;
- deterministic lexical selection through `adk-skill`;
- optional tenant-scoped hybrid retrieval using embedding and reranking.

Semantic Skill retrieval should only propose candidates. High-risk workflow activation requires explicit policy or confirmation.

## 10. Skill Evidence Package

Promotion candidates should include:

```text
Skill definition and content hash
successful traces
failed traces
user corrections
accepted/rejected output examples
input distribution summary
tool and permission usage
frequency and human time saved
model/tool cost
cross-user reuse statistics
known exceptions
security classification
owner and review history
```

Raw traces must be redacted and tenant-scoped. Do not copy customer data into a global Skill registry.

## 11. Promotion lifecycle

Suggested stages:

```text
personal
candidate
validated
production
organization-standard
retired
```

Example gates:

- `candidate`: repeated real use and at least one failure/correction example;
- `validated`: reused by multiple independent users or cases, with eval fixtures;
- `production`: typed workflow, validators, sandbox/policy, observability, owner, and rollback;
- `organization-standard`: multi-team adoption and SLO/maintenance commitment.

High-risk domains require explicit security and domain approval regardless of use count.

## 12. Compilation from Skill evidence

The compiler should not directly translate prose into a production graph. FDE analysis should separate:

- stable control flow;
- variable semantic decisions;
- deterministic validation;
- exceptional branches;
- approvals;
- side effects;
- rollback/compensation;
- reference data;
- customer-specific rules.

Research on workflow-to-Skill compilation supports an intermediate representation that preserves routing, semantics, and attachments rather than merely summarizing trajectories. Treat this as a research direction, not a reason to auto-publish generated workflows.

## 13. Versioning and integrity

- Skill packages are immutable once referenced by a lockfile.
- New content creates a new content identity and normally a new semantic version.
- Runtime records activated Skill IDs and hashes.
- Organization Skills should be stored in Git, code-reviewed, and mounted read-only.
- Local same-name shadowing should be disabled or explicitly namespaced in production.
- A future signed package format may attest publisher, review status, and SBOM.
