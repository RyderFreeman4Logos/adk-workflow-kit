# Repository Bootstrap, Feature Issue, and Hermes Todo Protocol

## 1. Primary-agent mandate

After research synthesis, the primary Hermes agent must perform these actions in the current working session:

1. choose and create the new repository;
2. add the minimal planning/scaffold files;
3. create labels and milestones;
4. create a dependency-aware set of feature issues;
5. order issues by priority and dependency;
6. add only ready, unblocked issues to the primary agent's Todo list;
7. publish a planning summary.

Do not merely return suggested issue titles.

## 2. Repository name selection

Evaluate at least these criteria:

- not misleadingly claiming to be official ADK-Rust;
- available GitHub/crates.io naming or a clear namespace strategy;
- easy CLI/crate naming;
- suitable if the project later becomes independent;
- no obvious trademark conflict;
- concise and searchable.

Provisional neutral choice: `adk-workflow-kit`. The agent may choose a better name and must record the decision in ADR-0001 or an equivalent repository-name ADR.

## 3. Initial repository contents

```text
README.md
LICENSE-APACHE
SECURITY.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md optional
rust-toolchain.toml
Cargo.toml
Cargo.lock
.gitignore
.github/workflows/ci.yml
.github/ISSUE_TEMPLATE/
docs/adr/
docs/architecture/
crates/ or a minimal placeholder crate
examples/
```

The initial scaffold must compile and pass formatting/lint/test CI, but should not pre-implement speculative APIs.

## 4. Required labels

### Type

```text
type:epic
type:feature
type:security
type:research
type:test
type:docs
type:upstream
type:refactor
```

### Priority

```text
priority:P0
priority:P1
priority:P2
priority:P3
```

### Status/dependency

```text
status:ready
status:blocked
status:needs-design
status:needs-upstream
status:deferred
```

### Area

```text
area:spec
area:ir
area:compiler
area:adk
area:runtime
area:workdir
area:sandbox
area:skills
area:review
area:tools
area:artifacts
area:policy
area:testkit
area:cli
area:dogfood
area:release
```

Use repository-native dependencies or explicit issue links in every blocked issue. Labels supplement rather than replace dependency links.

## 5. Milestones

Recommended milestones:

1. `M0 Planning and Scaffold`
2. `M1 Executable Walking Skeleton`
3. `M2 Skills and Isolated Execution`
4. `M3 Review and Reliability`
5. `M4 CodeSeek Parity`
6. `M5 Verbatim Parity`
7. `M6 v0.1 Release`
8. `Later / Research`

The primary agent may adjust names but should preserve measurable gates.

## 6. Feature issue format

Every implementation issue must contain:

```markdown
## Context
Why this is needed; links to source code, ADRs, and parent epic.

## Scope
Exact behaviors and public/internal boundaries.

## Non-goals
What must not be added in this issue.

## Proposed contract
Types, files, commands, schemas, or interfaces affected.

## Security and failure semantics
Capabilities, fail-closed behavior, limits, data handling.

## Acceptance criteria
Observable and testable completion conditions.

## Required tests
Unit, property, integration, conformance, dogfood, benchmark as applicable.

## Dependencies
- Blocked by #...
- Blocks #...

## Upstream analysis
Stable/main capability, existing issue/PR, local-vs-upstream decision.

## Risks and rollback
Known hazards and how to revert safely.
```

Do not create issues whose only acceptance criterion is “implemented.”

## 7. Epic format

Each epic includes:

- strategic outcome;
- architecture boundary;
- child issue checklist;
- milestone/gate;
- risks;
- explicit out-of-scope list;
- completion evidence.

An epic is not itself placed in the coding Todo list unless the agent uses it only as a tracking item.

## 8. Dependency metadata

Use both human-readable links and a machine-readable block in issue bodies:

```yaml
planning:
  id: COMPILER-003
  priority: P0
  milestone: M1
  blocked_by: [IR-002, REGISTRY-001]
  blocks: [CLI-VALIDATE-001]
  parallel_group: compiler-core
  estimated_size: M
```

The exact schema may change, but it must remain easy for Hermes to parse.

## 9. Priority model

Score candidate issues using:

```text
Priority value =
  critical-path weight
+ risk-reduction weight
+ cross-workflow reuse
+ testability unlock
+ security importance
+ user-visible leverage
- implementation uncertainty
- maintenance burden
```

Dependencies override raw score: a high-value blocked issue is not ready work.

### Suggested interpretation

- **P0:** required to establish architecture/security correctness or unblock the walking skeleton;
- **P1:** required for dogfood parity and v0.1;
- **P2:** valuable after core parity, may improve production readiness;
- **P3:** exploratory/deferred.

## 10. Issue creation procedure

1. Import all subagent candidates into a local planning table.
2. Normalize titles and IDs.
3. Merge duplicates.
4. Split oversized issues that cannot be reviewed independently.
5. Add dependencies.
6. Detect cycles in the issue graph.
7. Assign milestone and priority.
8. Create epics first.
9. Create leaf issues, linking parent and dependencies.
10. Re-read created issues to verify links and formatting.
11. Generate the ready queue.

Avoid blindly retrying issue creation if API status is uncertain; verify before duplicate creation.

## 11. Hermes Todo import

The Todo list should contain implementation-sized, currently unblocked issues in dependency order. Recommended initial Todo fields:

```text
issue URL/number
short task name
priority
parent epic
why ready
definition of done
expected files/crates
mandatory test command
```

Do not put all future issues into the active Todo list. The repository issue graph is the long-term plan; Todo is the executable frontier.

## 12. Initial Todo selection rule

At repository creation, the likely ready frontier is:

- architecture/reuse ADR completion;
- workspace and CI scaffold;
- CodeSeek characterization tests or extraction inventory;
- external spec/IR type skeleton;
- diagnostic infrastructure;
- fake registry/testkit skeleton;
- workdir threat-model/conformance fixture skeleton.

The primary agent must recompute this after creating actual dependencies.

## 13. No direct implementation before gates

The agent may implement only the minimal scaffold required for CI and issue planning. Broader code begins after:

- architecture ADRs merged or accepted;
- exact upstream baseline verified;
- initial issue DAG checked;
- security workdir/sandbox requirements represented;
- CodeSeek/Verbatim parity baselines identified.

## 14. Final planning report

The final Hermes response should include:

```text
Repository URL
Chosen name/license/visibility and rationale
Pinned ADK-Rust baseline
Created milestones and labels
Issue count by priority/area/milestone
Critical path
Dependency graph link or Mermaid
Ready Todo list
Deferred scope
Top risks
Upstream contribution plan
Any failed actions or uncertainties
```

The report must distinguish confirmed repository actions from recommendations not yet executed.
