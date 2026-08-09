# Executive Decision and Product Thesis

## 1. Decision

Create a reusable, opinionated workflow platform above ADK-Rust with four layers:

```text
Customer- or application-specific workflows
                │
Declarative workflow packages: TOML + prompts + Skills + schemas + tests
                │
Workflow compiler/runtime: canonical IR, registries, policy, workdirs, sandbox,
review loops, artifacts, lockfiles, evaluation, replay
                │
ADK-Rust stable: agents, graph, actions, tools, runner, sessions, skills,
sandbox/code execution, plugins, auth, telemetry, artifacts, eval
```

The proposed platform should make the common path configuration-driven while retaining a first-class Rust extension path. This is not a replacement for ADK-Rust. It is a narrower product that standardizes how an FDE team repeatedly builds reliable workflows for different customers and internal products.

## 2. Why the opportunity exists

ADK-Rust already provides most of the execution primitives, but a cross-customer FDE practice still needs decisions that a general framework cannot make on its behalf:

- stable application-facing contracts that do not expose ADK internals;
- a restricted declarative language and canonical intermediate representation;
- model, tool, validator, predicate, Skill, and node registries;
- per-run work directory and sandbox lifecycle;
- reproducible package lockfiles;
- bounded producer/reviewer/reviser patterns;
- evidence-backed Skill promotion;
- tenant, role, and data-classification policy;
- a uniform testkit, replay format, and failure taxonomy;
- scaffolding and issue patterns that allow agents and FDEs to work quickly.

CodeSeek already implements many runtime pieces. Verbatim already expresses strong fail-closed workflow contracts. This substantially lowers the risk of extracting the wrong abstraction from hypothetical requirements.

## 3. The product thesis

A large class of enterprise tasks can be represented as:

```text
bounded graph
+ typed tools
+ deterministic validators
+ selectively invoked LLM nodes
+ Skills and references
+ explicit budgets
+ isolated execution
+ observable artifacts
```

For these tasks, reliability need not come from a single expensive model producing a perfect answer. It can come from constraining the search space, exposing the right tools, validating objective properties, reviewing semantic defects, retrying only with structured feedback, and abstaining when the acceptance contract is not met.

This makes smaller tool-calling models economically useful. It does not make them universally trustworthy. The target is reliable completion of bounded and externally checkable work, not open-ended autonomous decision-making without supervision.

## 4. Permanent declarative orchestration

The default lifecycle should be:

```text
TOML workflow + Skills + prompts + schemas
                 │
                 ▼
validated canonical IR
                 │
                 ▼
compiled ADK-Rust graph
                 │
                 ▼
production execution
```

Production hardening should normally upgrade a node, validator, connector, or predicate to Rust while preserving the surrounding declarative graph. Rewriting the entire graph should be exceptional.

This gives four maturity levels:

1. **Pure declarative:** existing registered tools and generic agent/action nodes.
2. **Declarative plus Rust validators:** the common production form for evidence-sensitive workflows.
3. **Declarative plus registered Rust nodes:** high-frequency, transactional, performance-sensitive, or security-critical stages.
4. **Handwritten ADK graph:** only when dynamic topology, state reducers, checkpoint migration, transaction orchestration, or performance makes configuration less clear than Rust.

## 5. Organizational product loop

The platform should support this FDE lifecycle:

```text
Employees use Hermes in isolated environments
             │
Hermes records successful procedures, failures, and corrections as Skills
             │
Candidate Skill Evidence Packages are submitted
             │
FDEs cluster, validate, generalize, and compile repeated behavior
             │
A production workflow is published with a thin Runtime Skill as its interface
             │
Production failures and corrections feed the next version
```

A candidate `SKILL.md` alone is not enough evidence. Promotion decisions should use execution traces, accepted outputs, rejected outputs, corrections, tool and permission usage, cost, frequency, and cross-user reuse.

## 6. Reliability thesis

The strongest default graph is:

```text
produce
  → deterministic validation
      → semantic review
          → publish
          → structured revise → deterministic validation
          → abstain
```

A model reviewer produces typed defects; it does not directly declare objective constraints satisfied. A repaired output is always revalidated. Repeated-output, repeated-defect, oscillation, and budget detectors terminate unproductive loops.

The framework should optimize for three outcomes, in order:

1. correct, verified completion;
2. explicit incomplete/abstained result with useful diagnostics;
3. bounded failure without unauthorized side effects.

A plausible but unverified answer is worse than a typed abstention for workflows that claim reliability.

## 7. Economic thesis

Cost improvements come from more than cheaper tokens:

- less FDE discovery time because Skills preserve real corrections;
- reuse of tool, workdir, sandbox, artifact, test, and review infrastructure;
- fewer repeated model planning turns;
- deterministic code replacing stable reasoning steps;
- smaller models for constrained nodes;
- no duplicate retrieval when artifacts can be reused;
- fewer manual checks because outputs have explicit validators;
- controlled retries rather than uncontrolled agent loops;
- cross-customer reuse of patterns without sharing confidential content.

## 8. Best current judgment

The recommended strategic bets are:

- **Very likely:** shared runtime and test abstractions extracted from CodeSeek will reduce repeated engineering.
- **Likely:** grounded-answer, multi-hop research, code investigation, document extraction, reconciliation, and review workflows can remain declarative in production.
- **Likely:** per-run isolated workspaces will simplify both security and reproducibility.
- **Moderately likely:** a bounded reviewer graph will let 27B-class or sparse inexpensive models perform many constrained tasks at acceptable reliability.
- **Unlikely:** same-model review without deterministic checks will provide a general correctness guarantee.
- **Unlikely:** a universal TOML language that safely expresses arbitrary business logic is worth building.

## 9. Three dominant reasons to proceed

1. **The abstractions already recur in real code.** Lifecycle limits, typed tools, provenance, progressive artifacts, independent reviewer sessions, fail-closed outcomes, and bounded correction appear across CodeSeek and Verbatim.
2. **The upstream substrate is broad enough.** ADK-Rust 1.0 supplies stable agents, graphs, actions, Skills, sessions, plugins, eval, and sandbox/code-execution foundations.
3. **The platform creates compounding FDE leverage.** Each workflow contributes new patterns, validators, fixtures, Skill evidence, and tooling instead of becoming another isolated integration.

## 10. Strongest counterargument

The strongest objection is that premature abstraction can create a weakly typed second language that is harder to debug than direct Rust. That objection is valid and changes the implementation method:

- extract only after two real callers, except for foundational invariants;
- use a closed node and routing model;
- retain registered Rust escape hatches;
- force the first compiler to reproduce CodeSeek and Verbatim behavior;
- freeze v0.1 only after three materially different workflows pass parity tests.

It does not justify continuing to duplicate lifecycle, Skill, sandbox, and test infrastructure in every project.

## 11. Evidence that would reverse the decision

Reconsider the platform if, after the three dogfood workflows:

- most orchestration still requires compiler changes rather than new registered nodes;
- configuration failures take consistently longer to diagnose than Rust compiler errors;
- shared crates consume more maintenance than they remove;
- ADK-Rust upstream adds an equivalent opinionated package/compiler that fully satisfies the requirements;
- reviewer loops introduce more errors than they remove under representative evals;
- per-run isolation cannot meet required latency or operational cost.

Until then, the best decision is to proceed with a narrow, dogfood-driven platform.
