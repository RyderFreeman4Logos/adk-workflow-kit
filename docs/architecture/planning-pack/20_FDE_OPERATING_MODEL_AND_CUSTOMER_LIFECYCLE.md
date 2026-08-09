# FDE Operating Model and Customer Workflow Lifecycle

## 1. Strategic operating model

The platform is intended to support an organizational process, not only a developer library:

```text
Employee discovery use in Hermes
        → Skill and evidence accumulation
        → candidate submission and clustering
        → FDE analysis and workflow compilation
        → controlled pilot
        → production workflow plus thin Runtime Skill
        → observed failures/corrections feed the next version
```

The FDE gains leverage because the first artifact is no longer a vague interview transcript. It is a set of real tasks, corrections, failures, tool interactions, examples, and employee acceptance signals.

## 2. Customer deployment profiles

### Discovery profile

Purpose: allow employees to explore real work and improve personal Skills.

Recommended properties:

- one identity and isolated profile per employee;
- one independent container/workdir per active execution;
- Skill writes require user review or explicit approval;
- customer-approved model endpoints only;
- narrow employee credentials and tool scopes;
- full observable trace and cost metadata;
- no write access to organization-standard Skills;
- easy submission of a Candidate Skill Evidence Package.

### FDE development profile

Purpose: cluster candidate Skills, inspect evidence, build workflows, fixtures, and validators.

Recommended properties:

- access only to approved/redacted evidence packages;
- development registries and fake connectors by default;
- ability to run live customer connectors only through audited profiles;
- stronger model optional for design/review;
- Developer Skills mounted read-only;
- per-branch workflow packages and eval baselines;
- no automatic promotion to production.

### Production profile

Purpose: execute approved workflows through thin Runtime Skills, API, CLI, schedule, or event trigger.

Recommended properties:

- immutable package and lock;
- organization Skills read-only;
- no automatic Skill mutation;
- explicit tenant/role/policy identity;
- conforming sandbox;
- model endpoint and data-classification enforcement;
- deterministic validators and bounded review;
- approval before high-risk side effects;
- SLO, alerting, rollback, and owner.

Discovery and production should not share a mutable Skill directory or unrestricted long-lived container.

## 3. Candidate collection

A submission UI or CLI should allow an employee to submit:

- Skill ID/version/hash;
- task description and intended outcome;
- selected successful and failed runs;
- corrections the employee made;
- representative inputs and outputs;
- tool/permission list;
- frequency and estimated manual time;
- confidentiality classification;
- people/teams for whom the procedure may apply;
- known exceptions and “never do this” rules.

The employee controls submission. The system may recommend high-value candidates based on repeated use, but it should not silently send every personal trace to a central registry.

## 4. Candidate registry

The registry should store metadata and approved redacted artifacts, not arbitrary raw sessions.

Core functions:

- immutable candidate versions;
- provenance and submitter;
- tenant/department scope;
- duplicate/similarity clustering;
- success/failure/correction counts;
- usage/cost/time estimates;
- security classification;
- reviewer comments;
- promotion stage;
- related workflow/package IDs;
- retirement and replacement links.

Similarity is useful for clustering. It is not proof that two employees follow the same business rule.

## 5. FDE analysis responsibilities

The FDE or development team should convert evidence into an explicit engineering model:

1. Identify stable inputs, outputs, and preconditions.
2. Separate common flow from employee/customer-specific exceptions.
3. Classify each step as deterministic code, semantic model decision, reference lookup, approval, or side effect.
4. Extract objective validators and postconditions.
5. Identify rare but high-impact failure modes that successful traces omit.
6. Define permissions and data boundaries.
7. Define retry, idempotency, compensation, and abstention behavior.
8. Construct fixtures from successes, failures, corrections, and adversarial cases.
9. Decide whether the result should remain a Skill, become a workflow, or use a hybrid.
10. Assign an owner and maintenance policy.

A Skill is an input to this analysis, not a complete production requirements document.

## 6. Workflow eligibility rubric

Good candidates score highly on:

- frequency;
- employee time consumed;
- cross-user reuse;
- stable control flow;
- clear input/output contract;
- objective validators;
- bounded exceptions;
- low or controllable side-effect risk;
- available test data;
- meaningful cost reduction.

Poor early candidates include low-frequency one-off judgment, rapidly changing policy, irreversible action without verification, or tasks whose correct result is mostly subjective preference.

Suggested prioritization:

```text
candidate value =
  frequency
× manual time saved
× cross-user applicability
× standardization
× verifiability
× expected adoption
− implementation cost
− maintenance volatility
− expected failure loss
− security/compliance burden
```

The exact weights are customer-specific and should be recorded.

## 7. Conversion outcomes

### Keep as Skill

Appropriate when the value is knowledge, writing guidance, terminology, or flexible judgment and there is little stable executable control flow.

### Declarative workflow

Appropriate when topology is stable and existing tools/actions/validators can express it.

### Declarative workflow plus Rust validators/nodes

Expected production default when objective correctness, performance, transactions, or security matter.

### Handwritten ADK graph/application code

Appropriate when configuration would obscure complex dynamic topology, reducers, checkpoint migrations, distributed transaction handling, or performance constraints.

### Reject automation

Appropriate when expected loss, ambiguity, policy instability, or data constraints outweigh the benefit.

## 8. Pilot process

1. Freeze a candidate evidence set.
2. Create a versioned workflow package and eval baseline.
3. Run offline fixtures with scripted models/fake connectors.
4. Run shadow mode on real tasks without side effects.
5. Compare employee result and workflow result.
6. Require employee review and capture corrections.
7. Enable read-only production use.
8. Add approval-gated side effects only after measured reliability.
9. Roll out to a small group.
10. Promote only after predefined acceptance and rollback gates.

## 9. Runtime Skill after productionization

The production Skill should remain thin:

- explain when the workflow applies;
- collect typed missing parameters;
- show material assumptions;
- invoke a fixed workflow package/profile;
- report completed, incomplete, abstained, denied, or failed status;
- expose artifact links and citations;
- request approval or human escalation;
- avoid reimplementing stable control flow in prose.

## 10. Cost accounting

Measure total cost, not only model tokens:

```text
monthly benefit =
  executions
× (manual minutes before − manual minutes after)
× loaded labor rate / 60
+ avoided rework and error loss
− model/tool/compute cost
− approval/review time
− FDE development amortization
− maintenance and incident cost
```

Record separate cost for discovery, compilation, validation, review, and runtime. Artifact reuse and deterministic fast paths should be visible in the ledger.

## 11. Reliability and SLOs

Possible production indicators:

- verified completion rate;
- false-pass rate;
- abstention rate;
- employee correction rate;
- mean time saved;
- approval rejection rate;
- repeated-defect/no-progress rate;
- unauthorized action count;
- rollback frequency;
- model/tool cost per accepted completion;
- workflow version adoption.

High verified completion with a high false-pass rate is not success.

## 12. Governance

Every production workflow needs:

- business owner;
- technical owner;
- data classification;
- allowed roles;
- model policy;
- tool/side-effect policy;
- eval suite and acceptance thresholds;
- incident/rollback procedure;
- review cadence;
- retirement/replacement policy;
- current Runtime Skill and package links.

Organization-standard Skills and workflows are Git-managed and reviewed. Personal Skills remain personal until submitted.

## 13. Cross-customer reuse boundary

The shared platform can reuse:

- compiler/runtime code;
- generic patterns;
- test and sandbox infrastructure;
- generic validators and connectors where licensing/credentials permit;
- Developer Skills;
- redacted structural metrics.

It must not casually reuse:

- customer prompts containing confidential rules;
- raw traces;
- private references;
- credentials;
- customer-specific schemas/data;
- derived examples that reveal sensitive operations.

Customer packages should normally live in separate repositories and registries.

## 14. FDE scaling thesis

The intended effect is not to eliminate FDE judgment. It changes where that judgment is spent:

```text
less time reconstructing routine work from interviews
more time validating exceptions, security, objective correctness,
reusable architecture, evaluation, and production operation
```

This is the principal organizational reason to build the platform rather than continuing with isolated bespoke workflows.
