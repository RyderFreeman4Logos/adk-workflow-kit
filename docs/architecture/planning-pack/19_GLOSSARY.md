# Glossary

## ADK compatibility layer

The narrow crate/module that translates platform contracts to the exact pinned ADK-Rust APIs. It prevents ADK implementation types from leaking into durable application domains.

## Agent node

A graph node driven by an LLM Agent with a model role, prompt, explicit Skills, scoped tools, input mapping, output schema, and limits.

## Agent Skills

The public directory-based Skill format centered on `SKILL.md` with optional scripts, references, and assets.

## Artifact

An immutable or versioned stage payload addressed by a stable ID, usually content-derived, and read progressively rather than copied into every state transition.

## Canonical IR

The normalized, format-neutral representation of a workflow after defaults, file resolution, and semantic normalization. It is the basis for hashing, locking, analysis, and compilation.

## Characterization test

A test that captures current behavior before extraction or refactoring, especially failure, limit, permission, event, and artifact semantics.

## Closed operator

A routing or transformation operation selected from an enumerated, versioned set rather than arbitrary source text.

## Compiler

The component that parses a workflow package, normalizes it to IR, resolves registries, performs graph/policy/security analysis, creates a lock, and constructs an ADK executable plan.

## Connector

A registered, typed integration with an external system. It generally owns credentials outside the Skill script sandbox and exposes a narrow Tool or Node interface.

## Defect fingerprint

A stable representation of review/validation defects used to detect repeated failure and no-progress loops.

## Deterministic validator

Ordinary code that checks objective properties such as schema, provenance, access, citations, compilation, tests, or business invariants. It is authoritative over model review for those properties.

## Discovery Skill

A Skill created from real employee/Hermes use that captures procedure and correction evidence but is not automatically production-ready.

## Dogfood workflow

A real CodeSeek or Verbatim workflow used to force the platform abstractions to satisfy existing behavior.

## Effective capability set

The intersection of runtime, workflow, node, Skill, role, actor, tenant, and sandbox permissions.

## Evidence Package

The authorized immutable set of retrieved/source artifacts against which an output or review is validated.

## FDE

Forward Deployed Engineer: an engineer working close to a customer's real systems and processes, translating ambiguous operational knowledge into maintained software/workflows.

## Fail closed

Reject, fail, mark incomplete, or abstain when a requirement cannot be verified or enforced; never silently run with weaker policy.

## Lockfile

The immutable resolution record for workflow IR, resources, Skills, models, implementations, policies, sandbox profile, and ADK/runtime versions.

## No-progress detector

Runtime logic that terminates repair when output or defect hashes repeat, oscillate, or fail to improve within budget.

## Pattern pack

A reusable workflow topology plus schemas, Skills, fixtures, validators, security defaults, and tests.

## Per-run workdir

A unique filesystem root for one execution containing immutable inputs/packages and bounded mutable work/output/artifact directories.

## Predicate registry

A mapping from versioned predicate IDs in workflow configuration to tested Rust routing logic.

## Progressive disclosure

Expose only Skill metadata first, full instructions after activation, and references/artifacts only when needed.

## Registered node

A versioned Rust implementation bound into declarative topology through the Node Registry.

## Reviewer

An isolated semantic evaluator that emits a typed verdict and defects. It does not override deterministic validators.

## Reviser

An agent/node that receives explicit defects and produces a corrected candidate within bounded rounds.

## Runtime Skill

A thin user-facing Skill that selects/parameterizes/invokes a production workflow and explains outcomes.

## Sandbox backend capability

A control that a backend can actually enforce, such as filesystem isolation, network denial, memory limits, or PID limits.

## Skill Evidence Package

The candidate Skill plus successes, failures, corrections, examples, usage, costs, permissions, and reuse evidence used for promotion.

## Skill runtime manifest

The proposed `skill.runtime.toml` extension declaring scripts, resources, schemas, integrity hashes, and sandbox requirements.

## Source truth

The application-authoritative store and semantics for data, evidence, ACLs, and publication. Platform sessions/artifacts do not automatically become source truth.

## Structural replay

Re-execution or verification of observable graph events, model/tool fixtures, artifacts, and terminal behavior without requiring identical hidden reasoning or free-form text.

## Typed abstention

A first-class terminal result stating that the workflow did not publish a claimed-success output, with reason and diagnostics.

## Workflow package

A versioned unit containing workflow definition, lockfile, prompts, schemas, Skills or Skill references, evals, manifests, and licenses.

## Workflow specification

The human-authored external TOML schema.

## Workdir manager

The component that allocates, materializes, manifests, publishes, retains, and cleans per-run directories.
