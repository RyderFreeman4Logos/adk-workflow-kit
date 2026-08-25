# UP-002 Skill Resource and Script Hooks

## Scope

This document proposes the smallest upstream ADK-Rust extension needed for an activated Skill to expose declared resources and bounded scripts. It is a design proposal, not a runtime implementation, parser, executor, crawler, or GitHub automation. The proposal reuses the SKILL-004 contracts already present in this repository and does not introduce a second Skill runtime.

## Existing SKILL-004 contracts to preserve

The upstream design should keep these contracts as the single source of truth:

- `DeclaredSkillResource` identifies a non-executable resource and binds it to its declared SHA-256 digest.
- `DeclaredSkillScript` identifies a script, package-relative path, closed runtime name, input schema, output schema, digest, and sandbox capabilities.
- `skill.runtime.toml` is the companion manifest. Its version, Skill identity, resource declarations, and script declarations are parsed and canonicalized before planning.
- `SkillRuntimeLock` binds the activated Skill, manifest, scripts, resources, schemas, and content digests. A plan is invalid when any identity, path, runtime, schema, capability, count, or digest differs from the lock.
- `ScriptPlan` is a non-executable plan selected by declared script ID. The caller supplies typed input bytes, never a host command line or arbitrary path.
- `ScriptDeniedKind` and `SkillRuntimeManifestError` are typed, privacy-safe failures. Boundary failures must not serialize authored input, paths, commands, or secret-bearing content.

These types remain compiler/runtime boundary contracts. ADK-Rust should provide the upstream capability, while this repository keeps its application-domain schemas independent of ADK implementation types.

## Proposed hooks

### Resource hook

Add an ADK-Rust Skill resource hook that accepts an activated Skill identity, its validated `skill.runtime.toml` declaration, and the matching `SkillRuntimeLock`. The hook receives a `SkillResourceId`, not a filesystem path. It should:

1. require the resource to be declared by `DeclaredSkillResource`;
2. require the lock to bind the activated Skill, manifest, resource identity, and digest;
3. resolve the package-relative resource under the Skill root;
4. reject absolute paths, traversal, symlink escapes, undeclared globs, unsupported file types, and size or aggregate-read budget violations;
5. return bounded bytes or a typed denial with the resource identity and observed digest omitted from user-authored payloads where policy requires it;
6. expose provenance and the verified content digest so callers can cite the exact resource version.

The hook is read-only. Large resources are returned through an explicit paginated request or artifact handle rather than being copied wholesale into model context.

### Script hook

Add an ADK-Rust Skill script hook that accepts an activated Skill identity, a validated manifest and lock, a declared script ID, and JSON input validated against the declared input schema. The hook should:

1. select only a `DeclaredSkillScript` by ID;
2. verify the lock before planning or opening the script;
3. enforce the package-relative path grammar and content digest;
4. select only the closed runtime admitted by the upstream release (SKILL-004 currently plans `python3`);
5. validate input and reserve bounded time, memory, PID, disk, and output budgets;
6. execute inside the run sandbox with only declared mounts and capabilities, with network denied unless an explicit policy permits it;
7. validate structured output against the declared output schema;
8. return a bounded result or a typed `ScriptDeniedKind`/execution failure without accepting a caller-supplied command, interpreter flags, or arbitrary path.

The hook is an execution boundary, not a generic host shell tool. Script IDs and schema/resource IDs are the stable API; package layout and implementation runtime remain manifest-controlled and lock-bound.

## Boundary and failure rules

The effective capability set remains the intersection of compiled runtime capabilities, workflow-declared tools, active node tools, Skill allowed tools, actor scopes, tenant and role policy, and sandbox capabilities. An empty or denied intersection fails closed. Skills never grant permissions.

Manifest parsing, activation identity, resource lookup, lock verification, path containment, digest verification, schema validation, capability checks, and execution-budget checks must remain deterministic and typed. No model judgement may waive them. An upstream hook may add richer typed failures, but it must not replace or weaken the existing SKILL-004 failure categories.

## Upstream adoption shape

Propose the resource and script hooks as composable ADK-Rust interfaces around the existing activation, resource, sandbox, and tool contracts. The initial upstream contribution should include:

- the ID-based resource and script hook interfaces;
- lock-bound validation before any side effect;
- a reference sandbox adapter that is explicit about unsupported capabilities;
- typed denial and execution failures with redaction tests;
- focused tests for traversal, symlink escape, digest drift, runtime drift, schema failure, capability denial, budget exhaustion, and caller-supplied command rejection.

This repository should adopt the upstream capability only after the released ADK-Rust contract satisfies these invariants. Until then, the existing SKILL-004 contracts remain the local design baseline; no parallel manifest, parser, planner, or runtime should be created.

## Non-goals

This proposal does not define a new runtime, arbitrary command execution, live package discovery, automatic upstream filing, hosted CI, a GitHub workflow, a planning-pack change, or product runtime code. It also does not make scripts a permission source or turn prose in `SKILL.md` into executable workflow behavior.
