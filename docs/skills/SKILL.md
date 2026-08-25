# Skill Contract

A Skill is a validated, versioned resource boundary. `SkillManifest` parses the front matter identity and `activate_skill` returns a `SkillActivationReceipt` for the exact `SkillId` and version. Activation is discovery and validation; it does not execute scripts.

## Runtime declaration

`SkillRuntimeManifest` parses a v1 `skill.runtime.toml` declaration. It requires an exact Skill identity and version, bounded non-empty declarations, canonical script/resource ordering, unique identifiers and paths, valid SHA-256 digests, schema references that name declared resources, and known non-repeated `SandboxCapability` values. `parse_for_activation` rejects `ActivationMismatch`.

`SkillRuntimeLock` binds the Skill markdown, declared scripts, and resources entirely in memory. It verifies the Skill manifest, input sets, every declared digest, referenced JSON schemas, and the canonical manifest bytes before producing an immutable lock. Missing or mismatched inputs fail closed; no declaration is inferred from a path or runtime.

## Planning and execution

`plan_script_execution` produces a `ScriptPlan` from a locked manifest and requested input. `ScriptDenied` and `ScriptDeniedKind` distinguish invalid requests, missing scripts/resources, capability failures, and other fixed denial categories. A plan is not execution: the runtime must still enforce the lock and declared capabilities at the platform boundary.

Skill evidence is represented by `SkillEvidence`, `SkillEvidencePackage`, `SkillPlanningStage`, and `SkillPromotion`. These types keep discovery, planning, activation, and promotion evidence explicit instead of treating arbitrary text as an executable Skill contract.
