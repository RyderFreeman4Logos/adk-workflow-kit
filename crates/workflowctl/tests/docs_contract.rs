use std::fs;

const DOCS: &[(&str, &[&str])] = &[
    (
        "docs/architecture/ARCHITECTURE.md",
        &[
            "# Architecture",
            "workflow-spec",
            "workflow-ir",
            "workflow-compiler",
            "workflow-runtime",
            "workflow-review",
            "workflow-adk",
        ],
    ),
    (
        "docs/spec/WORKFLOW_SPEC.md",
        &[
            "# Workflow Specification",
            "WORKFLOW_SCHEMA_VERSION_V1",
            "NodeKind",
            "RouteOperator",
            "timeout_ms",
        ],
    ),
    (
        "docs/skills/SKILL.md",
        &[
            "# Skill Contract",
            "SkillManifest",
            "SkillRuntimeManifest",
            "SkillRuntimeLock",
            "ScriptDenied",
        ],
    ),
    (
        "docs/sandbox/SANDBOX.md",
        &[
            "# Sandbox Contract",
            "evaluate_context_policy",
            "ContextPolicyDeniedKind",
            "NetworkProfile",
            "SandboxCapability",
        ],
    ),
    (
        "docs/security/SECURITY.md",
        &[
            "# Security Contract",
            "audit_dependencies",
            "AuditDisposition",
            "BoundaryMiss",
            "redact",
        ],
    ),
];

#[test]
fn published_docs_cover_implemented_contracts_and_boundaries() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (relative_path, required_sections) in DOCS {
        let path = workspace.join(relative_path);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("required docs contract {relative_path}: {error}"));
        for required in *required_sections {
            assert!(
                contents.contains(required),
                "{relative_path} must document {required}"
            );
        }
    }
}
