use workflow_compiler::{
    BindingCategory, BindingRef, BindingValidationError, CompileError, RegistryResolutionError,
    ResolvedBinding, ResolvedRuntimePlan, RuntimePlanRegistry, RuntimePlanRequest, compile_str,
};

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "skill-plan"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
model = { role = "worker", id = "worker", version = "1" }
skills = [{ id = "code-investigation", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "worker"
to = "done"
"#;

struct Registry;

impl RuntimePlanRegistry for Registry {
    fn resolve(
        &self,
        category: BindingCategory,
        binding: &BindingRef,
    ) -> Result<ResolvedBinding, RegistryResolutionError> {
        match (category, binding.id(), binding.version()) {
            (BindingCategory::Model, "worker", "1") => {
                Ok(ResolvedBinding::new("worker", "1").with_metadata_identity("worker-lock"))
            }
            (BindingCategory::Skill, "code-investigation", "1") => {
                Ok(ResolvedBinding::new("code-investigation", "1")
                    .with_metadata_identity("skill-lock"))
            }
            _ => Err(RegistryResolutionError::missing(category, binding)),
        }
    }
}

#[test]
fn skill_bindings_require_worker_agents() {
    let non_agent = WORKFLOW.replace("kind = \"agent\"", "kind = \"action\"");
    assert!(matches!(
        compile_str("non-agent-skill.toml", &non_agent),
        Err(CompileError::Binding(
            BindingValidationError::InvalidPlacement
        ))
    ));

    let reviewer = WORKFLOW.replace("role = \"worker\"", "role = \"reviewer\"");
    assert!(matches!(
        compile_str("reviewer-skill.toml", &reviewer),
        Err(CompileError::Binding(BindingValidationError::ReviewerTool))
    ));
}

#[test]
fn resolves_exact_node_skill_and_lock() {
    let compiled = compile_str("skill-plan.toml", WORKFLOW).expect("workflow compiles");
    let plan = ResolvedRuntimePlan::resolve(RuntimePlanRequest::from_ir(compiled.ir()), &Registry)
        .expect("exact skill resolves");

    assert_eq!(
        plan.node_skills("worker")
            .iter()
            .map(|skill| (skill.id(), skill.version(), skill.metadata_identity()))
            .collect::<Vec<_>>(),
        vec![("code-investigation", "1", "skill-lock")],
    );
    assert_ne!(plan.plan_hash(), "");
}

#[test]
fn rejects_reserved_skill_tool_names_during_compiler_admission() {
    for name in ["activate_skill", "read_skill_resource", "run_skill_script"] {
        let workflow = WORKFLOW.replace(
            "skills = [{ id = \"code-investigation\", version = \"1\" }]",
            &format!("tools = [{{ id = \"{name}\", version = \"1\" }}]"),
        );
        assert!(compile_str("reserved-static-tool.toml", &workflow).is_err());
    }
}
