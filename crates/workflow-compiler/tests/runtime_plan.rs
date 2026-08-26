use std::collections::BTreeMap;

use workflow_compiler::{
    BindingCategory, BindingRef, CapabilitySet, PlanResolutionErrorKind, ResolvedBinding,
    ResolvedRuntimePlan, RuntimePlanRegistry, RuntimePlanRequest,
};
use workflow_ir::WorkflowIr;
use workflow_spec::parse_str;

const SOURCE: &str = r#"
schema_version = 1
edges = []
[workflow]
id = "demo"
version = "1"
entry = "done"
[[nodes]]
id = "done"
kind = "terminal"
"#;

fn request() -> RuntimePlanRequest {
    let spec = parse_str("fixture.toml", SOURCE).expect("fixture parses");
    RuntimePlanRequest::from_ir(&WorkflowIr::from(&spec))
        .with_model("model", "1")
        .with_tool("tool", "1")
        .with_validator("validator", "1")
        .with_predicate("predicate", "1")
        .with_skill("skill", "1")
        .with_sandbox("sandbox", "1")
        .with_workdir("workdir", "1")
        .with_checkpoint("checkpoint", "1")
        .with_event("event", "1")
        .with_artifact("artifact", "1")
}

#[derive(Default)]
struct FakeRegistry {
    entries: BTreeMap<(BindingCategory, String, String), ResolvedBinding>,
}

impl FakeRegistry {
    fn all() -> Self {
        let mut registry = Self::default();
        for (category, id) in [
            (BindingCategory::Model, "model"),
            (BindingCategory::Tool, "tool"),
            (BindingCategory::Validator, "validator"),
            (BindingCategory::Predicate, "predicate"),
            (BindingCategory::Skill, "skill"),
            (BindingCategory::Sandbox, "sandbox"),
            (BindingCategory::Workdir, "workdir"),
            (BindingCategory::Checkpoint, "checkpoint"),
            (BindingCategory::Event, "event"),
            (BindingCategory::Artifact, "artifact"),
        ] {
            registry.entries.insert(
                (category, id.to_owned(), "1".to_owned()),
                ResolvedBinding::new(id, "1"),
            );
        }
        registry
    }
}

impl RuntimePlanRegistry for FakeRegistry {
    fn resolve(
        &self,
        category: BindingCategory,
        binding: &BindingRef,
    ) -> Result<ResolvedBinding, workflow_compiler::RegistryResolutionError> {
        self.entries
            .get(&(
                category,
                binding.id().to_owned(),
                binding.version().to_owned(),
            ))
            .cloned()
            .ok_or_else(|| workflow_compiler::RegistryResolutionError::missing(category, binding))
    }
}

#[test]
fn equivalent_inputs_have_the_same_plan_hash() {
    let registry = FakeRegistry::all();
    let left = ResolvedRuntimePlan::resolve(request(), &registry).expect("left resolves");
    let right = ResolvedRuntimePlan::resolve(request(), &registry).expect("right resolves");
    assert_eq!(left.plan_hash(), right.plan_hash());
    assert_eq!(left.resume_identity(), right.resume_identity());
}

#[test]
fn missing_and_ambiguous_bindings_fail_before_execution() {
    let mut registry = FakeRegistry::all();
    registry
        .entries
        .remove(&(BindingCategory::Tool, "tool".into(), "1".into()));
    let error = ResolvedRuntimePlan::resolve(request(), &registry).expect_err("must fail closed");
    assert_eq!(error.kind(), PlanResolutionErrorKind::MissingBinding);

    let mut request = request();
    request.set_ambiguous(BindingCategory::Model, BindingRef::new("model", "1"));
    let error =
        ResolvedRuntimePlan::resolve(request, &FakeRegistry::all()).expect_err("must fail closed");
    assert_eq!(error.kind(), PlanResolutionErrorKind::AmbiguousBinding);
}

#[test]
fn effective_capabilities_only_narrow() {
    let registry = FakeRegistry::all();
    let mut narrow_request = request();
    narrow_request.set_capabilities(CapabilitySet::from(["read", "network"]));
    narrow_request.set_effective_capabilities(CapabilitySet::from(["read"]));
    let plan = ResolvedRuntimePlan::resolve(narrow_request, &registry).expect("narrowing resolves");
    assert_eq!(plan.effective_capabilities().as_slice(), &["read"]);

    let mut widening_request = request();
    widening_request.set_capabilities(CapabilitySet::from(["read"]));
    widening_request.set_effective_capabilities(CapabilitySet::from(["read", "network"]));
    let error =
        ResolvedRuntimePlan::resolve(widening_request, &registry).expect_err("widening denied");
    assert_eq!(error.kind(), PlanResolutionErrorKind::CapabilityWidening);
}

#[test]
fn projection_and_explain_output_have_no_secret_or_adk_type() {
    let registry = FakeRegistry::all();
    let plan = ResolvedRuntimePlan::resolve(request(), &registry).expect("resolves");
    let serialized = serde_json::to_string(&plan).expect("serializes");
    let explained = plan.explain();
    for output in [serialized, explained] {
        assert!(!output.contains("sk-live-secret"));
        assert!(!output.contains("adk_"));
        assert!(output.contains("<redacted>"));
    }
}

#[test]
fn resolution_covers_all_backend_neutral_projection_categories() {
    let plan = ResolvedRuntimePlan::resolve(request(), &FakeRegistry::all()).expect("resolves");
    assert_eq!(plan.models().len(), 1);
    assert_eq!(plan.tools().len(), 1);
    assert_eq!(plan.validators().len(), 1);
    assert_eq!(plan.predicates().len(), 1);
    assert_eq!(plan.skills().len(), 1);
    assert_eq!(plan.sandboxes().len(), 1);
    assert_eq!(plan.workdirs().len(), 1);
    assert_eq!(plan.checkpoints().len(), 1);
    assert_eq!(plan.events().len(), 1);
    assert_eq!(plan.artifacts().len(), 1);
}
