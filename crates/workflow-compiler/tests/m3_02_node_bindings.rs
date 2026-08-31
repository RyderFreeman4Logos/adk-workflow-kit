use std::{cell::RefCell, collections::BTreeMap};

use workflow_compiler::{
    BindingCategory, BindingRef, PlanResolutionErrorKind, RegistryResolutionError, ResolvedBinding,
    ResolvedRuntimePlan, RuntimePlanRegistry, RuntimePlanRequest, WorkflowLock, compile_str,
};

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "bindings"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
model = { role = "worker", id = "worker-model", version = "1" }
tool = { id = "echo", version = "1" }
[[nodes]]
id = "reviewer"
kind = "agent"
model = { role = "reviewer", id = "reviewer-model", version = "1" }
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "worker"
to = "reviewer"
[[edges]]
from = "reviewer"
to = "done"
"#;

#[test]
fn rejects_invalid_binding_placement_and_reviewer_tool() {
    let non_agent = WORKFLOW.replace("kind = \"agent\"", "kind = \"action\"");
    assert!(compile_str("non-agent.toml", &non_agent).is_err());
    let reviewer_tool = WORKFLOW.replace(
        "model = { role = \"reviewer\", id = \"reviewer-model\", version = \"1\" }",
        "model = { role = \"reviewer\", id = \"reviewer-model\", version = \"1\" }\ntool = { id = \"echo\", version = \"1\" }",
    );
    assert!(compile_str("reviewer-tool.toml", &reviewer_tool).is_err());
}

#[test]
fn canonical_node_bindings_drive_ir_and_lock_identity() {
    let worker = compile_str("worker.toml", WORKFLOW).expect("worker compiles");
    let changed = WORKFLOW.replace("worker-model", "other-model");
    let other = compile_str("other.toml", &changed).expect("other compiles");
    assert_ne!(worker.ir().canonical_hash(), other.ir().canonical_hash());
    assert_ne!(
        WorkflowLock::try_from_plan(&worker)
            .expect("worker lock")
            .ir_hash(),
        WorkflowLock::try_from_plan(&other)
            .expect("other lock")
            .ir_hash()
    );
}

#[derive(Default)]
struct Registry {
    entries: BTreeMap<(BindingCategory, String, String), ResolvedBinding>,
    calls: RefCell<Vec<(BindingCategory, String, String)>>,
    ambiguous: Option<BindingCategory>,
    empty: Option<BindingCategory>,
}

impl Registry {
    fn all() -> Self {
        let mut entries = BTreeMap::new();
        for (category, id) in [
            (BindingCategory::Model, "worker-model"),
            (BindingCategory::Model, "reviewer-model"),
            (BindingCategory::Tool, "echo"),
        ] {
            entries.insert(
                (category, id.to_owned(), "1".to_owned()),
                ResolvedBinding::new(id, "1"),
            );
        }
        Self {
            entries,
            ..Self::default()
        }
    }
}

impl RuntimePlanRegistry for Registry {
    fn resolve(
        &self,
        category: BindingCategory,
        binding: &BindingRef,
    ) -> Result<ResolvedBinding, RegistryResolutionError> {
        self.calls.borrow_mut().push((
            category,
            binding.id().to_owned(),
            binding.version().to_owned(),
        ));
        if self.ambiguous == Some(category) {
            return Err(RegistryResolutionError::ambiguous(category));
        }
        if self.empty == Some(category) {
            return Ok(ResolvedBinding::new("", ""));
        }
        self.entries
            .get(&(
                category,
                binding.id().to_owned(),
                binding.version().to_owned(),
            ))
            .cloned()
            .ok_or_else(|| RegistryResolutionError::missing(category, binding))
    }
}

fn request(source: &str) -> RuntimePlanRequest {
    let plan = compile_str("bindings.toml", source).expect("workflow compiles");
    RuntimePlanRequest::from_ir(plan.ir())
}

#[test]
fn resolved_plan_preserves_per_node_mapping() {
    let registry = Registry::all();
    let plan = ResolvedRuntimePlan::resolve(request(WORKFLOW), &registry).expect("plan resolves");
    assert_eq!(
        registry.calls.into_inner(),
        [
            (BindingCategory::Model, "reviewer-model".into(), "1".into()),
            (BindingCategory::Model, "worker-model".into(), "1".into()),
            (BindingCategory::Tool, "echo".into(), "1".into()),
        ]
    );
    let projection = plan.explain();
    assert!(projection.contains("reviewer"));
    assert!(projection.contains("worker"));
}

#[test]
fn node_binding_resolution_fails_closed() {
    let missing_model = WORKFLOW.replace(
        "model = { role = \"worker\", id = \"worker-model\", version = \"1\" }\n",
        "",
    );
    let cases = [
        (
            ResolvedRuntimePlan::resolve(request(&missing_model), &Registry::all()),
            PlanResolutionErrorKind::MissingBinding,
            BindingCategory::Model,
            "worker",
        ),
        (
            ResolvedRuntimePlan::resolve(request(WORKFLOW), &Registry::default()),
            PlanResolutionErrorKind::MissingBinding,
            BindingCategory::Model,
            "reviewer",
        ),
        (
            ResolvedRuntimePlan::resolve(
                request(WORKFLOW),
                &Registry {
                    ambiguous: Some(BindingCategory::Model),
                    ..Registry::all()
                },
            ),
            PlanResolutionErrorKind::AmbiguousBinding,
            BindingCategory::Model,
            "reviewer",
        ),
        (
            ResolvedRuntimePlan::resolve(
                request(WORKFLOW),
                &Registry {
                    empty: Some(BindingCategory::Model),
                    ..Registry::all()
                },
            ),
            PlanResolutionErrorKind::InvalidBinding,
            BindingCategory::Model,
            "reviewer",
        ),
    ];
    for (result, kind, category, node_id) in cases {
        let error = result.expect_err("node binding must fail closed");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.category(), Some(category));
        assert_eq!(error.node_id(), Some(node_id));
        assert!(error.to_string().contains(node_id));
    }

    let mut no_tool = Registry::all();
    no_tool
        .entries
        .remove(&(BindingCategory::Tool, "echo".into(), "1".into()));
    let error = ResolvedRuntimePlan::resolve(request(WORKFLOW), &no_tool)
        .expect_err("unknown tool must fail closed");
    assert_eq!(error.kind(), PlanResolutionErrorKind::MissingBinding);
    assert_eq!(error.category(), Some(BindingCategory::Tool));
    assert!(error.to_string().contains("worker"));
}
