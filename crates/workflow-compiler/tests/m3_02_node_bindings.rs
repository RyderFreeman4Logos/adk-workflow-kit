use std::{cell::RefCell, collections::BTreeMap};

use workflow_compiler::{
    BindingCategory, BindingRef, BindingValidationError, CompileError, PlanResolutionErrorKind,
    RegistryResolutionError, ResolvedBinding, ResolvedRuntimePlan, RuntimePlanRegistry,
    RuntimePlanRequest, WorkflowLock, compile_str,
};
use workflow_ir::IrModelRole;

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
    assert!(matches!(
        compile_str("non-agent.toml", &non_agent),
        Err(CompileError::Binding(
            BindingValidationError::InvalidPlacement
        ))
    ));
    let reviewer_tool = WORKFLOW.replace(
        "model = { role = \"reviewer\", id = \"reviewer-model\", version = \"1\" }",
        "model = { role = \"reviewer\", id = \"reviewer-model\", version = \"1\" }\ntool = { id = \"echo\", version = \"1\" }",
    );
    assert!(matches!(
        compile_str("reviewer-tool.toml", &reviewer_tool),
        Err(CompileError::Binding(BindingValidationError::ReviewerTool))
    ));
}

#[test]
fn canonical_node_bindings_drive_ir_and_lock_identity() {
    let baseline = compile_str("baseline.toml", WORKFLOW).expect("baseline compiles");
    let variants = [
        ("model id", WORKFLOW.replace("worker-model", "other-model")),
        (
            "model role",
            WORKFLOW.replace("role = \"reviewer\"", "role = \"worker\""),
        ),
        (
            "model version",
            WORKFLOW.replacen("version = \"1\" }", "version = \"2\" }", 1),
        ),
        (
            "tool id",
            WORKFLOW.replace("id = \"echo\"", "id = \"other-tool\""),
        ),
        (
            "tool version",
            WORKFLOW.replace(
                "tool = { id = \"echo\", version = \"1\" }",
                "tool = { id = \"echo\", version = \"2\" }",
            ),
        ),
    ];
    for (name, source) in variants {
        let changed = compile_str(format!("{name}.toml"), &source).expect("variant compiles");
        assert_ne!(
            baseline.ir().canonical_hash(),
            changed.ir().canonical_hash(),
            "{name} must change canonical identity"
        );
        assert_ne!(
            WorkflowLock::try_from_plan(&baseline)
                .expect("baseline lock")
                .ir_hash(),
            WorkflowLock::try_from_plan(&changed)
                .expect("variant lock")
                .ir_hash(),
            "{name} must change lock identity"
        );
    }

    let ownership_baseline = WORKFLOW.replace("role = \"reviewer\"", "role = \"worker\"");
    let ownership_swapped = ownership_baseline
        .replace("worker-model", "swap-model")
        .replace("reviewer-model", "worker-model")
        .replace("swap-model", "reviewer-model");
    let ownership_baseline =
        compile_str("ownership-baseline.toml", &ownership_baseline).expect("baseline compiles");
    let ownership_swapped =
        compile_str("ownership-swapped.toml", &ownership_swapped).expect("swap compiles");
    assert_ne!(
        ownership_baseline.ir().canonical_hash(),
        ownership_swapped.ir().canonical_hash(),
        "moving the same identities between nodes must change canonical identity"
    );
    assert_ne!(
        WorkflowLock::try_from_plan(&ownership_baseline)
            .expect("ownership baseline lock")
            .ir_hash(),
        WorkflowLock::try_from_plan(&ownership_swapped)
            .expect("ownership swapped lock")
            .ir_hash(),
        "moving the same identities between nodes must change lock identity"
    );

    let worker_node = "[[nodes]]\nid = \"worker\"\nkind = \"agent\"\nmodel = { role = \"worker\", id = \"worker-model\", version = \"1\" }\ntool = { id = \"echo\", version = \"1\" }\n";
    let reviewer_node = "[[nodes]]\nid = \"reviewer\"\nkind = \"agent\"\nmodel = { role = \"reviewer\", id = \"reviewer-model\", version = \"1\" }\n";
    let reordered = WORKFLOW.replace(
        &format!("{worker_node}{reviewer_node}"),
        &format!("{reviewer_node}{worker_node}"),
    );
    let reordered = compile_str("reordered.toml", &reordered).expect("reordered compiles");
    assert_eq!(
        baseline.ir().canonical_hash(),
        reordered.ir().canonical_hash()
    );
    assert_eq!(
        WorkflowLock::try_from_plan(&baseline)
            .expect("baseline lock")
            .ir_hash(),
        WorkflowLock::try_from_plan(&reordered)
            .expect("reordered lock")
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
    let reviewer = plan.node_model("reviewer").expect("reviewer binding");
    assert_eq!(
        plan.node_model_role("reviewer"),
        Some(IrModelRole::Reviewer)
    );
    assert_eq!((reviewer.id(), reviewer.version()), ("reviewer-model", "1"));
    assert!(plan.node_tool("reviewer").is_none());
    let worker = plan.node_model("worker").expect("worker binding");
    assert_eq!(plan.node_model_role("worker"), Some(IrModelRole::Worker));
    assert_eq!((worker.id(), worker.version()), ("worker-model", "1"));
    let tool = plan.node_tool("worker").expect("worker tool binding");
    assert_eq!((tool.id(), tool.version()), ("echo", "1"));
    assert_ne!(worker, reviewer);
    assert!(plan.node_model("done").is_none());
    assert!(plan.node_tool("done").is_none());
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
    assert_eq!(error.node_id(), Some("worker"));
    assert!(error.to_string().contains("worker"));

    let error = ResolvedRuntimePlan::resolve(
        request(WORKFLOW),
        &Registry {
            ambiguous: Some(BindingCategory::Tool),
            ..Registry::all()
        },
    )
    .expect_err("ambiguous tool must fail closed");
    assert_eq!(error.kind(), PlanResolutionErrorKind::AmbiguousBinding);
    assert_eq!(error.category(), Some(BindingCategory::Tool));
    assert_eq!(error.node_id(), Some("worker"));

    let error = ResolvedRuntimePlan::resolve(
        request(WORKFLOW),
        &Registry {
            empty: Some(BindingCategory::Tool),
            ..Registry::all()
        },
    )
    .expect_err("empty tool identity must fail closed");
    assert_eq!(error.kind(), PlanResolutionErrorKind::InvalidBinding);
    assert_eq!(error.category(), Some(BindingCategory::Tool));
    assert_eq!(error.node_id(), Some("worker"));
}
