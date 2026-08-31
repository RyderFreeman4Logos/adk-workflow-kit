use std::collections::BTreeMap;

use workflow_compiler::{
    BindingCategory, BindingRef, RegistryResolutionError, ResolvedBinding, ResolvedRuntimePlan,
    RuntimePlanRegistry, RuntimePlanRequest, compile_str,
};

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "multi-tools"
version = "1"
entry = "first"
[[nodes]]
id = "first"
kind = "agent"
model = { role = "worker", id = "worker-model", version = "1" }
tools = [{ id = "beta", version = "1" }, { id = "alpha", version = "1" }]
[[nodes]]
id = "second"
kind = "agent"
model = { role = "worker", id = "worker-model", version = "1" }
tools = [{ id = "gamma", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "first"
to = "second"
[[edges]]
from = "second"
to = "done"
"#;

struct Registry(BTreeMap<(BindingCategory, String, String), ResolvedBinding>);

impl Registry {
    fn all() -> Self {
        Self(
            [
                (BindingCategory::Model, "worker-model"),
                (BindingCategory::Tool, "alpha"),
                (BindingCategory::Tool, "beta"),
                (BindingCategory::Tool, "gamma"),
            ]
            .into_iter()
            .map(|(category, id)| {
                (
                    (category, id.into(), "1".into()),
                    ResolvedBinding::new(id, "1"),
                )
            })
            .collect(),
        )
    }
}

impl RuntimePlanRegistry for Registry {
    fn resolve(
        &self,
        category: BindingCategory,
        binding: &BindingRef,
    ) -> Result<ResolvedBinding, RegistryResolutionError> {
        self.0
            .get(&(category, binding.id().into(), binding.version().into()))
            .cloned()
            .ok_or_else(|| RegistryResolutionError::missing(category, binding))
    }
}

#[test]
fn resolves_named_subsets_and_hashes_registry_metadata() {
    let first = compile_str("first.toml", WORKFLOW).expect("multi-tool workflow compiles");
    let reordered = WORKFLOW.replace(
        "{ id = \"beta\", version = \"1\" }, { id = \"alpha\", version = \"1\" }",
        "{ id = \"alpha\", version = \"1\" }, { id = \"beta\", version = \"1\" }",
    );
    let reordered = compile_str("reordered.toml", &reordered).expect("reordered workflow compiles");
    assert_eq!(first.ir().canonical_hash(), reordered.ir().canonical_hash());

    let registry = Registry::all();
    let plan = ResolvedRuntimePlan::resolve(RuntimePlanRequest::from_ir(first.ir()), &registry)
        .expect("registry resolves");
    assert_eq!(
        plan.node_tools("first")
            .iter()
            .map(|tool| tool.id())
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    assert_eq!(
        plan.node_tools("second")
            .iter()
            .map(|tool| tool.id())
            .collect::<Vec<_>>(),
        ["gamma"]
    );
    assert_eq!(
        plan.plan_hash(),
        ResolvedRuntimePlan::resolve(RuntimePlanRequest::from_ir(reordered.ir()), &registry)
            .expect("reordered registry resolves")
            .plan_hash(),
        "source order does not alter a canonical plan"
    );
}
