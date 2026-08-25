use workflow_compiler::{
    GraphBuildError, GraphBuilder, ModelRegistry, NodeRegistry, PredicateRegistry, RegistryBinding,
    RegistryCategory, RegistryEntry, RegistryNotFound, SkillRegistry, ToolRegistry,
    ValidatorRegistry,
};
use workflow_spec::parse_str;

struct Registry {
    id: &'static str,
    version: &'static str,
    implementation: (),
}

macro_rules! registry_impl {
    ($trait:ident, $category:ident) => {
        impl $trait for Registry {
            type Implementation = ();

            fn resolve(
                &self,
                id: &str,
                version: &str,
            ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
                if (id, version) == (self.id, self.version) {
                    Ok(RegistryEntry::new(
                        &self.implementation,
                        self.id,
                        self.version,
                    ))
                } else {
                    Err(RegistryNotFound::new(
                        RegistryCategory::$category,
                        id,
                        version,
                    ))
                }
            }
        }
    };
}

registry_impl!(ModelRegistry, Model);
registry_impl!(ToolRegistry, Tool);
registry_impl!(NodeRegistry, Node);
registry_impl!(ValidatorRegistry, Validator);
registry_impl!(PredicateRegistry, Predicate);
registry_impl!(SkillRegistry, Skill);

const WORKFLOW: &str = r#"
schema_version = 1

[workflow]
id = "builder"
version = "1"
entry = "registered"

[[nodes]]
id = "registered"
kind = "registered"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "registered"
to = "done"
"#;

fn builder<'a>(
    registry: &'a Registry,
) -> GraphBuilder<'a, Registry, Registry, Registry, Registry, Registry, Registry> {
    GraphBuilder::new(registry, registry, registry, registry, registry, registry)
}

#[test]
fn builds_validated_graph_after_exact_registry_resolution() {
    let registry = Registry {
        id: "registered",
        version: "1",
        implementation: (),
    };
    let spec = parse_str("builder.workflow.toml", WORKFLOW).expect("fixture should parse");

    let graph = builder(&registry)
        .build(
            &spec,
            [RegistryBinding::new(
                RegistryCategory::Node,
                "registered",
                "1",
            )],
        )
        .expect("exact registered node should build");

    assert_eq!(graph.ir().nodes().len(), 2);
    assert_eq!(graph.registry_binding_count(), 1);
}

#[test]
fn rejects_missing_exact_registry_entry_without_graph() {
    let registry = Registry {
        id: "registered",
        version: "1",
        implementation: (),
    };
    let spec = parse_str("builder.workflow.toml", WORKFLOW).expect("fixture should parse");

    assert!(matches!(
        builder(&registry).build(
            &spec,
            [RegistryBinding::new(RegistryCategory::Node, "registered", "2")],
        ),
        Err(GraphBuildError::Registry(error))
            if error.category() == RegistryCategory::Node
                && error.id() == "registered"
                && error.version() == "2"
    ));
}
