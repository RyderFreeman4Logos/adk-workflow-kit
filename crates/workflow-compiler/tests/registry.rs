use std::any::Any;

use workflow_compiler::{
    ModelRegistry, NodeRegistry, PredicateRegistry, RegistryCategory, RegistryEntry,
    RegistryNotFound, SkillRegistry, ToolRegistry, ValidatorRegistry,
};

#[derive(Eq, PartialEq)]
struct ModelImplementation;
#[derive(Eq, PartialEq)]
struct ToolImplementation;
#[derive(Eq, PartialEq)]
struct NodeImplementation;
#[derive(Eq, PartialEq)]
struct ValidatorImplementation;
#[derive(Eq, PartialEq)]
struct PredicateImplementation;
#[derive(Eq, PartialEq)]
struct SkillImplementation;

struct FakeRegistry<T> {
    id: &'static str,
    version: &'static str,
    implementation: T,
}

impl<T> FakeRegistry<T> {
    fn lookup(
        &self,
        category: RegistryCategory,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, T>, RegistryNotFound> {
        if (id, version) == (self.id, self.version) {
            Ok(RegistryEntry::new(
                &self.implementation,
                self.id,
                self.version,
            ))
        } else {
            Err(RegistryNotFound::new(category, id, version))
        }
    }
}

macro_rules! fake_registry_contract {
    ($trait:ident, $category:ident, $implementation:ty) => {
        impl $trait for FakeRegistry<$implementation> {
            type Implementation = $implementation;

            fn resolve(
                &self,
                id: &str,
                version: &str,
            ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
                self.lookup(RegistryCategory::$category, id, version)
            }
        }
    };
}

fake_registry_contract!(ModelRegistry, Model, ModelImplementation);
fake_registry_contract!(ToolRegistry, Tool, ToolImplementation);
fake_registry_contract!(NodeRegistry, Node, NodeImplementation);
fake_registry_contract!(ValidatorRegistry, Validator, ValidatorImplementation);
fake_registry_contract!(PredicateRegistry, Predicate, PredicateImplementation);
fake_registry_contract!(SkillRegistry, Skill, SkillImplementation);

enum FakeRegistryCase<'a> {
    Model(&'a FakeRegistry<ModelImplementation>),
    Tool(&'a FakeRegistry<ToolImplementation>),
    Node(&'a FakeRegistry<NodeImplementation>),
    Validator(&'a FakeRegistry<ValidatorImplementation>),
    Predicate(&'a FakeRegistry<PredicateImplementation>),
    Skill(&'a FakeRegistry<SkillImplementation>),
}

impl FakeRegistryCase<'_> {
    fn resolve(&self, id: &str, version: &str) -> Result<(&dyn Any, &str, &str), RegistryNotFound> {
        match self {
            Self::Model(registry) => ModelRegistry::resolve(*registry, id, version).map(|entry| {
                (
                    entry.implementation() as &dyn Any,
                    entry.id(),
                    entry.version(),
                )
            }),
            Self::Tool(registry) => ToolRegistry::resolve(*registry, id, version).map(|entry| {
                (
                    entry.implementation() as &dyn Any,
                    entry.id(),
                    entry.version(),
                )
            }),
            Self::Node(registry) => NodeRegistry::resolve(*registry, id, version).map(|entry| {
                (
                    entry.implementation() as &dyn Any,
                    entry.id(),
                    entry.version(),
                )
            }),
            Self::Validator(registry) => {
                ValidatorRegistry::resolve(*registry, id, version).map(|entry| {
                    (
                        entry.implementation() as &dyn Any,
                        entry.id(),
                        entry.version(),
                    )
                })
            }
            Self::Predicate(registry) => {
                PredicateRegistry::resolve(*registry, id, version).map(|entry| {
                    (
                        entry.implementation() as &dyn Any,
                        entry.id(),
                        entry.version(),
                    )
                })
            }
            Self::Skill(registry) => SkillRegistry::resolve(*registry, id, version).map(|entry| {
                (
                    entry.implementation() as &dyn Any,
                    entry.id(),
                    entry.version(),
                )
            }),
        }
    }

    fn is_original(&self, implementation: &dyn Any) -> bool {
        match self {
            Self::Model(registry) => implementation
                .downcast_ref::<ModelImplementation>()
                .is_some_and(|value| std::ptr::eq(value, &registry.implementation)),
            Self::Tool(registry) => implementation
                .downcast_ref::<ToolImplementation>()
                .is_some_and(|value| std::ptr::eq(value, &registry.implementation)),
            Self::Node(registry) => implementation
                .downcast_ref::<NodeImplementation>()
                .is_some_and(|value| std::ptr::eq(value, &registry.implementation)),
            Self::Validator(registry) => implementation
                .downcast_ref::<ValidatorImplementation>()
                .is_some_and(|value| std::ptr::eq(value, &registry.implementation)),
            Self::Predicate(registry) => implementation
                .downcast_ref::<PredicateImplementation>()
                .is_some_and(|value| std::ptr::eq(value, &registry.implementation)),
            Self::Skill(registry) => implementation
                .downcast_ref::<SkillImplementation>()
                .is_some_and(|value| std::ptr::eq(value, &registry.implementation)),
        }
    }
}

struct Case<'a> {
    category: RegistryCategory,
    registry: FakeRegistryCase<'a>,
}

#[test]
fn fake_registries_resolve_only_exact_versioned_entries() {
    let models = FakeRegistry {
        id: "model-id",
        version: "1",
        implementation: ModelImplementation,
    };
    let tools = FakeRegistry {
        id: "tool-id",
        version: "1",
        implementation: ToolImplementation,
    };
    let nodes = FakeRegistry {
        id: "node-id",
        version: "1",
        implementation: NodeImplementation,
    };
    let validators = FakeRegistry {
        id: "validator-id",
        version: "1",
        implementation: ValidatorImplementation,
    };
    let predicates = FakeRegistry {
        id: "predicate-id",
        version: "1",
        implementation: PredicateImplementation,
    };
    let skills = FakeRegistry {
        id: "skill-id",
        version: "1",
        implementation: SkillImplementation,
    };
    let cases = [
        Case {
            category: RegistryCategory::Model,
            registry: FakeRegistryCase::Model(&models),
        },
        Case {
            category: RegistryCategory::Tool,
            registry: FakeRegistryCase::Tool(&tools),
        },
        Case {
            category: RegistryCategory::Node,
            registry: FakeRegistryCase::Node(&nodes),
        },
        Case {
            category: RegistryCategory::Validator,
            registry: FakeRegistryCase::Validator(&validators),
        },
        Case {
            category: RegistryCategory::Predicate,
            registry: FakeRegistryCase::Predicate(&predicates),
        },
        Case {
            category: RegistryCategory::Skill,
            registry: FakeRegistryCase::Skill(&skills),
        },
    ];

    for case in cases {
        let id = match case.category {
            RegistryCategory::Model => "model-id",
            RegistryCategory::Tool => "tool-id",
            RegistryCategory::Node => "node-id",
            RegistryCategory::Validator => "validator-id",
            RegistryCategory::Predicate => "predicate-id",
            RegistryCategory::Skill => "skill-id",
        };
        let resolved = case.registry.resolve(id, "1");
        match resolved {
            Ok((implementation, resolved_id, resolved_version)) => {
                assert!(case.registry.is_original(implementation));
                assert_eq!((resolved_id, resolved_version), (id, "1"));
            }
            Err(_) => unreachable!("exact entry should resolve"),
        }

        for (missing_id, missing_version) in [("wrong-id", "1"), (id, "2")] {
            match case.registry.resolve(missing_id, missing_version) {
                Ok(_) => unreachable!("only exact ID and version should resolve"),
                Err(error) => {
                    assert!(error.category() == case.category);
                    assert_eq!(error.id(), missing_id);
                    assert_eq!(error.version(), missing_version);
                }
            }
        }
    }
}

#[test]
fn registry_not_found_is_a_standard_error_with_exact_lookup_context() {
    let error = RegistryNotFound::new(RegistryCategory::Tool, "tool-id", "1");

    fn assert_standard_error<T: std::error::Error + std::fmt::Debug + std::fmt::Display>(_: &T) {}

    assert_standard_error(&error);
    assert_eq!(
        error.to_string(),
        "registry entry not found: category=Tool, id=tool-id, version=1"
    );
}
