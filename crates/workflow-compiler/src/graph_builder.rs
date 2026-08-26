use std::fmt;

use workflow_spec::WorkflowSpec;

use crate::{
    CompileError, CompiledPlan, ModelRegistry, NodeRegistry, PredicateRegistry, RegistryCategory,
    RegistryEntry, RegistryNotFound, SkillRegistry, ToolRegistry, ValidatorRegistry, validated_ir,
};

/// An exact registry identity to resolve while composing a graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryBinding {
    category: RegistryCategory,
    id: String,
    version: String,
}

impl RegistryBinding {
    /// Creates an exact, versioned registry binding request.
    pub fn new(category: RegistryCategory, id: &str, version: &str) -> Self {
        Self {
            category,
            id: id.to_owned(),
            version: version.to_owned(),
        }
    }

    /// Returns the registry category to resolve.
    pub fn category(&self) -> RegistryCategory {
        self.category
    }

    /// Returns the opaque registry ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact registry version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A typed rejection from graph normalization or registry composition.
#[derive(Debug)]
pub enum GraphBuildError {
    /// The source graph failed an existing compiler boundary check.
    Compile(CompileError),
    /// An exact requested registry entry was absent.
    Registry(RegistryNotFound),
    /// A registry returned an entry whose identity differs from the request.
    IdentityDrift(RegistryIdentityDrift),
}

/// The requested and returned identities of a successful but invalid registry resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryIdentityDrift {
    category: RegistryCategory,
    requested_id: String,
    requested_version: String,
    resolved_id: String,
    resolved_version: String,
}

impl RegistryIdentityDrift {
    fn new(
        category: RegistryCategory,
        binding: &RegistryBinding,
        entry: &RegistryEntry<'_, impl Sized>,
    ) -> Self {
        Self {
            category,
            requested_id: binding.id.clone(),
            requested_version: binding.version.clone(),
            resolved_id: entry.id().to_owned(),
            resolved_version: entry.version().to_owned(),
        }
    }
}

impl fmt::Display for RegistryIdentityDrift {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "registry identity drift: category={:?}, requested={:?}@{:?}, resolved={:?}@{:?}",
            self.category,
            self.requested_id,
            self.requested_version,
            self.resolved_id,
            self.resolved_version
        )
    }
}

impl std::error::Error for RegistryIdentityDrift {}

impl fmt::Display for GraphBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compile(error) => write!(formatter, "graph build failed: {error}"),
            Self::Registry(error) => write!(formatter, "graph registry binding failed: {error}"),
            Self::IdentityDrift(error) => {
                write!(formatter, "graph registry binding failed: {error}")
            }
        }
    }
}

impl std::error::Error for GraphBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compile(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::IdentityDrift(error) => Some(error),
        }
    }
}

/// Composes a validated workflow graph from the existing versioned registries.
///
/// The builder borrows registries, performs no implementation invocation, and retains only the
/// existing typed `CompiledPlan` graph. Predicate routes are resolved automatically; callers pass
/// other exact bindings because the v1 source graph carries no implementation IDs for its nodes.
pub struct GraphBuilder<'a, M, T, N, V, P, S> {
    models: &'a M,
    tools: &'a T,
    nodes: &'a N,
    validators: &'a V,
    predicates: &'a P,
    skills: &'a S,
}

impl<'a, M, T, N, V, P, S> GraphBuilder<'a, M, T, N, V, P, S>
where
    M: ModelRegistry,
    T: ToolRegistry,
    N: NodeRegistry,
    V: ValidatorRegistry,
    P: PredicateRegistry,
    S: SkillRegistry,
{
    /// Creates a builder from the six existing registry contracts.
    pub fn new(
        models: &'a M,
        tools: &'a T,
        nodes: &'a N,
        validators: &'a V,
        predicates: &'a P,
        skills: &'a S,
    ) -> Self {
        Self {
            models,
            tools,
            nodes,
            validators,
            predicates,
            skills,
        }
    }

    /// Normalizes and validates `spec`, then resolves every exact requested binding.
    pub fn build<I>(
        &self,
        spec: &WorkflowSpec,
        bindings: I,
    ) -> Result<CompiledPlan, GraphBuildError>
    where
        I: IntoIterator<Item = RegistryBinding>,
    {
        let ir = validated_ir(spec).map_err(GraphBuildError::Compile)?;
        let mut registry_binding_count = 0;

        for route in ir.routes() {
            Self::check_identity(
                RegistryCategory::Predicate,
                &RegistryBinding::new(
                    RegistryCategory::Predicate,
                    route.predicate().id(),
                    route.predicate().version(),
                ),
                self.predicates
                    .resolve(route.predicate().id(), route.predicate().version()),
            )?;
            registry_binding_count += 1;
        }

        for binding in bindings {
            self.resolve(&binding)?;
            registry_binding_count += 1;
        }

        Ok(CompiledPlan {
            ir,
            registry_binding_count,
        })
    }

    fn resolve(&self, binding: &RegistryBinding) -> Result<(), GraphBuildError> {
        match binding.category {
            RegistryCategory::Model => Self::check_identity(
                binding.category,
                binding,
                self.models.resolve(&binding.id, &binding.version),
            ),
            RegistryCategory::Tool => Self::check_identity(
                binding.category,
                binding,
                self.tools.resolve(&binding.id, &binding.version),
            ),
            RegistryCategory::Node => Self::check_identity(
                binding.category,
                binding,
                self.nodes.resolve(&binding.id, &binding.version),
            ),
            RegistryCategory::Validator => Self::check_identity(
                binding.category,
                binding,
                self.validators.resolve(&binding.id, &binding.version),
            ),
            RegistryCategory::Predicate => Self::check_identity(
                binding.category,
                binding,
                self.predicates.resolve(&binding.id, &binding.version),
            ),
            RegistryCategory::Skill => Self::check_identity(
                binding.category,
                binding,
                self.skills.resolve(&binding.id, &binding.version),
            ),
        }
    }

    fn check_identity<R>(
        category: RegistryCategory,
        binding: &RegistryBinding,
        result: Result<RegistryEntry<'_, R>, RegistryNotFound>,
    ) -> Result<(), GraphBuildError> {
        let entry = result.map_err(GraphBuildError::Registry)?;
        if entry.id() != binding.id || entry.version() != binding.version {
            return Err(GraphBuildError::IdentityDrift(RegistryIdentityDrift::new(
                category, binding, &entry,
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ModelRegistry, NodeRegistry, PredicateRegistry, RegistryEntry, SkillRegistry, ToolRegistry,
        ValidatorRegistry,
    };
    use workflow_spec::parse_str;

    struct DriftedRegistry;

    struct MissingRegistry;

    macro_rules! impl_drifted_registry {
        ($trait_name:ident) => {
            impl $trait_name for DriftedRegistry {
                type Implementation = ();

                fn resolve(
                    &self,
                    _id: &str,
                    _version: &str,
                ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
                    Ok(RegistryEntry::new(&(), "actual-id", "actual-version"))
                }
            }
        };
    }

    macro_rules! impl_missing_registry {
        ($trait_name:ident, $category:expr) => {
            impl $trait_name for MissingRegistry {
                type Implementation = ();

                fn resolve(
                    &self,
                    id: &str,
                    version: &str,
                ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
                    Err(RegistryNotFound::new($category, id, version))
                }
            }
        };
    }

    impl_drifted_registry!(ModelRegistry);
    impl_drifted_registry!(ToolRegistry);
    impl_drifted_registry!(NodeRegistry);
    impl_drifted_registry!(ValidatorRegistry);
    impl_drifted_registry!(PredicateRegistry);
    impl_drifted_registry!(SkillRegistry);

    impl_missing_registry!(ModelRegistry, RegistryCategory::Model);
    impl_missing_registry!(ToolRegistry, RegistryCategory::Tool);
    impl_missing_registry!(NodeRegistry, RegistryCategory::Node);
    impl_missing_registry!(ValidatorRegistry, RegistryCategory::Validator);
    impl_missing_registry!(PredicateRegistry, RegistryCategory::Predicate);
    impl_missing_registry!(SkillRegistry, RegistryCategory::Skill);

    fn builder(
        registry: &DriftedRegistry,
    ) -> GraphBuilder<
        '_,
        DriftedRegistry,
        DriftedRegistry,
        DriftedRegistry,
        DriftedRegistry,
        DriftedRegistry,
        DriftedRegistry,
    > {
        GraphBuilder::new(registry, registry, registry, registry, registry, registry)
    }

    fn missing_builder(
        registry: &MissingRegistry,
    ) -> GraphBuilder<
        '_,
        MissingRegistry,
        MissingRegistry,
        MissingRegistry,
        MissingRegistry,
        MissingRegistry,
        MissingRegistry,
    > {
        GraphBuilder::new(registry, registry, registry, registry, registry, registry)
    }

    fn spec(source: &str) -> WorkflowSpec {
        parse_str("test.toml", source).expect("test workflow must parse")
    }

    #[test]
    fn rejects_drifted_explicit_registry_identity() {
        let result = builder(&DriftedRegistry).build(
            &spec(
                r#"
schema_version = 1
edges = []
[workflow]
id = "workflow"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "terminal"
"#,
            ),
            [RegistryBinding::new(
                RegistryCategory::Tool,
                "requested-id",
                "requested-version",
            )],
        );

        assert!(matches!(result, Err(GraphBuildError::IdentityDrift(_))));
    }

    #[test]
    fn rejects_drifted_predicate_route_identity() {
        let result = builder(&DriftedRegistry).build(
            &spec(
                r#"
schema_version = 1
edges = []
[workflow]
id = "workflow"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "action"
[[nodes]]
id = "end"
kind = "terminal"
[[routes]]
from = "start"
[routes.predicate]
id = "requested-predicate"
version = "requested-version"
[routes.cases]
yes = "end"
"#,
            ),
            [] as [RegistryBinding; 0],
        );

        assert!(matches!(result, Err(GraphBuildError::IdentityDrift(_))));
    }

    #[test]
    fn rejects_missing_predicate_route_registry_entry() {
        let result = missing_builder(&MissingRegistry).build(
            &spec(
                r#"
schema_version = 1
edges = []
[workflow]
id = "workflow"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "action"
[[nodes]]
id = "end"
kind = "terminal"
[[routes]]
from = "start"
[routes.predicate]
id = "missing-predicate"
version = "9"
[routes.cases]
yes = "end"
"#,
            ),
            [] as [RegistryBinding; 0],
        );

        match result {
            Err(GraphBuildError::Registry(error)) => {
                assert_eq!(error.category(), RegistryCategory::Predicate);
                assert_eq!(error.id(), "missing-predicate");
                assert_eq!(error.version(), "9");
            }
            other => panic!("expected missing predicate registry entry, got {other:?}"),
        }
    }
}
