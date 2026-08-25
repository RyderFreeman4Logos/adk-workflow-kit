use std::fmt;

use workflow_spec::WorkflowSpec;

use crate::{
    validated_ir, CompileError, CompiledPlan, ModelRegistry, NodeRegistry, PredicateRegistry,
    RegistryCategory, RegistryNotFound, SkillRegistry, ToolRegistry, ValidatorRegistry,
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
}

impl fmt::Display for GraphBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compile(error) => write!(formatter, "graph build failed: {error}"),
            Self::Registry(error) => write!(formatter, "graph registry binding failed: {error}"),
        }
    }
}

impl std::error::Error for GraphBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compile(error) => Some(error),
            Self::Registry(error) => Some(error),
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
            self.predicates
                .resolve(route.predicate().id(), route.predicate().version())
                .map_err(GraphBuildError::Registry)?;
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
        let result = match binding.category {
            RegistryCategory::Model => self
                .models
                .resolve(&binding.id, &binding.version)
                .map(|_| ()),
            RegistryCategory::Tool => self
                .tools
                .resolve(&binding.id, &binding.version)
                .map(|_| ()),
            RegistryCategory::Node => self
                .nodes
                .resolve(&binding.id, &binding.version)
                .map(|_| ()),
            RegistryCategory::Validator => self
                .validators
                .resolve(&binding.id, &binding.version)
                .map(|_| ()),
            RegistryCategory::Predicate => self
                .predicates
                .resolve(&binding.id, &binding.version)
                .map(|_| ()),
            RegistryCategory::Skill => self
                .skills
                .resolve(&binding.id, &binding.version)
                .map(|_| ()),
        };
        result.map_err(GraphBuildError::Registry)
    }
}
