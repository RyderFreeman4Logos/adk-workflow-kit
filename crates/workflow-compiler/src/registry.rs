use std::fmt;

use crate::diagnostics::write_quoted;

/// Identifies the category that owns a registry entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryCategory {
    /// A model implementation.
    Model,
    /// A tool implementation.
    Tool,
    /// A workflow node implementation.
    Node,
    /// A validator implementation.
    Validator,
    /// A predicate implementation.
    Predicate,
    /// A Skill implementation.
    Skill,
}

/// A successful immutable registry resolution.
///
/// REG-001 v0.1 intentionally exposes only an opaque ID and exact opaque version.
/// Capability, schema, provenance, and lock metadata require later ratified contracts.
pub struct RegistryEntry<'a, T> {
    implementation: &'a T,
    id: &'a str,
    version: &'a str,
}

impl<'a, T> RegistryEntry<'a, T> {
    /// Creates a borrowed registry resolution with its exact identity and version.
    pub fn new(implementation: &'a T, id: &'a str, version: &'a str) -> Self {
        Self {
            implementation,
            id,
            version,
        }
    }

    /// Returns the original borrowed implementation.
    pub fn implementation(&self) -> &'a T {
        self.implementation
    }

    /// Returns the resolved opaque ID.
    pub fn id(&self) -> &'a str {
        self.id
    }

    /// Returns the resolved exact version.
    pub fn version(&self) -> &'a str {
        self.version
    }
}

/// An exact ID and version absent from a registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryNotFound {
    category: RegistryCategory,
    id: String,
    version: String,
}

impl RegistryNotFound {
    /// Creates a typed exact-lookup failure.
    pub fn new(category: RegistryCategory, id: &str, version: &str) -> Self {
        Self {
            category,
            id: id.to_owned(),
            version: version.to_owned(),
        }
    }

    /// Returns the registry category that was queried.
    pub fn category(&self) -> RegistryCategory {
        self.category
    }

    /// Returns the requested opaque ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the requested exact version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl fmt::Display for RegistryNotFound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "registry entry not found: category={:?}, id=",
            self.category
        )?;
        write_quoted(formatter, &self.id)?;
        formatter.write_str(", version=")?;
        write_quoted(formatter, &self.version)
    }
}

impl std::error::Error for RegistryNotFound {}

/// Resolves immutable model implementations by exact ID and version.
pub trait ModelRegistry {
    /// The model implementation type.
    type Implementation;

    /// Resolves an implementation only when both ID and version match exactly.
    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound>;
}

/// Resolves immutable tool implementations by exact ID and version.
pub trait ToolRegistry {
    /// The tool implementation type.
    type Implementation;

    /// Resolves an implementation only when both ID and version match exactly.
    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound>;
}

/// Resolves immutable workflow node implementations by exact ID and version.
pub trait NodeRegistry {
    /// The workflow node implementation type.
    type Implementation;

    /// Resolves an implementation only when both ID and version match exactly.
    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound>;
}

/// Resolves immutable validator implementations by exact ID and version.
pub trait ValidatorRegistry {
    /// The validator implementation type.
    type Implementation;

    /// Resolves an implementation only when both ID and version match exactly.
    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound>;
}

/// Resolves immutable predicate implementations by exact ID and version.
pub trait PredicateRegistry {
    /// The predicate implementation type.
    type Implementation;

    /// Resolves an implementation only when both ID and version match exactly.
    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound>;
}

/// Resolves immutable Skill implementations by exact ID and version.
pub trait SkillRegistry {
    /// The Skill implementation type.
    type Implementation;

    /// Resolves an implementation only when both ID and version match exactly.
    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound>;
}

/// Exact allowlist of canonical example predicate identities.
///
/// Implementations are never invoked; resolution only proves the ID/version pair.
pub struct BuiltinPredicateRegistry;

impl PredicateRegistry for BuiltinPredicateRegistry {
    type Implementation = ();

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        static IMPLEMENTATION: () = ();
        let identity = match (id, version) {
            ("coverage.decision@v1", "1.0.0") => ("coverage.decision@v1", "1.0.0"),
            ("review.verdict@v1", "1.0.0") => ("review.verdict@v1", "1.0.0"),
            ("grounding.verdict@v1", "1.0.0") => ("grounding.verdict@v1", "1.0.0"),
            _ => {
                return Err(RegistryNotFound::new(
                    RegistryCategory::Predicate,
                    id,
                    version,
                ));
            }
        };
        Ok(RegistryEntry::new(&IMPLEMENTATION, identity.0, identity.1))
    }
}
