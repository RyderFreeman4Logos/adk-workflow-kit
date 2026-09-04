//! Public registration of named, versioned tool implementations.

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{ToolBridgeError, ToolBridgeErrorKind, ToolHandler};

/// Exact ID/version lookup for a registered tool implementation.
pub struct ToolImplementationRegistry {
    tools: BTreeMap<(String, String), Arc<dyn ToolHandler>>,
}

impl ToolImplementationRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
        }
    }

    /// Registers a Rust implementation for one exact ID and version.
    pub fn register(
        &mut self,
        id: impl Into<String>,
        version: impl Into<String>,
        implementation: Arc<dyn ToolHandler>,
    ) -> Result<(), ToolImplementationRegistryError> {
        let id = id.into();
        let version = version.into();
        if id.is_empty() || version.is_empty() {
            return Err(ToolImplementationRegistryError::InvalidIdentity);
        }
        let key = (id, version);
        if self.tools.contains_key(&key) {
            return Err(ToolImplementationRegistryError::Duplicate);
        }
        self.tools.insert(key, implementation);
        Ok(())
    }

    /// Resolves an implementation only when both ID and version match exactly.
    pub fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<Arc<dyn ToolHandler>, ToolImplementationRegistryError> {
        self.tools
            .get(&(id.to_owned(), version.to_owned()))
            .cloned()
            .ok_or(ToolImplementationRegistryError::NotFound)
    }
}

impl Default for ToolImplementationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A closed registry lookup or registration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolImplementationRegistryError {
    /// The requested ID/version pair is absent.
    NotFound,
    /// The ID/version pair is already registered.
    Duplicate,
    /// An ID or version was empty.
    InvalidIdentity,
}

impl fmt::Display for ToolImplementationRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "tool implementation was not registered",
            Self::Duplicate => "tool implementation is already registered",
            Self::InvalidIdentity => "tool implementation ID and version must not be empty",
        })
    }
}

impl std::error::Error for ToolImplementationRegistryError {}

impl From<ToolImplementationRegistryError> for ToolBridgeError {
    fn from(error: ToolImplementationRegistryError) -> Self {
        Self::new(match error {
            ToolImplementationRegistryError::NotFound => ToolBridgeErrorKind::UnknownTool,
            ToolImplementationRegistryError::Duplicate => ToolBridgeErrorKind::DuplicateTool,
            ToolImplementationRegistryError::InvalidIdentity => ToolBridgeErrorKind::InvalidInput,
        })
    }
}
