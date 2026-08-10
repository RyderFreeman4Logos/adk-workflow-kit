use std::fmt;

use serde::Serialize;
use workflow_ir::{IrSchemaVersion, CANONICAL_IR_WIRE_VERSION_V1};

use crate::CompiledPlan;

/// An immutable v1 identity lock for one successfully compiled workflow plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkflowLock {
    lock_version: u16,
    canonical_ir_wire_version: u16,
    ir_schema_version: u32,
    workflow_id: String,
    workflow_version: String,
    ir_hash: String,
    semantic_resource_hashes: Vec<String>,
}

impl WorkflowLock {
    /// Generates the current-IR v1 lock entirely in memory.
    pub fn try_from_plan(plan: &CompiledPlan) -> Result<Self, WorkflowLockError> {
        let registry_binding_count = plan.registry_binding_count();
        if registry_binding_count != 0 {
            return Err(WorkflowLockError::UnsupportedSemanticResources {
                registry_binding_count,
            });
        }

        let ir = plan.ir();
        let hash = ir.canonical_hash();
        let ir_hash = format!(
            "sha256:{}",
            hash.as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );

        Ok(Self {
            lock_version: 1,
            canonical_ir_wire_version: CANONICAL_IR_WIRE_VERSION_V1,
            ir_schema_version: match ir.schema_version() {
                IrSchemaVersion::V1 => 1,
            },
            workflow_id: ir.workflow_id().as_str().to_owned(),
            workflow_version: ir.workflow_version().to_owned(),
            ir_hash,
            semantic_resource_hashes: Vec::new(),
        })
    }

    /// Returns the workflow lock schema version.
    pub fn lock_version(&self) -> u16 {
        self.lock_version
    }

    /// Returns the canonical IR wire version used by the recorded hash.
    pub fn canonical_ir_wire_version(&self) -> u16 {
        self.canonical_ir_wire_version
    }

    /// Returns the numeric normalized IR schema version.
    pub fn ir_schema_version(&self) -> u32 {
        self.ir_schema_version
    }

    /// Returns the canonical workflow identifier.
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Returns the canonical workflow version.
    pub fn workflow_version(&self) -> &str {
        &self.workflow_version
    }

    /// Returns the prefixed lowercase hexadecimal canonical IR hash.
    pub fn ir_hash(&self) -> &str {
        &self.ir_hash
    }

    /// Returns semantic resource hashes recorded by this lock profile.
    pub fn semantic_resource_hashes(&self) -> &[String] {
        &self.semantic_resource_hashes
    }

    /// Serializes the exact deterministic v1 TOML document in memory.
    pub fn to_toml(&self) -> Result<String, WorkflowLockError> {
        toml::to_string(self).map_err(WorkflowLockError::Serialization)
    }
}

/// A typed failure while generating or serializing a workflow lock.
#[derive(Debug)]
pub enum WorkflowLockError {
    /// The current lock profile cannot represent non-empty semantic resources.
    UnsupportedSemanticResources {
        /// The exact registry binding count rejected by the v1 profile.
        registry_binding_count: usize,
    },
    /// Deterministic TOML serialization failed before producing output.
    Serialization(toml::ser::Error),
}

impl fmt::Display for WorkflowLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSemanticResources {
                registry_binding_count,
            } => write!(
                formatter,
                "workflow lock v1 cannot represent {registry_binding_count} registry bindings"
            ),
            Self::Serialization(error) => {
                write!(formatter, "workflow lock serialization failed: {error}")
            }
        }
    }
}

impl std::error::Error for WorkflowLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedSemanticResources { .. } => None,
            Self::Serialization(error) => Some(error),
        }
    }
}
