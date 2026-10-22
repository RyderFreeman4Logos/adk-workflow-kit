//! Backend-only durable tool-audit identity and privacy projection.

use super::{
    AdkEventMapper, AdkEventMappingError, AdkEventMappingErrorKind, AdkRuntimeObservationKindV1,
    AdkRuntimeObservationV1, protect_large_payload, redact_skill_tool_results,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use workflow_runtime::{ArtifactStore, WorkflowRuntimeEventV1, redact_json_value};

// The execution owner publishes entries only after ledger and checkpoint commit.
// Values contain a tool name and a random token bound to the full admission identity in the checkpoint.
pub(crate) type ToolAuditIds = Arc<Mutex<BTreeMap<(String, String), (String, String)>>>;
pub(crate) const TOOL_AUDIT_PREFIX: &str = "tool-completed-v1-";

/// The normal tool-result privacy projection, reused before raw skill bodies
/// are discarded from the private checkpoint generation.
pub(crate) fn project_tool_results(output: Value) -> Result<Value, AdkEventMappingError> {
    redact_skill_tool_results(redact_json_value(&output))
}

impl AdkEventMapper {
    pub(crate) fn bind_tool_audit(&mut self, ids: ToolAuditIds) {
        self.tool_audit_ids = Some(ids);
    }

    pub(super) fn tool_completion_id(
        &self,
        node_id: &str,
        event: &adk_rust::Event,
        kind: AdkRuntimeObservationKindV1,
    ) -> Result<String, AdkEventMappingError> {
        let event_id = if kind == AdkRuntimeObservationKindV1::ToolCompleted {
            if let Some(ids) = &self.tool_audit_ids {
                let ids = ids.lock().map_err(|_| {
                    AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
                })?;
                let identities = event
                    .tool_results()
                    .iter()
                    .map(|result| {
                        let call_id = result.call_id.ok_or_else(|| {
                            AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
                        })?;
                        let (name, identity) = ids
                            .get(&(node_id.to_owned(), call_id.to_owned()))
                            .ok_or_else(|| {
                            AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
                        })?;
                        if name != result.name {
                            return Err(AdkEventMappingError::new(
                                AdkEventMappingErrorKind::InvalidObservation,
                            ));
                        }
                        Ok(identity.clone())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                format!("{TOOL_AUDIT_PREFIX}{}", identities.join("."))
            } else {
                event.id.clone()
            }
        } else {
            event.id.clone()
        };
        Ok(event_id)
    }

    /// Projects an execution-owner-verified durable fact through the same privacy
    /// and artifact limits as a normal ADK tool event. It grants no authority.
    pub(crate) fn map_durable_tool_event<S: ArtifactStore>(
        &mut self,
        id: String,
        node: &str,
        kind: AdkRuntimeObservationKindV1,
        output: Value,
        artifacts: &mut S,
    ) -> Result<WorkflowRuntimeEventV1, AdkEventMappingError> {
        let output = if kind == AdkRuntimeObservationKindV1::ToolCompleted {
            project_tool_results(output)?
        } else {
            redact_json_value(&output)
        };
        let observation = AdkRuntimeObservationV1::new(id, "durable-tool-audit", kind)
            .with_node_id(node)
            .with_response(output.clone())
            .with_structured_output(output.clone());
        self.map(protect_large_payload(observation, &output, artifacts)?)
    }
}
