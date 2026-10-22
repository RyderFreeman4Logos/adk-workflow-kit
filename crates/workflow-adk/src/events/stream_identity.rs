//! Private SDK response lifecycle; runtime event IDs still identify individual audit records.

use super::{
    AdkEventMapper, AdkEventMappingError, AdkEventMappingErrorKind, AdkRuntimeObservationKindV1,
};

pub(super) struct SourceEvent {
    node: String,
    invocation: String,
    author: String,
    branch: String,
    open: bool,
}

impl SourceEvent {
    pub(super) fn new(node: &str, event: &adk_rust::Event) -> Self {
        let response = &event.llm_response;
        Self {
            node: node.to_owned(),
            invocation: event.invocation_id.clone(),
            author: event.author.clone(),
            branch: event.branch.clone(),
            // FinishReason describes provider generation; it does not end an SDK
            // partial lifecycle. LlmAgent uses turn_complete, not FinishReason.
            open: is_model_response(event)
                && response.partial
                && !response.turn_complete
                && !response.interrupted
                && response.error_code.is_none()
                && response.error_message.is_none(),
        }
    }

    fn continues(&self, node: &str, event: &adk_rust::Event) -> bool {
        self.open
            && is_model_response(event)
            && self.node == node
            && self.invocation == event.invocation_id
            && self.author == event.author
            && self.branch == event.branch
    }
}

fn is_model_response(event: &adk_rust::Event) -> bool {
    // Tool notifications get fresh SDK IDs even when partial. LLM tool requests,
    // including long-running ones, still share their model response's ID.
    event.tool_progress_stream().is_none()
        && !super::is_tool_started(event)
        && event.tool_results().is_empty()
}

fn duplicate() -> AdkEventMappingError {
    AdkEventMappingError::new(AdkEventMappingErrorKind::DuplicateEventId)
}

impl AdkEventMapper {
    pub(super) fn stream_event_id(&self) -> Result<String, AdkEventMappingError> {
        let id = format!("adk-stream-{}", self.log.events().len() + 1);
        // A generated audit ID must not take a previously admitted SDK source's name,
        // including tool sources whose audit ID is a private durable token.
        if self.sdk_sources.contains_key(&id) {
            return Err(duplicate());
        }
        Ok(id)
    }

    pub(super) fn sdk_audit_id(
        &self,
        node: &str,
        event: &adk_rust::Event,
        kind: AdkRuntimeObservationKindV1,
    ) -> Result<String, AdkEventMappingError> {
        let base = self.tool_completion_id(node, event, kind)?;
        if let Some(source) = self.sdk_sources.get(&event.id) {
            if !source.continues(node, event) {
                return Err(duplicate());
            }
            // Official LlmAgent partials and their final share a response ID. Each
            // callback needs its own audit ID; provider call IDs and durable tool
            // completion tokens retain their existing, independent identities.
            return self.stream_event_id();
        } else if base != event.id
            && self
                .log
                .events()
                .iter()
                .any(|prior| prior.event_id() == event.id)
        {
            // Append checks unchanged IDs against audit history. A durable tool
            // token replaces the raw ID, so only that path needs this extra check.
            return Err(duplicate());
        }
        Ok(base)
    }
}
