//! Graph-frontier ownership for authored Isolated and Shared node visits.

use super::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Invocation {
    pub(super) step: usize,
    pub(super) conversation_start: usize,
    pub(super) model_iteration_start: u64,
}

pub(super) fn valid_invocation(state: &LoopState) -> bool {
    state.invocation.as_ref().is_none_or(|owner| {
        owner.model_iteration_start <= state.model_iterations
            && (!state.finish_admitted || owner.model_iteration_start < state.model_iterations)
            && state
                .pending_calls
                .iter()
                .all(|call| current_call(state, call))
            && (state.conversation.is_empty()
                || state
                    .conversation
                    .get(..owner.conversation_start)
                    .is_some_and(|prefix| {
                        let iterations = prefix
                            .iter()
                            .filter(|content| {
                                content
                                    .parts
                                    .iter()
                                    .any(|part| matches!(part, adk_rust::Part::FunctionCall { .. }))
                                    || admitted_finish(content).is_ok_and(|output| output.is_some())
                            })
                            .count();
                        u64::try_from(iterations).ok() == Some(owner.model_iteration_start)
                    }))
    })
}

pub(super) fn validate_checkpoint(
    ledger: &LoopLedgerStore,
    checkpoint: &DurableCheckpointV1,
    isolated: &BTreeSet<String>,
) -> Result<(), ExecutionError> {
    let state: State = serde_json::from_slice(checkpoint.state())
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
    let continuation: GraphContinuationV1 = serde_json::from_value(
        state
            .get(GRAPH_CONTINUATION_KEY)
            .cloned()
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?,
    )
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
    for node in isolated {
        let state = ledger.snapshot(node)?;
        if state.shared_pending.is_some() && !continuation.pending_nodes.contains(node) {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        if let Some(owner) = &state.invocation {
            if owner.step > continuation.step
                || (continuation.pending_nodes.contains(node) && owner.step != continuation.step)
            {
                return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
            }
        } else if state.model_iterations > 0 && continuation.pending_nodes.contains(node) {
            // Legacy completed nodes need no replay; an active old invocation
            // without a durable owner cannot prove which accepted finish to use.
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
    }
    Ok(())
}

pub(super) fn nodes(contracts: &BTreeMap<String, RuntimeAgentContract>) -> BTreeSet<String> {
    contracts.keys().cloned().collect()
}

impl LoopLedgerStore {
    pub(super) fn admit_frontier(
        &self,
        checkpoint: &Checkpoint,
        isolated: &BTreeSet<String>,
        mapper: &AdkEventMapper,
        artifacts: &FilesystemArtifactStore,
    ) -> Result<(), ExecutionError> {
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let mut next = nodes.clone();
        for node in checkpoint
            .pending_nodes
            .iter()
            .filter(|node| isolated.contains(*node))
        {
            let state = next.entry(node.clone()).or_default();
            if state
                .invocation
                .as_ref()
                .is_some_and(|owner| owner.step == checkpoint.step)
            {
                continue;
            }
            if state.shared_pending.is_some()
                || !state.pending_calls.is_empty()
                || (state.invocation.is_some() && !state.finish_admitted)
            {
                return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
            }
            state.invocation = Some(Invocation {
                step: checkpoint.step,
                conversation_start: state.conversation.len(),
                model_iteration_start: state.model_iterations,
            });
            state.previous_response_id = None;
            state.finish_admitted = false;
            state.finished_output = None;
            state.finish_successor = None;
        }
        // Save the real prefix before its checkpoint. An interrupted save leaves
        // the previous checkpoint and matching ledger generation recoverable.
        write_events(&self.path.with_file_name("events.jsonl"), mapper.events())?;
        let mut refs = BTreeSet::new();
        collect_event_artifact_refs(mapper.events(), artifacts, &mut refs);
        let state = checkpoint_state(checkpoint.state.clone(), checkpoint, None)?;
        let durable = DurableCheckpointV1::new(
            self.run_id.clone(),
            checkpoint
                .pending_nodes
                .first()
                .map(String::as_str)
                .unwrap_or("terminal"),
            mapper.events().last().map_or(0, |event| event.sequence()),
            serde_json::to_vec(&state)
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?,
            refs,
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        self.persist_generation(&next, Some(durable))?;
        *nodes = next;
        Ok(())
    }
}

impl LoopController {
    pub(super) fn enter_isolated(&self) -> adk_rust::Result<Option<adk_rust::Event>> {
        let state = self
            .ledger
            .snapshot(&self.node)
            .map_err(|_| self.fail(ExecutionErrorKind::Persistence, "loop ledger unavailable"))?;
        if state.invocation.is_none() {
            return Err(self.fail(
                ExecutionErrorKind::InvalidRunState,
                "workflow.loop.invalid_state",
            ));
        }
        let replay = state.finish_successor.clone();
        *self
            .state
            .lock()
            .map_err(|_| self.fail(ExecutionErrorKind::Persistence, "loop ledger unavailable"))? =
            state;
        replay
            .map(|output| restored_finish_event(&self.node, output))
            .transpose()
    }
}

pub(super) fn restored_finish_event(
    name: &str,
    output: Value,
) -> adk_rust::Result<adk_rust::Event> {
    let text = serde_json::to_string(&json!({"status":"finished", "output": output}))
        .map_err(|_| adk_rust::AdkError::agent("restored finish unavailable"))?;
    let mut event = adk_rust::Event::new(name);
    event.set_content(Content::new("assistant").with_text(text));
    event
        .provider_metadata
        .insert("workflow.cache_hit".to_owned(), "1".to_owned());
    Ok(event)
}

pub(super) fn current_call(state: &LoopState, call: &PendingCall) -> bool {
    state
        .invocation
        .as_ref()
        .is_none_or(|owner| call.model_iteration > owner.model_iteration_start)
}

pub(super) fn prepare_request(state: &mut LoopState, request: &mut LlmRequest) -> Result<bool, ()> {
    let owner = state.invocation.as_ref().ok_or(())?;
    let start = owner.conversation_start;
    if start > state.conversation.len() {
        return Err(());
    }
    let changed = state.conversation_reconstructed || state.conversation.len() == start;
    if state.conversation_reconstructed {
        let tail = state.conversation.split_off(start);
        state.conversation.extend(request.contents.clone());
        state.conversation.extend(tail);
        state.conversation_reconstructed = false;
    } else if state.conversation.len() == start {
        state.conversation.extend(request.contents.clone());
    }
    request.contents = state.conversation[start..].to_vec();
    request.previous_response_id = state.previous_response_id.clone();
    Ok(changed)
}

pub(super) fn frontier_observer<'a>(
    continuation: &'a GraphCheckpointMemory,
    initial: Option<Checkpoint>,
    ledger: &'a LoopLedgerStore,
    isolated: &'a BTreeSet<String>,
    terminal: &'a Mutex<Option<ExecutionErrorKind>>,
) -> impl FnMut(&str, usize, &AdkEventMapper, &FilesystemArtifactStore) -> Result<(), AdkGraphError> + 'a
{
    move |node, step, mapper, artifacts| {
        if isolated.is_empty() {
            return Ok(());
        }
        let result = continuation
            .latest()
            .or_else(|| initial.clone())
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::Persistence))
            .and_then(|checkpoint| {
                if checkpoint.step != step
                    || !checkpoint
                        .pending_nodes
                        .iter()
                        .any(|pending| pending == node)
                {
                    return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
                }
                ledger.admit_frontier(&checkpoint, isolated, mapper, artifacts)
            });
        result.map_err(|error| {
            record_terminal(terminal, error.kind());
            AdkGraphError::Failed
        })
    }
}

#[cfg(test)]
#[path = "isolated_tests.rs"]
mod tests;
