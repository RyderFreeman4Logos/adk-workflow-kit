//! Private projection of checkpoint-confirmed completions; never execution authority.

use super::*;
use crate::events::TOOL_AUDIT_PREFIX;

fn same_admission(left: &PendingCall, right: &PendingCall) -> bool {
    left.id == right.id
        && left.name == right.name
        && left.fingerprint == right.fingerprint
        && left.admission_ordinal == right.admission_ordinal
        && left.model_iteration == right.model_iteration
}

pub(super) fn prepare(
    nodes: &mut BTreeMap<String, LoopState>,
    committed: &BTreeMap<String, LoopState>,
) -> Result<(), ExecutionError> {
    for (node, state) in nodes {
        let mut ids = BTreeMap::new();
        let mut outputs = BTreeMap::new();
        for completed in &state.completed_calls {
            let call = completed.call();
            let prior = committed.get(node).filter(|prior| {
                prior
                    .completed_calls
                    .iter()
                    .any(|entry| same_admission(entry.call(), call))
            });
            let (id, output) = if let Some(prior) = prior {
                // Do not invent proof for historical unlinked completions.
                let (Some(id), Some(output)) = (
                    prior.completion_event_ids.get(&call.id),
                    prior.completion_event_outputs.get(&call.id),
                ) else {
                    continue;
                };
                (id.clone(), output.clone())
            } else {
                let response = call.response.as_ref().ok_or_else(invalid)?;
                let mut output = crate::events::project_tool_results(
                    json!([{"tool_name":call.name,"response":response}]),
                )
                .map_err(|_| invalid())?;
                (
                    adk_rust::Event::new("durable-tool-audit").id,
                    output
                        .as_array_mut()
                        .and_then(|items| items.pop())
                        .ok_or_else(invalid)?,
                )
            };
            ids.insert(call.id.clone(), id);
            outputs.insert(call.id.clone(), output);
        }
        state.completion_event_ids = ids;
        state.completion_event_outputs = outputs;
    }
    Ok(())
}

fn invalid() -> ExecutionError {
    ExecutionError::new(ExecutionErrorKind::InvalidRunState)
}

// This is also the pre-replay admission guard, before any artifact/restore IO.
fn validate_nodes(nodes: &BTreeMap<String, LoopState>) -> Result<(), ExecutionError> {
    if nodes.values().any(|state| {
        !state.finish_admitted
            && state.completed_calls.iter().any(|completed| {
                let id = &completed.call().id;
                !state.completion_event_ids.contains_key(id)
                    || !state.completion_event_outputs.contains_key(id)
            })
    }) {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn valid_bindings(state: &LoopState) -> bool {
    state
        .completion_event_ids
        .keys()
        .eq(state.completion_event_outputs.keys())
        && state.completion_event_ids.iter().all(|(call_id, token)| {
            state.completed_calls.iter().any(|completed| {
                completed.call().id == *call_id
                    && state
                        .completion_event_outputs
                        .get(call_id)
                        .and_then(|output| output.get("tool_name"))
                        .and_then(Value::as_str)
                        == Some(completed.call().name.as_str())
            }) && token.len() == 36
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        })
        && state
            .completion_event_ids
            .values()
            .collect::<BTreeSet<_>>()
            .len()
            == state.completion_event_ids.len()
}

pub(super) fn unique_tokens(nodes: &BTreeMap<String, LoopState>) -> bool {
    let tokens = nodes
        .values()
        .flat_map(|state| state.completion_event_ids.values())
        .collect::<Vec<_>>();
    tokens.iter().collect::<BTreeSet<_>>().len() == tokens.len()
}

pub(super) fn identities(
    nodes: &BTreeMap<String, LoopState>,
) -> BTreeMap<(String, String), (String, String)> {
    nodes
        .iter()
        .flat_map(|(node, state)| {
            state.completed_calls.iter().filter_map(|completed| {
                let call = completed.call();
                state.completion_event_ids.get(&call.id).map(|token| {
                    (
                        (node.clone(), call.id.clone()),
                        (call.name.clone(), token.clone()),
                    )
                })
            })
        })
        .collect()
}

fn event_output(
    event: &workflow_runtime::WorkflowRuntimeEventV1,
    artifacts: &impl ArtifactStore,
) -> Result<Option<Value>, ExecutionError> {
    let Some(reference) = event.payload().get("artifact_reference") else {
        return Ok(event.payload().get("structured_output").cloned());
    };
    let reference: ProtectedArtifactReferenceV1 =
        serde_json::from_value(reference.clone()).map_err(|_| invalid())?;
    let id = ArtifactId::parse(reference.artifact_id()).ok_or_else(invalid)?;
    let len = usize::try_from(reference.byte_len()).map_err(|_| invalid())?;
    if len == 0 || len > MAX_STATE_BYTES || reference.sha256() != format!("sha256:{}", id.as_str())
    {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let limit = ARTIFACT_LIMIT.min((len - bytes.len()) as u64);
        let page = artifacts
            .read_page(
                &id,
                PageRequest::new(
                    bytes.len() as u64,
                    NonZeroU64::new(limit).ok_or_else(invalid)?,
                ),
            )
            .map_err(|_| invalid())?;
        if page.bytes().is_empty() || page.bytes().len() > len - bytes.len() {
            return Err(invalid());
        }
        bytes.extend_from_slice(page.bytes());
        if page.next_offset() != (bytes.len() < len).then_some(bytes.len() as u64) {
            return Err(invalid());
        }
    }
    if format!("{:x}", Sha256::digest(&bytes)) != id.as_str() {
        return Err(invalid());
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let digest = workflow_runtime::redacted_json_digest(&value).map_err(|_| invalid())?;
    if event
        .payload()
        .get("structured_output_digest")
        .and_then(Value::as_str)
        != Some(digest.as_str())
    {
        return Err(invalid());
    }
    Ok(Some(value))
}

fn recorded(
    nodes: &BTreeMap<String, LoopState>,
    mapper: &AdkEventMapper,
    artifacts: &impl ArtifactStore,
) -> Result<BTreeSet<String>, ExecutionError> {
    let mut seen = BTreeSet::new();
    for event in mapper
        .events()
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolCompleted)
    {
        let node = event
            .node_id()
            .and_then(|node| nodes.get(node))
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let Some(encoded) = event.event_id().strip_prefix(TOOL_AUDIT_PREFIX) else {
            // A finished legacy node is never replayed. Preserve its historical
            // idless events; they do not justify compensating unfinished work.
            if node.finish_admitted && node.completion_event_ids.is_empty() {
                continue;
            }
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        };
        let tokens = encoded.split('.').collect::<Vec<_>>();
        if tokens.is_empty()
            || tokens.iter().collect::<BTreeSet<_>>().len() != tokens.len()
            || tokens
                .iter()
                .any(|token| !node.completion_event_ids.values().any(|id| id == token))
        {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        let expected = Value::Array(
            tokens
                .iter()
                .map(|token| {
                    let call = node
                        .completion_event_ids
                        .iter()
                        .find(|(_, id)| *id == *token)
                        .map(|(id, _)| id)
                        .ok_or_else(invalid)?;
                    node.completion_event_outputs
                        .get(call)
                        .cloned()
                        .ok_or_else(invalid)
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        let digest = workflow_runtime::redacted_json_digest(&expected).map_err(|_| invalid())?;
        if event
            .payload()
            .get("response_digest")
            .and_then(Value::as_str)
            != Some(digest.as_str())
            || match event_output(event, artifacts)? {
                Some(actual) => actual != expected,
                None => {
                    event
                        .payload()
                        .get("structured_output_digest")
                        .and_then(Value::as_str)
                        != Some(digest.as_str())
                }
            }
        {
            return Err(invalid());
        }
        for token in tokens {
            if !seen.insert(token.to_owned()) {
                return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
            }
        }
    }
    Ok(seen)
}

pub(super) fn validate_existing(
    ledger: &LoopLedgerStore,
    mapper: &AdkEventMapper,
    artifacts: &impl ArtifactStore,
) -> Result<(), ExecutionError> {
    if mapper.run_id() != ledger.run_id.as_str() {
        return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
    }
    let nodes = ledger
        .durable_nodes
        .lock()
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    validate_nodes(&nodes)?;
    recorded(&nodes, mapper, artifacts).map(|_| ())
}

pub(super) fn reconcile<S: ArtifactStore>(
    ledger: &LoopLedgerStore,
    mapper: &mut AdkEventMapper,
    artifacts: &mut S,
) -> Result<(), ExecutionError> {
    if mapper.run_id() != ledger.run_id.as_str() {
        return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
    }
    let nodes = ledger
        .durable_nodes
        .lock()
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?
        .clone();
    validate_nodes(&nodes)?;
    let recorded = recorded(&nodes, mapper, artifacts)?;
    let requested = mapper
        .events()
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolRequested)
        .map(|event| {
            Ok((
                event.node_id().map(str::to_owned),
                event_output(event, artifacts)?.ok_or_else(invalid)?,
            ))
        })
        .collect::<Result<Vec<_>, ExecutionError>>()?;
    for (node, state) in &nodes {
        for completed in &state.completed_calls {
            let call = completed.call();
            let Some(token) = state.completion_event_ids.get(&call.id) else {
                if state.finish_admitted {
                    continue;
                }
                return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
            };
            let attributed = requested.iter().any(|(owner, output)| owner.as_deref() == Some(node.as_str())
                && output.as_array().is_some_and(|items| items.contains(&json!({"tool_call_id":call.id,"tool_name":call.name,"argument_fingerprint":call.fingerprint}))));
            if !attributed {
                mapper.map_durable_tool_event(format!("tool-requested-{token}"), node,
                    AdkRuntimeObservationKindV1::ToolRequested, json!([{
                        "tool_call_id":call.id, "tool_name":call.name, "argument_fingerprint":call.fingerprint,
                    }]), artifacts).map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
            }
            if !recorded.contains(token) {
                let result = state
                    .completion_event_outputs
                    .get(&call.id)
                    .ok_or_else(invalid)?;
                mapper
                    .map_durable_tool_event(
                        format!("{TOOL_AUDIT_PREFIX}{token}"),
                        node,
                        AdkRuntimeObservationKindV1::ToolCompleted,
                        json!([result]),
                        artifacts,
                    )
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tool_audit_tests.rs"]
mod tests;
