//! Profile-driven execution and kit-owned run-state persistence.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt, fs,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use adk_rust::graph::prelude::{ExecutionConfig, State};
use adk_rust::graph::{Checkpoint, Checkpointer, GraphError};
use adk_rust::{Agent, agent::LlmAgentBuilder, async_trait};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_compiler::{
    BindingCategory, BindingRef, CapabilitySet, RegistryEntry, RegistryNotFound,
    RegistryResolutionError, ResolvedBinding, ResolvedRuntimePlan, RuntimePlanRegistry,
    RuntimePlanRequest, SkillId, SkillManifest, SkillRegistry, SkillResourceId, SkillResourceInput,
    SkillResourceLimits, SkillRuntimeLock, SkillRuntimeManifest, activate_skill, compile_file,
    execute_registered_script_in_child,
};
use workflow_ir::IrModelRole;
use workflow_runtime::{
    ArtifactId, ArtifactStore, BackendCapabilities, CapabilityIntersection, CheckpointManifestV1,
    DurableCheckpointV1, EffectCommit, EffectJournal, EffectKey, FilesystemArtifactStore,
    InMemoryArtifactStore, Materialization, PageRequest, PolicyCapabilities,
    ProtectedArtifactReferenceV1, PureTransformRequest, RequestedCapabilities, RunContext, RunId,
    RunLimits, RunSandbox, SandboxCapability, SqliteCheckpointStore, ToolBridge, ToolBridgeError,
    ToolBridgeErrorKind, ToolCall, ToolCallContext, ToolEnvelope, ToolFlags, ToolHandler,
    ToolProvenance, ToolRegistration, WorkdirManager, WorkflowRuntimeEventKindV1,
    contains_sensitive_key, intersect_policy_capabilities, redact_json_value, selection_identity,
    verify_sandbox_capabilities,
};
use workflow_spec::{SourcePath, read_bounded_regular_file};

use crate::{
    AdkGraphError, AdkGraphTranslator,
    events::{AdkEventMapper, AdkRuntimeObservationKindV1, AdkRuntimeObservationV1},
    model_profiles::{
        CredentialBroker, CredentialHandle, FakeModelProfile, ModelBinding, ModelProfileRegistry,
        OpenAiCompatibleProfile,
    },
    tool_bridge::AdkToolBridge,
};

const MAX_STATE_BYTES: usize = 1024 * 1024;
const ARTIFACT_LIMIT: u64 = 64 * 1024;
const GRAPH_CONTINUATION_KEY: &str = "kit_graph_continuation_v1";
const LOOP_LEDGER_FILE: &str = "loop-ledger.json";
const LOOP_LEDGER_DIGEST_KEY: &str = "kit_loop_ledger_digest_v1";
static NEXT_RUN: AtomicU64 = AtomicU64::new(0);
type BoundTool = (Vec<String>, Arc<AdkToolBridge<InMemoryArtifactStore>>);
type CompletedToolResponse = (String, String, String, String, Value);

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LoopState {
    model_iterations: u64,
    total_tool_calls: u64,
    tool_output_bytes: u64,
    tool_calls: BTreeMap<String, u64>,
    seen_ids: BTreeSet<String>,
    seen_calls: BTreeSet<(String, String)>,
    conversation: Vec<adk_rust::Content>,
    previous_response_id: Option<String>,
    pending_calls: VecDeque<PendingCall>,
    #[serde(default)]
    finish_admitted: bool,
    finished_output: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingCall {
    id: String,
    name: String,
    args: Value,
    fingerprint: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LoopLedgerV1 {
    schema_version: u8,
    checkpoint_identity: String,
    nodes: BTreeMap<String, LoopState>,
}

struct LoopLedgerStore {
    path: PathBuf,
    checkpoint_path: PathBuf,
    checkpoint_identity: String,
    checkpoint_manifest: CheckpointManifestV1,
    run_id: RunId,
    nodes: Mutex<BTreeMap<String, LoopState>>,
}

impl LoopLedgerStore {
    fn create(
        path: PathBuf,
        checkpoint_path: PathBuf,
        checkpoint_identity: String,
        checkpoint_manifest: CheckpointManifestV1,
        run_id: RunId,
    ) -> Result<Self, ExecutionError> {
        let store = Self {
            path,
            checkpoint_path,
            checkpoint_identity,
            checkpoint_manifest,
            run_id,
            nodes: Mutex::new(BTreeMap::new()),
        };
        store.persist_ledger(&BTreeMap::new())?;
        Ok(store)
    }

    fn open(
        path: PathBuf,
        checkpoint_path: PathBuf,
        checkpoint_identity: String,
        checkpoint_manifest: CheckpointManifestV1,
        run_id: RunId,
        checkpoint_digest: &str,
    ) -> Result<Self, ExecutionError> {
        let ledger = serde_json::from_slice::<LoopLedgerV1>(&bounded_read(&path)?)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        if ledger.schema_version != 2
            || ledger.checkpoint_identity != checkpoint_identity
            || checkpoint_digest != loop_ledger_digest(&ledger.nodes)?
            || ledger.nodes.values().any(|state| !valid_loop_state(state))
        {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        Ok(Self {
            path,
            checkpoint_path,
            checkpoint_identity,
            checkpoint_manifest,
            run_id,
            nodes: Mutex::new(ledger.nodes),
        })
    }

    fn snapshot(&self, node: &str) -> Result<LoopState, ExecutionError> {
        self.nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
            .map(|nodes| nodes.get(node).cloned().unwrap_or_default())
    }

    fn tool_call_limit(
        &self,
        node: &str,
        candidate: &LoopState,
        limits: &RunLimits,
    ) -> Result<Option<ExecutionErrorKind>, ExecutionError> {
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let states = nodes
            .iter()
            .map(|(name, state)| if name == node { candidate } else { state });
        let total = states.clone().fold(0_u64, |total, state| {
            total.saturating_add(state.total_tool_calls)
        });
        if total > limits.max_tool_calls().get() {
            return Ok(Some(ExecutionErrorKind::TotalToolCallsLimit));
        }
        let mut per_tool = BTreeMap::<String, u64>::new();
        for state in states {
            for (tool, count) in &state.tool_calls {
                *per_tool.entry(tool.clone()).or_default() = per_tool
                    .get(tool)
                    .copied()
                    .unwrap_or_default()
                    .saturating_add(*count);
            }
        }
        if per_tool
            .values()
            .any(|count| *count > limits.max_calls_per_tool().get())
        {
            return Ok(Some(ExecutionErrorKind::ToolCallsPerToolLimit));
        }
        nodes.insert(node.to_owned(), candidate.clone());
        self.persist_locked(&nodes)?;
        Ok(None)
    }

    fn output_byte_limit(
        &self,
        node: &str,
        candidate: &LoopState,
        limit: u64,
    ) -> Result<bool, ExecutionError> {
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let total = nodes
            .iter()
            .map(|(name, state)| if name == node { candidate } else { state })
            .fold(0_u64, |total, state| {
                total.saturating_add(state.tool_output_bytes)
            });
        if total > limit {
            return Ok(true);
        }
        nodes.insert(node.to_owned(), candidate.clone());
        self.persist_locked(&nodes)?;
        Ok(false)
    }

    fn replace(&self, node: &str, state: LoopState) -> Result<(), ExecutionError> {
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        nodes.insert(node.to_owned(), state);
        self.persist_locked(&nodes)
    }

    fn model_iterations(&self, node: &str) -> Result<u64, ExecutionError> {
        self.snapshot(node).map(|state| state.model_iterations)
    }

    fn finished_output(&self, node: &str) -> Result<Option<Value>, ExecutionError> {
        self.snapshot(node).map(|state| state.finished_output)
    }

    fn pending_calls(&self) -> Result<Vec<(String, PendingCall)>, ExecutionError> {
        let nodes = self
            .nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        Ok(nodes
            .iter()
            .flat_map(|(node, state)| {
                state
                    .pending_calls
                    .iter()
                    .cloned()
                    .map(|call| (node.clone(), call))
            })
            .collect())
    }

    fn completed_tool_responses(&self) -> Result<Vec<CompletedToolResponse>, ExecutionError> {
        let nodes = self
            .nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let mut completed = Vec::new();
        for (node, state) in nodes.iter() {
            let calls = state
                .conversation
                .iter()
                .flat_map(|content| &content.parts)
                .filter_map(|part| match part {
                    adk_rust::Part::FunctionCall {
                        name,
                        args,
                        id: Some(id),
                        ..
                    } => Some((
                        id.clone(),
                        (name.clone(), workflow_runtime::argument_fingerprint(args)),
                    )),
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>();
            for part in state.conversation.iter().flat_map(|content| &content.parts) {
                if let adk_rust::Part::FunctionResponse {
                    function_response,
                    id: Some(id),
                    ..
                } = part
                    && let Some((name, fingerprint)) = calls.get(id)
                {
                    completed.push((
                        node.clone(),
                        id.clone(),
                        name.clone(),
                        fingerprint.clone(),
                        function_response.response.clone(),
                    ));
                }
            }
        }
        Ok(completed)
    }

    fn complete_pending(
        &self,
        node: &str,
        call: &PendingCall,
        response: Value,
        max_output_bytes: u64,
    ) -> Result<(), ExecutionError> {
        let bytes = serde_json::to_vec(&response)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Tool))?;
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let other_output_bytes = nodes
            .iter()
            .filter(|(name, _)| name.as_str() != node)
            .fold(0_u64, |total, (_, state)| {
                total.saturating_add(state.tool_output_bytes)
            });
        let state = nodes
            .get_mut(node)
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let total = state
            .tool_output_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if other_output_bytes.saturating_add(total) > max_output_bytes {
            return Err(ExecutionError::new(
                ExecutionErrorKind::ToolOutputBytesLimit,
            ));
        }
        let index = state
            .pending_calls
            .iter()
            .position(|pending| {
                pending.id == call.id
                    && pending.name == call.name
                    && pending.fingerprint == call.fingerprint
            })
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let call = state
            .pending_calls
            .remove(index)
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        state.tool_output_bytes = total;
        state
            .conversation
            .push(tool_response_content(&call, response));
        self.persist_locked(&nodes)
    }

    fn persist_locked(&self, nodes: &BTreeMap<String, LoopState>) -> Result<(), ExecutionError> {
        self.persist_ledger(nodes)?;
        self.sync_checkpoint(nodes)
    }

    fn persist_ledger(&self, nodes: &BTreeMap<String, LoopState>) -> Result<(), ExecutionError> {
        write_json(
            &self.path,
            &LoopLedgerV1 {
                schema_version: 2,
                checkpoint_identity: self.checkpoint_identity.clone(),
                nodes: nodes.clone(),
            },
        )
    }

    fn sync_checkpoint(&self, nodes: &BTreeMap<String, LoopState>) -> Result<(), ExecutionError> {
        let mut store =
            SqliteCheckpointStore::open(&self.checkpoint_path, self.checkpoint_manifest.clone())
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let checkpoint = store
            .load_latest(&self.run_id)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let mut state = serde_json::from_slice::<State>(checkpoint.state())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        Self::bind_digest(&mut state, nodes)?;
        store
            .save_checkpoint(
                DurableCheckpointV1::new(
                    self.run_id.clone(),
                    checkpoint.node_id(),
                    checkpoint.event_sequence(),
                    serde_json::to_vec(&state)
                        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?,
                    checkpoint.artifact_refs().iter().cloned(),
                )
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?,
            )
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
    }

    fn bind_current_digest(&self, state: &mut State) -> Result<(), ExecutionError> {
        let nodes = self
            .nodes
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        Self::bind_digest(state, &nodes)
    }

    fn bind_digest(
        state: &mut State,
        nodes: &BTreeMap<String, LoopState>,
    ) -> Result<(), ExecutionError> {
        state.insert(
            LOOP_LEDGER_DIGEST_KEY.to_owned(),
            Value::String(loop_ledger_digest(nodes)?),
        );
        Ok(())
    }
}

fn loop_ledger_digest(nodes: &BTreeMap<String, LoopState>) -> Result<String, ExecutionError> {
    let canonical = serde_json::to_vec(&(2_u8, nodes))
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn checkpoint_ledger_digest(state: &[u8]) -> Result<String, ExecutionError> {
    serde_json::from_slice::<State>(state)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?
        .get(LOOP_LEDGER_DIGEST_KEY)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))
}

fn tool_response_content(call: &PendingCall, response: Value) -> adk_rust::Content {
    adk_rust::Content {
        role: "function".to_owned(),
        parts: vec![adk_rust::Part::FunctionResponse {
            function_response: adk_rust::FunctionResponseData::from_tool_result(
                &call.name, response,
            ),
            id: Some(call.id.clone()),
            annotations: None,
        }],
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelFinish {
    status: FinishStatus,
    output: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum FinishStatus {
    Finished,
}

fn admitted_finish(content: &adk_rust::Content) -> Result<Option<Value>, ()> {
    let mut output = None;
    let mut has_call = false;
    for part in &content.parts {
        match part {
            adk_rust::Part::Text { text } if !text.trim().is_empty() => {
                let ModelFinish {
                    status: FinishStatus::Finished,
                    output: next,
                } = serde_json::from_str(text).map_err(|_| ())?;
                if output.replace(next).is_some() {
                    return Err(());
                }
            }
            adk_rust::Part::FunctionCall { .. } => has_call = true,
            _ => {}
        }
    }
    if has_call && output.is_some() {
        return Err(());
    }
    if has_call {
        Ok(None)
    } else {
        output.map(Some).ok_or(())
    }
}

fn valid_terminal_state(state: &LoopState) -> bool {
    match (&state.finished_output, state.finish_admitted) {
        (None, false) => true,
        (Some(output), true) if state.pending_calls.is_empty() => {
            state
                .conversation
                .last()
                .and_then(|content| admitted_finish(content).ok().flatten())
                .as_ref()
                == Some(output)
        }
        _ => false,
    }
}

fn valid_loop_state(state: &LoopState) -> bool {
    if !valid_terminal_state(state) {
        return false;
    }

    let mut calls = VecDeque::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_calls = BTreeSet::new();
    let mut tool_calls = BTreeMap::<String, u64>::new();
    let mut completed_ids = BTreeSet::new();
    let mut tool_output_bytes = 0_u64;
    let mut model_iterations = 0_u64;

    for content in &state.conversation {
        let has_call = content
            .parts
            .iter()
            .any(|part| matches!(part, adk_rust::Part::FunctionCall { .. }));
        if has_call || admitted_finish(content).is_ok_and(|output| output.is_some()) {
            let Some(next) = model_iterations.checked_add(1) else {
                return false;
            };
            model_iterations = next;
        }
        for part in &content.parts {
            match part {
                adk_rust::Part::FunctionCall {
                    name,
                    args,
                    id: Some(id),
                    ..
                } if !id.is_empty() && args.is_object() => {
                    let fingerprint = workflow_runtime::argument_fingerprint(args);
                    if !seen_ids.insert(id.clone())
                        || !seen_calls.insert((name.clone(), fingerprint.clone()))
                    {
                        return false;
                    }
                    let Some(count) = tool_calls.get(name).copied().unwrap_or(0).checked_add(1)
                    else {
                        return false;
                    };
                    tool_calls.insert(name.clone(), count);
                    calls.push_back(PendingCall {
                        id: id.clone(),
                        name: name.clone(),
                        args: args.clone(),
                        fingerprint,
                    });
                }
                adk_rust::Part::FunctionCall { .. } => return false,
                adk_rust::Part::FunctionResponse {
                    function_response,
                    id: Some(id),
                    ..
                } if !id.is_empty() => {
                    if !seen_ids.contains(id) || !completed_ids.insert(id.clone()) {
                        return false;
                    }
                    let Ok(bytes) = serde_json::to_vec(&function_response.response) else {
                        return false;
                    };
                    let Ok(bytes) = u64::try_from(bytes.len()) else {
                        return false;
                    };
                    let Some(total) = tool_output_bytes.checked_add(bytes) else {
                        return false;
                    };
                    tool_output_bytes = total;
                }
                adk_rust::Part::FunctionResponse { .. } => return false,
                _ => {}
            }
        }
    }

    let pending_calls = calls
        .into_iter()
        .filter(|call| !completed_ids.contains(&call.id))
        .collect::<VecDeque<_>>();
    let Ok(total_tool_calls) = u64::try_from(seen_ids.len()) else {
        return false;
    };
    state.model_iterations == model_iterations
        && state.total_tool_calls == total_tool_calls
        && state.tool_calls == tool_calls
        && state.seen_ids == seen_ids
        && state.seen_calls == seen_calls
        && state.pending_calls.len() == pending_calls.len()
        && state
            .pending_calls
            .iter()
            .zip(pending_calls.iter())
            .all(|(actual, expected)| {
                actual.id == expected.id
                    && actual.name == expected.name
                    && actual.args == expected.args
                    && actual.fingerprint == expected.fingerprint
            })
        && state.tool_output_bytes == tool_output_bytes
}

fn ledger_checkpoint_identity(
    checkpoint_manifest: &CheckpointManifestV1,
) -> Result<String, ExecutionError> {
    let manifest = serde_json::to_vec(checkpoint_manifest)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    Ok(format!("sha256:{:x}", Sha256::digest(manifest)))
}

struct LoopController {
    limits: RunLimits,
    state: Mutex<LoopState>,
    node: String,
    ledger: Arc<LoopLedgerStore>,
    terminal: Arc<Mutex<Option<ExecutionErrorKind>>>,
    cancellation: Arc<AtomicBool>,
    last_progress: Arc<Mutex<Instant>>,
}

fn record_terminal(terminal: &Mutex<Option<ExecutionErrorKind>>, kind: ExecutionErrorKind) {
    if let Ok(mut terminal) = terminal.lock()
        && (terminal.is_none()
            || (*terminal == Some(ExecutionErrorKind::Tool)
                && kind == ExecutionErrorKind::ToolTimeLimit))
    {
        *terminal = Some(kind);
    }
}

impl LoopController {
    fn new(
        node: impl Into<String>,
        limits: RunLimits,
        ledger: Arc<LoopLedgerStore>,
        terminal: Arc<Mutex<Option<ExecutionErrorKind>>>,
        cancellation: Arc<AtomicBool>,
        last_progress: Arc<Mutex<Instant>>,
    ) -> Result<Self, ExecutionError> {
        let node = node.into();
        Ok(Self {
            limits,
            state: Mutex::new(ledger.snapshot(&node)?),
            node,
            ledger,
            terminal,
            cancellation,
            last_progress,
        })
    }

    fn fail(&self, kind: ExecutionErrorKind, marker: &'static str) -> adk_rust::AdkError {
        record_terminal(&self.terminal, kind);
        adk_rust::AdkError::agent(marker)
    }

    fn before_model(
        &self,
        mut request: adk_rust::LlmRequest,
    ) -> adk_rust::Result<adk_rust::LlmRequest> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(self.fail(ExecutionErrorKind::Cancelled, "workflow.loop.cancelled"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| adk_rust::AdkError::agent("model call state poisoned"))?;
        if state.model_iterations >= self.limits.max_model_turns().get() {
            return Err(self.fail(
                ExecutionErrorKind::ModelIterationsLimit,
                "workflow.loop.limit.model_iterations",
            ));
        }
        if state.conversation.is_empty() {
            state.conversation = request.contents.clone();
            self.ledger
                .replace(&self.node, state.clone())
                .map_err(|_| {
                    self.fail(ExecutionErrorKind::Persistence, "loop ledger unavailable")
                })?;
        } else {
            request.contents = state.conversation.clone();
            request.previous_response_id = state.previous_response_id.clone();
        }
        Ok(request)
    }

    fn observe_model(
        &self,
        response: &adk_rust::LlmResponse,
        allowed: &BTreeSet<String>,
    ) -> adk_rust::Result<()> {
        let content = response
            .content
            .as_ref()
            .ok_or_else(|| adk_rust::AdkError::agent("model response missing content"))?;
        let mut last_progress = self
            .last_progress
            .lock()
            .map_err(|_| adk_rust::AdkError::agent("model call state poisoned"))?;
        if last_progress.elapsed().as_millis() as u64 >= self.limits.max_idle_time_ms().get() {
            return Err(self.fail(
                ExecutionErrorKind::IdleTimeLimit,
                "workflow.loop.timeout.idle",
            ));
        }
        let finished_output = admitted_finish(content)
            .map_err(|_| adk_rust::AdkError::agent("model response missing typed finish"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| adk_rust::AdkError::agent("model call state poisoned"))?;
        let mut next = state.clone();
        for part in &content.parts {
            if let adk_rust::Part::FunctionCall { name, args, id, .. } = part {
                let id = id
                    .as_deref()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| adk_rust::AdkError::agent("model call missing ID"))?;
                if !allowed.contains(name) || !args.is_object() {
                    return Err(adk_rust::AdkError::agent(
                        "model call is unselected or schema-invalid",
                    ));
                }
                let fingerprint = workflow_runtime::argument_fingerprint(args);
                if !next.seen_ids.insert(id.to_owned())
                    || !next.seen_calls.insert((name.clone(), fingerprint.clone()))
                {
                    return Err(adk_rust::AdkError::agent("repeated model tool call"));
                }
                next.total_tool_calls = next.total_tool_calls.saturating_add(1);
                *next.tool_calls.entry(name.clone()).or_default() += 1;
                next.pending_calls.push_back(PendingCall {
                    id: id.to_owned(),
                    name: name.clone(),
                    args: args.clone(),
                    fingerprint,
                });
            }
        }
        next.finish_admitted = finished_output.is_some();
        next.finished_output = finished_output;
        next.model_iterations += 1;
        next.conversation.push(content.clone());
        next.previous_response_id = response.interaction_id.clone();
        if let Some(kind) = self
            .ledger
            .tool_call_limit(&self.node, &next, &self.limits)
            .map_err(|_| self.fail(ExecutionErrorKind::Persistence, "loop ledger unavailable"))?
        {
            let marker = match kind {
                ExecutionErrorKind::TotalToolCallsLimit => "workflow.loop.limit.total_tool_calls",
                ExecutionErrorKind::ToolCallsPerToolLimit => "workflow.loop.limit.per_tool_calls",
                _ => unreachable!(),
            };
            return Err(self.fail(kind, marker));
        }
        *state = next;
        *last_progress = Instant::now();
        Ok(())
    }

    fn observe_tool(
        &self,
        context: &dyn adk_rust::CallbackContext,
        response: &Value,
    ) -> adk_rust::Result<()> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(self.fail(ExecutionErrorKind::Cancelled, "workflow.loop.cancelled"));
        }
        let outcome = context
            .tool_outcome()
            .ok_or_else(|| self.fail(ExecutionErrorKind::Tool, "tool.bridge.failed"))?;
        if outcome.duration.as_millis() as u64 >= self.limits.max_tool_time_ms().get() {
            return Err(self.fail(
                ExecutionErrorKind::ToolTimeLimit,
                "workflow.loop.timeout.tool",
            ));
        }
        if !outcome.success {
            return Err(self.fail(ExecutionErrorKind::Tool, "tool.bridge.failed"));
        }
        let bytes = serde_json::to_vec(response)
            .map_err(|_| self.fail(ExecutionErrorKind::Tool, "tool.bridge.failed"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| adk_rust::AdkError::agent("model call state poisoned"))?;
        let mut next = state.clone();
        next.tool_output_bytes = next
            .tool_output_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let name = context
            .tool_name()
            .ok_or_else(|| self.fail(ExecutionErrorKind::Tool, "tool.bridge.failed"))?;
        let input = context
            .tool_input()
            .ok_or_else(|| self.fail(ExecutionErrorKind::Tool, "tool.bridge.failed"))?;
        let fingerprint = workflow_runtime::argument_fingerprint(input);
        let index = next
            .pending_calls
            .iter()
            .position(|call| call.name == name && call.fingerprint == fingerprint)
            .ok_or_else(|| self.fail(ExecutionErrorKind::Tool, "tool.bridge.failed"))?;
        let call = next
            .pending_calls
            .remove(index)
            .ok_or_else(|| self.fail(ExecutionErrorKind::Tool, "tool.bridge.failed"))?;
        next.conversation
            .push(tool_response_content(&call, response.clone()));
        if self
            .ledger
            .output_byte_limit(&self.node, &next, self.limits.max_tool_output_bytes().get())
            .map_err(|_| self.fail(ExecutionErrorKind::Persistence, "loop ledger unavailable"))?
        {
            return Err(self.fail(
                ExecutionErrorKind::ToolOutputBytesLimit,
                "workflow.loop.limit.tool_output_bytes",
            ));
        }
        *state = next;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphContinuationV1 {
    schema_version: u8,
    pending_nodes: Vec<String>,
    step: usize,
    retry: BTreeMap<String, u32>,
    route_frontier: BTreeMap<String, Value>,
    visits: BTreeMap<String, u64>,
}

impl GraphContinuationV1 {
    fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        let route_frontier = checkpoint
            .state
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix("route:")
                    .map(|node| (node.to_owned(), value.clone()))
            })
            .collect();
        let visits = checkpoint
            .state
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix("visits:")
                    .zip(value.as_u64())
                    .map(|(node, visits)| (node.to_owned(), visits))
            })
            .collect();
        Self {
            schema_version: 1,
            pending_nodes: checkpoint.pending_nodes.clone(),
            step: checkpoint.step,
            retry: checkpoint
                .attempts
                .iter()
                .map(|(node, attempts)| (node.clone(), *attempts))
                .collect(),
            route_frontier,
            visits,
        }
    }

    fn restore(
        self,
        state: &mut State,
        run_id: &str,
        nodes: &BTreeSet<String>,
    ) -> Option<Checkpoint> {
        if self.schema_version != 1
            || self
                .pending_nodes
                .iter()
                .chain(self.retry.keys())
                .chain(self.route_frontier.keys())
                .chain(self.visits.keys())
                .any(|node| !nodes.contains(node))
        {
            return None;
        }
        for (node, route) in &self.route_frontier {
            state.insert(format!("route:{node}"), route.clone());
        }
        for (node, visits) in &self.visits {
            state.insert(format!("visits:{node}"), json!(visits));
        }
        let mut checkpoint = Checkpoint::new(run_id, state.clone(), self.step, self.pending_nodes);
        checkpoint.attempts = self.retry.into_iter().collect();
        Some(checkpoint)
    }
}

#[derive(Default)]
struct GraphCheckpointMemory(Mutex<Option<Checkpoint>>);

impl GraphCheckpointMemory {
    fn latest(&self) -> Option<Checkpoint> {
        self.0.lock().ok()?.clone()
    }

    fn restore(&self, checkpoint: Checkpoint) -> bool {
        self.0
            .lock()
            .map(|mut saved| *saved = Some(checkpoint))
            .is_ok()
    }
}

#[async_trait]
impl Checkpointer for GraphCheckpointMemory {
    async fn save(&self, checkpoint: &Checkpoint) -> Result<String, GraphError> {
        *self
            .0
            .lock()
            .map_err(|_| GraphError::Other("graph checkpoint unavailable".to_owned()))? =
            Some(checkpoint.clone());
        Ok(checkpoint.checkpoint_id.clone())
    }

    async fn load(&self, thread_id: &str) -> Result<Option<Checkpoint>, GraphError> {
        Ok(self
            .latest()
            .filter(|checkpoint| checkpoint.thread_id == thread_id))
    }

    async fn load_by_id(&self, checkpoint_id: &str) -> Result<Option<Checkpoint>, GraphError> {
        Ok(self
            .latest()
            .filter(|checkpoint| checkpoint.checkpoint_id == checkpoint_id))
    }

    async fn list(&self, thread_id: &str) -> Result<Vec<Checkpoint>, GraphError> {
        Ok(self.load(thread_id).await?.into_iter().collect())
    }

    async fn delete(&self, thread_id: &str) -> Result<(), GraphError> {
        if self
            .latest()
            .is_some_and(|checkpoint| checkpoint.thread_id == thread_id)
        {
            *self
                .0
                .lock()
                .map_err(|_| GraphError::Other("graph checkpoint unavailable".to_owned()))? = None;
        }
        Ok(())
    }
}

fn checkpoint_state(
    mut state: State,
    checkpoint: &Checkpoint,
    prior_retry: Option<&BTreeMap<String, u32>>,
) -> Result<State, ExecutionError> {
    let mut continuation = GraphContinuationV1::from_checkpoint(checkpoint);
    if let Some(prior_retry) = prior_retry {
        for (node, attempts) in prior_retry {
            continuation.retry.entry(node.clone()).or_insert(*attempts);
        }
    }
    state.insert(
        GRAPH_CONTINUATION_KEY.to_owned(),
        serde_json::to_value(continuation)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?,
    );
    Ok(state)
}

fn restore_checkpoint_state(
    state: &mut State,
    run_id: &str,
    nodes: BTreeSet<String>,
) -> Result<Checkpoint, ExecutionError> {
    let continuation = state
        .remove(GRAPH_CONTINUATION_KEY)
        .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
    let continuation = serde_json::from_value::<GraphContinuationV1>(continuation)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
    continuation
        .restore(state, run_id, &nodes)
        .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SkillWire {
    id: String,
    version: String,
    root: PathBuf,
}

struct SkillPackage {
    id: SkillId,
    version: String,
    manifest: SkillManifest,
    skill_markdown: Vec<u8>,
    runtime: SkillRuntimeManifest,
    lock: SkillRuntimeLock,
    scripts: BTreeMap<String, Vec<u8>>,
    resources: BTreeMap<SkillResourceId, Vec<u8>>,
}

impl SkillPackage {
    fn load(wire: &SkillWire) -> Result<Self, ExecutionError> {
        let id = SkillId::new(&wire.id)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidProfile))?;
        if wire.version.is_empty() {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
        }
        let skill_markdown = package_file(&wire.root, "SKILL.md")?;
        let manifest = SkillManifest::parse(&wire.root, &skill_markdown)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
        let runtime_bytes = package_file(&wire.root, "skill.runtime.toml")?;
        let runtime = SkillRuntimeManifest::parse(&runtime_bytes)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
        if runtime.skill_id() != &id || runtime.skill_version() != wire.version {
            return Err(ExecutionError::new(
                ExecutionErrorKind::ImplementationBinding,
            ));
        }
        let mut scripts = BTreeMap::new();
        for script in runtime.scripts() {
            scripts.insert(
                script.id().as_str().to_owned(),
                package_file(&wire.root, script.path())?,
            );
        }
        let mut resources = BTreeMap::new();
        for resource in runtime.resources() {
            resources.insert(
                resource.id().clone(),
                package_file(&wire.root, resource.id().as_str())?,
            );
        }
        let lock = SkillRuntimeLock::try_from_declared_bytes(
            &runtime,
            &skill_markdown,
            scripts
                .iter()
                .map(|(id, bytes)| (id.as_str(), bytes.as_slice())),
            resources.iter().map(|(id, bytes)| (id, bytes.as_slice())),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
        let package = Self {
            id,
            version: wire.version.clone(),
            manifest,
            skill_markdown,
            runtime,
            lock,
            scripts,
            resources,
        };
        let activation = activate_skill(&package, &package.id, &package.version)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
        SkillRuntimeManifest::parse_for_activation(&activation, &runtime_bytes)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
        Ok(package)
    }

    fn binding(&self) -> Result<ResolvedBinding, ExecutionError> {
        let identity = self
            .lock
            .to_toml()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
        Ok(ResolvedBinding::new(self.id.as_str(), &self.version)
            .with_metadata_identity(format!("sha256:{:x}", Sha256::digest(identity))))
    }

    fn capabilities(&self) -> impl Iterator<Item = SandboxCapability> + '_ {
        self.runtime
            .scripts()
            .iter()
            .flat_map(|script| script.capabilities().iter().copied())
    }

    fn read_resource(
        &self,
        id: &SkillResourceId,
        request: PageRequest,
    ) -> Result<Value, ToolBridgeError> {
        if !self.resources.contains_key(id) {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied));
        }
        let activation = activate_skill(self, &self.id, &self.version)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let capabilities = intersect_policy_capabilities(
            &RequestedCapabilities::new([SandboxCapability::FilesystemRead]),
            &[PolicyCapabilities::new([SandboxCapability::FilesystemRead])],
        )
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied))?;
        let mut resources = activation
            .attach_resources(
                &capabilities,
                SkillResourceLimits::new(
                    NonZeroUsize::new(self.resources.len().max(1))
                        .expect("positive resource limit"),
                    NonZeroU64::new(65_536).expect("positive resource limit"),
                    NonZeroU64::new(65_536).expect("positive page limit"),
                    NonZeroU64::new(65_536).expect("positive read limit"),
                ),
                self.resources
                    .iter()
                    .map(|(id, bytes)| SkillResourceInput::file(id.clone(), bytes.clone())),
            )
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let read = resources
            .read_skill_resource(id, request)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        Ok(json!({
            "resource_id": read.metadata().id().as_str(),
            "result_ref": read.metadata().artifact_id().as_str(),
            "content": String::from_utf8_lossy(read.page().bytes()),
        }))
    }
}

impl SkillRegistry for SkillPackage {
    type Implementation = SkillManifest;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        if id == self.id.as_str() && version == self.version {
            Ok(RegistryEntry::new(
                &self.manifest,
                self.id.as_str(),
                &self.version,
            ))
        } else {
            Err(RegistryNotFound::new(
                workflow_compiler::RegistryCategory::Skill,
                id,
                version,
            ))
        }
    }
}

fn package_file(root: &Path, relative: &str) -> Result<Vec<u8>, ExecutionError> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 65_536 {
        return Err(ExecutionError::new(
            ExecutionErrorKind::ImplementationBinding,
        ));
    }
    fs::read(path).map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))
}

/// A validated runtime profile supplied to the reusable ADK executor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfileV1 {
    schema_version: u16,
    model: ModelWire,
    reviewer_model: Option<ModelWire>,
    tool: Option<ToolWire>,
    #[serde(default)]
    tools: Vec<ToolWire>,
    #[serde(default)]
    skills: Vec<SkillWire>,
    pure_transform: Option<PureTransformWire>,
    sandbox: SandboxWire,
    #[serde(default)]
    loop_policy: Option<LoopPolicyWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
enum ModelWire {
    Fake {
        name: String,
        version: String,
        model: String,
        responses: Vec<Value>,
        #[serde(default)]
        response_delay_ms: u64,
    },
    OpenaiCompatible {
        name: String,
        version: String,
        model: String,
        base_url: String,
        credential_env: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolWire {
    name: String,
    result: Value,
    input_schema: Value,
    #[serde(default)]
    delay_ms: u64,
    #[serde(default)]
    handler_error: bool,
    #[serde(default)]
    required_capabilities: Vec<String>,
    #[serde(default)]
    required_scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PureTransformWire {
    module: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SandboxWire {
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LoopPolicyWire {
    schema_version: u16,
    max_model_iterations: u32,
    max_total_tool_calls: u64,
    max_tool_calls_per_tool: u64,
    wall_time_ms: u64,
    idle_time_ms: u64,
    tool_time_ms: u64,
    max_tool_output_bytes: u64,
}

impl ExecutionProfileV1 {
    /// Parses and validates one bounded, secret-free profile projection.
    pub fn parse(bytes: &[u8]) -> Result<Self, ExecutionError> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
        }
        let profile: Self = serde_json::from_slice(bytes)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidProfile))?;
        if profile.schema_version != 1 {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
        }
        for model in std::iter::once(&profile.model).chain(profile.reviewer_model.iter()) {
            match model {
                ModelWire::Fake {
                    name,
                    version,
                    model,
                    responses,
                    response_delay_ms,
                } => {
                    if [name, version, model]
                        .into_iter()
                        .any(|value| value.is_empty())
                        || responses.is_empty()
                        || *response_delay_ms > 60_000
                        || responses.iter().any(|response| match response {
                            Value::String(value) => value.is_empty(),
                            Value::Object(value) => value
                                .get("calls")
                                .and_then(Value::as_array)
                                .is_none_or(Vec::is_empty),
                            _ => true,
                        })
                    {
                        return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
                    }
                }
                ModelWire::OpenaiCompatible {
                    name,
                    version,
                    model,
                    base_url,
                    credential_env,
                } => {
                    if [name, version, model, base_url, credential_env]
                        .into_iter()
                        .any(|value| value.is_empty())
                    {
                        return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
                    }
                }
            }
        }
        let mut tool_names = BTreeSet::new();
        if profile
            .tool_wires()
            .any(|tool| tool.name.is_empty() || !tool_names.insert(tool.name.as_str()))
            || profile
                .pure_transform
                .as_ref()
                .is_some_and(|transform| transform.module.is_empty())
        {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
        }
        if profile.loop_policy.as_ref().is_some_and(|policy| {
            policy.schema_version != 1
                || policy.max_model_iterations == 0
                || policy.max_total_tool_calls == 0
                || policy.max_tool_calls_per_tool == 0
                || policy.wall_time_ms == 0
                || policy.idle_time_ms == 0
                || policy.tool_time_ms == 0
                || policy.max_tool_output_bytes == 0
        }) {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
        }
        profile.capabilities()?;
        Ok(profile)
    }

    fn tool_wires(&self) -> impl Iterator<Item = &ToolWire> {
        self.tool.iter().chain(&self.tools)
    }

    fn skill_packages(&self) -> Result<BTreeMap<String, Arc<SkillPackage>>, ExecutionError> {
        let mut packages = BTreeMap::new();
        for wire in &self.skills {
            let package = Arc::new(SkillPackage::load(wire)?);
            if packages.insert(wire.id.clone(), package).is_some() {
                return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
            }
        }
        Ok(packages)
    }

    fn capabilities(
        &self,
    ) -> Result<(Vec<SandboxCapability>, Vec<SandboxCapability>), ExecutionError> {
        let sandbox = self
            .sandbox
            .capabilities
            .iter()
            .map(|value| parse_capability(value))
            .collect::<Result<Vec<_>, _>>()?;
        let mut required = self
            .tool_wires()
            .flat_map(|tool| tool.required_capabilities.iter())
            .map(|value| parse_capability(value))
            .collect::<Result<Vec<_>, _>>()?;
        required.extend(
            self.skill_packages()?
                .values()
                .flat_map(|package| package.capabilities()),
        );
        required.sort_unstable_by_key(SandboxCapability::as_str);
        required.dedup();
        Ok((sandbox, required))
    }

    fn bind_model(
        &self,
        role: IrModelRole,
        completed_turns: u64,
    ) -> Result<Arc<ModelBinding>, ExecutionError> {
        let model = match role {
            IrModelRole::Worker => &self.model,
            IrModelRole::Reviewer => self
                .reviewer_model
                .as_ref()
                .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?,
        };
        let registry = match (role, model) {
            (
                IrModelRole::Worker,
                ModelWire::Fake {
                    name,
                    version,
                    model,
                    responses,
                    response_delay_ms,
                },
            ) => ModelProfileRegistry::new().with_worker(FakeModelProfile::from_values(
                name,
                version,
                model,
                responses
                    .iter()
                    .skip(usize::try_from(completed_turns).unwrap_or(usize::MAX))
                    .cloned()
                    .collect(),
                *response_delay_ms,
            )),
            (
                IrModelRole::Reviewer,
                ModelWire::Fake {
                    name,
                    version,
                    model,
                    responses,
                    response_delay_ms,
                },
            ) => ModelProfileRegistry::new().with_reviewer(FakeModelProfile::from_values(
                name,
                version,
                model,
                responses
                    .iter()
                    .skip(usize::try_from(completed_turns).unwrap_or(usize::MAX))
                    .cloned()
                    .collect(),
                *response_delay_ms,
            )),
            (
                IrModelRole::Worker,
                ModelWire::OpenaiCompatible {
                    name,
                    version,
                    model,
                    base_url,
                    credential_env,
                },
            ) => ModelProfileRegistry::new().with_worker(OpenAiCompatibleProfile::new(
                name,
                version,
                model,
                base_url,
                CredentialHandle::environment(credential_env),
            )),
            (
                IrModelRole::Reviewer,
                ModelWire::OpenaiCompatible {
                    name,
                    version,
                    model,
                    base_url,
                    credential_env,
                },
            ) => ModelProfileRegistry::new().with_reviewer(OpenAiCompatibleProfile::new(
                name,
                version,
                model,
                base_url,
                CredentialHandle::environment(credential_env),
            )),
        }
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidProfile))?;
        match role {
            IrModelRole::Worker => registry.bind_worker(&CredentialBroker::new()),
            IrModelRole::Reviewer => registry.bind_reviewer(&CredentialBroker::new()),
        }
        .map(Arc::new)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Model))
    }

    fn transform_module(&self) -> Result<Option<Vec<u8>>, ExecutionError> {
        self.pure_transform
            .as_ref()
            .map(|transform| {
                read_bounded_regular_file(
                    &SourcePath::from(transform.module.as_str()),
                    PureTransformRequest::MAX_MODULE_BYTES,
                )
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidProfile))
            })
            .transpose()
    }

    fn model_binding(&self) -> (&str, &str) {
        Self::wire_binding(&self.model)
    }

    fn wire_binding(model: &ModelWire) -> (&str, &str) {
        match model {
            ModelWire::Fake { name, version, .. }
            | ModelWire::OpenaiCompatible { name, version, .. } => (name, version),
        }
    }

    fn model_binding_for_role(&self, role: IrModelRole) -> Option<(&str, &str)> {
        match role {
            IrModelRole::Worker => Some(self.model_binding()),
            IrModelRole::Reviewer => self.reviewer_model.as_ref().map(Self::wire_binding),
        }
    }

    fn tool_registration(&self, tool: &ToolWire) -> Result<ToolRegistration, ExecutionError> {
        let required_capabilities = tool
            .required_capabilities
            .iter()
            .map(|capability| parse_capability(capability))
            .collect::<Result<Vec<_>, _>>()?;
        let implementation_digest = serde_json::to_vec(&tool.result)
            .map(|result| format!("sha256:{:x}", Sha256::digest(result)))
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
        ToolRegistration::for_types::<Value, Value>(
            &tool.name,
            ToolProvenance::new(&tool.name, "1"),
            ToolFlags::new(true, true, true),
        )
        .and_then(|registration| registration.with_input_schema(tool.input_schema.clone()))
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))
        .map(|registration| {
            registration
                .with_required_capabilities(required_capabilities)
                .with_required_scopes(tool.required_scopes.iter().cloned())
                .with_timeout(self.run_limits().max_tool_time_ms())
                .with_implementation_digest(implementation_digest)
        })
    }

    fn tool_bindings(&self) -> Result<Vec<ResolvedBinding>, ExecutionError> {
        self.tool_wires()
            .map(|tool| {
                let registration = self.tool_registration(tool)?;
                let metadata_identity =
                    selection_identity(std::iter::once((registration.name(), &registration)))
                        .map_err(|_| {
                            ExecutionError::new(ExecutionErrorKind::ImplementationBinding)
                        })?;
                Ok(ResolvedBinding::new(registration.name(), "1")
                    .with_metadata_identity(metadata_identity))
            })
            .collect()
    }

    fn bind_resolved_model(
        &self,
        plan: &ResolvedRuntimePlan,
        node_id: &str,
        completed_turns: u64,
    ) -> Result<Arc<ModelBinding>, ExecutionError> {
        let binding = plan.node_model(node_id).ok_or_else(|| {
            ExecutionError::binding(
                ExecutionErrorKind::MissingBinding,
                BindingCategory::Model,
                None,
            )
        })?;
        let role = plan.node_model_role(node_id).ok_or_else(|| {
            ExecutionError::binding(
                ExecutionErrorKind::MissingBinding,
                BindingCategory::Model,
                None,
            )
        })?;
        let expected = self.model_binding_for_role(role);
        if expected != Some((binding.id(), binding.version())) {
            return Err(ExecutionError::binding(
                ExecutionErrorKind::MismatchedBinding,
                BindingCategory::Model,
                Some(binding),
            ));
        }
        let registry = ExecutionRuntimeRegistry::new(self)?;
        registry
            .resolve(
                BindingCategory::Model,
                &BindingRef::new(binding.id(), binding.version()),
            )
            .map_err(|error| map_registry_error(error, Some(binding)))?;
        self.bind_model(role, completed_turns).map_err(|_| {
            ExecutionError::binding(
                ExecutionErrorKind::ImplementationBinding,
                BindingCategory::Model,
                Some(binding),
            )
        })
    }

    fn profile_identity(&self) -> String {
        let (worker, worker_version) = self.model_binding();
        match self.reviewer_model.as_ref().map(Self::wire_binding) {
            Some((reviewer, reviewer_version)) => {
                format!("worker={worker}:{worker_version};reviewer={reviewer}:{reviewer_version}")
            }
            None => format!("worker={worker}:{worker_version}"),
        }
    }

    fn run_limits(&self) -> RunLimits {
        let positive = |value| NonZeroU64::new(value).expect("validated positive loop policy");
        let policy = self.loop_policy.as_ref();
        RunLimits::new(
            positive(policy.map_or(100, |value| u64::from(value.max_model_iterations))),
            positive(policy.map_or(100, |value| value.max_total_tool_calls)),
            positive(policy.map_or(100, |value| value.max_tool_calls_per_tool)),
            positive(policy.map_or(60_000, |value| value.wall_time_ms)),
            positive(policy.map_or(60_000, |value| value.idle_time_ms)),
            positive(policy.map_or(60_000, |value| value.tool_time_ms)),
            positive(policy.map_or(ARTIFACT_LIMIT, |value| value.max_tool_output_bytes)),
        )
    }
}

struct ExecutionRuntimeRegistry {
    candidates: BTreeMap<BindingCategory, Vec<ResolvedBinding>>,
}

impl ExecutionRuntimeRegistry {
    fn new(profile: &ExecutionProfileV1) -> Result<Self, ExecutionError> {
        let mut candidates = BTreeMap::new();
        let (model, version) = profile.model_binding();
        let mut models = vec![ResolvedBinding::new(model, version)];
        if let Some(reviewer) = &profile.reviewer_model {
            let (model, version) = ExecutionProfileV1::wire_binding(reviewer);
            models.push(ResolvedBinding::new(model, version));
        }
        candidates.insert(BindingCategory::Model, models);
        let tools = profile.tool_bindings()?;
        if !tools.is_empty() {
            candidates.insert(BindingCategory::Tool, tools);
        }
        let skills = profile
            .skill_packages()?
            .values()
            .map(|package| package.binding())
            .collect::<Result<Vec<_>, _>>()?;
        if !skills.is_empty() {
            candidates.insert(BindingCategory::Skill, skills);
        }
        Ok(ExecutionRuntimeRegistry { candidates })
    }
}

impl RuntimePlanRegistry for ExecutionRuntimeRegistry {
    fn resolve(
        &self,
        category: BindingCategory,
        binding: &BindingRef,
    ) -> Result<ResolvedBinding, RegistryResolutionError> {
        let matches = self
            .candidates
            .get(&category)
            .into_iter()
            .flatten()
            .filter(|candidate| {
                candidate.id() == binding.id() && candidate.version() == binding.version()
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [candidate] => Ok((*candidate).clone()),
            [] => Err(RegistryResolutionError::missing(category, binding)),
            _ => Err(RegistryResolutionError::ambiguous(category)),
        }
    }
}

fn map_registry_error(
    error: RegistryResolutionError,
    resolved: Option<&ResolvedBinding>,
) -> ExecutionError {
    let kind = match error.kind() {
        workflow_compiler::RegistryResolutionErrorKind::Missing => {
            ExecutionErrorKind::MissingBinding
        }
        workflow_compiler::RegistryResolutionErrorKind::Ambiguous => {
            ExecutionErrorKind::AmbiguousBinding
        }
    };
    ExecutionError::binding(kind, error.category(), resolved)
}

fn resolve_runtime_plan(
    profile: &ExecutionProfileV1,
    ir: &workflow_ir::WorkflowIr,
) -> Result<ResolvedRuntimePlan, ExecutionError> {
    let mut request = RuntimePlanRequest::from_ir(ir);
    let (backend_capabilities, required_capabilities) = profile.capabilities()?;
    let requested = CapabilitySet::new(required_capabilities.iter().map(SandboxCapability::as_str));
    let effective = CapabilitySet::new(
        required_capabilities
            .iter()
            .filter(|capability| {
                backend_capabilities
                    .iter()
                    .any(|backend| backend == *capability)
            })
            .map(SandboxCapability::as_str),
    );
    request.set_capabilities(requested);
    request.set_effective_capabilities(effective);
    ResolvedRuntimePlan::resolve(request, &ExecutionRuntimeRegistry::new(profile)?).map_err(
        |error| {
            let kind = match error.kind() {
                workflow_compiler::PlanResolutionErrorKind::MissingBinding => {
                    ExecutionErrorKind::MissingBinding
                }
                workflow_compiler::PlanResolutionErrorKind::AmbiguousBinding => {
                    ExecutionErrorKind::AmbiguousBinding
                }
                workflow_compiler::PlanResolutionErrorKind::CapabilityWidening
                | workflow_compiler::PlanResolutionErrorKind::InvalidBinding => {
                    ExecutionErrorKind::MismatchedBinding
                }
            };
            ExecutionError::binding(
                kind,
                error.category().unwrap_or(BindingCategory::Model),
                None,
            )
        },
    )
}

fn effective_sandbox_capabilities(
    plan: &ResolvedRuntimePlan,
) -> Result<Vec<SandboxCapability>, ExecutionError> {
    plan.effective_capabilities()
        .as_slice()
        .into_iter()
        .map(parse_capability)
        .collect()
}

fn parse_capability(value: &str) -> Result<SandboxCapability, ExecutionError> {
    match value {
        "filesystem.read" => Ok(SandboxCapability::FilesystemRead),
        "filesystem.write" => Ok(SandboxCapability::FilesystemWrite),
        "network" => Ok(SandboxCapability::Network),
        "process.spawn" => Ok(SandboxCapability::ProcessSpawn),
        "limit.pids" => Ok(SandboxCapability::MaximumPids),
        "limit.cpu_time" => Ok(SandboxCapability::CpuTime),
        "limit.wall_time" => Ok(SandboxCapability::WallTime),
        "limit.idle_time" => Ok(SandboxCapability::IdleTime),
        "limit.memory" => Ok(SandboxCapability::Memory),
        "limit.output_bytes" => Ok(SandboxCapability::OutputBytes),
        "limit.open_files" => Ok(SandboxCapability::OpenFiles),
        "environment.variables" => Ok(SandboxCapability::EnvironmentVariables),
        "syscall.profile" => Ok(SandboxCapability::SyscallProfile),
        "identity.user_group" => Ok(SandboxCapability::UserGroupIdentity),
        "device.access" => Ok(SandboxCapability::DeviceAccess),
        _ => Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile)),
    }
}

struct RestoredFinishAgent {
    name: String,
    output: Value,
}

#[async_trait]
impl Agent for RestoredFinishAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "durably restored workflow finish"
    }

    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }

    fn capabilities(&self) -> adk_rust::AgentCapabilities {
        adk_rust::AgentCapabilities {
            shared_state: true,
            ..adk_rust::AgentCapabilities::default()
        }
    }

    async fn run(
        &self,
        _context: Arc<dyn adk_rust::InvocationContext>,
    ) -> adk_rust::Result<adk_rust::EventStream> {
        let text = serde_json::to_string(&json!({
            "status": "finished",
            "output": self.output,
        }))
        .map_err(|_| adk_rust::AdkError::agent("restored finish unavailable"))?;
        let mut event = adk_rust::Event::new(&self.name);
        event.set_content(adk_rust::Content::new("assistant").with_text(text));
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])))
    }
}

fn build_profile_agent(
    name: &str,
    model: Arc<ModelBinding>,
    tool: Option<BoundTool>,
    limits: RunLimits,
    ledger: Arc<LoopLedgerStore>,
    effect_fence: Arc<EffectFence>,
) -> Result<Arc<dyn Agent>, ExecutionError> {
    let (names, toolset) = match tool {
        Some((names, toolset)) => (names, Some(toolset)),
        None => (Vec::new(), None),
    };
    let allowed = Arc::new(names.into_iter().collect::<BTreeSet<_>>());
    let controller = Arc::new(LoopController::new(
        name,
        limits,
        ledger,
        Arc::clone(&effect_fence.terminal),
        Arc::clone(&effect_fence.cancellation),
        Arc::clone(&effect_fence.last_progress),
    )?);
    let before_controller = Arc::clone(&controller);
    let tool_controller = Arc::clone(&controller);
    let tool_error_controller = Arc::clone(&controller);
    let tool_timeout = std::time::Duration::from_millis(controller.limits.max_tool_time_ms().get());
    let mut builder = LlmAgentBuilder::new(name)
        .description("workflow-kit profile-driven agent")
        .model(model)
        .output_schema(json!({
            "type": "object",
            "properties": {
                "status": {"const": "finished"},
                "output": {}
            },
            "required": ["status", "output"],
            "additionalProperties": false
        }))
        .output_max_retries(0)
        .max_iterations(
            u32::try_from(controller.limits.max_model_turns().get())
                .unwrap_or(u32::MAX)
                .saturating_add(1),
        )
        .tool_timeout(tool_timeout)
        .before_model_callback(Box::new(move |_context, request| {
            let controller = Arc::clone(&before_controller);
            Box::pin(async move {
                Ok(adk_rust::BeforeModelResult::Continue(
                    controller.before_model(request)?,
                ))
            })
        }))
        .after_model_callback(Box::new(move |_context, response| {
            let allowed = Arc::clone(&allowed);
            let controller = Arc::clone(&controller);
            Box::pin(async move {
                controller.observe_model(&response, &allowed)?;
                Ok(None)
            })
        }))
        .after_tool_callback_full(Box::new(move |context, _tool, _args, response| {
            let controller = Arc::clone(&tool_controller);
            Box::pin(async move {
                controller.observe_tool(context.as_ref(), &response)?;
                Ok(None)
            })
        }))
        .on_tool_error(Box::new(move |_context, _tool, _args, error| {
            let controller = Arc::clone(&tool_error_controller);
            Box::pin(async move {
                let error = error.to_ascii_lowercase();
                let (kind, code) = if error.contains("authorization_denied") {
                    (
                        ExecutionErrorKind::AuthorizationDenied,
                        "tool.bridge.authorization_denied",
                    )
                } else if error.contains("timeout") || error.contains("timed out") {
                    (
                        ExecutionErrorKind::ToolTimeLimit,
                        "workflow.loop.timeout.tool",
                    )
                } else {
                    (ExecutionErrorKind::Tool, "tool.bridge.failed")
                };
                Err(controller.fail(kind, code))
            })
        }));
    if let Some(toolset) = toolset {
        builder = builder.toolset(toolset);
    }
    builder
        .build()
        .map(|agent| Arc::new(agent) as Arc<dyn Agent>)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))
}

/// Stable terminal information returned by run, resume, and inspect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    run_id: String,
    workflow_id: String,
    status: String,
    artifact_id: String,
    run_root: PathBuf,
    resume_count: u64,
    plan_hash: String,
    resume_identity: String,
}

impl ExecutionReceipt {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn status(&self) -> &str {
        &self.status
    }
    pub fn run_root(&self) -> &Path {
        &self.run_root
    }
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
    pub fn resume_identity(&self) -> &str {
        &self.resume_identity
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunManifestV2 {
    schema_version: u16,
    run_id: String,
    workflow_id: String,
    workflow_version: String,
    workdir_id: String,
    profile_identity: String,
    adk_rust_version: String,
    status: String,
    artifact_id: String,
    resume_count: u64,
    plan_hash: String,
    resume_identity: String,
    checkpoint_manifest: Option<CheckpointManifestV1>,
}

impl RunManifestV2 {
    fn receipt(&self, run_root: PathBuf) -> ExecutionReceipt {
        ExecutionReceipt {
            run_id: self.run_id.clone(),
            workflow_id: self.workflow_id.clone(),
            status: self.status.clone(),
            artifact_id: self.artifact_id.clone(),
            run_root,
            resume_count: self.resume_count,
            plan_hash: self.plan_hash.clone(),
            resume_identity: self.resume_identity.clone(),
        }
    }
}

/// Stable execution failure categories used by the CLI facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionErrorKind {
    InvalidProfile,
    MissingBinding,
    AmbiguousBinding,
    MismatchedBinding,
    ImplementationBinding,
    SandboxDenied,
    Compile,
    Workdir,
    Model,
    Tool,
    Adk,
    AuthorizationDenied,
    ModelIterationsLimit,
    TotalToolCallsLimit,
    ToolCallsPerToolLimit,
    ToolOutputBytesLimit,
    WallTimeLimit,
    IdleTimeLimit,
    ToolTimeLimit,
    Cancelled,
    Persistence,
    RunNotFound,
    IncompatibleManifest,
    InvalidRunState,
}

fn execution_error_kind(error: AdkGraphError) -> ExecutionErrorKind {
    match error {
        AdkGraphError::AuthorizationDenied => ExecutionErrorKind::AuthorizationDenied,
        AdkGraphError::ModelIterationsLimit => ExecutionErrorKind::ModelIterationsLimit,
        AdkGraphError::TotalToolCallsLimit => ExecutionErrorKind::TotalToolCallsLimit,
        AdkGraphError::ToolCallsPerToolLimit => ExecutionErrorKind::ToolCallsPerToolLimit,
        AdkGraphError::ToolOutputBytesLimit => ExecutionErrorKind::ToolOutputBytesLimit,
        AdkGraphError::WallTimeLimit => ExecutionErrorKind::WallTimeLimit,
        AdkGraphError::IdleTimeLimit => ExecutionErrorKind::IdleTimeLimit,
        AdkGraphError::ToolTimeLimit => ExecutionErrorKind::ToolTimeLimit,
        AdkGraphError::Cancelled => ExecutionErrorKind::Cancelled,
        AdkGraphError::ToolFailed => ExecutionErrorKind::Tool,
        _ => ExecutionErrorKind::Adk,
    }
}

fn execution_status(kind: ExecutionErrorKind) -> &'static str {
    match kind {
        ExecutionErrorKind::ModelIterationsLimit
        | ExecutionErrorKind::TotalToolCallsLimit
        | ExecutionErrorKind::ToolCallsPerToolLimit
        | ExecutionErrorKind::ToolOutputBytesLimit => "limit_exceeded",
        ExecutionErrorKind::WallTimeLimit
        | ExecutionErrorKind::IdleTimeLimit
        | ExecutionErrorKind::ToolTimeLimit => "timed_out",
        ExecutionErrorKind::Cancelled => "cancelled",
        _ => "failed",
    }
}

fn execution_deadline(limits: &RunLimits) -> Result<Instant, ExecutionError> {
    Instant::now()
        .checked_add(Duration::from_millis(limits.max_wall_time_ms().get()))
        .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::WallTimeLimit))
}

async fn wait_for_run_deadline(
    deadline: Instant,
    terminal_kind: &Mutex<Option<ExecutionErrorKind>>,
    cancellation: &AtomicBool,
    last_progress: &Mutex<Instant>,
    idle_timeout: Duration,
) -> ExecutionErrorKind {
    loop {
        if cancellation.load(Ordering::Acquire) {
            return ExecutionErrorKind::Cancelled;
        }
        if let Some(kind) = terminal_kind.lock().ok().and_then(|terminal| *terminal) {
            return kind;
        }
        let now = Instant::now();
        if now >= deadline {
            return ExecutionErrorKind::WallTimeLimit;
        }
        let idle_deadline = last_progress
            .lock()
            .ok()
            .and_then(|progress| progress.checked_add(idle_timeout))
            .unwrap_or(now);
        if now >= idle_deadline {
            return ExecutionErrorKind::IdleTimeLimit;
        }
        adk_rust::tokio::time::sleep(
            deadline
                .min(idle_deadline)
                .saturating_duration_since(now)
                .min(Duration::from_millis(1)),
        )
        .await;
    }
}

fn invoke_graph_with_deadline<F>(
    runtime: &adk_rust::tokio::runtime::Runtime,
    deadline: Instant,
    terminal_kind: &Arc<Mutex<Option<ExecutionErrorKind>>>,
    cancellation: &AtomicBool,
    last_progress: &Mutex<Instant>,
    idle_timeout: Duration,
    future: F,
) -> Result<State, ExecutionError>
where
    F: Future<Output = Result<State, AdkGraphError>>,
{
    runtime
        .block_on(async {
            adk_rust::tokio::select! {
                result = future => result,
                kind = wait_for_run_deadline(
                    deadline,
                    terminal_kind,
                    cancellation,
                    last_progress,
                    idle_timeout,
                ) => {
                    record_terminal(terminal_kind, kind);
                    Err(AdkGraphError::WallTimeLimit)
                }
            }
        })
        .map_err(|error| {
            let kind = terminal_kind
                .lock()
                .ok()
                .and_then(|terminal| *terminal)
                .unwrap_or_else(|| execution_error_kind(error));
            ExecutionError::new(kind)
        })
}

fn resume_failure(
    root: &Path,
    events_path: &Path,
    manifest: &mut RunManifestV2,
    resume_count: u64,
    mapper: &AdkEventMapper,
    error: ExecutionError,
) -> ExecutionError {
    manifest.status = execution_status(error.kind()).to_owned();
    manifest.resume_count = resume_count;
    let events_result = write_events(events_path, mapper.events());
    let manifest_result = write_json(&root.join("run-manifest.json"), manifest);
    let receipt = manifest.receipt(root.to_path_buf());
    if events_result.is_err() || manifest_result.is_err() {
        ExecutionError::new(ExecutionErrorKind::Persistence).with_receipt(receipt)
    } else {
        error.with_receipt(receipt)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionError {
    kind: ExecutionErrorKind,
    receipt: Option<Box<ExecutionReceipt>>,
    binding_category: Option<BindingCategory>,
    resolved_binding: Option<ResolvedBinding>,
}

impl ExecutionError {
    fn new(kind: ExecutionErrorKind) -> Self {
        Self {
            kind,
            receipt: None,
            binding_category: None,
            resolved_binding: None,
        }
    }
    fn binding(
        kind: ExecutionErrorKind,
        category: BindingCategory,
        resolved_binding: Option<&ResolvedBinding>,
    ) -> Self {
        Self {
            kind,
            receipt: None,
            binding_category: Some(category),
            resolved_binding: resolved_binding.cloned(),
        }
    }
    pub const fn kind(&self) -> ExecutionErrorKind {
        self.kind
    }
    pub fn receipt(&self) -> Option<&ExecutionReceipt> {
        self.receipt.as_deref()
    }
    pub fn binding_category(&self) -> Option<BindingCategory> {
        self.binding_category
    }
    pub fn resolved_binding(&self) -> Option<&ResolvedBinding> {
        self.resolved_binding.as_ref()
    }
    fn with_receipt(mut self, receipt: ExecutionReceipt) -> Self {
        self.receipt = Some(Box::new(receipt));
        self
    }
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "workflow ADK execution failed: {:?}", self.kind)
    }
}
impl std::error::Error for ExecutionError {}

/// Executes compiled workflows through the real ADK graph boundary.
pub struct ExecutionBackend;

impl ExecutionBackend {
    pub fn run(
        workflow: impl AsRef<Path>,
        profile: ExecutionProfileV1,
        input: Value,
        workdir_base: impl AsRef<Path>,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        Self::run_cancellable(
            workflow,
            profile,
            input,
            workdir_base,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn run_cancellable(
        workflow: impl AsRef<Path>,
        profile: ExecutionProfileV1,
        input: Value,
        workdir_base: impl AsRef<Path>,
        cancellation: Arc<AtomicBool>,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        let input_bytes = serde_json::to_vec(&input)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidProfile))?;
        if input_bytes.len() > PureTransformRequest::MAX_JSON_BYTES {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
        }
        if contains_sensitive_key(&input) {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
        }
        let (sandbox_capabilities, required_capabilities) = profile.capabilities()?;
        let requested = RequestedCapabilities::new(required_capabilities.iter().copied());
        verify_sandbox_capabilities(
            &requested,
            &BackendCapabilities::new(sandbox_capabilities.iter().copied()),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::SandboxDenied))?;

        let compiled = compile_file(workflow.as_ref().to_string_lossy().as_ref())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Compile))?;
        let resolved_plan = resolve_runtime_plan(&profile, compiled.ir())?;
        let resolved_models = compiled
            .ir()
            .nodes()
            .iter()
            .filter(|node| node.kind() == workflow_ir::IrNodeKind::Agent)
            .map(|node| {
                profile
                    .bind_resolved_model(&resolved_plan, node.id().as_str(), 0)
                    .map(|model| (node.id().as_str().to_owned(), model))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let effective_capabilities = effective_sandbox_capabilities(&resolved_plan)?;
        let transform_module = profile.transform_module()?;
        let recursion_limit = compiled
            .ir()
            .nodes()
            .iter()
            .filter_map(workflow_ir::IrNode::max_visits)
            .map(|visits| visits as usize)
            .sum::<usize>()
            .max(50);
        let manager = WorkdirManager::new(workdir_base)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
        let run_id = fresh_run_id()?;
        let checkpoint_manifest = build_checkpoint_manifest(
            &run_id,
            (
                compiled.ir().workflow_id().as_str(),
                compiled.ir().workflow_version(),
            ),
            crate::canonical_ir_hash(compiled.ir()),
            &profile,
            &resolved_plan,
            transform_module.as_deref(),
        )?;
        let ledger_identity = ledger_checkpoint_identity(&checkpoint_manifest)?;
        let context = RunContext::new(run_id.clone(), profile.run_limits());
        let mut mapper = AdkEventMapper::new(run_id.as_str(), compiled.ir().workflow_id().as_str())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let run_workdir = manager
            .materialize(
                &run_id,
                &Materialization {
                    skills: Some(Vec::new()),
                    ..Materialization::default()
                },
            )
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
        let run_root = run_workdir.root().to_path_buf();
        let workdir_id = run_workdir.id().as_str().to_owned();
        let workflow_source = fs::read(workflow.as_ref())
            .ok()
            .filter(|bytes| !bytes.is_empty() && bytes.len() <= MAX_STATE_BYTES);
        let mut artifacts = FilesystemArtifactStore::try_new(
            run_root.join("artifacts"),
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive artifact limit"),
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive page limit"),
        )
        .ok();
        let mut persistence_error = None;
        let mut checkpoint_failed = false;
        if workflow_source
            .as_deref()
            .is_none_or(|source| write_atomic(&run_root.join("workflow.toml"), source).is_err())
            || write_json(&run_root.join("execution-profile.json"), &profile).is_err()
            || write_json(&run_root.join("execution-input.json"), &input).is_err()
        {
            persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
        }
        let effect_journal = match EffectJournal::open(run_root.join("effects.sqlite")) {
            Ok(journal) => Some(Arc::new(journal)),
            Err(_) => {
                persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                None
            }
        };
        let loop_ledger = match LoopLedgerStore::create(
            run_root.join(LOOP_LEDGER_FILE),
            run_root.join("checkpoint.sqlite"),
            ledger_identity,
            checkpoint_manifest.clone(),
            run_id.clone(),
        ) {
            Ok(ledger) => Some(Arc::new(ledger)),
            Err(_) => {
                persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                None
            }
        };
        let mut checkpoint_store = match SqliteCheckpointStore::open(
            run_root.join("checkpoint.sqlite"),
            checkpoint_manifest.clone(),
        ) {
            Ok(store) => Some(store),
            Err(_) => {
                checkpoint_failed = true;
                persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                None
            }
        };
        if artifacts.is_none() {
            persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
        }
        if mapper
            .map(AdkRuntimeObservationV1::new(
                "workflow-started",
                "workflowctl",
                AdkRuntimeObservationKindV1::WorkflowStarted,
            ))
            .is_err()
        {
            persistence_error.get_or_insert(ExecutionError::new(ExecutionErrorKind::Persistence));
        }
        if persistence_error.is_none() {
            let initial = Checkpoint::new(
                run_id.as_str(),
                State::new(),
                0,
                vec![compiled.ir().entry_node_id().as_str().to_owned()],
            );
            let initial_state = checkpoint_state(State::new(), &initial, None)
                .and_then(|mut state| {
                    LoopLedgerStore::bind_digest(&mut state, &BTreeMap::new())?;
                    serde_json::to_vec(&state)
                        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
                })
                .and_then(|state| {
                    DurableCheckpointV1::new(
                        run_id.clone(),
                        compiled.ir().entry_node_id().as_str().to_owned(),
                        mapper.events().last().map_or(0, |event| event.sequence()),
                        state,
                        BTreeSet::<String>::new(),
                    )
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
                });
            if write_events(&run_root.join("events.jsonl"), mapper.events()).is_err()
                || initial_state.as_ref().is_err_and(|_| true)
                || checkpoint_store.as_mut().is_none_or(|store| {
                    initial_state
                        .as_ref()
                        .is_ok_and(|checkpoint| store.save_checkpoint(checkpoint.clone()).is_err())
                })
            {
                persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
            } else {
                let provisional = RunManifestV2 {
                    schema_version: 2,
                    run_id: run_id.as_str().to_owned(),
                    workflow_id: compiled.ir().workflow_id().as_str().to_owned(),
                    workflow_version: compiled.ir().workflow_version().to_owned(),
                    workdir_id: workdir_id.clone(),
                    profile_identity: profile.profile_identity(),
                    adk_rust_version: "2.1.0".to_owned(),
                    status: "running".to_owned(),
                    artifact_id: "unavailable".to_owned(),
                    resume_count: 0,
                    plan_hash: resolved_plan.plan_hash().to_owned(),
                    resume_identity: resolved_plan.resume_identity().to_owned(),
                    checkpoint_manifest: Some(checkpoint_manifest.clone()),
                };
                if write_json(&run_root.join("run-manifest.json"), &provisional).is_err() {
                    persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                }
            }
        }
        let execution = if persistence_error.is_some() {
            Err(ExecutionError::new(ExecutionErrorKind::Persistence))
        } else {
            let artifacts = artifacts.as_mut().expect("artifact store must be present");
            let loop_ledger =
                Arc::clone(loop_ledger.as_ref().expect("loop ledger must be present"));
            (|| {
                let sandbox = RunSandbox::new(context, run_workdir, effective_capabilities.clone())
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::SandboxDenied))?;
                let deadline = execution_deadline(&profile.run_limits())?;
                let terminal_kind = Arc::new(Mutex::new(None));
                let last_progress = Arc::new(Mutex::new(Instant::now()));
                let effect_fence = Arc::new(EffectFence {
                    cancellation: Arc::clone(&cancellation),
                    wall_deadline: deadline,
                    idle_timeout: Duration::from_millis(
                        profile.run_limits().max_idle_time_ms().get(),
                    ),
                    tool_timeout: Duration::from_millis(
                        profile.run_limits().max_tool_time_ms().get(),
                    ),
                    terminal: Arc::clone(&terminal_kind),
                    last_progress: Arc::clone(&last_progress),
                });
                let tool_registry = build_tool_registry(
                    &profile,
                    &resolved_plan,
                    sandbox,
                    &run_id,
                    effect_journal.clone(),
                    Arc::clone(&effect_fence),
                )?;
                let agents = compiled
                    .ir()
                    .nodes()
                    .iter()
                    .filter(|node| node.kind() == workflow_ir::IrNodeKind::Agent)
                    .map(|node| -> Result<_, ExecutionError> {
                        let model = resolved_models
                            .get(node.id().as_str())
                            .cloned()
                            .ok_or_else(|| {
                                ExecutionError::new(ExecutionErrorKind::ImplementationBinding)
                            })?;
                        let agent = build_profile_agent(
                            node.id().as_str(),
                            model,
                            build_toolset(
                                &tool_registry,
                                node.id().as_str(),
                                resolved_plan.node_tools(node.id().as_str()),
                                resolved_plan.node_skills(node.id().as_str()),
                                &effective_capabilities,
                            )?,
                            profile.run_limits(),
                            Arc::clone(&loop_ledger),
                            Arc::clone(&effect_fence),
                        )?;
                        Ok((node.id().as_str().to_owned(), agent))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                let continuation = Arc::new(GraphCheckpointMemory::default());
                let graph = AdkGraphTranslator::new()
                    .translate_resolved_with_profile(
                        &resolved_plan,
                        compiled.ir(),
                        &agents,
                        transform_module.as_deref(),
                        &input,
                        Some(continuation.clone()),
                    )
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Adk))?;
                let runtime = adk_rust::tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Adk))?;
                let state = invoke_graph_with_deadline(
                    &runtime,
                    deadline,
                    &terminal_kind,
                    &cancellation,
                    &last_progress,
                    Duration::from_millis(profile.run_limits().max_idle_time_ms().get()),
                    graph.invoke_observed(
                        State::new(),
                        ExecutionConfig::new(run_id.as_str()).with_recursion_limit(recursion_limit),
                        &mut mapper,
                        artifacts,
                    ),
                )?;
                if let Some(kind) = terminal_kind.lock().ok().and_then(|terminal| *terminal) {
                    return Err(ExecutionError::new(kind));
                }
                let state = checkpoint_state(
                    state,
                    &continuation
                        .latest()
                        .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::Adk))?,
                    None,
                )?;
                state
                    .contains_key("terminal")
                    .then_some(state)
                    .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::Adk))
            })()
        };
        let mut status = mapper
            .events()
            .iter()
            .rev()
            .find_map(|event| match event.kind() {
                WorkflowRuntimeEventKindV1::WorkflowIncomplete => Some("incomplete"),
                WorkflowRuntimeEventKindV1::WorkflowFailed => Some("failed"),
                _ => None,
            });
        if let Err(error) = &execution
            && status.is_none()
        {
            status = Some(execution_status(error.kind()));
            if mapper
                .map(AdkRuntimeObservationV1::new(
                    "workflow-failed",
                    "workflowctl",
                    AdkRuntimeObservationKindV1::WorkflowFailed,
                ))
                .is_err()
            {
                persistence_error
                    .get_or_insert(ExecutionError::new(ExecutionErrorKind::Persistence));
            }
        }
        let mut status = status.unwrap_or("succeeded");
        let mut node_output_refs = BTreeMap::new();
        let mut references_overflowed = false;
        let mut reference_count = 0_u64;
        let mut reference_hasher = Sha256::new();
        if let (Ok(state), Some(artifacts)) = (&execution, artifacts.as_mut()) {
            for node in compiled.ir().nodes().iter().filter(|node| {
                !matches!(
                    node.kind(),
                    workflow_ir::IrNodeKind::Agent | workflow_ir::IrNodeKind::Terminal
                )
            }) {
                let id = node.id().as_str();
                let Some(output) = state.get(&format!("node:{id}")) else {
                    continue;
                };
                let reference = (|| {
                    let encoded = serde_json::to_vec(&redact_json_value(output))
                        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
                    let artifact_id = artifacts
                        .put(&encoded)
                        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
                    ProtectedArtifactReferenceV1::new(
                        artifact_id.as_str(),
                        format!("sha256:{}", artifact_id.as_str()),
                        u64::try_from(encoded.len())
                            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?,
                    )
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
                })();
                match reference {
                    Ok(reference) => {
                        reference_count += 1;
                        match serde_json::to_vec(&(id, &reference)) {
                            Ok(encoded) => {
                                reference_hasher.update(encoded);
                                reference_hasher.update([0]);
                            }
                            Err(_) => {
                                persistence_error.get_or_insert(ExecutionError::new(
                                    ExecutionErrorKind::Persistence,
                                ));
                            }
                        }
                        if !references_overflowed {
                            node_output_refs.insert(id.to_owned(), reference);
                            references_overflowed = serde_json::to_vec(&node_output_refs)
                                .map_or(true, |encoded| encoded.len() > ARTIFACT_LIMIT as usize);
                            if references_overflowed {
                                node_output_refs.clear();
                            }
                        }
                    }
                    Err(error) if persistence_error.is_none() => persistence_error = Some(error),
                    Err(_) => {}
                }
            }
        }
        let reference_digest = format!("sha256:{:x}", reference_hasher.finalize());
        if references_overflowed {
            checkpoint_failed = true;
            persistence_error.get_or_insert(ExecutionError::new(ExecutionErrorKind::Persistence));
        }
        crash_barrier("before-result");
        if let Err(error) = write_events(&run_root.join("events.jsonl"), mapper.events()) {
            persistence_error.get_or_insert(error);
        }
        crash_barrier("after-result");
        if persistence_error.is_none() {
            if let (Ok(state), Some(store), Some(loop_ledger)) =
                (&execution, checkpoint_store.as_mut(), loop_ledger.as_ref())
            {
                let mut state = state.clone();
                if loop_ledger.bind_current_digest(&mut state).is_err() {
                    checkpoint_failed = true;
                    persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                }
                let state_bytes = match serde_json::to_vec(&state) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        checkpoint_failed = true;
                        persistence_error =
                            Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                        Vec::new()
                    }
                };
                if !state_bytes.is_empty() {
                    let node_id = mapper
                        .events()
                        .iter()
                        .rev()
                        .find_map(|event| event.node_id())
                        .unwrap_or("terminal")
                        .to_owned();
                    let mut artifact_refs = node_output_refs
                        .values()
                        .map(|reference| reference.artifact_id().to_owned())
                        .collect::<BTreeSet<_>>();
                    for event in mapper.events() {
                        if let Some(artifact_id) = event
                            .payload()
                            .get("artifact_reference")
                            .and_then(|reference| reference.get("artifact_id"))
                            .and_then(Value::as_str)
                        {
                            artifact_refs.insert(artifact_id.to_owned());
                        }
                    }
                    match DurableCheckpointV1::new(
                        run_id.clone(),
                        node_id,
                        mapper.events().last().map_or(0, |event| event.sequence()),
                        state_bytes,
                        artifact_refs,
                    ) {
                        Ok(checkpoint) => {
                            crash_barrier("before-checkpoint");
                            if store.save_checkpoint(checkpoint).is_err() {
                                checkpoint_failed = true;
                                persistence_error =
                                    Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                            }
                            crash_barrier("after-checkpoint");
                        }
                        Err(_) => {
                            checkpoint_failed = true;
                            persistence_error =
                                Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                        }
                    }
                }
            } else if execution.is_ok() {
                checkpoint_failed = true;
                persistence_error = Some(ExecutionError::new(ExecutionErrorKind::Persistence));
            }
        }
        if checkpoint_failed {
            status = "failed";
        }
        let terminal = match bounded_terminal_artifact(
            run_id.as_str(),
            status,
            execution
                .as_ref()
                .ok()
                .and_then(|state| state.get("terminal")),
            &node_output_refs,
            references_overflowed,
            reference_count,
            &reference_digest,
        ) {
            Ok(terminal) => terminal,
            Err(error) => {
                persistence_error.get_or_insert(error);
                Vec::new()
            }
        };
        let artifact_id = match artifacts.as_mut() {
            Some(artifacts) => match artifacts.put(&terminal) {
                Ok(artifact_id) => artifact_id.as_str().to_owned(),
                Err(_) => {
                    persistence_error
                        .get_or_insert(ExecutionError::new(ExecutionErrorKind::Persistence));
                    "unavailable".to_owned()
                }
            },
            None => "unavailable".to_owned(),
        };
        let manifest = RunManifestV2 {
            schema_version: 2,
            run_id: run_id.as_str().to_owned(),
            workflow_id: compiled.ir().workflow_id().as_str().to_owned(),
            workflow_version: compiled.ir().workflow_version().to_owned(),
            workdir_id,
            profile_identity: profile.profile_identity(),
            adk_rust_version: "2.1.0".to_owned(),
            status: status.to_owned(),
            artifact_id,
            resume_count: 0,
            plan_hash: resolved_plan.plan_hash().to_owned(),
            resume_identity: resolved_plan.resume_identity().to_owned(),
            checkpoint_manifest: Some(checkpoint_manifest),
        };
        if let Err(error) = write_json(&run_root.join("run-manifest.json"), &manifest) {
            persistence_error.get_or_insert(error);
        }
        let receipt = manifest.receipt(run_root);
        match (execution.err(), persistence_error) {
            (Some(error), _) | (None, Some(error)) => Err(error.with_receipt(receipt)),
            (None, None) => Ok(receipt),
        }
    }

    pub fn inspect(
        workdir_base: impl AsRef<Path>,
        run_id: &str,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        let (root, manifest) = find_run(workdir_base.as_ref(), run_id)?;
        Ok(manifest.receipt(root))
    }

    pub fn resume(
        workdir_base: impl AsRef<Path>,
        run_id: &str,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        Self::resume_cancellable(workdir_base, run_id, Arc::new(AtomicBool::new(false)))
    }

    pub fn resume_cancellable(
        workdir_base: impl AsRef<Path>,
        run_id: &str,
        cancellation: Arc<AtomicBool>,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        let (root, mut manifest) = find_run(workdir_base.as_ref(), run_id)?;
        if !matches!(manifest.status.as_str(), "running" | "succeeded") {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        let checkpoint_manifest = manifest
            .checkpoint_manifest
            .clone()
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let ledger_identity = ledger_checkpoint_identity(&checkpoint_manifest)?;
        let run_identity = RunId::new(run_id.to_owned())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let base = root
            .parent()
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let manager = WorkdirManager::new(base)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let run_workdir = manager
            .reopen(&run_identity, &root)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        if run_workdir.id().as_str() != manifest.workdir_id {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        let mut checkpoint_store = SqliteCheckpointStore::open(
            root.join("checkpoint.sqlite"),
            checkpoint_manifest.clone(),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let checkpoint = checkpoint_store
            .load_latest(&run_identity)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let mut artifacts = FilesystemArtifactStore::try_new(
            root.join("artifacts"),
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive artifact limit"),
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive page limit"),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        for reference in checkpoint.artifact_refs() {
            let artifact_id = ArtifactId::parse(reference)
                .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
            let page = artifacts
                .read_page(
                    &artifact_id,
                    PageRequest::new(
                        0,
                        NonZeroU64::new(ARTIFACT_LIMIT).expect("positive page size"),
                    ),
                )
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
            if page.next_offset().is_some()
                || format!("{:x}", Sha256::digest(page.bytes())) != artifact_id.as_str()
            {
                return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
            }
        }
        let profile =
            ExecutionProfileV1::parse(&bounded_read(&root.join("execution-profile.json"))?)?;
        let (sandbox_capabilities, required_capabilities) = profile.capabilities()?;
        verify_sandbox_capabilities(
            &RequestedCapabilities::new(required_capabilities.iter().copied()),
            &BackendCapabilities::new(sandbox_capabilities.iter().copied()),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let input =
            serde_json::from_slice::<Value>(&bounded_read(&root.join("execution-input.json"))?)
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let workflow = root.join("workflow.toml");
        let compiled = compile_file(workflow.to_string_lossy().as_ref())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        if compiled.ir().workflow_id().as_str() != manifest.workflow_id
            || compiled.ir().workflow_version() != manifest.workflow_version
        {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        let resolved_plan = resolve_runtime_plan(&profile, compiled.ir())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        if manifest.plan_hash != resolved_plan.plan_hash()
            || manifest.resume_identity != resolved_plan.resume_identity()
        {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        for node in compiled
            .ir()
            .nodes()
            .iter()
            .filter(|node| node.kind() == workflow_ir::IrNodeKind::Agent)
        {
            profile.bind_resolved_model(&resolved_plan, node.id().as_str(), 0)?;
        }
        let transform_module = profile.transform_module()?;
        let live_checkpoint_manifest = build_checkpoint_manifest(
            &run_identity,
            (
                compiled.ir().workflow_id().as_str(),
                compiled.ir().workflow_version(),
            ),
            crate::canonical_ir_hash(compiled.ir()),
            &profile,
            &resolved_plan,
            transform_module.as_deref(),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        if live_checkpoint_manifest != checkpoint_manifest {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        let effective_capabilities = effective_sandbox_capabilities(&resolved_plan)?;
        let events_path = root.join("events.jsonl");
        let mut events = read_events(&events_path)?;
        let event_sequence = events.last().map_or(0, |event| event.sequence());
        if event_sequence > checkpoint.event_sequence() {
            let prefix_len = events
                .iter()
                .take_while(|event| event.sequence() <= checkpoint.event_sequence())
                .count();
            if prefix_len != checkpoint.event_sequence() as usize {
                return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
            }
            events.truncate(prefix_len);
            write_events(&events_path, &events)?;
        } else if event_sequence != checkpoint.event_sequence() {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        let tool_event_counts = events
            .iter()
            .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolCompleted)
            .filter_map(|event| event.node_id())
            .fold(BTreeMap::new(), |mut counts, node| {
                *counts.entry(node.to_owned()).or_insert(0_usize) += 1;
                counts
            });
        let mut mapper = AdkEventMapper::resume(run_id, &manifest.workflow_id, events)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let next = manifest.resume_count + 1;
        mapper
            .map(AdkRuntimeObservationV1::new(
                format!("workflow-resumed-{next}"),
                "workflowctl",
                AdkRuntimeObservationKindV1::WorkflowResumed,
            ))
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let sandbox = RunSandbox::new(
            RunContext::new(run_identity.clone(), profile.run_limits()),
            run_workdir,
            effective_capabilities.clone(),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let effect_journal = Arc::new(
            EffectJournal::open(root.join("effects.sqlite"))
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?,
        );
        let deadline = execution_deadline(&profile.run_limits())?;
        let terminal_kind = Arc::new(Mutex::new(None));
        let last_progress = Arc::new(Mutex::new(Instant::now()));
        let effect_fence = Arc::new(EffectFence {
            cancellation: Arc::clone(&cancellation),
            wall_deadline: deadline,
            idle_timeout: Duration::from_millis(profile.run_limits().max_idle_time_ms().get()),
            tool_timeout: Duration::from_millis(profile.run_limits().max_tool_time_ms().get()),
            terminal: Arc::clone(&terminal_kind),
            last_progress: Arc::clone(&last_progress),
        });
        let loop_ledger = Arc::new(LoopLedgerStore::open(
            root.join(LOOP_LEDGER_FILE),
            root.join("checkpoint.sqlite"),
            ledger_identity,
            checkpoint_manifest.clone(),
            run_identity.clone(),
            checkpoint_ledger_digest(checkpoint.state())?.as_str(),
        )?);
        let tool_registry = build_tool_registry(
            &profile,
            &resolved_plan,
            sandbox,
            &run_identity,
            Some(Arc::clone(&effect_journal)),
            Arc::clone(&effect_fence),
        )?;
        let toolsets = compiled
            .ir()
            .nodes()
            .iter()
            .filter(|node| node.kind() == workflow_ir::IrNodeKind::Agent)
            .map(|node| -> Result<_, ExecutionError> {
                Ok((
                    node.id().as_str().to_owned(),
                    build_toolset(
                        &tool_registry,
                        node.id().as_str(),
                        resolved_plan.node_tools(node.id().as_str()),
                        resolved_plan.node_skills(node.id().as_str()),
                        &effective_capabilities,
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if let Err(error) =
            replay_pending_tools(&loop_ledger, &toolsets, profile.run_limits(), &effect_fence)
        {
            return Err(resume_failure(
                &root,
                &events_path,
                &mut manifest,
                next,
                &mapper,
                error,
            ));
        }
        restore_tool_events(&loop_ledger, &tool_event_counts, &mut mapper)?;
        let agents = compiled
            .ir()
            .nodes()
            .iter()
            .filter(|node| node.kind() == workflow_ir::IrNodeKind::Agent)
            .map(|node| -> Result<_, ExecutionError> {
                let name = node.id().as_str();
                let agent = if let Some(output) = loop_ledger.finished_output(name)? {
                    Arc::new(RestoredFinishAgent {
                        name: name.to_owned(),
                        output,
                    }) as Arc<dyn Agent>
                } else {
                    let completed_turns = loop_ledger.model_iterations(name)?;
                    let model =
                        profile.bind_resolved_model(&resolved_plan, name, completed_turns)?;
                    build_profile_agent(
                        name,
                        model,
                        toolsets.get(name).cloned().flatten(),
                        profile.run_limits(),
                        Arc::clone(&loop_ledger),
                        Arc::clone(&effect_fence),
                    )?
                };
                Ok((name.to_owned(), agent))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut state = serde_json::from_slice::<State>(checkpoint.state())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let nodes = compiled
            .ir()
            .nodes()
            .iter()
            .map(|node| node.id().as_str().to_owned())
            .collect();
        let restored = restore_checkpoint_state(&mut state, run_id, nodes)?;
        let retry = restored
            .attempts
            .iter()
            .map(|(node, attempts)| (node.clone(), *attempts))
            .collect::<BTreeMap<_, _>>();
        let continuation = Arc::new(GraphCheckpointMemory::default());
        if !continuation.restore(restored.clone()) {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        let graph = AdkGraphTranslator::new()
            .translate_resolved_with_profile(
                &resolved_plan,
                compiled.ir(),
                &agents,
                transform_module.as_deref(),
                &input,
                Some(continuation.clone()),
            )
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let recursion_limit = compiled
            .ir()
            .nodes()
            .iter()
            .filter_map(workflow_ir::IrNode::max_visits)
            .map(|visits| visits as usize)
            .sum::<usize>()
            .max(50);
        let runtime = adk_rust::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let state = match invoke_graph_with_deadline(
            &runtime,
            deadline,
            &terminal_kind,
            &cancellation,
            &last_progress,
            Duration::from_millis(profile.run_limits().max_idle_time_ms().get()),
            graph.invoke_observed(
                state,
                ExecutionConfig::new(run_id)
                    .with_recursion_limit(recursion_limit)
                    .with_resume_from(&restored.checkpoint_id),
                &mut mapper,
                &mut artifacts,
            ),
        ) {
            Ok(state) => state,
            Err(error) => {
                return Err(resume_failure(
                    &root,
                    &events_path,
                    &mut manifest,
                    next,
                    &mapper,
                    error,
                ));
            }
        };
        let mut state = checkpoint_state(
            state,
            &continuation
                .latest()
                .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?,
            Some(&retry),
        )?;
        loop_ledger.bind_current_digest(&mut state)?;
        let state_bytes = serde_json::to_vec(&state)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let node_id = mapper
            .events()
            .iter()
            .rev()
            .find_map(|event| event.node_id())
            .unwrap_or("terminal")
            .to_owned();
        let mut artifact_refs = checkpoint
            .artifact_refs()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for event in mapper.events() {
            if let Some(artifact_id) = event
                .payload()
                .get("artifact_reference")
                .and_then(|reference| reference.get("artifact_id"))
                .and_then(Value::as_str)
            {
                artifact_refs.insert(artifact_id.to_owned());
            }
        }
        let checkpoint = DurableCheckpointV1::new(
            run_identity.clone(),
            node_id,
            mapper.events().last().map_or(0, |event| event.sequence()),
            state_bytes,
            artifact_refs,
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let terminal = bounded_terminal_artifact(
            run_id,
            "succeeded",
            state.get("terminal"),
            &BTreeMap::<String, ProtectedArtifactReferenceV1>::new(),
            false,
            0,
            &format!("sha256:{:x}", Sha256::digest([])),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let artifact_id = artifacts
            .put(&terminal)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?
            .as_str()
            .to_owned();
        crash_barrier("before-result");
        write_events(&events_path, mapper.events())?;
        crash_barrier("after-result");
        crash_barrier("before-checkpoint");
        checkpoint_store
            .save_checkpoint(checkpoint)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        crash_barrier("after-checkpoint");
        manifest.status = "succeeded".to_owned();
        manifest.artifact_id = artifact_id;
        manifest.resume_count = next;
        write_json(&root.join("run-manifest.json"), &manifest)?;
        Ok(manifest.receipt(root))
    }
}

fn build_checkpoint_manifest(
    run_id: &RunId,
    workflow: (&str, &str),
    workflow_hash: String,
    profile: &ExecutionProfileV1,
    plan: &ResolvedRuntimePlan,
    transform_module: Option<&[u8]>,
) -> Result<CheckpointManifestV1, ExecutionError> {
    let profile_identity = serde_json::to_vec(&(
        &profile.model,
        &profile.reviewer_model,
        &profile.tool,
        &profile.tools,
        &profile.loop_policy,
    ))
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    let effective_capabilities = plan.effective_capabilities().as_slice().join("\n");
    let mut manifest = CheckpointManifestV1::new(run_id, workflow.0, workflow.1)
        .with_workflow_hash(workflow_hash.clone())
        .with_resource_hash("workflow.ir", workflow_hash)
        .with_implementation("model", profile.profile_identity())
        .with_implementation("adk-rust", "2.1.0")
        .with_implementation("loop-ledger", "v2")
        .with_implementation(
            "execution-profile",
            format!("sha256:{:x}", Sha256::digest(profile_identity)),
        )
        .with_sandbox_policy_hash(format!(
            "sha256:{:x}",
            Sha256::digest(effective_capabilities.as_bytes())
        ))
        .with_implementation("toolset", plan.resume_identity())
        .with_event_log_identity("workflow-runtime-events-v1");
    if let Some(transform) = transform_module {
        manifest = manifest.with_resource_hash(
            "pure-transform",
            format!("sha256:{:x}", Sha256::digest(transform)),
        );
    }
    for package in profile.skill_packages()?.values() {
        let prefix = format!("skill.{}", package.id.as_str());
        manifest = manifest
            .with_implementation(
                format!("{prefix}.activation"),
                format!("{}:{}", package.id.as_str(), package.version),
            )
            .with_resource_hash(
                format!("{prefix}.skill_markdown"),
                format!("sha256:{:x}", Sha256::digest(&package.skill_markdown)),
            );
        for (id, bytes) in &package.scripts {
            manifest = manifest.with_resource_hash(
                format!("{prefix}.script.{id}"),
                format!("sha256:{:x}", Sha256::digest(bytes)),
            );
        }
        for (id, bytes) in &package.resources {
            manifest = manifest.with_resource_hash(
                format!("{prefix}.resource.{}", id.as_str()),
                format!("sha256:{:x}", Sha256::digest(bytes)),
            );
        }
    }
    Ok(manifest)
}

struct EffectFence {
    cancellation: Arc<AtomicBool>,
    wall_deadline: Instant,
    idle_timeout: Duration,
    tool_timeout: Duration,
    terminal: Arc<Mutex<Option<ExecutionErrorKind>>>,
    last_progress: Arc<Mutex<Instant>>,
}

impl EffectFence {
    fn tool_deadline(&self) -> Instant {
        Instant::now()
            .checked_add(self.tool_timeout)
            .map_or(self.wall_deadline, |deadline| {
                deadline.min(self.wall_deadline)
            })
    }

    fn idle_deadline(&self) -> Instant {
        self.last_progress
            .lock()
            .ok()
            .and_then(|progress| progress.checked_add(self.idle_timeout))
            .unwrap_or_else(Instant::now)
    }

    fn wait(&self, delay: Duration) -> Result<Instant, ToolBridgeError> {
        let tool_deadline = self.tool_deadline();
        let complete_at = Instant::now().checked_add(delay).unwrap_or(tool_deadline);
        test_effect_barrier(&self.cancellation);
        loop {
            self.admit(tool_deadline)?;
            let now = Instant::now();
            if now >= complete_at {
                return Ok(tool_deadline);
            }
            std::thread::sleep(
                complete_at
                    .min(tool_deadline)
                    .min(self.wall_deadline)
                    .min(self.idle_deadline())
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(1)),
            );
        }
    }

    fn admit(&self, tool_deadline: Instant) -> Result<(), ToolBridgeError> {
        let kind = if self.cancellation.load(Ordering::Acquire) {
            Some(ExecutionErrorKind::Cancelled)
        } else if Instant::now() >= self.wall_deadline {
            Some(ExecutionErrorKind::WallTimeLimit)
        } else if self
            .last_progress
            .lock()
            .map_or(true, |progress| progress.elapsed() >= self.idle_timeout)
        {
            Some(ExecutionErrorKind::IdleTimeLimit)
        } else if Instant::now() >= tool_deadline {
            Some(ExecutionErrorKind::ToolTimeLimit)
        } else {
            None
        };
        if let Some(kind) = kind {
            record_terminal(&self.terminal, kind);
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed));
        }
        Ok(())
    }

    fn execution_error(&self) -> ExecutionError {
        ExecutionError::new(
            self.terminal
                .lock()
                .ok()
                .and_then(|terminal| *terminal)
                .unwrap_or(ExecutionErrorKind::Tool),
        )
    }

    fn mark_progress(&self) -> Result<(), ToolBridgeError> {
        *self
            .last_progress
            .lock()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))? =
            Instant::now();
        Ok(())
    }
}

fn test_effect_barrier(cancellation: &AtomicBool) {
    let Ok(root) = std::env::var("WORKFLOW_KIT_TEST_EFFECT_BARRIER") else {
        return;
    };
    let root = PathBuf::from(root);
    let _ = fs::write(root.join("ready"), b"ready");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !root.join("cancel").is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if root.join("cancel").is_file() {
        cancellation.store(true, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
enum SkillToolAction {
    Activate,
    Read,
    Run,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateSkillInput {
    skill_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadSkillResourceInput {
    skill_id: String,
    resource_id: String,
    #[serde(default)]
    offset: u64,
    limit: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunSkillScriptInput {
    skill_id: String,
    script_id: String,
    input: Value,
}

struct SkillToolHandler {
    action: SkillToolAction,
    packages: BTreeMap<String, Arc<SkillPackage>>,
    plan: ResolvedRuntimePlan,
    provenance: ToolProvenance,
}

impl ToolHandler for SkillToolHandler {
    fn execute(
        &self,
        sandbox: &workflow_runtime::ChildSandbox<'_>,
        context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        let skill_name = match self.action {
            SkillToolAction::Activate => {
                serde_json::from_value::<ActivateSkillInput>(arguments.clone())
                    .map(|input| input.skill_id)
            }
            SkillToolAction::Read => {
                serde_json::from_value::<ReadSkillResourceInput>(arguments.clone())
                    .map(|input| input.skill_id)
            }
            SkillToolAction::Run => {
                serde_json::from_value::<RunSkillScriptInput>(arguments.clone())
                    .map(|input| input.skill_id)
            }
        }
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied))?;
        let skill_id = self
            .packages
            .get(&skill_name)
            .ok_or_else(|| ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied))?;
        let binding = skill_id
            .binding()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        if !self
            .plan
            .node_skills(context.actor())
            .iter()
            .any(|allowed| allowed == &binding)
        {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied));
        }
        let payload = match self.action {
            SkillToolAction::Activate => {
                let activation = activate_skill(skill_id.as_ref(), &skill_id.id, &skill_id.version)
                    .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
                json!({
                    "skill_id": activation.id().as_str(),
                    "version": activation.version(),
                    "instructions_ref": format!("sha256:{:x}", Sha256::digest(activation.instructions())),
                    "instructions": activation.instructions(),
                })
            }
            SkillToolAction::Read => {
                let input = serde_json::from_value::<ReadSkillResourceInput>(arguments.clone())
                    .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied))?;
                let resource_id = SkillResourceId::new(&input.resource_id)
                    .ok()
                    .ok_or_else(|| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
                let limit = NonZeroU64::new(input.limit)
                    .ok_or_else(|| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
                skill_id.read_resource(&resource_id, PageRequest::new(input.offset, limit))?
            }
            SkillToolAction::Run => {
                let input = serde_json::from_value::<RunSkillScriptInput>(arguments.clone())
                    .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied))?;
                let script_id = input.script_id;
                let input = serde_json::to_vec(&input.input)
                    .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
                let script_bytes = skill_id
                    .scripts
                    .get(&script_id)
                    .ok_or_else(|| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
                let receipt = execute_registered_script_in_child(
                    &skill_id.runtime,
                    &skill_id.lock,
                    &script_id,
                    &input,
                    script_bytes,
                    sandbox,
                )
                .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
                if !receipt.exit_success() {
                    return Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed));
                }
                serde_json::from_slice(receipt.stdout())
                    .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?
            }
        };
        Ok(ToolEnvelope::success(payload, self.provenance.clone()))
    }
}

fn skill_tool_registration(
    name: &str,
    capabilities: impl IntoIterator<Item = SandboxCapability>,
    read_only: bool,
) -> Result<ToolRegistration, ExecutionError> {
    ToolRegistration::for_types::<Value, Value>(
        name,
        ToolProvenance::new("skill.runtime", "1"),
        ToolFlags::new(read_only, true, true),
    )
    .map(|registration| {
        registration
            .with_required_capabilities(capabilities)
            .with_timeout(NonZeroU64::new(60_000).expect("positive timeout"))
            .with_idempotency(if read_only {
                workflow_runtime::ToolIdempotency::NotRequired
            } else {
                workflow_runtime::ToolIdempotency::StableKey
            })
    })
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))
}

fn build_tool_registry(
    profile: &ExecutionProfileV1,
    plan: &ResolvedRuntimePlan,
    sandbox: RunSandbox,
    run_id: &RunId,
    effect_journal: Option<Arc<EffectJournal>>,
    effect_fence: Arc<EffectFence>,
) -> Result<ToolBridge, ExecutionError> {
    let mut bridge = ToolBridge::new(sandbox);
    for tool in profile.tool_wires() {
        let registration = profile.tool_registration(tool)?;
        let provenance = registration.provenance().clone();
        bridge
            .register(
                registration,
                StaticToolHandler {
                    result: tool.result.clone(),
                    provenance,
                    run_id: run_id.as_str().to_owned(),
                    node_id: tool.name.clone(),
                    effect_journal: effect_journal.clone(),
                    effect_fence: Arc::clone(&effect_fence),
                    delay_ms: tool.delay_ms,
                    handler_error: tool.handler_error,
                },
            )
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
    }
    let packages = profile.skill_packages()?;
    if !packages.is_empty() {
        let script_capabilities = packages
            .values()
            .flat_map(|package| package.capabilities())
            .collect::<Vec<_>>();
        let script_is_read_only = !script_capabilities.iter().any(|capability| {
            matches!(
                capability,
                SandboxCapability::FilesystemWrite | SandboxCapability::Network
            )
        });
        for (name, action, capabilities, read_only) in [
            (
                "activate_skill",
                SkillToolAction::Activate,
                Vec::new(),
                true,
            ),
            (
                "read_skill_resource",
                SkillToolAction::Read,
                vec![SandboxCapability::FilesystemRead],
                true,
            ),
            (
                "run_skill_script",
                SkillToolAction::Run,
                script_capabilities,
                script_is_read_only,
            ),
        ] {
            let registration = skill_tool_registration(name, capabilities, read_only)?;
            let provenance = registration.provenance().clone();
            bridge
                .register(
                    registration,
                    SkillToolHandler {
                        action,
                        packages: packages.clone(),
                        plan: plan.clone(),
                        provenance,
                    },
                )
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
        }
    }
    Ok(bridge)
}

fn build_toolset(
    bridge: &ToolBridge,
    node_id: &str,
    bindings: &[ResolvedBinding],
    skills: &[ResolvedBinding],
    effective_capabilities: &[SandboxCapability],
) -> Result<Option<BoundTool>, ExecutionError> {
    if bindings.is_empty() && skills.is_empty() {
        return Ok(None);
    }
    let mut names = bindings
        .iter()
        .map(|binding| binding.id().to_owned())
        .collect::<Vec<_>>();
    if !skills.is_empty() && !names.iter().any(|name| name == "activate_skill") {
        names.extend([
            "activate_skill".to_owned(),
            "read_skill_resource".to_owned(),
            "run_skill_script".to_owned(),
        ]);
    }
    let authority = CapabilityIntersection::new(
        effective_capabilities.iter().copied(),
        names.iter(),
        names.iter(),
        std::iter::empty::<String>(),
        names.iter(),
        names.iter(),
        effective_capabilities.iter().copied(),
    );
    let adapter = AdkToolBridge::for_selected(
        bridge,
        names.iter().map(String::as_str),
        node_id,
        authority,
        None,
        InMemoryArtifactStore::new(
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive artifact limit"),
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive page limit"),
        ),
    )
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::ImplementationBinding))?;
    Ok(Some((names, Arc::new(adapter))))
}

fn replay_pending_tools(
    ledger: &LoopLedgerStore,
    toolsets: &BTreeMap<String, Option<BoundTool>>,
    limits: RunLimits,
    effect_fence: &EffectFence,
) -> Result<(), ExecutionError> {
    for (node, pending) in ledger.pending_calls()? {
        let toolset = toolsets
            .get(&node)
            .and_then(Option::as_ref)
            .map(|(_, toolset)| toolset)
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let toolset = Arc::clone(toolset);
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .spawn(move || {
                let response = toolset.invoke(ToolCall::new(
                    &pending.name,
                    &pending.id,
                    &node,
                    pending.args.clone(),
                ));
                let _ = sender.send((node, pending, response));
            })
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Tool))?;
        let tool_deadline = effect_fence.tool_deadline();
        let (node, pending, response) = loop {
            effect_fence
                .admit(tool_deadline)
                .map_err(|_| effect_fence.execution_error())?;
            match receiver.recv_timeout(Duration::from_millis(1)) {
                Ok(result) => break result,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ExecutionError::new(ExecutionErrorKind::Tool));
                }
            }
        };
        effect_fence
            .admit(tool_deadline)
            .map_err(|_| effect_fence.execution_error())?;
        let response = response.map_err(|error| {
            let kind = match error.kind() {
                ToolBridgeErrorKind::CapabilityDenied | ToolBridgeErrorKind::ApprovalDenied => {
                    ExecutionErrorKind::AuthorizationDenied
                }
                _ => ExecutionErrorKind::Tool,
            };
            ExecutionError::new(kind)
        })?;
        let response = serde_json::to_value(response)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Tool))?;
        ledger.complete_pending(
            &node,
            &pending,
            response,
            limits.max_tool_output_bytes().get(),
        )?;
    }
    Ok(())
}

fn restore_tool_events(
    ledger: &LoopLedgerStore,
    existing: &BTreeMap<String, usize>,
    mapper: &mut AdkEventMapper,
) -> Result<(), ExecutionError> {
    let mut seen = BTreeMap::new();
    for (node, call_id, tool_name, argument_fingerprint, response) in
        ledger.completed_tool_responses()?
    {
        let count = seen.entry(node.clone()).or_insert(0_usize);
        if *count >= existing.get(&node).copied().unwrap_or(0) {
            mapper
                .map(
                    AdkRuntimeObservationV1::new(
                        format!(
                            "tool-replayed-{:x}",
                            Sha256::digest(format!("{node}\0{call_id}").as_bytes())
                        ),
                        "workflowctl",
                        AdkRuntimeObservationKindV1::ToolCompleted,
                    )
                    .with_node_id(&node)
                    .with_response(response)
                    .with_structured_output(json!([{
                        "tool_call_id": call_id,
                        "tool_name": tool_name,
                        "argument_fingerprint": argument_fingerprint,
                    }])),
                )
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        }
        *count += 1;
    }
    Ok(())
}

struct StaticToolHandler {
    result: Value,
    provenance: ToolProvenance,
    run_id: String,
    node_id: String,
    effect_journal: Option<Arc<EffectJournal>>,
    effect_fence: Arc<EffectFence>,
    delay_ms: u64,
    handler_error: bool,
}

impl ToolHandler for StaticToolHandler {
    fn execute(
        &self,
        _sandbox: &workflow_runtime::ChildSandbox<'_>,
        _context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        if self.handler_error {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed));
        }
        crash_barrier("before-effect");
        let tool_deadline = self
            .effect_fence
            .wait(Duration::from_millis(self.delay_ms))?;
        let result = if let Some(journal) = &self.effect_journal {
            let key = EffectKey::new(&self.run_id, &self.node_id, &self.node_id, arguments);
            self.effect_fence.admit(tool_deadline)?;
            match journal.commit(&key, &self.result) {
                Ok(EffectCommit::Committed) => self.result.clone(),
                Ok(EffectCommit::AlreadyCommitted(result)) => result,
                Err(_) => return Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed)),
            }
        } else {
            self.result.clone()
        };
        crash_barrier("after-effect");
        self.effect_fence.mark_progress()?;
        Ok(ToolEnvelope::success(result, self.provenance.clone()))
    }
}

fn crash_barrier(name: &str) {
    let configured = std::env::var("WORKFLOW_KIT_TEST_CRASH_BARRIER").ok();
    if configured.as_deref() != Some(name) {
        return;
    }
    #[cfg(unix)]
    {
        // Test-only barrier: the real workflowctl process is killed, not a simulated run.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
    }
}

fn fresh_run_id() -> Result<RunId, ExecutionError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?
        .as_nanos();
    RunId::new(format!(
        "run-{nanos}-{}",
        NEXT_RUN.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))
}

fn bounded_terminal_artifact(
    run_id: &str,
    status: &str,
    terminal: Option<&Value>,
    node_output_refs: &BTreeMap<String, ProtectedArtifactReferenceV1>,
    references_overflowed: bool,
    reference_count: u64,
    reference_digest: &str,
) -> Result<Vec<u8>, ExecutionError> {
    let terminal = terminal.map(redact_json_value).unwrap_or(Value::Null);
    let complete = serde_json::to_vec(&json!({
        "run_id": run_id,
        "status": status,
        "terminal": &terminal,
        "node_output_refs": node_output_refs,
    }))
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    if !references_overflowed && complete.len() <= ARTIFACT_LIMIT as usize {
        return Ok(complete);
    }

    let summary = json!({
        "count": reference_count,
        "sha256": reference_digest,
        "overflowed": references_overflowed,
    });
    let bounded = serde_json::to_vec(&json!({
        "run_id": run_id,
        "status": status,
        "terminal": &terminal,
        "node_output_refs": {},
        "node_output_refs_summary": summary,
    }))
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    if bounded.len() <= ARTIFACT_LIMIT as usize {
        return Ok(bounded);
    }

    let terminal_bytes = serde_json::to_vec(&terminal)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    serde_json::to_vec(&json!({
        "run_id": run_id,
        "status": status,
        "terminal": Value::Null,
        "terminal_digest": format!("sha256:{:x}", Sha256::digest(&terminal_bytes)),
        "terminal_byte_len": terminal_bytes.len(),
        "node_output_refs": {},
        "node_output_refs_summary": summary,
    }))
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
}

fn find_run(base: &Path, run_id: &str) -> Result<(PathBuf, RunManifestV2), ExecutionError> {
    WorkdirManager::new(base).map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
    let base =
        fs::canonicalize(base).map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
    // ponytail: scan run manifests; add an index when run counts make lookup measurable.
    for entry in
        fs::read_dir(&base).map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?
    {
        let entry = entry.map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
        let file_type = entry
            .file_type()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        let manifest_path = path.join("run-manifest.json");
        let Ok(bytes) = bounded_read(&manifest_path) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if value.get("run_id").and_then(Value::as_str) != Some(run_id) {
            continue;
        }
        let manifest = serde_json::from_value::<RunManifestV2>(value)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::IncompatibleManifest))?;
        if manifest.schema_version == 2 {
            return Ok((path, manifest));
        }
        return Err(ExecutionError::new(
            ExecutionErrorKind::IncompatibleManifest,
        ));
    }
    Err(ExecutionError::new(ExecutionErrorKind::RunNotFound))
}

fn bounded_read(path: &Path) -> Result<Vec<u8>, ExecutionError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_STATE_BYTES as u64
    {
        return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
    }
    fs::read(path).map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))
}

fn read_events(
    path: &Path,
) -> Result<Vec<workflow_runtime::WorkflowRuntimeEventV1>, ExecutionError> {
    let bytes = bounded_read(path)?;
    std::str::from_utf8(&bytes)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))
        })
        .collect()
}

fn write_events(
    path: &Path,
    events: &[workflow_runtime::WorkflowRuntimeEventV1],
) -> Result<(), ExecutionError> {
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        bytes.push(b'\n');
    }
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ExecutionError::new(ExecutionErrorKind::Persistence));
    }
    write_atomic(path, &bytes)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), ExecutionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ExecutionError::new(ExecutionErrorKind::Persistence));
    }
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ExecutionError> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    fs::rename(temporary, path).map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
}

#[cfg(test)]
mod execution_registry_tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn fanout_ledger() -> (PathBuf, Arc<LoopLedgerStore>) {
        let root = std::env::temp_dir().join(format!(
            "workflow-adk-fanout-{}",
            NEXT_RUN.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("fan-out fixture directory");
        let run_id = RunId::new("fanout-limits".to_owned()).expect("valid fixture run ID");
        let manifest = CheckpointManifestV1::new(&run_id, "fanout", "1");
        let checkpoint_path = root.join("checkpoint.sqlite");
        let mut checkpoints = SqliteCheckpointStore::open(&checkpoint_path, manifest.clone())
            .expect("fan-out checkpoint store");
        checkpoints
            .save_checkpoint(
                DurableCheckpointV1::new(
                    run_id.clone(),
                    "fanout",
                    0,
                    serde_json::to_vec(&State::new()).expect("checkpoint state"),
                    BTreeSet::<String>::new(),
                )
                .expect("fan-out checkpoint"),
            )
            .expect("save fan-out checkpoint");
        let ledger = LoopLedgerStore::create(
            root.join(LOOP_LEDGER_FILE),
            checkpoint_path,
            "fanout".to_owned(),
            manifest,
            run_id,
        )
        .expect("fan-out ledger");
        ledger
            .replace("left", LoopState::default())
            .expect("left sibling state");
        ledger
            .replace("right", LoopState::default())
            .expect("right sibling state");
        (root, Arc::new(ledger))
    }

    fn limits(max_tool_calls: u64, max_calls_per_tool: u64) -> RunLimits {
        let limit = |value| NonZeroU64::new(value).expect("positive limit");
        RunLimits::new(
            limit(100),
            limit(max_tool_calls),
            limit(max_calls_per_tool),
            limit(100),
            limit(100),
            limit(100),
            limit(100),
        )
    }

    fn sibling_fanout<T: Send>(
        ledger: &Arc<LoopLedgerStore>,
        candidate: &LoopState,
        admit: impl Fn(&LoopLedgerStore, &str, &LoopState) -> T + Send + Sync,
    ) -> [T; 2] {
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let left_barrier = Arc::clone(&barrier);
            let left_admit = &admit;
            let left = scope.spawn(move || {
                left_barrier.wait();
                left_admit(ledger, "left", candidate)
            });
            let right_barrier = Arc::clone(&barrier);
            let right_admit = &admit;
            let right = scope.spawn(move || {
                right_barrier.wait();
                right_admit(ledger, "right", candidate)
            });
            [
                left.join().expect("left sibling"),
                right.join().expect("right sibling"),
            ]
        })
    }

    #[test]
    fn sibling_fanout_limit_admission_persists_once() {
        let call = LoopState {
            total_tool_calls: 1,
            tool_calls: BTreeMap::from([(String::from("search_code"), 1)]),
            ..LoopState::default()
        };
        let (root, ledger) = fanout_ledger();
        let outcomes = sibling_fanout(&ledger, &call, |ledger, node, candidate| {
            ledger.tool_call_limit(node, candidate, &limits(1, 2))
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.as_ref().expect("ledger").is_none())
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter_map(|outcome| *outcome.as_ref().expect("ledger"))
                .collect::<Vec<_>>(),
            vec![ExecutionErrorKind::TotalToolCallsLimit]
        );
        assert_eq!(
            ledger.snapshot("left").unwrap().total_tool_calls
                + ledger.snapshot("right").unwrap().total_tool_calls,
            1
        );
        assert_eq!(
            serde_json::from_slice::<LoopLedgerV1>(&fs::read(root.join(LOOP_LEDGER_FILE)).unwrap())
                .unwrap()
                .nodes
                .values()
                .map(|state| state.total_tool_calls)
                .sum::<u64>(),
            1
        );
        fs::remove_dir_all(root).unwrap();

        let (root, ledger) = fanout_ledger();
        let outcomes = sibling_fanout(&ledger, &call, |ledger, node, candidate| {
            ledger.tool_call_limit(node, candidate, &limits(2, 1))
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.as_ref().expect("ledger").is_none())
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter_map(|outcome| *outcome.as_ref().expect("ledger"))
                .collect::<Vec<_>>(),
            vec![ExecutionErrorKind::ToolCallsPerToolLimit]
        );
        fs::remove_dir_all(root).unwrap();

        let bytes = LoopState {
            tool_output_bytes: 5,
            ..LoopState::default()
        };
        let (root, ledger) = fanout_ledger();
        let outcomes = sibling_fanout(&ledger, &bytes, |ledger, node, candidate| {
            ledger.output_byte_limit(node, candidate, 5)
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| !*outcome.as_ref().expect("ledger"))
                .count(),
            1
        );
        assert_eq!(
            ledger.snapshot("left").unwrap().tool_output_bytes
                + ledger.snapshot("right").unwrap().tool_output_bytes,
            5
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn registry_with(candidates: &[(BindingCategory, &str, &str)]) -> ExecutionRuntimeRegistry {
        let mut grouped = BTreeMap::new();
        for &(category, id, version) in candidates {
            grouped
                .entry(category)
                .or_insert_with(Vec::new)
                .push(ResolvedBinding::new(id, version));
        }
        ExecutionRuntimeRegistry {
            candidates: grouped,
        }
    }

    #[test]
    fn registry_requires_exact_category_id_and_version() {
        let registry = registry_with(&[(BindingCategory::Model, "model-a", "2")]);
        let resolved = registry
            .resolve(BindingCategory::Model, &BindingRef::new("model-a", "2"))
            .expect("exact model identity should resolve");
        assert_eq!(resolved.id(), "model-a");
        assert_eq!(resolved.version(), "2");
        assert_eq!(
            registry
                .resolve(BindingCategory::Tool, &BindingRef::new("model-a", "2"))
                .expect_err("category mismatch should be missing")
                .kind(),
            workflow_compiler::RegistryResolutionErrorKind::Missing
        );
        assert_eq!(
            registry
                .resolve(BindingCategory::Model, &BindingRef::new("model-a", "1"))
                .expect_err("version mismatch should be missing")
                .kind(),
            workflow_compiler::RegistryResolutionErrorKind::Missing
        );
    }

    #[test]
    fn ambiguous_registry_binding_maps_to_typed_error_with_projection() {
        let registry = registry_with(&[
            (BindingCategory::Tool, "tool-a", "1"),
            (BindingCategory::Tool, "tool-a", "1"),
        ]);
        let projection = ResolvedBinding::new("tool-a", "1");
        let error = map_registry_error(
            registry
                .resolve(
                    BindingCategory::Tool,
                    &BindingRef::new(projection.id(), projection.version()),
                )
                .expect_err("duplicate implementation must be ambiguous"),
            Some(&projection),
        );
        assert_eq!(error.kind(), ExecutionErrorKind::AmbiguousBinding);
        assert_eq!(error.binding_category(), Some(BindingCategory::Tool));
        assert_eq!(error.resolved_binding(), Some(&projection));
    }
}
