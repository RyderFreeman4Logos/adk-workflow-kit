//! Profile-driven execution and kit-owned run-state persistence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use adk_rust::graph::prelude::{ExecutionConfig, State};
use adk_rust::graph::{Checkpoint, Checkpointer, GraphError};
use adk_rust::{
    Agent, AgentCapabilities, Content, Event, EventStream, FunctionResponseData, InvocationContext,
    LlmRequest, Part, async_trait, futures::StreamExt as _,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_compiler::compile_file;
use workflow_runtime::{
    ArtifactId, ArtifactStore, BackendCapabilities, CapabilityIntersection, CheckpointManifestV1,
    DurableCheckpointV1, FilesystemArtifactStore, InMemoryArtifactStore, PageRequest,
    ProtectedArtifactReferenceV1, PureTransformRequest, RequestedCapabilities, RunContext, RunId,
    RunLimits, RunSandbox, SandboxCapability, SqliteCheckpointStore, ToolBridge, ToolBridgeError,
    ToolCallContext, ToolEnvelope, ToolFlags, ToolHandler, ToolProvenance, ToolRegistration,
    WorkdirManager, WorkflowRuntimeEventKindV1, contains_sensitive_key, redact_json_value,
    verify_sandbox_capabilities,
};
use workflow_spec::{SourcePath, read_bounded_regular_file};

use crate::{
    AdkGraphTranslator,
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
static NEXT_RUN: AtomicU64 = AtomicU64::new(0);
type BoundTool = (String, Arc<AdkToolBridge<InMemoryArtifactStore>>);

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

/// A validated runtime profile supplied to the reusable ADK executor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfileV1 {
    schema_version: u16,
    model: ModelWire,
    tool: Option<ToolWire>,
    pure_transform: Option<PureTransformWire>,
    sandbox: SandboxWire,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
enum ModelWire {
    Fake {
        name: String,
        version: String,
        model: String,
        responses: Vec<String>,
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
    #[serde(default)]
    required_capabilities: Vec<String>,
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
        match &profile.model {
            ModelWire::Fake {
                name,
                version,
                model,
                responses,
            } => {
                if [name, version, model]
                    .into_iter()
                    .any(|value| value.is_empty())
                    || responses.is_empty()
                    || responses.iter().any(String::is_empty)
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
        if profile
            .tool
            .as_ref()
            .is_some_and(|tool| tool.name.is_empty())
            || profile
                .pure_transform
                .as_ref()
                .is_some_and(|transform| transform.module.is_empty())
        {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
        }
        profile.capabilities()?;
        Ok(profile)
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
        let required = self
            .tool
            .as_ref()
            .into_iter()
            .flat_map(|tool| tool.required_capabilities.iter())
            .map(|value| parse_capability(value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((sandbox, required))
    }

    fn bind_model(&self) -> Result<Arc<ModelBinding>, ExecutionError> {
        let registry = match &self.model {
            ModelWire::Fake {
                name,
                version,
                model,
                responses,
            } => ModelProfileRegistry::new().with_worker(FakeModelProfile::new(
                name,
                version,
                model,
                responses.clone(),
            )),
            ModelWire::OpenaiCompatible {
                name,
                version,
                model,
                base_url,
                credential_env,
            } => ModelProfileRegistry::new().with_worker(OpenAiCompatibleProfile::new(
                name,
                version,
                model,
                base_url,
                CredentialHandle::environment(credential_env),
            )),
        }
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidProfile))?;
        registry
            .bind_worker(&CredentialBroker::new())
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

    fn profile_identity(&self) -> String {
        match &self.model {
            ModelWire::Fake { name, version, .. }
            | ModelWire::OpenaiCompatible { name, version, .. } => format!("{name}:{version}"),
        }
    }
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

#[derive(Clone)]
struct ProfileAgent {
    name: String,
    model: Arc<ModelBinding>,
    tool: Option<BoundTool>,
    input: Value,
}

#[async_trait]
impl Agent for ProfileAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "workflow-kit profile-driven agent"
    }

    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            shared_state: true,
            ..AgentCapabilities::default()
        }
    }

    async fn run(&self, context: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        let request = LlmRequest::new(
            self.model.resolved_model_identity(),
            vec![Content::new("user").with_text(self.input.to_string())],
        );
        let mut responses = self
            .model
            .generate_content(request, false)
            .await
            .map_err(|error| adk_rust::AdkError::agent(error.to_string()))?;
        let mut events = Vec::new();
        while let Some(response) = responses.next().await {
            let mut event = Event::new(context.invocation_id());
            event.llm_response =
                response.map_err(|error| adk_rust::AdkError::agent(error.to_string()))?;
            events.push(Ok(event));
        }
        if events.is_empty() {
            return Err(adk_rust::AdkError::agent("model returned no events"));
        }

        if let Some((name, bridge)) = &self.tool {
            let call_id = format!("{}-tool", context.invocation_id());
            let mut requested = Event::new(context.invocation_id());
            requested.set_content(Content {
                role: "model".to_owned(),
                parts: vec![Part::FunctionCall {
                    name: name.clone(),
                    args: self.input.clone(),
                    id: Some(call_id.clone()),
                    thought_signature: None,
                }],
            });
            events.push(Ok(requested));
            let result = bridge
                .invoke(workflow_runtime::ToolCall::new(
                    name,
                    &call_id,
                    context.user_id(),
                    self.input.clone(),
                ))
                .map_err(|error| adk_rust::AdkError::tool(error.to_string()))?;
            let mut completed = Event::new(context.invocation_id());
            completed.set_content(Content {
                role: "function".to_owned(),
                parts: vec![Part::FunctionResponse {
                    function_response: FunctionResponseData::new(
                        name,
                        serde_json::to_value(result)
                            .map_err(|error| adk_rust::AdkError::tool(error.to_string()))?,
                    ),
                    id: Some(call_id),
                    annotations: None,
                }],
            });
            events.push(Ok(completed));
        }
        Ok(Box::pin(adk_rust::futures::stream::iter(events)))
    }
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunManifestV1 {
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
    checkpoint_manifest: Option<CheckpointManifestV1>,
}

impl RunManifestV1 {
    fn receipt(&self, run_root: PathBuf) -> ExecutionReceipt {
        ExecutionReceipt {
            run_id: self.run_id.clone(),
            workflow_id: self.workflow_id.clone(),
            status: self.status.clone(),
            artifact_id: self.artifact_id.clone(),
            run_root,
            resume_count: self.resume_count,
        }
    }
}

/// Stable execution failure categories used by the CLI facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionErrorKind {
    InvalidProfile,
    SandboxDenied,
    Compile,
    Workdir,
    Model,
    Tool,
    Adk,
    Persistence,
    RunNotFound,
    InvalidRunState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionError {
    kind: ExecutionErrorKind,
    receipt: Option<Box<ExecutionReceipt>>,
}

impl ExecutionError {
    fn new(kind: ExecutionErrorKind) -> Self {
        Self {
            kind,
            receipt: None,
        }
    }
    pub const fn kind(&self) -> ExecutionErrorKind {
        self.kind
    }
    pub fn receipt(&self) -> Option<&ExecutionReceipt> {
        self.receipt.as_deref()
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
        let transform_module = profile.transform_module()?;
        let model = profile.bind_model()?;
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
            compiled.ir().workflow_id().as_str(),
            compiled.ir().workflow_version(),
            crate::canonical_ir_hash(compiled.ir()),
            &profile,
            transform_module.as_deref(),
        )?;
        let context = RunContext::new(run_id.clone(), run_limits());
        let mut mapper = AdkEventMapper::new(run_id.as_str(), compiled.ir().workflow_id().as_str())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let run_workdir = manager
            .allocate(&run_id)
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
        let execution = if persistence_error.is_some() {
            Err(ExecutionError::new(ExecutionErrorKind::Persistence))
        } else {
            let artifacts = artifacts.as_mut().expect("artifact store must be present");
            (|| {
                let sandbox = RunSandbox::new(context, run_workdir, sandbox_capabilities)
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::SandboxDenied))?;
                let tool = build_tool(&profile, sandbox, &required_capabilities)?;
                let agents = compiled
                    .ir()
                    .nodes()
                    .iter()
                    .filter(|node| node.kind() == workflow_ir::IrNodeKind::Agent)
                    .map(|node| {
                        let agent: Arc<dyn Agent> = Arc::new(ProfileAgent {
                            name: node.id().as_str().to_owned(),
                            model: Arc::clone(&model),
                            tool: tool.clone(),
                            input: input.clone(),
                        });
                        (node.id().as_str().to_owned(), agent)
                    })
                    .collect::<BTreeMap<_, _>>();
                let continuation = Arc::new(GraphCheckpointMemory::default());
                let graph = AdkGraphTranslator::new()
                    .translate_profile_with_checkpointer(
                        &compiled,
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
                let state = runtime
                    .block_on(graph.invoke_observed(
                        State::new(),
                        ExecutionConfig::new(run_id.as_str()).with_recursion_limit(recursion_limit),
                        &mut mapper,
                        artifacts,
                    ))
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Adk))?;
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
        if execution.is_err() && status.is_none() {
            status = Some("failed");
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
        if let Err(error) = write_events(&run_root.join("events.jsonl"), mapper.events()) {
            persistence_error.get_or_insert(error);
        }
        if persistence_error.is_none() {
            if let (Ok(state), Some(store)) = (&execution, checkpoint_store.as_mut()) {
                let state_bytes = match serde_json::to_vec(state) {
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
                            if store.save_checkpoint(checkpoint).is_err() {
                                checkpoint_failed = true;
                                persistence_error =
                                    Some(ExecutionError::new(ExecutionErrorKind::Persistence));
                            }
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
        let manifest = RunManifestV1 {
            schema_version: 1,
            run_id: run_id.as_str().to_owned(),
            workflow_id: compiled.ir().workflow_id().as_str().to_owned(),
            workflow_version: compiled.ir().workflow_version().to_owned(),
            workdir_id,
            profile_identity: profile.profile_identity(),
            adk_rust_version: "2.1.0".to_owned(),
            status: status.to_owned(),
            artifact_id,
            resume_count: 0,
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
        let (root, mut manifest) = find_run(workdir_base.as_ref(), run_id)?;
        let checkpoint_manifest = manifest
            .checkpoint_manifest
            .clone()
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let run_identity = RunId::new(run_id.to_owned())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
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
        let transform_module = profile.transform_module()?;
        let live_checkpoint_manifest = build_checkpoint_manifest(
            &run_identity,
            compiled.ir().workflow_id().as_str(),
            compiled.ir().workflow_version(),
            crate::canonical_ir_hash(compiled.ir()),
            &profile,
            transform_module.as_deref(),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        if live_checkpoint_manifest != checkpoint_manifest {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
        let model = profile.bind_model()?;
        let (sandbox_capabilities, required_capabilities) = profile.capabilities()?;
        verify_sandbox_capabilities(
            &RequestedCapabilities::new(required_capabilities.iter().copied()),
            &BackendCapabilities::new(sandbox_capabilities.iter().copied()),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let events_path = root.join("events.jsonl");
        let events = read_events(&events_path)?;
        if events.last().map_or(0, |event| event.sequence()) != checkpoint.event_sequence() {
            return Err(ExecutionError::new(ExecutionErrorKind::InvalidRunState));
        }
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
        let base = root
            .parent()
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let manager = WorkdirManager::new(base)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let run_workdir = manager
            .reopen(&run_identity, &root)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let sandbox = RunSandbox::new(
            RunContext::new(run_identity.clone(), run_limits()),
            run_workdir,
            sandbox_capabilities,
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let tool = build_tool(&profile, sandbox, &required_capabilities)?;
        let agents = compiled
            .ir()
            .nodes()
            .iter()
            .filter(|node| node.kind() == workflow_ir::IrNodeKind::Agent)
            .map(|node| {
                let agent: Arc<dyn Agent> = Arc::new(ProfileAgent {
                    name: node.id().as_str().to_owned(),
                    model: Arc::clone(&model),
                    tool: tool.clone(),
                    input: input.clone(),
                });
                (node.id().as_str().to_owned(), agent)
            })
            .collect::<BTreeMap<_, _>>();
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
            .translate_profile_with_checkpointer(
                &compiled,
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
        let state = runtime
            .block_on(
                graph.invoke_observed(
                    state,
                    ExecutionConfig::new(run_id)
                        .with_recursion_limit(recursion_limit)
                        .with_resume_from(&restored.checkpoint_id),
                    &mut mapper,
                    &mut artifacts,
                ),
            )
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        let state = checkpoint_state(
            state,
            &continuation
                .latest()
                .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?,
            Some(&retry),
        )?;
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
        write_events(&events_path, mapper.events())?;
        checkpoint_store
            .save_checkpoint(checkpoint)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidRunState))?;
        manifest.resume_count = next;
        write_json(&root.join("run-manifest.json"), &manifest)?;
        Ok(manifest.receipt(root))
    }
}

fn build_checkpoint_manifest(
    run_id: &RunId,
    workflow_id: &str,
    workflow_version: &str,
    workflow_hash: String,
    profile: &ExecutionProfileV1,
    transform_module: Option<&[u8]>,
) -> Result<CheckpointManifestV1, ExecutionError> {
    let profile_hash = serde_json::to_vec(profile)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    let mut manifest = CheckpointManifestV1::new(run_id, workflow_id, workflow_version)
        .with_workflow_hash(workflow_hash.clone())
        .with_resource_hash("workflow.ir", workflow_hash)
        .with_implementation("model", profile.profile_identity())
        .with_implementation("adk-rust", "2.1.0")
        .with_implementation(
            "execution-profile",
            format!("sha256:{:x}", Sha256::digest(profile_hash)),
        )
        .with_sandbox_policy_hash(format!(
            "sha256:{:x}",
            Sha256::digest(profile.sandbox.capabilities.join("\n").as_bytes())
        ))
        .with_event_log_identity("workflow-runtime-events-v1");
    if let Some(tool) = &profile.tool {
        manifest = manifest.with_implementation("tool", format!("{}:profile", tool.name));
    }
    if let Some(transform) = transform_module {
        manifest = manifest.with_resource_hash(
            "pure-transform",
            format!("sha256:{:x}", Sha256::digest(transform)),
        );
    }
    Ok(manifest)
}

fn build_tool(
    profile: &ExecutionProfileV1,
    sandbox: RunSandbox,
    required_capabilities: &[SandboxCapability],
) -> Result<Option<BoundTool>, ExecutionError> {
    let Some(tool) = &profile.tool else {
        return Ok(None);
    };
    let provenance = ToolProvenance::new("profile.fake-tool", "1");
    let registration = ToolRegistration::for_types::<Value, Value>(
        &tool.name,
        provenance.clone(),
        ToolFlags::new(true, true, true),
    )
    .map_err(|_| ExecutionError::new(ExecutionErrorKind::InvalidProfile))?
    .with_required_capabilities(required_capabilities.iter().copied());
    let mut bridge = ToolBridge::new(sandbox);
    bridge
        .register(
            registration,
            StaticToolHandler {
                result: tool.result.clone(),
                provenance: provenance.clone(),
            },
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Tool))?;
    let adapter = AdkToolBridge::new(
        bridge,
        CapabilityIntersection::all_for_tool(&tool.name, required_capabilities.iter().copied()),
        None,
        InMemoryArtifactStore::new(
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive artifact limit"),
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive page limit"),
        ),
    );
    Ok(Some((tool.name.clone(), Arc::new(adapter))))
}

struct StaticToolHandler {
    result: Value,
    provenance: ToolProvenance,
}

impl ToolHandler for StaticToolHandler {
    fn execute(
        &self,
        _sandbox: &workflow_runtime::ChildSandbox<'_>,
        _context: &ToolCallContext,
        _arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        Ok(ToolEnvelope::success(
            self.result.clone(),
            self.provenance.clone(),
        ))
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

fn run_limits() -> RunLimits {
    let positive = |value| NonZeroU64::new(value).expect("run limits are positive");
    RunLimits::new(
        positive(100),
        positive(100),
        positive(100),
        positive(60_000),
        positive(60_000),
        positive(60_000),
        positive(ARTIFACT_LIMIT),
    )
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

fn find_run(base: &Path, run_id: &str) -> Result<(PathBuf, RunManifestV1), ExecutionError> {
    WorkdirManager::new(base).map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
    // ponytail: scan run manifests; add an index when run counts make lookup measurable.
    for entry in fs::read_dir(base).map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))? {
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
        let Ok(manifest) = serde_json::from_slice::<RunManifestV1>(&bytes) else {
            continue;
        };
        if manifest.schema_version == 1 && manifest.run_id == run_id {
            return Ok((path, manifest));
        }
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
