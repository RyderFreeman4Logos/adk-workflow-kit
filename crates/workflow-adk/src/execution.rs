//! Profile-driven execution and kit-owned run-state persistence.

use std::{
    collections::BTreeMap,
    fmt, fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use adk_rust::graph::prelude::{ExecutionConfig, State};
use adk_rust::{
    Agent, AgentCapabilities, Content, Event, EventStream, FunctionResponseData, InvocationContext,
    LlmRequest, Part, async_trait, futures::StreamExt as _,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use workflow_compiler::compile_file;
use workflow_runtime::{
    ArtifactStore, BackendCapabilities, CapabilityIntersection, FilesystemArtifactStore,
    InMemoryArtifactStore, PureTransformRequest, RequestedCapabilities, RunContext, RunId,
    RunLimits, RunSandbox, SandboxCapability, ToolBridge, ToolBridgeError, ToolCallContext,
    ToolEnvelope, ToolFlags, ToolHandler, ToolProvenance, ToolRegistration, WorkdirManager,
    WorkflowRuntimeEventKindV1, verify_sandbox_capabilities,
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
static NEXT_RUN: AtomicU64 = AtomicU64::new(0);
type BoundTool = (String, Arc<AdkToolBridge<InMemoryArtifactStore>>);

/// A validated runtime profile supplied to the reusable ADK executor.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfileV1 {
    schema_version: u16,
    model: ModelWire,
    tool: Option<ToolWire>,
    pure_transform: Option<PureTransformWire>,
    sandbox: SandboxWire,
}

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolWire {
    name: String,
    result: Value,
    #[serde(default)]
    required_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PureTransformWire {
    module: String,
}

#[derive(Clone, Debug, Deserialize)]
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
        let manager = WorkdirManager::new(workdir_base)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
        let run_id = fresh_run_id()?;
        let context = RunContext::new(run_id.clone(), run_limits());
        let mut mapper = AdkEventMapper::new(run_id.as_str(), compiled.ir().workflow_id().as_str())
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let run_workdir = manager
            .allocate(&run_id)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Workdir))?;
        let run_root = run_workdir.root().to_path_buf();
        let workdir_id = run_workdir.id().as_str().to_owned();
        let mut artifacts = FilesystemArtifactStore::try_new(
            run_root.join("artifacts"),
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive artifact limit"),
            NonZeroU64::new(ARTIFACT_LIMIT).expect("positive page limit"),
        )
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        mapper
            .map(AdkRuntimeObservationV1::new(
                "workflow-started",
                "workflowctl",
                AdkRuntimeObservationKindV1::WorkflowStarted,
            ))
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let execution = (|| {
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
            let graph = AdkGraphTranslator::new()
                .translate_profile(&compiled, &agents, transform_module.as_deref(), &input)
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Adk))?;
            let runtime = adk_rust::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Adk))?;
            let state = runtime
                .block_on(graph.invoke_observed(
                    State::new(),
                    ExecutionConfig::new(run_id.as_str()),
                    &mut mapper,
                    &mut artifacts,
                ))
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Adk))?;
            state
                .contains_key("terminal")
                .then_some(state)
                .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::Adk))
        })();
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
            mapper
                .map(AdkRuntimeObservationV1::new(
                    "workflow-failed",
                    "workflowctl",
                    AdkRuntimeObservationKindV1::WorkflowFailed,
                ))
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
            status = Some("failed");
        }
        let status = status.unwrap_or("succeeded");
        let node_outputs = execution.as_ref().ok().map_or_else(BTreeMap::new, |state| {
            compiled
                .ir()
                .nodes()
                .iter()
                .filter(|node| {
                    !matches!(
                        node.kind(),
                        workflow_ir::IrNodeKind::Agent | workflow_ir::IrNodeKind::Terminal
                    )
                })
                .filter_map(|node| {
                    let id = node.id().as_str();
                    state
                        .get(&format!("node:{id}"))
                        .cloned()
                        .map(|output| (id.to_owned(), output))
                })
                .collect()
        });
        let terminal = serde_json::to_vec(&serde_json::json!({
            "run_id": run_id.as_str(),
            "status": status,
            "terminal": execution.as_ref().ok().and_then(|state| state.get("terminal")),
            "node_outputs": node_outputs
        }))
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let artifact_id = artifacts
            .put(&terminal)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        write_events(&run_root.join("events.jsonl"), mapper.events())?;
        let manifest = RunManifestV1 {
            schema_version: 1,
            run_id: run_id.as_str().to_owned(),
            workflow_id: compiled.ir().workflow_id().as_str().to_owned(),
            workflow_version: compiled.ir().workflow_version().to_owned(),
            workdir_id,
            profile_identity: profile.profile_identity(),
            adk_rust_version: "2.1.0".to_owned(),
            status: status.to_owned(),
            artifact_id: artifact_id.as_str().to_owned(),
            resume_count: 0,
        };
        write_json(&run_root.join("run-manifest.json"), &manifest)?;
        let receipt = manifest.receipt(run_root);
        match execution {
            Ok(_) => Ok(receipt),
            Err(error) => Err(error.with_receipt(receipt)),
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
        let events_path = root.join("events.jsonl");
        let events = read_events(&events_path)?;
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
        write_events(&events_path, mapper.events())?;
        manifest.resume_count = next;
        write_json(&root.join("run-manifest.json"), &manifest)?;
        Ok(manifest.receipt(root))
    }
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
    write_atomic(path, &bytes)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), ExecutionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ExecutionError> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
    fs::rename(temporary, path).map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
}
