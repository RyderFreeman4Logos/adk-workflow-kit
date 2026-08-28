//! Deterministic offline ADK-Rust test doubles and exact tool registry fixtures.

mod bench;
pub mod code_investigation;
mod eval;
mod non_progress;
mod replay;
mod sandbox;

pub use bench::{BenchmarkDiagnostics, BenchmarkReport, BenchmarkSample, run_suite};

use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use adk_rust::{
    AdkError, ErrorCategory, ErrorComponent, Llm, LlmRequest, LlmResponse, LlmResponseStream, Tool,
    ToolContext, async_trait,
};
use serde_json::Value;
use workflow_compiler::{RegistryCategory, RegistryEntry, RegistryNotFound, ToolRegistry};
use workflow_runtime::{RunController, RunLimitKind, RunTerminalCause, RunTimeoutKind};

pub use eval::{
    EvalAcknowledgement, EvalDiagnosticKind, EvalDisposition, EvalEnvelope, EvalError, EvalFixture,
    EvalInput, compile_eval,
};
pub use non_progress::{NoProgressError, NoProgressReason, NonProgressDetector};
pub use replay::{ReplayBundle, ReplayError, ReplayErrorKind, ReplayEvent, StructuralTrace};
pub use sandbox::{
    FakeSandboxBackend, FakeSandboxReceipt, FakeSandboxRequest, FakeSandboxRequestError,
    FakeSandboxRequestErrorKind,
};

use workflow_runtime::{Checkpoint, CheckpointBackend, CheckpointError, RunId};

/// A deterministic side-effect count used by kill/resume fixtures.
#[derive(Default)]
pub struct SideEffectLedger {
    commits: usize,
}

impl SideEffectLedger {
    fn commit(&mut self) {
        self.commits += 1;
    }

    /// Returns the number of committed side effects.
    pub fn commits(&self) -> usize {
        self.commits
    }
}

struct FixtureCheckpointBackend {
    checkpoint: Option<Checkpoint>,
}

impl CheckpointBackend for FixtureCheckpointBackend {
    fn load(&self, run_id: &RunId) -> Result<Option<Checkpoint>, CheckpointError> {
        Ok(self
            .checkpoint
            .as_ref()
            .filter(|checkpoint| checkpoint.run_id() == run_id)
            .cloned())
    }

    fn save(&mut self, checkpoint: Checkpoint) -> Result<(), CheckpointError> {
        self.checkpoint = Some(checkpoint);
        Ok(())
    }
}

/// A kill/resume fixture that records a side effect before checkpointing it.
pub struct KillResumeFixture {
    backend: FixtureCheckpointBackend,
    ledger: SideEffectLedger,
}

impl KillResumeFixture {
    /// Creates an offline fixture with the supplied side-effect ledger.
    pub fn new(ledger: SideEffectLedger) -> Self {
        Self {
            backend: FixtureCheckpointBackend { checkpoint: None },
            ledger,
        }
    }

    /// Simulates a killed worker after the side effect and durable checkpoint.
    pub fn kill_after_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.ledger.commit();
        self.backend
            .save(checkpoint)
            .expect("fixture checkpoint backend must save");
    }

    /// Resumes a run without repeating a side effect already checkpointed.
    pub fn resume(&mut self, run_id: &RunId) -> Result<(), CheckpointError> {
        match self.backend.load(run_id)? {
            Some(checkpoint) if checkpoint.state() == b"done" => {}
            Some(_) | None => self.ledger.commit(),
        }
        Ok(())
    }

    /// Stores a checkpoint and exercises the resumed side-effect operation.
    pub fn resume_with_checkpoint(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Result<(), CheckpointError> {
        let run_id = checkpoint.run_id().clone();
        self.backend.save(checkpoint)?;
        self.resume(&run_id)
    }

    /// Returns the fixture's side-effect ledger.
    pub fn ledger(&self) -> &SideEffectLedger {
        &self.ledger
    }
}

/// A deterministic completion signal injected by this testkit.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FaultSignal {
    /// A host-enforced time ceiling was reached.
    Timeout(RunTimeoutKind),
    /// A host-enforced count or byte ceiling was reached.
    RateLimit(RunLimitKind),
    /// A bounded output payload could not be decoded.
    InvalidOutput,
    /// A tool output stream crossed its byte ceiling.
    OutputFlood {
        /// Bytes accepted before the rejecting chunk.
        accepted_bytes: u64,
    },
    /// The supplied controller or payload did not meet an injector precondition.
    InjectionPreconditionFailed,
}

/// A privacy-safe diagnostic returned by a deterministic fault injector.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FaultDiagnostic {
    signal: FaultSignal,
}

impl FaultDiagnostic {
    fn new(signal: FaultSignal) -> Self {
        Self { signal }
    }

    /// Returns the typed fault signal without retaining injected payload bytes.
    pub const fn signal(&self) -> FaultSignal {
        self.signal
    }
}

impl fmt::Display for FaultDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.signal {
            FaultSignal::Timeout(kind) => {
                write!(
                    formatter,
                    "injected fault: run timed out ({})",
                    timeout_name(kind)
                )
            }
            FaultSignal::RateLimit(kind) => {
                write!(
                    formatter,
                    "injected fault: quota exhausted ({})",
                    limit_name(kind)
                )
            }
            FaultSignal::InvalidOutput => formatter.write_str("injected fault: invalid output"),
            FaultSignal::OutputFlood { accepted_bytes } => write!(
                formatter,
                "injected fault: output byte ceiling rejected (accepted {accepted_bytes} bytes)"
            ),
            FaultSignal::InjectionPreconditionFailed => {
                formatter.write_str("injected fault: injector precondition was not met")
            }
        }
    }
}

impl fmt::Debug for FaultSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout(kind) => formatter.debug_tuple("Timeout").field(kind).finish(),
            Self::RateLimit(kind) => formatter.debug_tuple("RateLimit").field(kind).finish(),
            Self::InvalidOutput => formatter.write_str("InvalidOutput"),
            Self::OutputFlood { accepted_bytes } => formatter
                .debug_struct("OutputByteCeiling")
                .field("accepted_bytes", accepted_bytes)
                .finish(),
            Self::InjectionPreconditionFailed => formatter.write_str("InjectionPreconditionFailed"),
        }
    }
}

impl fmt::Debug for FaultDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.signal {
            FaultSignal::OutputFlood { accepted_bytes } => formatter
                .debug_struct("FaultDiagnostic")
                .field("code", &"output_byte_ceiling")
                .field("accepted_bytes", &accepted_bytes)
                .finish(),
            signal => formatter
                .debug_struct("FaultDiagnostic")
                .field("signal", &signal)
                .finish(),
        }
    }
}

impl std::error::Error for FaultDiagnostic {}

/// Injects a timeout through the existing host controller.
pub fn inject_timeout(
    controller: &mut RunController<'_>,
    elapsed: Duration,
    expected: RunTimeoutKind,
) -> FaultDiagnostic {
    match controller.poll(elapsed) {
        Err(termination) => match termination.cause() {
            RunTerminalCause::TimedOut(kind) if kind == expected => {
                FaultDiagnostic::new(FaultSignal::Timeout(kind))
            }
            _ => FaultDiagnostic::new(FaultSignal::InjectionPreconditionFailed),
        },
        Ok(()) => FaultDiagnostic::new(FaultSignal::InjectionPreconditionFailed),
    }
}

/// Injects quota exhaustion through the existing host controller.
pub fn inject_rate_limit(controller: &mut RunController<'_>, elapsed: Duration) -> FaultDiagnostic {
    match controller.admit_model_turn(elapsed) {
        Err(termination) => match termination.cause() {
            RunTerminalCause::LimitExceeded(kind) => {
                FaultDiagnostic::new(FaultSignal::RateLimit(kind))
            }
            _ => FaultDiagnostic::new(FaultSignal::InjectionPreconditionFailed),
        },
        Ok(()) => FaultDiagnostic::new(FaultSignal::InjectionPreconditionFailed),
    }
}

/// Injects an invalid bounded JSON output without retaining its bytes.
pub fn inject_invalid_output<T>(payload: &[u8], maximum_bytes: usize) -> FaultDiagnostic
where
    T: serde::de::DeserializeOwned,
{
    if payload.len() > maximum_bytes || serde_json::from_slice::<T>(payload).is_err() {
        FaultDiagnostic::new(FaultSignal::InvalidOutput)
    } else {
        FaultDiagnostic::new(FaultSignal::InjectionPreconditionFailed)
    }
}

/// Injects a tool-output flood through the existing host controller.
pub fn inject_output_flood(
    controller: &mut RunController<'_>,
    elapsed: Duration,
    accepted_bytes: u64,
) -> FaultDiagnostic {
    match controller.accept_tool_output(elapsed, u64::MAX) {
        Err(termination) => match termination.cause() {
            RunTerminalCause::LimitExceeded(RunLimitKind::ToolOutputBytes) => {
                FaultDiagnostic::new(FaultSignal::OutputFlood { accepted_bytes })
            }
            _ => FaultDiagnostic::new(FaultSignal::InjectionPreconditionFailed),
        },
        Ok(()) => FaultDiagnostic::new(FaultSignal::InjectionPreconditionFailed),
    }
}

fn timeout_name(kind: RunTimeoutKind) -> &'static str {
    match kind {
        RunTimeoutKind::WallTime => "wall time",
        RunTimeoutKind::IdleTime => "idle time",
        RunTimeoutKind::ToolTime => "tool time",
    }
}

fn limit_name(kind: RunLimitKind) -> &'static str {
    match kind {
        RunLimitKind::ModelTurns => "model turns",
        RunLimitKind::TotalToolCalls => "total tool calls",
        RunLimitKind::ToolCallsPerTool => "tool calls per tool",
        RunLimitKind::ToolOutputBytes => "tool output bytes",
    }
}

type RequestPredicate = dyn Fn(&LlmRequest) -> Result<(), String> + Send + Sync;

fn model_error(code: &'static str, message: impl Into<String>) -> AdkError {
    AdkError::new(
        ErrorComponent::Model,
        ErrorCategory::Internal,
        code,
        message,
    )
}

fn tool_error(code: &'static str, message: impl Into<String>) -> AdkError {
    AdkError::new(ErrorComponent::Tool, ErrorCategory::Internal, code, message)
}

/// One expected model request and its deterministic response.
pub struct ScriptStep {
    predicate: Box<RequestPredicate>,
    response: LlmResponse,
}

impl ScriptStep {
    /// Creates a step from an explicit request predicate and response.
    pub fn new<F>(predicate: F, response: LlmResponse) -> Self
    where
        F: Fn(&LlmRequest) -> Result<(), String> + Send + Sync + 'static,
    {
        Self {
            predicate: Box::new(predicate),
            response,
        }
    }
}

struct ScriptState {
    steps: VecDeque<ScriptStep>,
    requests: Vec<LlmRequest>,
}

/// A finite, ordered ADK model script that fails closed on unexpected requests.
pub struct ScriptedLlm {
    state: Mutex<ScriptState>,
}

impl ScriptedLlm {
    /// Creates a scripted model with the supplied ordered steps.
    pub fn new(steps: Vec<ScriptStep>) -> Self {
        Self {
            state: Mutex::new(ScriptState {
                steps: steps.into(),
                requests: Vec::new(),
            }),
        }
    }

    /// Returns stable copies of all observed requests.
    pub fn requests(&self) -> adk_rust::Result<Vec<LlmRequest>> {
        self.state
            .lock()
            .map(|state| state.requests.clone())
            .map_err(|_| {
                model_error(
                    "model.scripted.state_poisoned",
                    "scripted model state is poisoned",
                )
            })
    }

    /// Returns the number of unconsumed script steps.
    pub fn remaining_steps(&self) -> adk_rust::Result<usize> {
        self.state
            .lock()
            .map(|state| state.steps.len())
            .map_err(|_| {
                model_error(
                    "model.scripted.state_poisoned",
                    "scripted model state is poisoned",
                )
            })
    }
}

#[async_trait]
impl Llm for ScriptedLlm {
    fn name(&self) -> &str {
        "scripted-llm"
    }

    async fn generate_content(
        &self,
        request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<LlmResponseStream> {
        let mut state = self.state.lock().map_err(|_| {
            model_error(
                "model.scripted.state_poisoned",
                "scripted model state is poisoned",
            )
        })?;
        state.requests.push(request.clone());

        let response = {
            let step = state.steps.front().ok_or_else(|| {
                model_error(
                    "model.scripted.exhausted",
                    "scripted model has no remaining response",
                )
            })?;
            (step.predicate)(&request)
                .map_err(|message| model_error("model.scripted.request_mismatch", message))?;
            step.response.clone()
        };
        let _ = state.steps.pop_front();

        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(response)])))
    }
}

/// One exact function call observed by a [`FakeTool`].
#[derive(Clone, Debug, PartialEq)]
pub struct FakeToolCall {
    function_call_id: String,
    arguments: Value,
}

impl FakeToolCall {
    /// Returns the exact ADK function-call ID.
    pub fn function_call_id(&self) -> &str {
        &self.function_call_id
    }

    /// Returns the exact JSON arguments supplied by ADK.
    pub fn arguments(&self) -> &Value {
        &self.arguments
    }
}

/// An ADK tool with deterministic JSON output and an in-memory call ledger.
pub struct FakeTool {
    name: String,
    description: String,
    response: Value,
    calls: Mutex<Vec<FakeToolCall>>,
}

impl FakeTool {
    /// Creates a deterministic fake tool.
    pub fn new(name: impl Into<String>, description: impl Into<String>, response: Value) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            response,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Returns stable copies of all observed calls.
    pub fn calls(&self) -> adk_rust::Result<Vec<FakeToolCall>> {
        self.calls.lock().map(|calls| calls.clone()).map_err(|_| {
            tool_error(
                "tool.fake.state_poisoned",
                "fake tool call state is poisoned",
            )
        })
    }
}

#[async_trait]
impl Tool for FakeTool {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    async fn execute(
        &self,
        context: Arc<dyn ToolContext>,
        arguments: Value,
    ) -> adk_rust::Result<Value> {
        self.calls
            .lock()
            .map_err(|_| {
                tool_error(
                    "tool.fake.state_poisoned",
                    "fake tool call state is poisoned",
                )
            })?
            .push(FakeToolCall {
                function_call_id: context.function_call_id().to_owned(),
                arguments,
            });
        Ok(self.response.clone())
    }
}

/// A compiler tool registry containing one exact opaque ID and version pair.
pub struct FakeToolRegistry<T> {
    id: String,
    version: String,
    implementation: T,
}

impl<T> FakeToolRegistry<T> {
    /// Creates a single-entry exact-version registry.
    pub fn new(id: impl Into<String>, version: impl Into<String>, implementation: T) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            implementation,
        }
    }
}

impl<T> ToolRegistry for FakeToolRegistry<T> {
    type Implementation = T;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        if (id, version) == (self.id.as_str(), self.version.as_str()) {
            Ok(RegistryEntry::new(
                &self.implementation,
                &self.id,
                &self.version,
            ))
        } else {
            Err(RegistryNotFound::new(RegistryCategory::Tool, id, version))
        }
    }
}
