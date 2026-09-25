//! Explicit host-only backend entry. No profile adapters or durable continuation.
use super::{
    ExecutionBackend, ExecutionError, ExecutionErrorKind, execution_error_kind, fresh_run_id,
};
use crate::{AdkGraphTranslator, events::AdkEventMapper};
use adk_rust::graph::prelude::{ExecutionConfig, State};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use workflow_runtime::{
    ArtifactId, ArtifactStore, RunId,
    behavioral::{ProbeReport, TrustedScript},
};
use workflow_spec::WorkflowSpec;

/// In-memory execution evidence; not a durable checkpoint or replay capability.
/// The host's artifact store has retained the report before this is returned.
/// `NoCompromiseObserved` is not a Clean verdict.
pub struct BehavioralExecutionReceipt {
    pub run_id: RunId,
    pub report: ProbeReport,
    pub observer: AdkEventMapper,
}

#[cfg(feature = "test-support")]
std::thread_local! {
    pub(super) static MODEL_BINDINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static TOOL_REGISTRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl ExecutionBackend {
    /// Test seam: consume this thread's model-binding/tool-registry entry counts.
    /// These precede credential resolution and invocation, not simulated tool steps.
    #[cfg(feature = "test-support")]
    pub fn take_adapter_counts_for_tests() -> (usize, usize) {
        (MODEL_BINDINGS.replace(0), TOOL_REGISTRIES.replace(0))
    }

    /// Execute a host-authorized inert script through the authored ADK terminal.
    ///
    /// The host must independently authenticate the inputs to `TrustedScript`.
    /// Spec/IR approval, exact source and host controls are checked before graph
    /// construction; normalization/provenance are rebound inside the observed run.
    /// Each call creates a fresh backend run ID, never one supplied by JSON.
    ///
    /// No profile, credential broker, model/tool adapter, checkpoint, result cache
    /// or filesystem run directory is created. Host artifact storage is the only
    /// injected IO and is outside the inert reducer. Cancellation/deadlines are
    /// cooperative, not OS containment. Resume and serialized authority are not
    /// supported; ordinary `run` and CLI entry points still deny behavioral opt-in.
    /// Like `run`, this synchronous entry must be called outside a Tokio runtime.
    pub fn run_with_sentinel_script<S: ArtifactStore>(
        spec: &WorkflowSpec,
        script: TrustedScript,
        input: Value,
        artifacts: &mut S,
        cancelled: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<BehavioralExecutionReceipt, ExecutionError> {
        let compiled = workflow_compiler::compile_spec_with_sentinel_script(spec, &script)
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Compile))?;
        let raw = crate::sentinel_workflow::byte_payload(&input)
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::AuthorizationDenied))?;
        let source = ArtifactId::parse(format!("{:x}", Sha256::digest(&raw)))
            .ok_or_else(|| ExecutionError::new(ExecutionErrorKind::AuthorizationDenied))?;
        if !script.approves_source(&source) {
            return Err(ExecutionError::new(ExecutionErrorKind::AuthorizationDenied));
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(ExecutionError::new(ExecutionErrorKind::Cancelled));
        }
        if Instant::now() >= deadline {
            return Err(ExecutionError::new(ExecutionErrorKind::WallTimeLimit));
        }
        let run_id = fresh_run_id()?;
        let mut observer =
            AdkEventMapper::new(run_id.as_str(), compiled.ir().workflow_id().as_str())
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let graph = AdkGraphTranslator::new()
            .with_sentinel_trusted_script(&compiled, script)
            .and_then(|translator| translator.translate(&compiled))
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Adk))?;
        let runtime = adk_rust::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Adk))?;
        let mut state = State::new();
        state.insert("input".to_owned(), input);
        let (_, report) = runtime
            .block_on(graph.invoke_observed_with_sentinel_script(
                state,
                ExecutionConfig::new(run_id.as_str()),
                &mut observer,
                artifacts,
                cancelled,
                deadline,
            ))
            .map_err(|error| ExecutionError::new(execution_error_kind(error)))?;
        Ok(BehavioralExecutionReceipt {
            run_id,
            report,
            observer,
        })
    }
}
