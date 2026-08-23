//! One bounded workflow-to-pure-transform execution request seam.

use std::{fmt, time::Duration};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    ArtifactError, ArtifactId, ArtifactStore, PureTransformBackend, PureTransformError,
    PureTransformRequest, PureTransformRequestError, RequestedCapabilities, RunContext,
    RunController, RunOutcome, RunResult, RunTerminalCause, RunWorkdir,
};

/// The version of the deterministic pure-transform execution plan.
pub const PURE_TRANSFORM_PLAN_VERSION_V1: u16 = 1;
/// The only implementation binding admitted by this seam.
pub const PURE_TRANSFORM_BINDING_ID: &str = "pure-transform";
/// The version of the pure-transform implementation binding.
pub const PURE_TRANSFORM_BINDING_VERSION: &str = "1";

/// A verified immutable binding between one workflow identity and WASM bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct PureTransformBinding {
    workflow_id: String,
    workflow_version: String,
    module_digest: String,
    module: Vec<u8>,
}

impl fmt::Debug for PureTransformBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PureTransformBinding")
            .field("workflow_id", &self.workflow_id)
            .field("workflow_version", &self.workflow_version)
            .field("binding_id", &PURE_TRANSFORM_BINDING_ID)
            .field("binding_version", &PURE_TRANSFORM_BINDING_VERSION)
            .field("module_digest", &self.module_digest)
            .field("module_bytes", &self.module.len())
            .finish()
    }
}

impl PureTransformBinding {
    /// Verifies identity fields and binds the declared digest to immutable module bytes.
    pub fn new(
        workflow_id: impl Into<String>,
        workflow_version: impl Into<String>,
        module_digest: impl Into<String>,
        module: impl AsRef<[u8]>,
    ) -> Result<Self, PureTransformPlanError> {
        let workflow_id = workflow_id.into();
        let workflow_version = workflow_version.into();
        let module_digest = module_digest.into();
        let module = module.as_ref();
        if !valid_identity(&workflow_id)
            || !valid_identity(&workflow_version)
            || !valid_digest(&module_digest)
        {
            return Err(PureTransformPlanError::InvalidIdentity);
        }
        if module.is_empty() {
            return Err(PureTransformPlanError::MissingModule);
        }
        if module_digest != digest(module) {
            return Err(PureTransformPlanError::DigestMismatch);
        }
        Ok(Self {
            workflow_id,
            workflow_version,
            module_digest,
            module: module.to_vec(),
        })
    }

    /// Returns the verified workflow identifier.
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Returns the verified workflow version.
    pub fn workflow_version(&self) -> &str {
        &self.workflow_version
    }

    /// Returns the fixed implementation binding identifier.
    pub const fn binding_id(&self) -> &'static str {
        PURE_TRANSFORM_BINDING_ID
    }

    /// Returns the fixed implementation binding version.
    pub const fn binding_version(&self) -> &'static str {
        PURE_TRANSFORM_BINDING_VERSION
    }

    /// Returns the verified lowercase SHA-256 module digest.
    pub fn module_digest(&self) -> &str {
        &self.module_digest
    }

    /// Returns the bound module bytes without granting mutable access.
    pub fn module_bytes(&self) -> &[u8] {
        &self.module
    }
}

/// A deterministic, versioned plan for one pure-transform request.
#[derive(Clone, Eq, PartialEq)]
pub struct PureTransformPlanV1 {
    binding: PureTransformBinding,
    input: Value,
    requested: RequestedCapabilities,
    input_digest: String,
    input_bytes: usize,
}

impl fmt::Debug for PureTransformPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PureTransformPlanV1")
            .field("version", &PURE_TRANSFORM_PLAN_VERSION_V1)
            .field("binding", &self.binding)
            .field("input_digest", &self.input_digest)
            .field("input_bytes", &self.input_bytes)
            .finish()
    }
}

impl PureTransformPlanV1 {
    /// Returns the deterministic plan version.
    pub const fn version(&self) -> u16 {
        PURE_TRANSFORM_PLAN_VERSION_V1
    }

    /// Validates the bounded request without executing a backend or touching artifacts.
    pub fn new(
        binding: PureTransformBinding,
        input: Value,
        requested: RequestedCapabilities,
    ) -> Result<Self, PureTransformPlanError> {
        let serialized = serde_json::to_vec(&input).map_err(|_| {
            PureTransformPlanError::Request(PureTransformRequestError::JsonSerializationFailed)
        })?;
        PureTransformRequest::new(binding.module_bytes(), input.clone(), requested.clone())?;
        Ok(Self {
            binding,
            input,
            requested,
            input_digest: digest(&serialized),
            input_bytes: serialized.len(),
        })
    }

    /// Returns the verified binding used by this plan.
    pub fn binding(&self) -> &PureTransformBinding {
        &self.binding
    }

    /// Renders the stable plan description without execution or artifact mutation.
    pub fn render(&self) -> String {
        format!(
            "plan_version={PURE_TRANSFORM_PLAN_VERSION_V1}\nbackend={PURE_TRANSFORM_BINDING_ID}\nbinding_version={PURE_TRANSFORM_BINDING_VERSION}\nworkflow_id={}\nworkflow_version={}\nmodule_digest={}\ninput_digest={}\ninput_bytes={}\nartifact=sha256(serialized-json-output)\nexecution=not_started\n",
            self.binding.workflow_id(),
            self.binding.workflow_version(),
            self.binding.module_digest(),
            self.input_digest,
            self.input_bytes,
        )
    }

    /// Executes the bounded transform and publishes its non-empty JSON output.
    pub fn execute<S: ArtifactStore, F: FnMut() -> Duration>(
        &self,
        context: &RunContext,
        controller: &mut RunController<'_>,
        mut elapsed: F,
        workdir: &RunWorkdir,
        artifacts: &mut S,
    ) -> RunResult<ArtifactId, PureTransformExecutionError> {
        if context.run_id() != workdir.run_id() {
            return failed(context, PureTransformExecutionError::WorkdirRunMismatch);
        }

        if let Err(termination) = controller.poll(elapsed()) {
            return terminal_failure(context, termination);
        }

        let request = match PureTransformRequest::new(
            self.binding.module_bytes(),
            self.input.clone(),
            self.requested.clone(),
        ) {
            Ok(request) => request,
            Err(error) => return failed(context, PureTransformExecutionError::Request(error)),
        };
        let output = match PureTransformBackend::new().execute(&request) {
            Ok(output) => output,
            Err(error) => return failed(context, PureTransformExecutionError::Backend(error)),
        };
        let output = match serde_json::to_vec(&output) {
            Ok(output) if !output.is_empty() => output,
            Ok(_) => return failed(context, PureTransformExecutionError::EmptyOutput),
            Err(_) => return failed(context, PureTransformExecutionError::OutputSerialization),
        };
        if let Err(termination) = controller.finish(elapsed()) {
            return terminal_failure(context, termination);
        }

        match artifacts.put(&output) {
            Ok(artifact_id) => RunResult::new(
                context.run_id().clone(),
                RunOutcome::Completed {
                    output: artifact_id,
                },
            ),
            Err(error) => failed(context, PureTransformExecutionError::Artifact(error)),
        }
    }
}

fn terminal_failure(
    context: &RunContext,
    termination: crate::RunTermination,
) -> RunResult<ArtifactId, PureTransformExecutionError> {
    let cause = termination.cause();
    RunResult::new(
        context.run_id().clone(),
        cause.into_outcome(PureTransformExecutionError::Controller(cause)),
    )
}

fn failed(
    context: &RunContext,
    diagnostic: PureTransformExecutionError,
) -> RunResult<ArtifactId, PureTransformExecutionError> {
    RunResult::new(context.run_id().clone(), RunOutcome::Failed { diagnostic })
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", crate::encode_hex(&Sha256::digest(bytes)))
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| !byte.is_ascii_control())
}

fn valid_digest(value: &str) -> bool {
    let hex = value.strip_prefix("sha256:");
    hex.is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// A typed plan-construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PureTransformPlanError {
    /// The workflow identity or declared digest is malformed.
    InvalidIdentity,
    /// The declared module payload is absent.
    MissingModule,
    /// The declared module digest does not match the payload.
    DigestMismatch,
    /// The bounded pure-transform request could not be constructed.
    Request(PureTransformRequestError),
}

impl fmt::Display for PureTransformPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity => formatter.write_str("pure transform identity is invalid"),
            Self::MissingModule => formatter.write_str("pure transform module is missing"),
            Self::DigestMismatch => formatter.write_str("pure transform module digest mismatched"),
            Self::Request(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for PureTransformPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PureTransformRequestError> for PureTransformPlanError {
    fn from(error: PureTransformRequestError) -> Self {
        Self::Request(error)
    }
}

/// A typed failure from the execution and publication boundary.
#[derive(Debug)]
pub enum PureTransformExecutionError {
    /// The workdir belongs to a different run context.
    WorkdirRunMismatch,
    /// The existing controller rejected a run boundary.
    Controller(RunTerminalCause),
    /// The bounded request could not be reconstructed.
    Request(PureTransformRequestError),
    /// The existing pure-transform backend rejected or failed the module.
    Backend(PureTransformError),
    /// The backend result could not be serialized as JSON bytes.
    OutputSerialization,
    /// The backend returned no bytes to publish.
    EmptyOutput,
    /// The existing artifact store rejected publication.
    Artifact(ArtifactError),
}

impl fmt::Display for PureTransformExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkdirRunMismatch => formatter.write_str("run context and workdir do not match"),
            Self::Controller(cause) => {
                write!(formatter, "run controller rejected execution: {cause:?}")
            }
            Self::Request(error) => fmt::Display::fmt(error, formatter),
            Self::Backend(error) => fmt::Display::fmt(error, formatter),
            Self::OutputSerialization => {
                formatter.write_str("pure transform output serialization failed")
            }
            Self::EmptyOutput => formatter.write_str("pure transform output is empty"),
            Self::Artifact(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for PureTransformExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Backend(error) => Some(error),
            Self::Artifact(error) => Some(error),
            _ => None,
        }
    }
}
