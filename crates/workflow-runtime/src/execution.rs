//! One bounded workflow-to-pure-transform execution request seam.

use std::{fmt, time::Duration};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    ArtifactError, ArtifactId, ArtifactStore, PureTransformBackend, PureTransformError,
    PureTransformRequest, PureTransformRequestError, RequestedCapabilities, RunContext,
    RunController, RunOutcome, RunResult, RunWorkdir,
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
        mut controller: RunController<'_>,
        mut elapsed: F,
        workdir: &RunWorkdir,
        artifacts: &mut S,
    ) -> RunResult<ArtifactId, PureTransformExecutionError> {
        if context.run_id() != workdir.run_id() {
            return identity_failure(
                context,
                controller,
                PureTransformExecutionError::WorkdirRunMismatch,
            );
        }
        if !controller.belongs_to(context) {
            return identity_failure(
                context,
                controller,
                PureTransformExecutionError::ControllerRunMismatch,
            );
        }

        if let Err(termination) = controller.preflight_finish(elapsed()) {
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
        let staged = match artifacts.stage(&output) {
            Ok(staged) => staged,
            Err(error) => return failed(context, PureTransformExecutionError::Artifact(error)),
        };
        // All blocking write/fsync preparation happened during staging; the
        // final wall-clock authority check runs before visibility.
        if let Err(termination) = controller.finish(elapsed()) {
            return terminal_failure(context, termination);
        }

        match artifacts.commit(staged) {
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

fn identity_failure(
    context: &RunContext,
    controller: RunController<'_>,
    mismatch: PureTransformExecutionError,
) -> RunResult<ArtifactId, PureTransformExecutionError> {
    match controller.into_rejection_termination() {
        Some(termination) => {
            let cause = termination.cause();
            RunResult::new(
                context.run_id().clone(),
                cause.into_outcome(PureTransformExecutionError::IdentityRejection {
                    mismatch: Box::new(mismatch),
                    termination,
                }),
            )
        }
        None => failed(context, mismatch),
    }
}

fn terminal_failure(
    context: &RunContext,
    termination: crate::RunTermination,
) -> RunResult<ArtifactId, PureTransformExecutionError> {
    let cause = termination.cause();
    RunResult::new(
        context.run_id().clone(),
        cause.into_outcome(PureTransformExecutionError::ControllerTermination(
            termination,
        )),
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
    /// The controller belongs to a different run context.
    ControllerRunMismatch,
    /// The existing controller rejected a run boundary with one-shot cleanup.
    ControllerTermination(crate::RunTermination),
    /// An identity rejection retained both its mismatch and controller termination.
    IdentityRejection {
        /// The rejected workdir or controller identity.
        mismatch: Box<Self>,
        /// The controller's terminal cause and complete source authority.
        termination: crate::RunTermination,
    },
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
            Self::ControllerRunMismatch => {
                formatter.write_str("run context and controller do not match")
            }
            Self::ControllerTermination(termination) => write!(
                formatter,
                "run controller rejected execution: {:?}",
                termination.cause()
            ),
            Self::IdentityRejection {
                mismatch,
                termination,
            } => write!(
                formatter,
                "run identity rejected execution: {mismatch}; controller termination: {:?}",
                termination.cause()
            ),

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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        num::NonZeroU64,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::json;

    use super::*;
    use crate::{
        pure_transform::{backend_executions, reset_backend_executions},
        ArtifactPage, FilesystemArtifactStore, InMemoryArtifactStore, PageRequest, RetentionPolicy,
        RunControlError, RunId, RunLimits, RunStatus, RunTerminalCause, RunTimeoutKind,
        SandboxCapability, StagedArtifact, WorkdirManager,
    };

    const IDENTITY_WASM: &[u8] = include_bytes!("../tests/fixtures/pure_transform_identity.wasm");
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "workflow-runtime-execution-unit-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("test root must be unique");
            Self(root)
        }

        fn manager(&self) -> WorkdirManager {
            let base = self.0.join("workdirs");
            fs::create_dir(&base).expect("workdir base must be created");
            WorkdirManager::new(base).expect("workdir base must be trusted")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct CountingStore {
        inner: InMemoryArtifactStore,
        stages: usize,
        commits: usize,
    }

    impl CountingStore {
        fn new() -> Self {
            let limit = NonZeroU64::new(64 * 1024).expect("positive limit");
            Self {
                inner: InMemoryArtifactStore::new(limit, limit),
                stages: 0,
                commits: 0,
            }
        }
    }

    impl ArtifactStore for CountingStore {
        fn stage(&mut self, bytes: &[u8]) -> Result<StagedArtifact, ArtifactError> {
            self.stages += 1;
            self.inner.stage(bytes)
        }

        fn commit(&mut self, staged: StagedArtifact) -> Result<ArtifactId, ArtifactError> {
            self.commits += 1;
            self.inner.commit(staged)
        }

        fn put(&mut self, bytes: &[u8]) -> Result<ArtifactId, ArtifactError> {
            self.commits += 1;
            self.inner.put(bytes)
        }

        fn read_page(
            &self,
            id: &ArtifactId,
            request: PageRequest,
        ) -> Result<ArtifactPage, ArtifactError> {
            self.inner.read_page(id, request)
        }

        fn set_retention(
            &mut self,
            id: &ArtifactId,
            policy: RetentionPolicy,
        ) -> Result<(), ArtifactError> {
            self.inner.set_retention(id, policy)
        }

        fn retention(&self, id: &ArtifactId) -> Result<RetentionPolicy, ArtifactError> {
            self.inner.retention(id)
        }
    }

    fn run(id: &str, wall_ms: u64) -> RunContext {
        run_with_idle(id, wall_ms, 1_000)
    }

    fn run_with_idle(id: &str, wall_ms: u64, idle_ms: u64) -> RunContext {
        let one = NonZeroU64::new(1).expect("positive limit");
        RunContext::new(
            RunId::new(String::from(id)).expect("test run ID must be valid"),
            RunLimits::new(
                one,
                one,
                one,
                NonZeroU64::new(wall_ms).expect("positive wall limit"),
                NonZeroU64::new(idle_ms).expect("positive idle limit"),
                NonZeroU64::new(1_000).expect("positive tool limit"),
                NonZeroU64::new(64 * 1024).expect("positive output limit"),
            ),
        )
    }

    fn plan(module: &[u8]) -> PureTransformPlanV1 {
        PureTransformPlanV1::new(
            PureTransformBinding::new("workflow", "1", digest(module), module)
                .expect("test binding must be valid"),
            json!({"value": 7}),
            RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
        )
        .expect("test plan must be valid")
    }

    #[test]
    fn controller_context_mismatch_is_rejected_before_sampling_backend_and_put() {
        for (context_id, context_wall, controller_id, controller_wall) in [
            ("strict-context", 1, "loose-controller", 1_000),
            ("loose-context", 1_000, "strict-controller", 1),
        ] {
            let root = TestRoot::new();
            let manager = root.manager();
            let context = run(context_id, context_wall);
            let controller_context = run(controller_id, controller_wall);
            let mut workdir = manager
                .allocate(context.run_id())
                .expect("workdir must allocate");
            let controller = RunController::new(&controller_context);
            let mut samples = 0;
            let mut artifacts = CountingStore::new();
            reset_backend_executions();

            let result = plan(IDENTITY_WASM).execute(
                &context,
                controller,
                || {
                    samples += 1;
                    Duration::ZERO
                },
                &workdir,
                &mut artifacts,
            );

            assert!(matches!(
                result.outcome(),
                RunOutcome::Failed {
                    diagnostic: PureTransformExecutionError::ControllerRunMismatch
                }
            ));
            assert_eq!(samples, 0);
            assert_eq!(backend_executions(), 0);
            assert_eq!(artifacts.commits, 0);
            workdir.cleanup().expect("workdir must clean up");
        }
    }

    #[test]
    fn same_run_id_with_differing_complete_limits_is_rejected_before_backend() {
        // Wall-time and idle-time are independent complete-limit fields; both
        // must bind controller authority to the full semantic limits value.
        for (context_wall_ms, controller_wall_ms, context_idle_ms, controller_idle_ms) in
            [(1, 1_000, 1_000, 1_000), (1_000, 1_000, 1, 1_000)]
        {
            let root = TestRoot::new();
            let manager = root.manager();
            let context = run_with_idle("shared-run-id", context_wall_ms, context_idle_ms);
            let controller_context =
                run_with_idle("shared-run-id", controller_wall_ms, controller_idle_ms);
            let mut workdir = manager
                .allocate(context.run_id())
                .expect("workdir must allocate");
            let controller = RunController::new(&controller_context);
            let mut samples = 0;
            let mut artifacts = CountingStore::new();
            reset_backend_executions();

            let result = plan(IDENTITY_WASM).execute(
                &context,
                controller,
                || {
                    samples += 1;
                    Duration::ZERO
                },
                &workdir,
                &mut artifacts,
            );

            assert!(
                matches!(
                    result.outcome(),
                    RunOutcome::Failed {
                        diagnostic: PureTransformExecutionError::ControllerRunMismatch
                    }
                ),
                "a permissive controller must not serve a restrictive context with the same run ID"
            );
            assert_eq!(samples, 0);
            assert_eq!(backend_executions(), 0);
            assert_eq!(artifacts.commits, 0);
            workdir.cleanup().expect("workdir must clean up");
        }
    }

    #[test]
    fn workdir_mismatch_with_active_tool_retains_exact_one_shot_cleanup() {
        let root = TestRoot::new();
        let manager = root.manager();
        let context = run("workdir-mismatch-active", 1_000);
        let other_run = run("workdir-other-run", 1_000);
        let mut workdir = manager
            .allocate(other_run.run_id())
            .expect("workdir for another run must allocate");
        let mut controller = RunController::new(&context);
        controller
            .begin_tool_call(Duration::ZERO, "exact-tool", "7")
            .expect("tool call must begin");
        let mut artifacts = CountingStore::new();
        reset_backend_executions();

        let result = plan(IDENTITY_WASM).execute(
            &context,
            controller,
            || Duration::ZERO,
            &workdir,
            &mut artifacts,
        );

        let termination = match result.outcome() {
            RunOutcome::Failed {
                diagnostic:
                    PureTransformExecutionError::IdentityRejection {
                        mismatch,
                        termination,
                    },
            } => {
                assert!(matches!(
                    mismatch.as_ref(),
                    PureTransformExecutionError::WorkdirRunMismatch
                ));
                termination
            }
            other => panic!(
                "workdir mismatch with an active tool must retain its rejection and termination, got {other:?}"
            ),
        };
        assert_eq!(
            termination.cause(),
            RunTerminalCause::Failed(RunControlError::RunFinishWithActiveToolCall)
        );
        assert_eq!(termination.source_context(), &context);
        let cleanup = termination
            .cleanup()
            .expect("exactly one cleanup authority");
        assert_eq!(cleanup.exact_tool_id(), "exact-tool");
        assert_eq!(cleanup.exact_version(), "7");
        assert_eq!(backend_executions(), 0);
        assert_eq!(artifacts.commits, 0);
        workdir.cleanup().expect("workdir must clean up");
    }

    #[test]
    fn controller_mismatch_with_active_tool_retains_exact_one_shot_cleanup() {
        // Both controller-identity mismatch flavors must preserve the cleanup:
        // a different run ID, and the R3-F1 complete-limits mismatch.
        for (context_id, controller_id, context_wall_ms, controller_wall_ms) in [
            (
                "controller-mismatch-a",
                "controller-mismatch-b",
                1_000,
                1_000,
            ),
            ("limits-mismatch", "limits-mismatch", 1, 1_000),
        ] {
            let root = TestRoot::new();
            let manager = root.manager();
            let context = run(context_id, context_wall_ms);
            let controller_context = run(controller_id, controller_wall_ms);
            let mut workdir = manager
                .allocate(context.run_id())
                .expect("workdir must allocate");
            let mut controller = RunController::new(&controller_context);
            controller
                .begin_tool_call(Duration::ZERO, "exact-tool", "7")
                .expect("tool call must begin");
            let mut artifacts = CountingStore::new();
            reset_backend_executions();

            let result = plan(IDENTITY_WASM).execute(
                &context,
                controller,
                || Duration::ZERO,
                &workdir,
                &mut artifacts,
            );

            let termination = match result.outcome() {
                RunOutcome::Failed {
                    diagnostic:
                        PureTransformExecutionError::IdentityRejection {
                            mismatch,
                            termination,
                        },
                } => {
                    assert!(matches!(
                        mismatch.as_ref(),
                        PureTransformExecutionError::ControllerRunMismatch
                    ));
                    termination
                }
                other => panic!(
                    "controller mismatch with an active tool must retain its rejection and termination, got {other:?}"
                ),
            };
            assert_eq!(
                termination.cause(),
                RunTerminalCause::Failed(RunControlError::RunFinishWithActiveToolCall)
            );
            let cleanup = termination
                .cleanup()
                .expect("exactly one cleanup authority");
            assert_eq!(cleanup.exact_tool_id(), "exact-tool");
            assert_eq!(cleanup.exact_version(), "7");
            assert_eq!(
                termination.source_context(),
                &controller_context,
                "the cleanup must retain the controller's complete source authority"
            );
            assert_eq!(backend_executions(), 0);
            assert_eq!(artifacts.stages, 0);
            assert_eq!(artifacts.commits, 0);
            workdir.cleanup().expect("workdir must clean up");
        }
    }

    #[test]
    fn delayed_artifact_preparation_cannot_publish_after_wall_deadline() {
        let root = TestRoot::new();
        let manager = root.manager();
        let context = run("delayed-artifact-store", 1);
        let mut workdir = manager
            .allocate(context.run_id())
            .expect("workdir must allocate");
        let clock = AtomicU64::new(0);

        struct ClockStore<'a> {
            inner: FilesystemArtifactStore,
            clock: &'a AtomicU64,
        }

        impl ArtifactStore for ClockStore<'_> {
            fn stage(&mut self, bytes: &[u8]) -> Result<StagedArtifact, ArtifactError> {
                // Durable preparation advances the wall clock past the ceiling.
                self.clock.fetch_add(1, Ordering::Relaxed);
                self.inner.stage(bytes)
            }

            fn commit(&mut self, staged: StagedArtifact) -> Result<ArtifactId, ArtifactError> {
                self.inner.commit(staged)
            }

            fn read_page(
                &self,
                id: &ArtifactId,
                request: PageRequest,
            ) -> Result<ArtifactPage, ArtifactError> {
                self.inner.read_page(id, request)
            }

            fn set_retention(
                &mut self,
                id: &ArtifactId,
                policy: RetentionPolicy,
            ) -> Result<(), ArtifactError> {
                self.inner.set_retention(id, policy)
            }

            fn retention(&self, id: &ArtifactId) -> Result<RetentionPolicy, ArtifactError> {
                self.inner.retention(id)
            }
        }

        let store_root = root.0.join("artifacts");
        let mut artifacts = ClockStore {
            inner: FilesystemArtifactStore::new(
                &store_root,
                NonZeroU64::new(64 * 1024).expect("positive content limit"),
                NonZeroU64::new(64 * 1024).expect("positive page limit"),
            ),
            clock: &clock,
        };
        reset_backend_executions();

        let result = plan(IDENTITY_WASM).execute(
            &context,
            RunController::new(&context),
            || Duration::from_millis(clock.load(Ordering::Relaxed)),
            &workdir,
            &mut artifacts,
        );

        assert!(
            matches!(
                result.outcome(),
                RunOutcome::TimedOut {
                    timeout: RunTimeoutKind::WallTime,
                    ..
                }
            ),
            "artifact preparation that crosses the wall deadline must not complete"
        );
        assert_eq!(backend_executions(), 1);
        assert_eq!(
            fs::read_dir(&store_root)
                .expect("store root must be readable")
                .count(),
            0,
            "no artifact may become visible after the wall deadline"
        );
        workdir.cleanup().expect("workdir must clean up");
    }

    #[test]
    fn active_tool_is_rejected_before_backend_with_exact_one_shot_cleanup() {
        let root = TestRoot::new();
        let manager = root.manager();
        let context = run("active-tool", 1_000);
        let mut workdir = manager
            .allocate(context.run_id())
            .expect("workdir must allocate");
        let mut controller = RunController::new(&context);
        controller
            .begin_tool_call(Duration::ZERO, "exact-tool", "7")
            .expect("tool call must begin");
        let mut artifacts = CountingStore::new();
        reset_backend_executions();

        let result = plan(IDENTITY_WASM).execute(
            &context,
            controller,
            || Duration::ZERO,
            &workdir,
            &mut artifacts,
        );

        let termination = match result.outcome() {
            RunOutcome::Failed {
                diagnostic: PureTransformExecutionError::ControllerTermination(termination),
            } => termination,
            other => panic!("active tool must return its termination, got {other:?}"),
        };
        assert_eq!(
            termination.cause(),
            RunTerminalCause::Failed(RunControlError::RunFinishWithActiveToolCall)
        );
        let cleanup = termination.cleanup().expect("cleanup must be recoverable");
        assert_eq!(cleanup.exact_tool_id(), "exact-tool");
        assert_eq!(cleanup.exact_version(), "7");
        assert_eq!(backend_executions(), 0);
        assert_eq!(artifacts.commits, 0);
        workdir.cleanup().expect("workdir must clean up");
    }

    #[test]
    fn render_never_enters_backend_for_valid_or_invalid_module() {
        for module in [IDENTITY_WASM, b"digest-valid but invalid wasm".as_slice()] {
            reset_backend_executions();
            assert!(plan(module).render().contains("execution=not_started"));
            assert_eq!(backend_executions(), 0);
        }
    }

    #[test]
    fn controller_pre_gates_skip_backend_while_post_timeout_records_one_call() {
        let root = TestRoot::new();
        let manager = root.manager();
        let transform = plan(IDENTITY_WASM);
        let mut artifacts = CountingStore::new();

        let cancelled_run = run("cancelled", 1_000);
        let mut cancelled_workdir = manager
            .allocate(cancelled_run.run_id())
            .expect("workdir must allocate");
        let mut cancelled = RunController::new(&cancelled_run);
        let _ = cancelled.request_cancel(Duration::ZERO);
        reset_backend_executions();
        let cancelled_result = transform.execute(
            &cancelled_run,
            cancelled,
            || Duration::ZERO,
            &cancelled_workdir,
            &mut artifacts,
        );
        assert!(matches!(
            cancelled_result.outcome(),
            RunOutcome::Cancelled { .. }
        ));
        assert_eq!(backend_executions(), 0);
        assert_eq!(artifacts.commits, 0);

        let timed_out_run = run("pre-timeout", 1);
        let mut timed_out_workdir = manager
            .allocate(timed_out_run.run_id())
            .expect("workdir must allocate");
        let timed_out = RunController::new(&timed_out_run);
        reset_backend_executions();
        let timed_out_result = transform.execute(
            &timed_out_run,
            timed_out,
            || Duration::from_millis(1),
            &timed_out_workdir,
            &mut artifacts,
        );
        assert!(matches!(
            timed_out_result.outcome(),
            RunOutcome::TimedOut {
                timeout: RunTimeoutKind::WallTime,
                ..
            }
        ));
        assert_eq!(backend_executions(), 0);
        assert_eq!(artifacts.commits, 0);

        let post_run = run("post-timeout", 1);
        let mut post_workdir = manager
            .allocate(post_run.run_id())
            .expect("workdir must allocate");
        let post = RunController::new(&post_run);
        let mut elapsed = [Duration::ZERO, Duration::from_millis(1)].into_iter();
        reset_backend_executions();
        let post_result = transform.execute(
            &post_run,
            post,
            || elapsed.next().expect("two controller samples are expected"),
            &post_workdir,
            &mut artifacts,
        );
        assert!(matches!(
            post_result.outcome(),
            RunOutcome::TimedOut {
                timeout: RunTimeoutKind::WallTime,
                ..
            }
        ));
        assert_eq!(backend_executions(), 1);
        assert_eq!(artifacts.commits, 0);

        cancelled_workdir.cleanup().expect("workdir must clean up");
        timed_out_workdir.cleanup().expect("workdir must clean up");
        post_workdir.cleanup().expect("workdir must clean up");
    }

    #[test]
    fn cancelled_controller_mismatch_preserves_latched_cause_not_mismatch() {
        // CA-4: a controller that already terminalized must surface its latched
        // terminal cause on a later identity rejection, never a bare mismatch.
        let root = TestRoot::new();
        let manager = root.manager();
        let owner = run("cancelled-owner-a", 1_000);
        let requested = run("requested-b", 1_000);
        let mut workdir = manager
            .allocate(requested.run_id())
            .expect("workdir must allocate");
        let mut controller = RunController::new(&owner);
        controller
            .begin_tool_call(Duration::ZERO, "exact-tool", "7")
            .expect("tool call must begin");
        let first = controller.request_cancel(Duration::ZERO);
        assert!(
            first.cleanup().is_some(),
            "the first terminal delivery must own the active-tool cleanup"
        );
        let mut artifacts = CountingStore::new();
        reset_backend_executions();

        let result = plan(IDENTITY_WASM).execute(
            &requested,
            controller,
            || Duration::ZERO,
            &workdir,
            &mut artifacts,
        );

        assert_eq!(
            result.status(),
            RunStatus::Cancelled,
            "an identity rejection must retain the controller's latched terminal cause"
        );
        match result.outcome() {
            RunOutcome::Cancelled {
                diagnostic:
                    PureTransformExecutionError::IdentityRejection {
                        mismatch,
                        termination,
                    },
            } => {
                assert!(matches!(
                    mismatch.as_ref(),
                    PureTransformExecutionError::ControllerRunMismatch
                ));
                assert_eq!(termination.cause(), RunTerminalCause::Cancelled);
                assert_eq!(termination.source_context(), &owner);
                assert!(termination.cleanup().is_none());
            }
            other => panic!("latched cause must retain its identity rejection, got {other:?}"),
        }
        assert_eq!(backend_executions(), 0);
        assert_eq!(artifacts.stages, 0);
        assert_eq!(artifacts.commits, 0);
        workdir.cleanup().expect("workdir must clean up");
    }

    #[test]
    fn both_mismatches_with_active_tool_preserve_mismatch_and_cleanup() {
        // CA-3: workdir C + context B + active-tool controller A; the rejection
        // must preserve the typed mismatch AND the termination, never present a
        // bare termination that hides which identity mismatched.
        let root = TestRoot::new();
        let manager = root.manager();
        let requested = run("requested-b", 1_000);
        let third = run("workdir-c", 1_000);
        let owner = run("controller-a", 1_000);
        let mut workdir = manager
            .allocate(third.run_id())
            .expect("workdir must allocate");
        let mut controller = RunController::new(&owner);
        controller
            .begin_tool_call(Duration::ZERO, "exact-tool", "7")
            .expect("tool call must begin");
        let mut artifacts = CountingStore::new();
        reset_backend_executions();

        let result = plan(IDENTITY_WASM).execute(
            &requested,
            controller,
            || Duration::ZERO,
            &workdir,
            &mut artifacts,
        );

        match result.outcome() {
            RunOutcome::Failed {
                diagnostic:
                    PureTransformExecutionError::IdentityRejection {
                        mismatch,
                        termination,
                    },
            } => {
                assert!(matches!(
                    mismatch.as_ref(),
                    PureTransformExecutionError::WorkdirRunMismatch
                ));
                assert_eq!(termination.source_context(), &owner);
                assert!(termination.cleanup().is_some());
            }
            other => {
                panic!("both mismatches must retain typed rejection and termination, got {other:?}")
            }
        }
        assert_eq!(result.run_id(), requested.run_id());
        assert_eq!(backend_executions(), 0);
        assert_eq!(artifacts.stages, 0);
        assert_eq!(artifacts.commits, 0);
        workdir.cleanup().expect("workdir must clean up");
    }

    #[test]
    fn tool_deadline_with_active_tool_yields_timed_out_with_exact_one_shot_cleanup() {
        // CA-5 pin: the post-identity preflight tool-deadline row must keep the
        // matched context's label, exactly one cleanup, and zero backend work.
        let root = TestRoot::new();
        let manager = root.manager();
        let one = NonZeroU64::new(1).expect("positive limit");
        let context = RunContext::new(
            RunId::new(String::from("tool-deadline-pin")).expect("run ID must be valid"),
            RunLimits::new(
                one,
                one,
                one,
                NonZeroU64::new(100_000).expect("positive wall limit"),
                NonZeroU64::new(100_000).expect("positive idle limit"),
                NonZeroU64::new(100).expect("positive tool limit"),
                NonZeroU64::new(64 * 1024).expect("positive output limit"),
            ),
        );
        let mut workdir = manager
            .allocate(context.run_id())
            .expect("workdir must allocate");
        let mut controller = RunController::new(&context);
        controller
            .begin_tool_call(Duration::ZERO, "exact-tool", "7")
            .expect("tool call must begin");
        let mut artifacts = CountingStore::new();
        reset_backend_executions();

        let result = plan(IDENTITY_WASM).execute(
            &context,
            controller,
            || Duration::from_millis(101),
            &workdir,
            &mut artifacts,
        );

        let termination = match result.outcome() {
            RunOutcome::TimedOut {
                timeout: RunTimeoutKind::ToolTime,
                diagnostic: PureTransformExecutionError::ControllerTermination(termination),
            } => termination,
            other => panic!("tool deadline must time out with its termination, got {other:?}"),
        };
        assert_eq!(
            termination.cause(),
            RunTerminalCause::TimedOut(RunTimeoutKind::ToolTime)
        );
        let cleanup = termination
            .cleanup()
            .expect("exactly one cleanup authority");
        assert_eq!(cleanup.exact_tool_id(), "exact-tool");
        assert_eq!(cleanup.exact_version(), "7");
        assert_eq!(backend_executions(), 0);
        assert_eq!(artifacts.stages, 0);
        assert_eq!(artifacts.commits, 0);
        workdir.cleanup().expect("workdir must clean up");
    }
}
