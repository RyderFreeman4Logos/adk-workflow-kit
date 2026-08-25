//! Cooperative run enforcement, terminal contracts, and sandbox preflight.

mod approval;
mod artifact;
mod bubblewrap;
mod controller;
mod execution;
mod hot_reload;
mod observability;
mod policy;
mod production_profile;
mod pure_transform;
mod session;
mod tool;
mod workdir;

pub use approval::{
    evaluate_approval, ApprovalDecision, ApprovalGranted, ApprovalTerminal, ApprovalTerminalKind,
};
pub use artifact::{
    ArtifactError, ArtifactErrorKind, ArtifactId, ArtifactPage, ArtifactStore,
    FilesystemArtifactStore, InMemoryArtifactStore, PageRequest, RetentionPolicy, StagedArtifact,
};
pub use bubblewrap::{
    BubblewrapError, BubblewrapReceipt, BubblewrapRequest, BubblewrapRequestError,
    BubblewrapRequestErrorKind, LinuxBubblewrapBackend,
};
pub use controller::{
    RunControlError, RunController, RunTerminalCause, RunTermination, ToolCallCleanup,
};
pub use execution::{
    PureTransformBinding, PureTransformExecutionError, PureTransformPlanError, PureTransformPlanV1,
    PURE_TRANSFORM_BINDING_ID, PURE_TRANSFORM_BINDING_VERSION, PURE_TRANSFORM_PLAN_VERSION_V1,
};
pub use hot_reload::{DevelopmentHotReload, HotReloadError, HotReloadErrorKind};
pub use observability::{
    CallLedgerRecord, EventCounts, ObservabilityError, OtelMapping, RedactedEvent,
    SensitiveSnapshot, SensitiveSnapshotKind, REDACTION_MARKER,
};
pub use policy::{
    evaluate_context_policy, Classification, ContextPolicyDenied, ContextPolicyDeniedKind,
    EffectivePolicy, InvalidNetworkDestination, InvalidPolicyToken, NetworkDestination,
    NetworkProfile, PolicyLayer, PolicySubject, RoleToken, TenantId,
};
pub use production_profile::{
    ProductionProfile, ProductionProfileBinding, ProductionProfileError,
    ProductionProfileErrorKind, ProductionProfileRegistry,
};
pub use pure_transform::{
    PureTransformBackend, PureTransformError, PureTransformRequest, PureTransformRequestError,
};
pub use session::{
    RunSessionIds, SessionId, SessionIdentityError, SessionIdentityErrorKind, SessionRole,
};
pub use tool::{
    decode_structured_tool_output, StructuredOutputError, ToolEnvelope, ToolFailure, ToolFlags,
    ToolProvenance, ToolRegistration, ToolRegistrationError,
};
pub use workdir::{
    CleanupOutcome, Materialization, RunWorkdir, WorkdirError, WorkdirErrorKind, WorkdirId,
    WorkdirManager,
};

use std::{collections::HashSet, fmt, num::NonZeroU64};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// An opaque caller-supplied run identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RunId(String);

impl RunId {
    /// Creates a run identifier from a non-empty owned string.
    pub fn new(value: String) -> Result<Self, InvalidRunId> {
        if value.is_empty() {
            Err(InvalidRunId)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the identifier exactly as supplied by the caller.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RunId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// The error returned for an empty run identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRunId;

impl fmt::Display for InvalidRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("run ID must not be empty")
    }
}

impl std::error::Error for InvalidRunId {}

/// Required positive ceilings for one run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    max_model_turns: NonZeroU64,
    max_tool_calls: NonZeroU64,
    max_calls_per_tool: NonZeroU64,
    max_wall_time_ms: NonZeroU64,
    max_idle_time_ms: NonZeroU64,
    max_tool_time_ms: NonZeroU64,
    max_tool_output_bytes: NonZeroU64,
}

impl RunLimits {
    /// Creates required positive run ceilings.
    pub fn new(
        max_model_turns: NonZeroU64,
        max_tool_calls: NonZeroU64,
        max_calls_per_tool: NonZeroU64,
        max_wall_time_ms: NonZeroU64,
        max_idle_time_ms: NonZeroU64,
        max_tool_time_ms: NonZeroU64,
        max_tool_output_bytes: NonZeroU64,
    ) -> Self {
        Self {
            max_model_turns,
            max_tool_calls,
            max_calls_per_tool,
            max_wall_time_ms,
            max_idle_time_ms,
            max_tool_time_ms,
            max_tool_output_bytes,
        }
    }

    /// Returns the inclusive model-turn ceiling.
    pub fn max_model_turns(&self) -> NonZeroU64 {
        self.max_model_turns
    }

    /// Returns the inclusive total tool-call ceiling.
    pub fn max_tool_calls(&self) -> NonZeroU64 {
        self.max_tool_calls
    }

    /// Returns the inclusive per-tool call ceiling.
    pub fn max_calls_per_tool(&self) -> NonZeroU64 {
        self.max_calls_per_tool
    }

    /// Returns the wall-time ceiling in milliseconds.
    pub fn max_wall_time_ms(&self) -> NonZeroU64 {
        self.max_wall_time_ms
    }

    /// Returns the idle-time ceiling in milliseconds.
    pub fn max_idle_time_ms(&self) -> NonZeroU64 {
        self.max_idle_time_ms
    }

    /// Returns the per-tool time ceiling in milliseconds.
    pub fn max_tool_time_ms(&self) -> NonZeroU64 {
        self.max_tool_time_ms
    }

    /// Returns the cumulative tool-output ceiling in bytes.
    pub fn max_tool_output_bytes(&self) -> NonZeroU64 {
        self.max_tool_output_bytes
    }
}

/// Immutable identity and limits for one run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunContext {
    run_id: RunId,
    limits: RunLimits,
}

impl RunContext {
    /// Creates a run context from its owned identity and limits.
    pub fn new(run_id: RunId, limits: RunLimits) -> Self {
        Self { run_id, limits }
    }

    /// Returns the run identifier.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Returns the run limits.
    pub fn limits(&self) -> &RunLimits {
        &self.limits
    }
}

/// A terminal run classifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// The run produced its completed output.
    Completed,
    /// The run explicitly abstained.
    Abstained,
    /// The run ended without completing its requested work.
    Incomplete,
    /// The run failed.
    Failed,
    /// The run was cancelled.
    Cancelled,
    /// The run exceeded a time ceiling.
    TimedOut,
    /// The run exceeded a count or byte ceiling.
    LimitExceeded,
    /// Policy denied the run.
    PolicyDenied,
}

/// The time ceiling exceeded by a timed-out run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTimeoutKind {
    /// The run exceeded its wall-time ceiling.
    WallTime,
    /// The run exceeded its idle-time ceiling.
    IdleTime,
    /// A tool call exceeded its time ceiling.
    ToolTime,
}

/// The non-time ceiling exceeded by a run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunLimitKind {
    /// The run exceeded its model-turn ceiling.
    ModelTurns,
    /// The run exceeded its total tool-call ceiling.
    TotalToolCalls,
    /// A tool exceeded its per-tool call ceiling.
    ToolCallsPerTool,
    /// The run exceeded its cumulative tool-output byte ceiling.
    ToolOutputBytes,
}

/// A typed terminal run outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunOutcome<T, D> {
    /// The run completed with typed output.
    Completed { output: T },
    /// The run abstained with a typed diagnostic.
    Abstained { diagnostic: D },
    /// The run ended incomplete with a typed diagnostic.
    Incomplete { diagnostic: D },
    /// The run failed with a typed diagnostic.
    Failed { diagnostic: D },
    /// The run was cancelled with a typed diagnostic.
    Cancelled { diagnostic: D },
    /// The run exceeded a time ceiling.
    TimedOut {
        /// The exceeded time ceiling.
        timeout: RunTimeoutKind,
        /// The terminal diagnostic.
        diagnostic: D,
    },
    /// The run exceeded a count or byte ceiling.
    LimitExceeded {
        /// The exceeded non-time ceiling.
        limit: RunLimitKind,
        /// The terminal diagnostic.
        diagnostic: D,
    },
    /// Policy denied the run with a typed diagnostic.
    PolicyDenied { diagnostic: D },
}

impl<T, D> RunOutcome<T, D> {
    /// Returns the terminal classifier derived from this outcome.
    pub fn status(&self) -> RunStatus {
        match self {
            Self::Completed { .. } => RunStatus::Completed,
            Self::Abstained { .. } => RunStatus::Abstained,
            Self::Incomplete { .. } => RunStatus::Incomplete,
            Self::Failed { .. } => RunStatus::Failed,
            Self::Cancelled { .. } => RunStatus::Cancelled,
            Self::TimedOut { .. } => RunStatus::TimedOut,
            Self::LimitExceeded { .. } => RunStatus::LimitExceeded,
            Self::PolicyDenied { .. } => RunStatus::PolicyDenied,
        }
    }
}

/// An immutable typed terminal result for one run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunResult<T, D> {
    run_id: RunId,
    outcome: RunOutcome<T, D>,
}

impl<T, D> RunResult<T, D> {
    /// Creates a terminal result from its owned identity and outcome.
    pub fn new(run_id: RunId, outcome: RunOutcome<T, D>) -> Self {
        Self { run_id, outcome }
    }

    /// Returns the run identifier.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Returns the typed terminal outcome.
    pub fn outcome(&self) -> &RunOutcome<T, D> {
        &self.outcome
    }

    /// Returns the terminal classifier derived from the outcome.
    pub fn status(&self) -> RunStatus {
        self.outcome.status()
    }
}

/// A sandbox capability class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxCapability {
    /// Read access to declared filesystem resources.
    FilesystemRead,
    /// Write access to declared filesystem resources.
    FilesystemWrite,
    /// Network access.
    Network,
    /// Child process spawning.
    ProcessSpawn,
    /// A maximum process count.
    MaximumPids,
    /// A CPU time limit.
    CpuTime,
    /// A wall-clock time limit.
    WallTime,
    /// An idle time limit.
    IdleTime,
    /// A memory limit.
    Memory,
    /// An output byte limit.
    OutputBytes,
    /// An open file limit.
    OpenFiles,
    /// Access to declared environment variables.
    EnvironmentVariables,
    /// Enforcement of a syscall profile.
    SyscallProfile,
    /// Enforcement of a user and group identity.
    UserGroupIdentity,
    /// Access to declared devices.
    DeviceAccess,
}

impl SandboxCapability {
    /// Returns the stable diagnostic name of this capability class.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemWrite => "filesystem.write",
            Self::Network => "network",
            Self::ProcessSpawn => "process.spawn",
            Self::MaximumPids => "limit.pids",
            Self::CpuTime => "limit.cpu_time",
            Self::WallTime => "limit.wall_time",
            Self::IdleTime => "limit.idle_time",
            Self::Memory => "limit.memory",
            Self::OutputBytes => "limit.output_bytes",
            Self::OpenFiles => "limit.open_files",
            Self::EnvironmentVariables => "environment.variables",
            Self::SyscallProfile => "syscall.profile",
            Self::UserGroupIdentity => "identity.user_group",
            Self::DeviceAccess => "device.access",
        }
    }
}

/// Capability classes required by a workflow.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedCapabilities {
    capabilities: HashSet<SandboxCapability>,
    network_destination: Option<NetworkDestination>,
}

impl fmt::Debug for RequestedCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestedCapabilities")
            .field("capabilities", &self.capabilities)
            .field(
                "network_destination",
                &self.network_destination.as_ref().map(|_| "exact"),
            )
            .finish()
    }
}

impl RequestedCapabilities {
    /// Collects and deduplicates required capability classes.
    pub fn new(capabilities: impl IntoIterator<Item = SandboxCapability>) -> Self {
        Self {
            capabilities: capabilities.into_iter().collect(),
            network_destination: None,
        }
    }

    /// Attaches an exact destination to a network request.
    pub fn with_network_destination(mut self, destination: NetworkDestination) -> Self {
        self.network_destination = Some(destination);
        self
    }

    /// Returns whether the request requires the supplied capability class.
    pub fn contains(&self, capability: SandboxCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Returns the requested exact network destination, if any.
    pub fn network_destination(&self) -> Option<&NetworkDestination> {
        self.network_destination.as_ref()
    }
}

/// Capability classes allowed by one anonymous policy layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PolicyCapabilities(HashSet<SandboxCapability>);

impl PolicyCapabilities {
    /// Collects and deduplicates capability classes allowed by this layer.
    pub fn new(capabilities: impl IntoIterator<Item = SandboxCapability>) -> Self {
        Self(capabilities.into_iter().collect())
    }
}

/// Capability classes authorized by every policy layer for one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveCapabilities(Vec<SandboxCapability>);

impl EffectiveCapabilities {
    /// Returns authorized capability classes in stable diagnostic-name order.
    pub fn capabilities(&self) -> &[SandboxCapability] {
        &self.0
    }
}

/// Requested capability classes that policy layers do not authorize.
#[derive(Debug)]
pub struct CapabilityPolicyDenied {
    missing: Vec<SandboxCapability>,
}

impl CapabilityPolicyDenied {
    /// Returns missing capability classes in stable diagnostic-name order.
    pub fn missing(&self) -> &[SandboxCapability] {
        &self.missing
    }
}

impl fmt::Display for CapabilityPolicyDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("capability policy denied")?;
        for capability in &self.missing {
            formatter.write_str(": ")?;
            formatter.write_str(capability.as_str())?;
        }
        Ok(())
    }
}

impl std::error::Error for CapabilityPolicyDenied {}

/// Authorizes a complete request only when every policy layer allows it.
pub fn intersect_policy_capabilities(
    requested: &RequestedCapabilities,
    policy_layers: &[PolicyCapabilities],
) -> Result<EffectiveCapabilities, CapabilityPolicyDenied> {
    let mut allowed = HashSet::new();
    if let Some((first_layer, remaining_layers)) = policy_layers.split_first() {
        allowed.clone_from(&first_layer.0);
        for layer in remaining_layers {
            allowed.retain(|capability| layer.0.contains(capability));
        }
    }

    let mut missing = requested
        .capabilities
        .difference(&allowed)
        .copied()
        .collect::<Vec<_>>();
    missing.sort_unstable_by_key(SandboxCapability::as_str);

    if requested.capabilities.is_empty() || !missing.is_empty() {
        return Err(CapabilityPolicyDenied { missing });
    }

    let mut effective = requested.capabilities.iter().copied().collect::<Vec<_>>();
    effective.sort_unstable_by_key(SandboxCapability::as_str);
    Ok(EffectiveCapabilities(effective))
}

/// Capability classes a backend can enforce.
pub struct BackendCapabilities(HashSet<SandboxCapability>);

impl BackendCapabilities {
    /// Collects and deduplicates enforceable capability classes.
    pub fn new(capabilities: impl IntoIterator<Item = SandboxCapability>) -> Self {
        Self(capabilities.into_iter().collect())
    }
}

/// Required sandbox capability classes that a backend cannot enforce.
#[derive(Debug)]
pub struct UnsatisfiedCapabilities {
    missing: Vec<SandboxCapability>,
}

impl UnsatisfiedCapabilities {
    /// Returns every missing capability in stable diagnostic-name order.
    pub fn missing(&self) -> &[SandboxCapability] {
        &self.missing
    }
}

impl fmt::Display for UnsatisfiedCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unsatisfied sandbox capabilities: ")?;
        for (index, capability) in self.missing.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }
            formatter.write_str(capability.as_str())?;
        }
        Ok(())
    }
}

impl std::error::Error for UnsatisfiedCapabilities {}

/// Verifies that the backend can enforce every requested capability class.
pub fn verify_sandbox_capabilities(
    requested: &RequestedCapabilities,
    backend: &BackendCapabilities,
) -> Result<(), UnsatisfiedCapabilities> {
    let mut missing = requested
        .capabilities
        .difference(&backend.0)
        .copied()
        .collect::<Vec<_>>();
    missing.sort_unstable_by_key(SandboxCapability::as_str);

    if missing.is_empty() {
        Ok(())
    } else {
        Err(UnsatisfiedCapabilities { missing })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(value: &str) -> TenantId {
        TenantId::new(value).unwrap()
    }

    fn role(value: &str) -> RoleToken {
        RoleToken::new(value).unwrap()
    }

    #[test]
    fn network_destination_debug_redacts_host_and_port_direct_and_nested() {
        let destination = NetworkDestination::new("SENTINEL_HOST", 4242).unwrap();
        let direct = format!("{destination:?}");
        let requested = RequestedCapabilities::new([SandboxCapability::Network])
            .with_network_destination(destination);
        let nested = format!("{requested:?}");

        assert!(direct.contains("NetworkDestination"));
        assert!(nested.contains("RequestedCapabilities"));
        assert!(!direct.contains("SENTINEL_HOST"));
        assert!(!direct.contains("4242"));
        assert!(!nested.contains("SENTINEL_HOST"));
        assert!(!nested.contains("4242"));
    }

    #[test]
    fn network_profile_is_required_for_network_capability() {
        let subject = PolicySubject::new("tenant", "role", Classification::Public).unwrap();
        let layer = PolicyLayer::new(
            [tenant("tenant")],
            [role("role")],
            Classification::Restricted,
            NetworkProfile::None,
            [],
            PolicyCapabilities::new([SandboxCapability::Network]),
        );
        let requested = RequestedCapabilities::new([SandboxCapability::Network]);

        let denial = evaluate_context_policy(&subject, &requested, &[layer]).unwrap_err();

        assert_eq!(
            denial.kind(),
            ContextPolicyDeniedKind::NetworkProfileRequired
        );
    }

    #[test]
    fn cross_tenant_access_is_denied_without_echo() {
        let subject =
            PolicySubject::new("SECRET_TENANT", "SECRET_ROLE", Classification::Public).unwrap();
        let layer = PolicyLayer::new(
            [tenant("other-tenant")],
            [role("SECRET_ROLE")],
            Classification::Restricted,
            NetworkProfile::LoopbackOnly,
            [],
            PolicyCapabilities::new([SandboxCapability::FilesystemRead]),
        );
        let requested = RequestedCapabilities::new([SandboxCapability::FilesystemRead]);

        let denial = evaluate_context_policy(&subject, &requested, &[layer]).unwrap_err();
        let display = denial.to_string();
        let debug = format!("{denial:?}");

        assert_eq!(denial.kind(), ContextPolicyDeniedKind::TenantMismatch);
        assert!(!display.contains("SECRET_TENANT"));
        assert!(!display.contains("SECRET_ROLE"));
        assert!(!debug.contains("SECRET_TENANT"));
        assert!(!debug.contains("SECRET_ROLE"));
    }

    #[test]
    fn classification_cannot_downgrade_without_validator() {
        let subject = PolicySubject::new("tenant", "role", Classification::Confidential).unwrap();
        let layer = PolicyLayer::new(
            [tenant("tenant")],
            [role("role")],
            Classification::Public,
            NetworkProfile::LoopbackOnly,
            [],
            PolicyCapabilities::new([SandboxCapability::FilesystemRead]),
        );
        let requested = RequestedCapabilities::new([SandboxCapability::FilesystemRead]);

        let denial = evaluate_context_policy(&subject, &requested, &[layer]).unwrap_err();

        assert_eq!(denial.kind(), ContextPolicyDeniedKind::ClassificationDenied);
    }

    #[test]
    fn unknown_policy_fields_fail_closed() {
        let decoded = serde_json::from_str::<PolicyLayer>(
            r#"{
                "allowed_tenants": ["tenant"],
                "allowed_roles": ["role"],
                "max_classification": "restricted",
                "network_profile": "none",
                "brokered_destinations": [],
                "capabilities": ["filesystem_read"],
                "unexpected": "SECRET"
            }"#,
        );

        assert!(decoded.is_err());
    }

    #[test]
    fn denial_redacts_secret_and_payload_markers() {
        let subject =
            PolicySubject::new("TENANT_SECRET", "ROLE_SECRET", Classification::Public).unwrap();
        let layer = PolicyLayer::new(
            [tenant("other-tenant")],
            [role("ROLE_SECRET")],
            Classification::Restricted,
            NetworkProfile::LoopbackOnly,
            [],
            PolicyCapabilities::new([SandboxCapability::FilesystemRead]),
        );
        let requested = RequestedCapabilities::new([SandboxCapability::FilesystemRead]);
        let denial = evaluate_context_policy(&subject, &requested, &[layer]).unwrap_err();
        let rendered = format!("{} {:?}", denial, denial);

        assert_eq!(denial.kind(), ContextPolicyDeniedKind::TenantMismatch);
        assert!(!rendered.contains("SECRET"));
        assert!(!rendered.contains("TENANT_SECRET"));
        assert!(!rendered.contains("{\"payload\":\"secret\"}"));
    }

    fn assert_invalid_network_destination_decode(
        payload: serde_json::Value,
        forbidden_markers: &[&str],
    ) {
        let direct_error =
            serde_json::from_value::<NetworkDestination>(payload.clone()).unwrap_err();
        let direct_rendered = format!("{direct_error} {direct_error:?}");
        for marker in forbidden_markers {
            assert!(!direct_rendered.contains(marker));
        }

        let nested_payload = serde_json::json!({
            "allowed_tenants": ["tenant"],
            "allowed_roles": ["role"],
            "max_classification": "restricted",
            "network_profile": "brokered_allowlist",
            "brokered_destinations": [payload],
            "capabilities": ["network"]
        });
        let nested_error = serde_json::from_value::<PolicyLayer>(nested_payload).unwrap_err();
        let nested_rendered = format!("{nested_error} {nested_error:?}");
        for marker in forbidden_markers {
            assert!(!nested_rendered.contains(marker));
        }
    }

    #[test]
    fn deserialized_network_destination_rejects_empty_host_direct_and_nested() {
        assert_invalid_network_destination_decode(
            serde_json::json!({"host": "", "port": 443}),
            &["\"host\":\"\""],
        );
    }

    #[test]
    fn deserialized_network_destination_rejects_wildcard_host_direct_and_nested() {
        assert_invalid_network_destination_decode(
            serde_json::json!({"host": "SECRET_*_HOST", "port": 443}),
            &["SECRET_*_HOST"],
        );
    }

    #[test]
    fn deserialized_network_destination_rejects_zero_port_direct_and_nested() {
        assert_invalid_network_destination_decode(
            serde_json::json!({"host": "SECRET_ZERO_HOST", "port": 0}),
            &["SECRET_ZERO_HOST"],
        );
    }

    #[test]
    fn brokered_destination_outside_allowlist_is_denied() {
        let subject = PolicySubject::new("tenant", "role", Classification::Public).unwrap();
        let allowed = NetworkDestination::new("allowed.example", 443).unwrap();
        let outside = NetworkDestination::new("outside.example", 443).unwrap();
        let layer = PolicyLayer::new(
            [tenant("tenant")],
            [role("role")],
            Classification::Restricted,
            NetworkProfile::BrokeredAllowlist,
            [allowed],
            PolicyCapabilities::new([SandboxCapability::Network]),
        );
        let requested = RequestedCapabilities::new([SandboxCapability::Network])
            .with_network_destination(outside);

        let denial = evaluate_context_policy(&subject, &requested, &[layer]).unwrap_err();

        assert_eq!(denial.kind(), ContextPolicyDeniedKind::DestinationDenied);
    }

    #[test]
    fn full_network_is_never_inferred() {
        let subject = PolicySubject::new("tenant", "role", Classification::Public).unwrap();
        let allowed = NetworkDestination::new("allowed.example", 443).unwrap();
        let capabilities = PolicyCapabilities::new([SandboxCapability::Network]);
        let full_layer = PolicyLayer::new(
            [tenant("tenant")],
            [role("role")],
            Classification::Restricted,
            NetworkProfile::Full,
            [],
            capabilities.clone(),
        );
        let brokered_layer = PolicyLayer::new(
            [tenant("tenant")],
            [role("role")],
            Classification::Restricted,
            NetworkProfile::BrokeredAllowlist,
            [allowed.clone()],
            capabilities,
        );
        let requested = RequestedCapabilities::new([SandboxCapability::Network])
            .with_network_destination(allowed);

        let effective =
            evaluate_context_policy(&subject, &requested, &[full_layer, brokered_layer]).unwrap();

        assert_eq!(
            effective.network_profile(),
            NetworkProfile::BrokeredAllowlist
        );
        assert_ne!(effective.network_profile(), NetworkProfile::Full);
    }

    #[test]
    fn incompatible_network_profiles_fail_closed() {
        let subject = PolicySubject::new("tenant", "role", Classification::Public).unwrap();
        let destination = NetworkDestination::new("broker.example", 443).unwrap();
        let capabilities = PolicyCapabilities::new([SandboxCapability::Network]);
        let loopback_layer = PolicyLayer::new(
            [tenant("tenant")],
            [role("role")],
            Classification::Restricted,
            NetworkProfile::LoopbackOnly,
            [],
            capabilities.clone(),
        );
        let brokered_layer = PolicyLayer::new(
            [tenant("tenant")],
            [role("role")],
            Classification::Restricted,
            NetworkProfile::BrokeredAllowlist,
            [destination.clone()],
            capabilities,
        );
        let requested = RequestedCapabilities::new([SandboxCapability::Network])
            .with_network_destination(destination);

        let denial =
            evaluate_context_policy(&subject, &requested, &[loopback_layer, brokered_layer])
                .unwrap_err();

        assert_eq!(
            denial.kind(),
            ContextPolicyDeniedKind::NetworkProfileRequired
        );
    }
}
