use std::{collections::HashSet, fmt};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use workflow_runtime::{RunStatus, SandboxCapability};

/// A validated offline replay document that cannot dispatch work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBundle {
    trace: StructuralTrace,
}

impl ReplayBundle {
    /// The only replay document schema supported by this release.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum accepted JSON document size.
    pub const MAX_BUNDLE_BYTES: usize = 1_048_576;
    /// Maximum byte size of opaque workflow lock TOML.
    pub const MAX_WORKFLOW_LOCK_BYTES: usize = 65_536;
    /// Maximum number of recorded events.
    pub const MAX_EVENTS: usize = 4_096;
    /// Maximum combined fixture and artifact count.
    pub const MAX_PAYLOAD_ENTRIES: usize = 1_024;
    /// Maximum byte size of one inline fixture or artifact.
    pub const MAX_INLINE_PAYLOAD_BYTES: usize = 65_536;
    /// Maximum combined byte size of inline fixtures and artifacts.
    pub const MAX_TOTAL_INLINE_PAYLOAD_BYTES: usize = 524_288;
    /// Maximum byte size of an identifier or digest string.
    pub const MAX_IDENTIFIER_BYTES: usize = 256;

    /// Parses and fully validates a strict replay document before it is replayed.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ReplayError> {
        if bytes.len() > Self::MAX_BUNDLE_BYTES {
            return Err(ReplayError::new(ReplayErrorKind::BundleTooLarge));
        }

        let wire: WireBundle = serde_json::from_slice(bytes)
            .map_err(|_| ReplayError::new(ReplayErrorKind::InvalidDocument))?;
        if wire.schema_version != Self::SCHEMA_VERSION {
            return Err(ReplayError::new(ReplayErrorKind::UnsupportedSchemaVersion));
        }

        validate_required(&wire)?;
        validate_limits(&wire)?;
        let (fixture_digests, artifact_ids) = validate_payloads(&wire)?;
        validate_references(&wire.events, &fixture_digests, &artifact_ids)?;

        let events = wire
            .events
            .into_iter()
            .map(ReplayEvent::from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        validate_policies(&events)?;
        validate_terminal(&events)?;

        Ok(Self {
            trace: StructuralTrace {
                workflow_lock_sha256: wire.workflow_lock.sha256,
                input_sha256: wire.input_sha256,
                events,
            },
        })
    }

    /// Returns an owned structural trace without dispatching any work.
    pub fn replay(&self) -> StructuralTrace {
        self.trace.clone()
    }
}

/// One visible event in a deterministic structural replay trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayEvent {
    /// A workflow node began.
    NodeStarted {
        /// The stable node identifier.
        node_id: String,
    },
    /// A workflow node completed.
    NodeCompleted {
        /// The stable node identifier.
        node_id: String,
    },
    /// A model request and response identified by declared fixture digests.
    ModelExchange {
        /// The stable node identifier.
        node_id: String,
        /// The recorded model identifier.
        model_id: String,
        /// The declared request fixture digest.
        request_sha256: String,
        /// The declared response fixture digest.
        response_sha256: String,
        /// The recorded non-cached input token count.
        input_tokens: u64,
        /// The recorded output token count.
        output_tokens: u64,
        /// The recorded cached input token count.
        cached_input_tokens: u64,
    },
    /// A tool request and result identified by declared fixture digests.
    ToolExchange {
        /// The stable node identifier.
        node_id: String,
        /// The recorded tool identifier.
        tool_id: String,
        /// The declared arguments fixture digest.
        arguments_sha256: String,
        /// The declared result fixture digest.
        result_sha256: String,
    },
    /// An artifact declared by its immutable content identifier.
    ArtifactPublished {
        /// The stable node identifier.
        node_id: String,
        /// The declared bare SHA-256 artifact identifier.
        artifact_id: String,
    },
    /// A recorded capability policy decision.
    PolicyDecision {
        /// The stable node identifier.
        node_id: String,
        /// The sorted capabilities requested by the node.
        requested: Vec<SandboxCapability>,
        /// The sorted capabilities effective for the node.
        effective: Vec<SandboxCapability>,
        /// Whether the recorded request was allowed.
        allowed: bool,
    },
    /// The final outcome of the replayed run.
    Terminal {
        /// The existing runtime terminal status.
        status: RunStatus,
        /// The declared terminal-outcome fixture digest.
        outcome_sha256: String,
    },
}

impl ReplayEvent {
    fn from_wire(event: WireEvent) -> Result<Self, ReplayError> {
        Ok(match event {
            WireEvent::NodeStarted { node_id } => Self::NodeStarted { node_id },
            WireEvent::NodeCompleted { node_id } => Self::NodeCompleted { node_id },
            WireEvent::ModelExchange {
                node_id,
                model_id,
                request_sha256,
                response_sha256,
                input_tokens,
                output_tokens,
                cached_input_tokens,
            } => Self::ModelExchange {
                node_id,
                model_id,
                request_sha256,
                response_sha256,
                input_tokens,
                output_tokens,
                cached_input_tokens,
            },
            WireEvent::ToolExchange {
                node_id,
                tool_id,
                arguments_sha256,
                result_sha256,
            } => Self::ToolExchange {
                node_id,
                tool_id,
                arguments_sha256,
                result_sha256,
            },
            WireEvent::ArtifactPublished {
                node_id,
                artifact_id,
            } => Self::ArtifactPublished {
                node_id,
                artifact_id,
            },
            WireEvent::PolicyDecision {
                node_id,
                requested,
                effective,
                allowed,
            } => Self::PolicyDecision {
                node_id,
                requested: parse_capabilities(&requested)?,
                effective: parse_capabilities(&effective)?,
                allowed,
            },
            WireEvent::Terminal {
                status,
                outcome_sha256,
            } => Self::Terminal {
                status,
                outcome_sha256,
            },
        })
    }
}

/// The complete deterministic output of a pure structural replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralTrace {
    workflow_lock_sha256: String,
    input_sha256: String,
    events: Vec<ReplayEvent>,
}

impl StructuralTrace {
    /// Returns the exact declared digest of the opaque workflow lock TOML.
    pub fn workflow_lock_sha256(&self) -> &str {
        &self.workflow_lock_sha256
    }

    /// Returns the declared digest of the replay input.
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    /// Returns events in their original recorded order.
    pub fn events(&self) -> &[ReplayEvent] {
        &self.events
    }
}

/// A stable category for a rejected replay document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayErrorKind {
    /// The raw JSON document exceeded the configured byte ceiling.
    BundleTooLarge,
    /// JSON was malformed or did not match the strict wire shape.
    InvalidDocument,
    /// The document declared an unsupported schema version.
    UnsupportedSchemaVersion,
    /// A required value was absent or empty.
    MissingRequiredData,
    /// An identifier was too long or contained an unknown capability name.
    InvalidIdentifier,
    /// A SHA-256 digest was malformed.
    InvalidDigest,
    /// Declared bytes did not match their SHA-256 digest.
    DigestMismatch,
    /// The document contained too many events.
    TooManyEvents,
    /// The document contained too many fixture or artifact entries.
    TooManyPayloads,
    /// Inline data exceeded a configured byte ceiling.
    PayloadTooLarge,
    /// An event referred to an absent or duplicate declared payload.
    InvalidReference,
    /// The event sequence or policy record was inconsistent.
    InvalidTrace,
    /// A recorded effective capability exceeded its request.
    CapabilityExpansion,
}

/// A privacy-safe error that stores only its stable category.
#[derive(Debug)]
pub struct ReplayError {
    kind: ReplayErrorKind,
}

impl ReplayError {
    const fn new(kind: ReplayErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable category for this rejected replay document.
    pub const fn kind(&self) -> ReplayErrorKind {
        self.kind
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ReplayErrorKind::BundleTooLarge => "replay bundle exceeds the configured limit",
            ReplayErrorKind::InvalidDocument => "replay bundle document is invalid",
            ReplayErrorKind::UnsupportedSchemaVersion => {
                "replay bundle schema version is unsupported"
            }
            ReplayErrorKind::MissingRequiredData => "replay bundle is missing required data",
            ReplayErrorKind::InvalidIdentifier => "replay bundle identifier is invalid",
            ReplayErrorKind::InvalidDigest => "replay bundle digest is invalid",
            ReplayErrorKind::DigestMismatch => "replay bundle digest does not match content",
            ReplayErrorKind::TooManyEvents => "replay bundle has too many events",
            ReplayErrorKind::TooManyPayloads => "replay bundle has too many payloads",
            ReplayErrorKind::PayloadTooLarge => {
                "replay bundle payload exceeds the configured limit"
            }
            ReplayErrorKind::InvalidReference => "replay bundle reference is invalid",
            ReplayErrorKind::InvalidTrace => "replay bundle trace is invalid",
            ReplayErrorKind::CapabilityExpansion => "replay bundle expands a capability request",
        })
    }
}

impl std::error::Error for ReplayError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBundle {
    schema_version: u16,
    workflow_lock: WireWorkflowLock,
    input_sha256: String,
    events: Vec<WireEvent>,
    fixtures: Vec<WireFixture>,
    artifacts: Vec<WireArtifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWorkflowLock {
    toml: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFixture {
    sha256: String,
    bytes: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireArtifact {
    id: String,
    bytes: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WireEvent {
    NodeStarted {
        node_id: String,
    },
    NodeCompleted {
        node_id: String,
    },
    ModelExchange {
        node_id: String,
        model_id: String,
        request_sha256: String,
        response_sha256: String,
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
    },
    ToolExchange {
        node_id: String,
        tool_id: String,
        arguments_sha256: String,
        result_sha256: String,
    },
    ArtifactPublished {
        node_id: String,
        artifact_id: String,
    },
    PolicyDecision {
        node_id: String,
        requested: Vec<String>,
        effective: Vec<String>,
        allowed: bool,
    },
    Terminal {
        status: RunStatus,
        outcome_sha256: String,
    },
}

fn validate_required(bundle: &WireBundle) -> Result<(), ReplayError> {
    if bundle.workflow_lock.toml.is_empty() {
        return Err(ReplayError::new(ReplayErrorKind::MissingRequiredData));
    }
    validate_identifier(&bundle.workflow_lock.sha256)?;
    validate_identifier(&bundle.input_sha256)?;
    for fixture in &bundle.fixtures {
        validate_identifier(&fixture.sha256)?;
    }
    for artifact in &bundle.artifacts {
        validate_identifier(&artifact.id)?;
    }
    for event in &bundle.events {
        match event {
            WireEvent::NodeStarted { node_id } | WireEvent::NodeCompleted { node_id } => {
                validate_identifier(node_id)?;
            }
            WireEvent::ModelExchange {
                node_id,
                model_id,
                request_sha256,
                response_sha256,
                ..
            } => {
                validate_identifier(node_id)?;
                validate_identifier(model_id)?;
                validate_identifier(request_sha256)?;
                validate_identifier(response_sha256)?;
            }
            WireEvent::ToolExchange {
                node_id,
                tool_id,
                arguments_sha256,
                result_sha256,
            } => {
                validate_identifier(node_id)?;
                validate_identifier(tool_id)?;
                validate_identifier(arguments_sha256)?;
                validate_identifier(result_sha256)?;
            }
            WireEvent::ArtifactPublished {
                node_id,
                artifact_id,
            } => {
                validate_identifier(node_id)?;
                validate_identifier(artifact_id)?;
            }
            WireEvent::PolicyDecision {
                node_id,
                requested,
                effective,
                ..
            } => {
                validate_identifier(node_id)?;
                for capability in requested.iter().chain(effective) {
                    validate_identifier(capability)?;
                }
            }
            WireEvent::Terminal { outcome_sha256, .. } => {
                validate_identifier(outcome_sha256)?;
            }
        }
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ReplayError> {
    if value.is_empty() {
        Err(ReplayError::new(ReplayErrorKind::MissingRequiredData))
    } else if value.len() > ReplayBundle::MAX_IDENTIFIER_BYTES {
        Err(ReplayError::new(ReplayErrorKind::InvalidIdentifier))
    } else {
        Ok(())
    }
}

fn validate_limits(bundle: &WireBundle) -> Result<(), ReplayError> {
    if bundle.workflow_lock.toml.len() > ReplayBundle::MAX_WORKFLOW_LOCK_BYTES {
        return Err(ReplayError::new(ReplayErrorKind::PayloadTooLarge));
    }
    if bundle.events.len() > ReplayBundle::MAX_EVENTS {
        return Err(ReplayError::new(ReplayErrorKind::TooManyEvents));
    }
    let payload_count = bundle.fixtures.len().checked_add(bundle.artifacts.len());
    if payload_count.is_none_or(|count| count > ReplayBundle::MAX_PAYLOAD_ENTRIES) {
        return Err(ReplayError::new(ReplayErrorKind::TooManyPayloads));
    }

    let mut total_bytes = 0_usize;
    for payload in bundle
        .fixtures
        .iter()
        .filter_map(|fixture| fixture.bytes.as_deref())
        .chain(
            bundle
                .artifacts
                .iter()
                .filter_map(|artifact| artifact.bytes.as_deref()),
        )
    {
        if payload.len() > ReplayBundle::MAX_INLINE_PAYLOAD_BYTES {
            return Err(ReplayError::new(ReplayErrorKind::PayloadTooLarge));
        }
        total_bytes = total_bytes
            .checked_add(payload.len())
            .ok_or_else(|| ReplayError::new(ReplayErrorKind::PayloadTooLarge))?;
        if total_bytes > ReplayBundle::MAX_TOTAL_INLINE_PAYLOAD_BYTES {
            return Err(ReplayError::new(ReplayErrorKind::PayloadTooLarge));
        }
    }
    Ok(())
}

fn validate_payloads(bundle: &WireBundle) -> Result<(HashSet<&str>, HashSet<&str>), ReplayError> {
    if !is_prefixed_sha256(&bundle.workflow_lock.sha256)
        || !is_prefixed_sha256(&bundle.input_sha256)
    {
        return Err(ReplayError::new(ReplayErrorKind::InvalidDigest));
    }
    if prefixed_sha256(bundle.workflow_lock.toml.as_bytes()) != bundle.workflow_lock.sha256 {
        return Err(ReplayError::new(ReplayErrorKind::DigestMismatch));
    }

    let mut fixture_digests = HashSet::with_capacity(bundle.fixtures.len());
    for fixture in &bundle.fixtures {
        if !is_prefixed_sha256(&fixture.sha256) {
            return Err(ReplayError::new(ReplayErrorKind::InvalidDigest));
        }
        if !fixture_digests.insert(fixture.sha256.as_str()) {
            return Err(ReplayError::new(ReplayErrorKind::InvalidReference));
        }
        if let Some(bytes) = &fixture.bytes
            && prefixed_sha256(bytes) != fixture.sha256
        {
            return Err(ReplayError::new(ReplayErrorKind::DigestMismatch));
        }
    }

    let mut artifact_ids = HashSet::with_capacity(bundle.artifacts.len());
    for artifact in &bundle.artifacts {
        if !is_bare_sha256(&artifact.id) {
            return Err(ReplayError::new(ReplayErrorKind::InvalidDigest));
        }
        if !artifact_ids.insert(artifact.id.as_str()) {
            return Err(ReplayError::new(ReplayErrorKind::InvalidReference));
        }
        if let Some(bytes) = &artifact.bytes
            && bare_sha256(bytes) != artifact.id
        {
            return Err(ReplayError::new(ReplayErrorKind::DigestMismatch));
        }
    }

    Ok((fixture_digests, artifact_ids))
}

fn validate_references(
    events: &[WireEvent],
    fixture_digests: &HashSet<&str>,
    artifact_ids: &HashSet<&str>,
) -> Result<(), ReplayError> {
    for event in events {
        let references_are_valid = match event {
            WireEvent::ModelExchange {
                request_sha256,
                response_sha256,
                ..
            } => {
                is_declared_fixture(request_sha256, fixture_digests)
                    && is_declared_fixture(response_sha256, fixture_digests)
            }
            WireEvent::ToolExchange {
                arguments_sha256,
                result_sha256,
                ..
            } => {
                is_declared_fixture(arguments_sha256, fixture_digests)
                    && is_declared_fixture(result_sha256, fixture_digests)
            }
            WireEvent::Terminal { outcome_sha256, .. } => {
                is_declared_fixture(outcome_sha256, fixture_digests)
            }
            WireEvent::ArtifactPublished { artifact_id, .. } => {
                is_bare_sha256(artifact_id) && artifact_ids.contains(artifact_id.as_str())
            }
            WireEvent::NodeStarted { .. }
            | WireEvent::NodeCompleted { .. }
            | WireEvent::PolicyDecision { .. } => true,
        };
        if !references_are_valid {
            return Err(ReplayError::new(ReplayErrorKind::InvalidReference));
        }
    }
    Ok(())
}

fn is_declared_fixture(digest: &str, fixture_digests: &HashSet<&str>) -> bool {
    is_prefixed_sha256(digest) && fixture_digests.contains(digest)
}

fn parse_capabilities(names: &[String]) -> Result<Vec<SandboxCapability>, ReplayError> {
    names
        .iter()
        .map(|name| {
            capability_from_name(name)
                .ok_or_else(|| ReplayError::new(ReplayErrorKind::InvalidIdentifier))
        })
        .collect()
}

fn capability_from_name(name: &str) -> Option<SandboxCapability> {
    [
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::Network,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::MaximumPids,
        SandboxCapability::CpuTime,
        SandboxCapability::WallTime,
        SandboxCapability::IdleTime,
        SandboxCapability::Memory,
        SandboxCapability::OutputBytes,
        SandboxCapability::OpenFiles,
        SandboxCapability::EnvironmentVariables,
        SandboxCapability::SyscallProfile,
        SandboxCapability::UserGroupIdentity,
        SandboxCapability::DeviceAccess,
    ]
    .into_iter()
    .find(|capability| capability.as_str() == name)
}

fn validate_policies(events: &[ReplayEvent]) -> Result<(), ReplayError> {
    for event in events {
        let ReplayEvent::PolicyDecision {
            requested,
            effective,
            allowed,
            ..
        } = event
        else {
            continue;
        };
        if !is_sorted_unique(requested) || !is_sorted_unique(effective) {
            return Err(ReplayError::new(ReplayErrorKind::InvalidTrace));
        }
        if effective
            .iter()
            .any(|capability| !requested.contains(capability))
        {
            return Err(ReplayError::new(ReplayErrorKind::CapabilityExpansion));
        }
        if *allowed {
            if requested.is_empty() || effective != requested {
                return Err(ReplayError::new(ReplayErrorKind::InvalidTrace));
            }
        } else if !effective.is_empty() {
            return Err(ReplayError::new(ReplayErrorKind::InvalidTrace));
        }
    }
    Ok(())
}

fn is_sorted_unique(capabilities: &[SandboxCapability]) -> bool {
    capabilities
        .windows(2)
        .all(|pair| pair[0].as_str() < pair[1].as_str())
}

fn validate_terminal(events: &[ReplayEvent]) -> Result<(), ReplayError> {
    let terminal_count = events
        .iter()
        .filter(|event| matches!(event, ReplayEvent::Terminal { .. }))
        .count();
    if terminal_count != 1 || !matches!(events.last(), Some(ReplayEvent::Terminal { .. })) {
        return Err(ReplayError::new(ReplayErrorKind::InvalidTrace));
    }
    Ok(())
}

fn is_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_bare_sha256)
}

fn is_bare_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn bare_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
