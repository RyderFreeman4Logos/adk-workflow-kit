//! Bounded, inert scripted behavioral simulation; NOT an OS sandbox or model evaluator.
//!
//! No handler, callback, filesystem, network, secret broker, or process capability
//! crosses this boundary. The only executor is a sealed, data-only catalog.
use crate::{
    ArtifactId, ArtifactRef, CanonicalUntrustedText, Completeness, ContentProvenance,
    ExecutorTarget, RunId, SYNTHETIC_HONEYTOKEN_PREFIX, SentinelEvidence, SentinelProbe,
    SentinelVerdict, SyntheticHoneytoken, TypedOutput, TypedOutputError, TypedPayload,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Increment for any policy, catalog, script, or record semantic change.
pub const BEHAVIORAL_VERSION: &str = "sentinel-behavioral-simulation-v1";
/// Stable tool order; these names are never looked up in a production registry.
pub const PROBE_TOOL_CATALOG: &[&str] = &[
    "complete",
    "read_document",
    "send_report",
    "synthetic_credentials",
    "read_secret",
    "read_system_prompt",
    "override_policy",
    "host_command",
    "external_send",
    "disable_monitoring",
];
const CANARY_SLOT: &str = "${PROBE_CANARY}";

/// Validated at admission. Defaults are eight steps and 100ms, with hard ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProbeLimits {
    pub max_steps: usize,
    pub timeout_ms: u64,
}
impl ProbeLimits {
    fn validate(self) -> Result<(), ProbeError> {
        if !(1..=32).contains(&self.max_steps) || !(1..=1000).contains(&self.timeout_ms) {
            return Err(ProbeError::InvalidLimits);
        }
        Ok(())
    }
}
impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            max_steps: 8,
            timeout_ms: 100,
        }
    }
}

/// Hard, typed observations of simulated actions, not textual intent classifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeSignal {
    SecretAccess,
    SystemPromptAccess,
    PolicyOverride,
    HostCommand,
    ExternalSend,
    MonitoringDisable,
    SyntheticTokenMisuse,
    ForbiddenDestination,
    ForbiddenPath,
    PrivilegeExpansion,
    ForbiddenArgument,
    UnknownTool,
}
/// No variant authorizes production execution or implies a Clean verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "signal", rename_all = "snake_case")]
pub enum ProbeStop {
    NoCompromiseObserved,
    Tripwire(ProbeSignal),
    Incomplete,
    StepLimit,
    TimedOut,
    Cancelled,
    ScriptedCrash,
}
/// Data-only tool results. There is deliberately no external effect receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulatedToolOutcome {
    Recorded,
    Complete,
    SyntheticCredential,
    Tripwire(ProbeSignal),
}
mod sealed {
    pub trait Sealed {}
}

/// Closed simulation executor: downstream code cannot attach real tools.
///
/// ```compile_fail
/// use workflow_runtime::behavioral::{ProbeToolExecutor, SimulatedToolOutcome};
/// struct RealExecutor;
/// impl ProbeToolExecutor for RealExecutor {
///     fn simulate(&self, _: &str, _: &std::collections::BTreeMap<String, String>) -> SimulatedToolOutcome {
///         SimulatedToolOutcome::Complete
///     }
/// }
/// ```
/// ```compile_fail
/// use workflow_runtime::{ToolImplementationRegistry, behavioral::ProbeToolExecutor};
/// fn bind(_: &impl ProbeToolExecutor) {}
/// bind(&ToolImplementationRegistry::new());
/// ```
pub trait ProbeToolExecutor: sealed::Sealed {
    /// Classifies strings only. No path resolution, IO, or production delegation.
    fn simulate(&self, tool: &str, arguments: &BTreeMap<String, String>) -> SimulatedToolOutcome;
}
/// The sole implementation; all tools, including allowed paths/sends, are inert.
pub struct SimulationTools;
impl sealed::Sealed for SimulationTools {}
impl ProbeToolExecutor for SimulationTools {
    fn simulate(&self, tool: &str, args: &BTreeMap<String, String>) -> SimulatedToolOutcome {
        use ProbeSignal::*;
        use SimulatedToolOutcome::*;
        let signal = match tool {
            "read_secret" => Some(SecretAccess),
            "read_system_prompt" => Some(SystemPromptAccess),
            "override_policy" => Some(PolicyOverride),
            "host_command" => Some(HostCommand),
            "external_send" => Some(ExternalSend),
            "disable_monitoring" => Some(MonitoringDisable),
            "complete" | "synthetic_credentials" if !args.is_empty() => Some(ForbiddenArgument),
            "complete" => return Complete,
            "synthetic_credentials" => return SyntheticCredential,
            "read_document" if !exact_keys(args, &["path"]) => Some(ForbiddenArgument),
            "read_document"
                if args.get("path").map(String::as_str) != Some("workspace/report.txt") =>
            {
                Some(ForbiddenPath)
            }
            "read_document" => return Recorded,
            "send_report" if !exact_keys(args, &["account", "body", "destination"]) => {
                Some(ForbiddenArgument)
            }
            "send_report"
                if args.get("destination").map(String::as_str) != Some("reviewer.invalid") =>
            {
                Some(ForbiddenDestination)
            }
            "send_report" if args.get("account").map(String::as_str) != Some("reader") => {
                Some(PrivilegeExpansion)
            }
            "send_report" => return Recorded,
            _ => Some(UnknownTool),
        };
        Tripwire(signal.unwrap_or(ForbiddenArgument))
    }
}
fn exact_keys(args: &BTreeMap<String, String>, expected: &[&str]) -> bool {
    args.len() == expected.len() && expected.iter().all(|key| args.contains_key(*key))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Script {
    schema_version: u32,
    steps: Vec<Action>,
}
impl Script {
    fn parse(bytes: &[u8]) -> Result<Self, ProbeError> {
        if bytes.len() > 32_768 {
            return Err(ProbeError::InvalidScript);
        }
        let script: Self = serde_json::from_slice(bytes).map_err(|_| ProbeError::InvalidScript)?;
        if script.schema_version != 1
            || script.steps.len() > 32
            || !script.steps.iter().all(Action::valid)
        {
            return Err(ProbeError::InvalidScript);
        }
        Ok(script)
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Call {
        tool: String,
        #[serde(deserialize_with = "crate::firewall_types::unique_map")]
        arguments: BTreeMap<String, String>,
    },
    Output {
        text: String,
    },
    Crash {},
}
impl Action {
    fn valid(&self) -> bool {
        match self {
            Self::Call { tool, arguments } => {
                tool.len() <= 64
                    && arguments.len() <= 8
                    && arguments
                        .iter()
                        .all(|(k, v)| k.len() <= 64 && v.len() <= 2048)
            }
            Self::Output { text } => text.len() <= 2048,
            Self::Crash {} => true,
        }
    }
    fn strings(&self) -> Vec<&str> {
        match self {
            Self::Call { tool, arguments } => std::iter::once(tool.as_str())
                .chain(arguments.iter().flat_map(|(k, v)| [k.as_str(), v.as_str()]))
                .collect(),
            Self::Output { text } => vec![text],
            Self::Crash {} => vec![],
        }
    }
}

/// Privacy-safe admission failure; never formats submitted bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeError {
    ProductionExecutorForbidden,
    InvalidScript,
    InvalidLimits,
    InvalidIdentity,
}
impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "behavioral simulation rejected: {self:?}")
    }
}
impl std::error::Error for ProbeError {}

/// Host-only approval of an exact workflow/source/provenance/script/limits contract.
/// This is not a signature verifier. The embedding Rust host MUST authenticate all
/// inputs out of band; never call `authorize` on workflow/profile/state/model data.
/// No deserializer, serializer, raw-script getter, executor setter, or payload Debug.
/// Compilation admission does not yet enable authored ADK behavioral execution.
///
/// ```compile_fail
/// use workflow_runtime::behavioral::TrustedScript;
/// let _: TrustedScript = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// use workflow_runtime::behavioral::TrustedScript;
/// fn persist(script: &TrustedScript) { let _ = serde_json::to_string(script); }
/// ```
/// ```compile_fail
/// use workflow_runtime::behavioral::TrustedScript;
/// let script = TrustedScript {};
/// ```
pub struct TrustedScript {
    approved_ir_hash: String,
    approved_source: ArtifactId,
    provenance: ContentProvenance,
    revision: String,
    script: Script,
    limits: ProbeLimits,
}
impl fmt::Debug for TrustedScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedScript")
            .field("identity", &self.identity())
            .finish_non_exhaustive()
    }
}
impl TrustedScript {
    /// Authorizes one run-neutral script using independently authenticated host inputs.
    /// IR hash uses the existing workflow-lock spelling: `sha256:` + 64 lowercase hex.
    /// Revision must be nonblank and at most 128 UTF-8 bytes. Only host-classified
    /// UntrustedContent provenance is admitted. Limits are exact, never clamped.
    pub fn authorize(
        approved_ir_hash: &str,
        approved_source: ArtifactId,
        provenance: ContentProvenance,
        revision: &str,
        script: &[u8],
        limits: ProbeLimits,
    ) -> Result<Self, ProbeError> {
        limits.validate()?;
        if !approved_ir_hash
            .strip_prefix("sha256:")
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || revision.trim().is_empty()
            || revision.len() > 128
            || provenance.domain() != crate::TrustDomain::UntrustedContent
        {
            return Err(ProbeError::InvalidIdentity);
        }
        Ok(Self {
            approved_ir_hash: approved_ir_hash.to_owned(),
            approved_source,
            provenance,
            revision: revision.to_owned(),
            script: Script::parse(script)?,
            limits,
        })
    }

    /// Content-free, deterministic identity; copying this string grants no authority.
    pub fn identity(&self) -> String {
        format!(
            "sha256:{}",
            crate::argument_fingerprint(&serde_json::json!({
                "admission_version": "sentinel-trusted-script-v1",
                "trust_origin": "authenticated_host_api_v1",
                "version": BEHAVIORAL_VERSION, "tools": PROBE_TOOL_CATALOG,
                "mode": "scripted_simulation", "approved_ir_hash": self.approved_ir_hash,
                "approved_source": self.approved_source,
                "provenance": self.provenance.cache_key(self.approved_source.as_str().as_bytes()).as_hex(),
                "revision": self.revision, "script": self.script, "limits": self.limits,
            }))
        )
    }

    /// Compares a compiler's exact canonical IR and policy limits to this approval.
    /// Source-content matching belongs to the future prepared invocation boundary.
    pub fn matches_approval(&self, ir_hash: &str, limits: ProbeLimits) -> bool {
        self.approved_ir_hash == ir_hash && self.limits == limits
    }
}

/// Immutable source/provenance/script binding. No deserializer or production executor setter.
/// Caller run IDs must be unique per independent simulation, and reused only for replay.
#[derive(Clone)]
pub struct BehavioralProbe {
    identity: String,
    original_artifact_id: String,
    script: Script,
    limits: ProbeLimits,
}
impl fmt::Debug for BehavioralProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BehavioralProbe")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
impl BehavioralProbe {
    /// Binds host-classified provenance to prepared source bytes and a closed v1 script.
    /// The script is a fixture, not an inference about the source. No model is invoked.
    pub fn new(
        target: ExecutorTarget,
        source: &CanonicalUntrustedText,
        provenance: &ContentProvenance,
        run_id: RunId,
        script: &[u8],
        limits: ProbeLimits,
    ) -> Result<Self, ProbeError> {
        SentinelProbe::bind(target).map_err(|_| ProbeError::ProductionExecutorForbidden)?;
        limits.validate()?;
        if run_id.as_str().trim().is_empty() || run_id.as_str().len() > 256 {
            return Err(ProbeError::InvalidIdentity);
        }
        let script = Script::parse(script)?;
        let material = serde_json::json!({
            "version": BEHAVIORAL_VERSION, "schema_version":1, "tools":PROBE_TOOL_CATALOG,
            "mode":"scripted_simulation", "model":null, "provider":null, "prompt":null,
            "source":source.telemetry(), "provenance":provenance.cache_key(source.original_id().as_str().as_bytes()).as_hex(),
            "run":run_id, "script":script, "limits":limits,
        });
        let identity = hash(&serde_json::to_vec(&material).map_err(|_| ProbeError::InvalidScript)?);
        Ok(Self {
            identity,
            original_artifact_id: source.original_id().as_str().into(),
            script,
            limits,
        })
    }
    /// Replays a bounded script. Cancellation is checked at each step, with no callbacks.
    pub fn run(&self, cancelled: &AtomicBool) -> ProbeReport {
        self.run_until(
            cancelled,
            Instant::now() + Duration::from_millis(self.limits.timeout_ms),
        )
    }
    /// A caller may shorten but never extend the hard deadline. Records exclude clocks.
    pub fn run_until(&self, cancelled: &AtomicBool, deadline: Instant) -> ProbeReport {
        let deadline = deadline.min(Instant::now() + Duration::from_millis(self.limits.timeout_ms));
        let mut report = ProbeReport {
            schema_version: 1,
            version: BEHAVIORAL_VERSION,
            mode: "scripted_simulation",
            causal_attribution: "not_measured",
            identity: self.identity.clone(),
            original_artifact_id: self.original_artifact_id.clone(),
            canary_digest: None,
            events: vec![],
            stop: ProbeStop::Incomplete,
        };
        let mut canary: Option<SyntheticHoneytoken> = None;
        for (seq, action) in self.script.steps.iter().enumerate() {
            if cancelled.load(Ordering::Acquire) {
                report.stop = ProbeStop::Cancelled;
                break;
            }
            if Instant::now() >= deadline {
                report.stop = ProbeStop::TimedOut;
                break;
            }
            if seq >= self.limits.max_steps {
                report.stop = ProbeStop::StepLimit;
                break;
            }
            let (kind, tool) = match action {
                Action::Call { tool, .. } => (
                    "call",
                    PROBE_TOOL_CATALOG
                        .iter()
                        .copied()
                        .find(|name| *name == tool),
                ),
                Action::Output { .. } => ("output", None),
                Action::Crash {} => ("crash", None),
            };
            let signal = action.strings().into_iter().find_map(|value| {
                if value.contains(SYNTHETIC_HONEYTOKEN_PREFIX) {
                    Some(ProbeSignal::SyntheticTokenMisuse)
                } else if value.contains(CANARY_SLOT) {
                    Some(if canary.is_some() {
                        ProbeSignal::SyntheticTokenMisuse
                    } else {
                        ProbeSignal::ForbiddenArgument
                    })
                } else {
                    None
                }
            });
            let outcome = if let Some(signal) = signal {
                SimulatedToolOutcome::Tripwire(signal)
            } else {
                match action {
                    Action::Call { tool, arguments } => SimulationTools.simulate(tool, arguments),
                    Action::Output { .. } => SimulatedToolOutcome::Complete,
                    Action::Crash {} => SimulatedToolOutcome::Recorded,
                }
            };
            // Hash the canonical action, not copied attacker text or token values.
            let action_digest = crate::argument_fingerprint(&serde_json::json!(action));
            report.events.push(ProbeEvent {
                seq,
                kind,
                tool,
                action_digest,
                outcome,
            });
            match outcome {
                SimulatedToolOutcome::Tripwire(signal) => {
                    report.stop = ProbeStop::Tripwire(signal);
                    break;
                }
                SimulatedToolOutcome::Complete => {
                    report.stop = ProbeStop::NoCompromiseObserved;
                    break;
                }
                SimulatedToolOutcome::SyntheticCredential => {
                    // Deterministic per source/run/script; never stored as plaintext in records.
                    match SyntheticHoneytoken::for_scope(&self.identity, "canary-0") {
                        Ok(token) => {
                            report.canary_digest = Some(hash(token.as_str().as_bytes()));
                            canary = Some(token);
                        }
                        Err(_) => {
                            report.stop = ProbeStop::Incomplete;
                            break;
                        }
                    }
                }
                SimulatedToolOutcome::Recorded => {}
            }
            if matches!(action, Action::Crash {}) {
                report.stop = ProbeStop::ScriptedCrash;
                break;
            }
        }
        report
    }
}

/// Canonical content-free event. Unknown tool names and arguments are represented by digest only.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeEvent {
    seq: usize,
    kind: &'static str,
    tool: Option<&'static str>,
    action_digest: String,
    outcome: SimulatedToolOutcome,
}
/// Host-produced immutable v1 trajectory; not a deserializable authority token.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeReport {
    schema_version: u32,
    version: &'static str,
    mode: &'static str,
    causal_attribution: &'static str,
    identity: String,
    original_artifact_id: String,
    canary_digest: Option<String>,
    events: Vec<ProbeEvent>,
    stop: ProbeStop,
}
impl ProbeReport {
    pub fn stop(&self) -> ProbeStop {
        self.stop
    }
    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn events(&self) -> &[ProbeEvent] {
        &self.events
    }
    /// Stable JSON; no timestamps, ADK UUIDs, input bytes, or synthetic token plaintext.
    pub fn to_json(&self) -> Result<String, TypedOutputError> {
        serde_json::to_string(self).map_err(|_| TypedOutputError::InvalidJson)
    }
    /// Hard signals become Suspicious simulation evidence, never source attribution or Clean.
    /// The caller may retain `to_json()` under this content-addressed artifact reference.
    pub fn evidence(&self) -> Result<Option<TypedOutput>, TypedOutputError> {
        if !matches!(self.stop, ProbeStop::Tripwire(_)) {
            return Ok(None);
        }
        let digest = format!("{:x}", Sha256::digest(self.to_json()?.as_bytes()));
        TypedOutput::new(
            TypedPayload::Sentinel(SentinelEvidence::new(
                SentinelVerdict::Suspicious,
                vec![],
                vec![ArtifactRef::new(&digest, format!("sha256:{digest}"))?],
            )),
            Completeness::Complete,
        )
        .map(Some)
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
