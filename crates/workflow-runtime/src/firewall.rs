//! Deterministic hard policy. No model, IO, raw documents, or approval override.
//!
//! The embedding application owns policy, goal, and target snapshots. Successful
//! decisions describe policy admission, not proof of task alignment (#239) or an
//! execution/approval ledger (#240). Re-evaluate against fresh targets before use.
pub use crate::firewall_types::{
    ArgumentBinding, ArgumentRule, FIREWALL_IMPLEMENTATION_VERSION, FIREWALL_SCHEMA_VERSION,
    FirewallPolicy, FirewallReason, ProposalProvenance, SideEffectClass, SideEffectDescriptor,
    TargetState, TargetVersion, ToolAdmission, ToolArgument, ToolIntent, ToolProposal, ToolRule,
    TrustedGoal,
};
use crate::{
    Completeness, FirewallDecision, FirewallRecord, SYNTHETIC_HONEYTOKEN_PREFIX,
    SyntheticSecretPolicy, TypedOutput, TypedOutputError, TypedPayload, argument_fingerprint,
    contains_sensitive_key,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_PROPOSAL_BYTES: usize = 16_384;

impl ToolProposal {
    /// Decode a bounded strict request. Errors contain no attacker-controlled text.
    pub fn decode(bytes: &[u8]) -> Result<Self, FirewallReason> {
        if bytes.len() > MAX_PROPOSAL_BYTES {
            return Err(FirewallReason::Arguments);
        }
        serde_json::from_slice(bytes).map_err(|_| FirewallReason::Schema)
    }

    /// Lexically sorted keys and scalar JSON spellings; not RFC 8785 float coercion.
    pub fn canonical_arguments(&self) -> String {
        serde_json::to_string(&self.arguments).expect("scalar argument serialization")
    }

    /// Uses the same canonical fingerprint as the call-scoped approval boundary.
    pub fn arguments_digest(&self) -> String {
        digest(&self.arguments)
    }
}

impl FirewallPolicy {
    /// All bytes affecting admission, including target revisions, are identity-bound.
    pub fn identity(&self) -> String {
        digest(self)
    }

    /// Evaluate all hard checks first. Human approval can never convert a denial.
    pub fn evaluate(&self, goal: &TrustedGoal, proposal: &ToolProposal) -> ToolDecision {
        let reason = self.check(goal, proposal).err().unwrap_or_else(|| {
            if self
                .tools
                .get(&proposal.intent.tool_id)
                .is_some_and(|rule| rule.admission == ToolAdmission::LowRisk)
            {
                FirewallReason::LowRisk
            } else {
                FirewallReason::HumanApproval
            }
        });
        let decision = match reason {
            FirewallReason::LowRisk => FirewallDecision::Allow,
            FirewallReason::HumanApproval => FirewallDecision::RequireHumanApproval,
            _ => FirewallDecision::Deny,
        };
        ToolDecision {
            decision,
            reason,
            identity: digest(&json!({"implementation":FIREWALL_IMPLEMENTATION_VERSION,
                "schema_version":FIREWALL_SCHEMA_VERSION,"policy":self,"goal":goal,
                "proposal":proposal,"reason":reason,
                "security":crate::SECURITY_MODEL_VERSION,"secrets":crate::SECRET_POLICY_VERSION})),
        }
    }

    fn check(&self, goal: &TrustedGoal, proposal: &ToolProposal) -> Result<(), FirewallReason> {
        let intent = &proposal.intent;
        if [
            self.schema_version,
            goal.schema_version,
            proposal.schema_version,
            intent.schema_version,
            intent.effect.schema_version,
            intent.target_version.schema_version,
        ]
        .iter()
        .any(|version| *version != FIREWALL_SCHEMA_VERSION)
        {
            return Err(FirewallReason::Schema);
        }
        if !token(&self.version, 128) || self.forbidden_markers.iter().any(String::is_empty) {
            return Err(FirewallReason::Policy);
        }
        if !token(&goal.id, 128) || !token(&goal.version, 128) || intent.goal_id != goal.id {
            return Err(FirewallReason::Goal);
        }
        if !valid_digest(&proposal.provenance.source_digest)
            || proposal.provenance.arguments_digest != proposal.arguments_digest()
        {
            return Err(FirewallReason::Provenance);
        }
        let rule = self
            .tools
            .get(&intent.tool_id)
            .filter(|rule| {
                token(&intent.tool_id, 128)
                    && token(&rule.version, 128)
                    && rule.version == intent.tool_version
            })
            .ok_or(FirewallReason::Tool)?;
        if intent.capabilities != rule.capabilities
            || !rule.capabilities.is_subset(&goal.capabilities)
        {
            return Err(FirewallReason::Capability);
        }
        if !token(&intent.scope, 256)
            || !rule.scopes.contains(&intent.scope)
            || !goal.scopes.contains(&intent.scope)
        {
            return Err(FirewallReason::Scope);
        }
        if !token(&intent.destination, 256)
            || !rule.destinations.contains(&intent.destination)
            || !goal.destinations.contains(&intent.destination)
        {
            return Err(FirewallReason::Destination);
        }
        let arguments = proposal.canonical_arguments();
        if arguments.contains(SYNTHETIC_HONEYTOKEN_PREFIX)
            || self
                .forbidden_markers
                .iter()
                .any(|marker| arguments.contains(marker))
            || SyntheticSecretPolicy::default()
                .sanitize_log(&arguments)
                .is_err()
            || contains_sensitive_key(&value(&proposal.arguments))
        {
            return Err(FirewallReason::Secret);
        }
        if arguments.len() > MAX_PROPOSAL_BYTES
            || rule.arguments.len() != proposal.arguments.len()
            || !rule.arguments.iter().all(|(name, constraint)| {
                proposal
                    .arguments
                    .get(name)
                    .is_some_and(|argument| constraint.accepts(argument))
            })
            || rule.scope.resolve(proposal).as_deref() != Some(intent.scope.as_str())
            || rule.destination.resolve(proposal).as_deref() != Some(intent.destination.as_str())
            || rule.resource.resolve(proposal).as_deref() != Some(intent.resource.as_str())
        {
            return Err(FirewallReason::Arguments);
        }
        if rule.effect != intent.effect.class
            || (rule.admission == ToolAdmission::LowRisk
                && !matches!(rule.effect, SideEffectClass::None | SideEffectClass::Read))
        {
            return Err(FirewallReason::SideEffect);
        }
        let mut targets = self.targets.iter().filter(|target| {
            target.scope == intent.scope
                && target.destination == intent.destination
                && target.resource == intent.resource
        });
        let target = targets.next().ok_or(FirewallReason::StaleTarget)?;
        if targets.next().is_some()
            || !token(&intent.resource, 256)
            || !token(&intent.target_version.revision, 256)
            || target.version.schema_version != FIREWALL_SCHEMA_VERSION
            || target.version != intent.target_version
        {
            return Err(FirewallReason::StaleTarget);
        }
        Ok(())
    }
}

impl ArgumentRule {
    fn accepts(&self, argument: &ToolArgument) -> bool {
        match (self, argument) {
            (Self::Integer { min, max }, ToolArgument::Integer(value)) => {
                min <= value && value <= max
            }
            (Self::Boolean, ToolArgument::Boolean(_)) => true,
            (Self::Token { max_bytes }, ToolArgument::Token(value)) => {
                token(value, (*max_bytes).min(256))
            }
            (Self::Choice { values }, ToolArgument::Token(value)) => {
                token(value, 256) && values.contains(value)
            }
            _ => false,
        }
    }
}
impl ArgumentBinding {
    fn resolve(&self, proposal: &ToolProposal) -> Option<String> {
        match self {
            Self::Literal { value } => Some(value.clone()),
            Self::Argument { name } => proposal.arguments.get(name).map(|arg| match arg {
                ToolArgument::Token(value) => value.clone(),
                ToolArgument::Integer(value) => value.to_string(),
                ToolArgument::Boolean(value) => value.to_string(),
            }),
        }
    }
}
fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/:@#".contains(&byte))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn value(value: &impl Serialize) -> Value {
    serde_json::to_value(value).expect("Firewall data serialization")
}
fn digest(data: &impl Serialize) -> String {
    argument_fingerprint(&value(data))
}

/// Compact, strictly decoded report stamp. It conveys no execution authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StampWire")]
pub struct FirewallStamp {
    schema_version: u32,
    reason: FirewallReason,
    identity: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StampWire {
    schema_version: u32,
    reason: FirewallReason,
    identity: String,
}
impl TryFrom<StampWire> for FirewallStamp {
    type Error = &'static str;
    fn try_from(wire: StampWire) -> Result<Self, Self::Error> {
        if wire.schema_version != FIREWALL_SCHEMA_VERSION || !valid_digest(&wire.identity) {
            return Err("invalid Firewall stamp");
        }
        Ok(Self {
            schema_version: wire.schema_version,
            reason: wire.reason,
            identity: wire.identity,
        })
    }
}
impl FirewallStamp {
    pub fn reason(&self) -> FirewallReason {
        self.reason
    }
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// Non-forgeable in-process decision, with one identity for cache, approval, and checkpoint use.
/// Serialization is a report, never an authority token or an executor permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDecision {
    decision: FirewallDecision,
    reason: FirewallReason,
    identity: String,
}
impl ToolDecision {
    pub fn decision(&self) -> FirewallDecision {
        self.decision
    }
    pub fn reason(&self) -> FirewallReason {
        self.reason
    }
    pub fn identity(&self) -> &str {
        &self.identity
    }
    /// Compact shared v1 output. The content identity binds the full trusted evaluation.
    pub fn typed_output(&self) -> Result<TypedOutput, TypedOutputError> {
        TypedOutput::new(
            TypedPayload::Firewall(FirewallRecord::new(self.decision, vec![]).with_policy(
                FirewallStamp {
                    schema_version: FIREWALL_SCHEMA_VERSION,
                    reason: self.reason,
                    identity: self.identity.clone(),
                },
            )),
            Completeness::Complete,
        )
    }
    pub fn render_json(&self) -> Result<String, TypedOutputError> {
        self.typed_output()?.to_json()
    }
    pub fn render_markdown(&self) -> Result<String, TypedOutputError> {
        Ok(crate::render_markdown(&self.typed_output()?))
    }
}
