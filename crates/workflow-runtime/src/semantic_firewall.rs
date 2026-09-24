//! Independent semantic evidence. Models cannot grant authority or weaken hard policy.
use crate::firewall::ToolDecision;
use crate::{FirewallDecision, TypedOutputError, admit_for_reducer, parse_typed_output};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SEMANTIC_FIREWALL_VERSION: &str = "semantic-firewall-v1";
pub const MAX_JUDGE_OUTPUT_BYTES: usize = 384;

/// Fixed independent axes; their order is also the stable graph/schema order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeKind {
    TaskAlignment,
    PrivilegeScope,
    Destination,
    DataFlow,
}
impl JudgeKind {
    pub const ALL: [Self; 4] = [
        Self::TaskAlignment,
        Self::PrivilegeScope,
        Self::Destination,
        Self::DataFlow,
    ];
    pub fn id(self) -> &'static str {
        match self {
            Self::TaskAlignment => "task_alignment",
            Self::PrivilegeScope => "privilege_scope",
            Self::Destination => "destination",
            Self::DataFlow => "data_flow",
        }
    }
    /// Each judge has an independently named v1 schema using the shared Firewall wire.
    /// No evidence text, policy stamp, rationale, or invented artifact is admitted.
    pub fn output_schema(self) -> Value {
        json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":format!("urn:workflow-kit:semantic:{}:v1", self.id()),
            "type":"object","additionalProperties":false,
            "required":["schema_version","node","completeness","payload"],
            "properties":{"schema_version":{"const":1},"node":{"const":"firewall"},
            "completeness":{"const":"complete"},"payload":{"type":"object","additionalProperties":false,
            "required":["kind","decision","artifacts"],"properties":{"kind":{"const":"firewall"},
            "decision":{"enum":["alw","den","rha"]},"artifacts":{"const":[]}}}}})
    }
}

/// Trusted host impact classification, never inferred from model confidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    Low,
    High,
}

/// A validated report paired with its host-owned judge identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JudgeOutput {
    judge: JudgeKind,
    decision: FirewallDecision,
}

// Typed wire decoding rejects duplicate keys before Value/schema conversion.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u32,
    node: String,
    completeness: String,
    payload: Payload,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    kind: String,
    decision: String,
    artifacts: Vec<Value>,
}
impl JudgeOutput {
    pub fn decode(judge: JudgeKind, bytes: &[u8]) -> Result<Self, TypedOutputError> {
        if bytes.len() > MAX_JUDGE_OUTPUT_BYTES {
            return Err(TypedOutputError::OverBudget);
        }
        let wire: Wire =
            serde_json::from_slice(bytes).map_err(|_| TypedOutputError::InvalidJson)?;
        if wire.schema_version != 1
            || wire.node != "firewall"
            || wire.completeness != "complete"
            || wire.payload.kind != "firewall"
            || !wire.payload.artifacts.is_empty()
        {
            return Err(TypedOutputError::InvalidJson);
        }
        admit_for_reducer(&parse_typed_output(bytes)?)?;
        let decision = match wire.payload.decision.as_str() {
            "alw" => FirewallDecision::Allow,
            "den" => FirewallDecision::Deny,
            "rha" => FirewallDecision::RequireHumanApproval,
            _ => return Err(TypedOutputError::UnknownReasonCode),
        };
        Ok(Self { judge, decision })
    }
    pub fn judge(&self) -> JudgeKind {
        self.judge
    }
    pub fn decision(&self) -> FirewallDecision {
        self.decision
    }
}

/// Pure monotonic reduction: complete evidence is mandatory, no voting averages.
pub fn reduce(hard: &ToolDecision, impact: Impact, reports: &[JudgeOutput]) -> FirewallDecision {
    use FirewallDecision::{Allow, Deny, RequireHumanApproval};
    if hard.decision() != Allow {
        return hard.decision();
    }
    let axes = reports
        .iter()
        .map(|r| r.judge)
        .collect::<std::collections::BTreeSet<_>>();
    if reports.len() != JudgeKind::ALL.len() || axes.len() != JudgeKind::ALL.len() {
        return Deny;
    }
    let denied = reports.iter().filter(|r| r.decision == Deny).count();
    if denied == reports.len() {
        return Deny;
    }
    if impact == Impact::High && denied > 0 {
        return RequireHumanApproval;
    }
    if denied > 0 {
        return Deny;
    }
    if reports.iter().any(|r| r.decision == RequireHumanApproval) {
        return RequireHumanApproval;
    }
    Allow
}

/// Host-authored summaries, bound to the exact proposal by FirewallInvocation.
/// Never populate these from raw retrieved prose or model-produced summaries.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticFacts {
    pub schema_version: u32,
    pub trusted_goal: String,
    pub action: String,
    pub scope: String,
    pub destination: String,
    pub data_class: DataClass,
    pub provenance: crate::TrustDomain,
    pub argument_summary: String,
    pub impact: Impact,
}
#[derive(Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Distinct v1 projections exclude unrelated facts and every raw-content field.
#[derive(Clone, Serialize, schemars::JsonSchema)]
pub struct JudgeInput {
    #[schemars(range(min = 1, max = 1))]
    schema_version: u32,
    features: JudgeFeatures,
}
#[derive(Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "judge", rename_all = "snake_case", deny_unknown_fields)]
enum JudgeFeatures {
    TaskAlignment {
        goal: String,
        action: String,
    },
    PrivilegeScope {
        goal: String,
        action: String,
        scope: String,
    },
    Destination {
        goal: String,
        action: String,
        destination: String,
    },
    DataFlow {
        action: String,
        destination: String,
        data_class: DataClass,
        provenance: crate::TrustDomain,
        argument_summary: String,
    },
}
impl JudgeInput {
    pub fn schema() -> Value {
        serde_json::to_value(schemars::schema_for!(Self)).expect("static input schema")
    }
}
impl SemanticFacts {
    /// Fixed total ceiling, no controls or known secret markers. Error carries no input.
    pub fn validate(&self) -> Result<(), TypedOutputError> {
        if self.schema_version != 1 {
            return Err(TypedOutputError::UnknownSchemaVersion);
        }
        for text in [
            &self.trusted_goal,
            &self.action,
            &self.scope,
            &self.destination,
            &self.argument_summary,
        ] {
            if text.trim().is_empty()
                || text.len() > 512
                || text.chars().any(char::is_control)
                || text.contains(crate::SYNTHETIC_HONEYTOKEN_PREFIX)
                || crate::SyntheticSecretPolicy::default()
                    .sanitize_log(text)
                    .is_err()
            {
                return Err(TypedOutputError::InvalidJson);
            }
        }
        Ok(())
    }
    pub fn input(&self, judge: JudgeKind) -> Result<JudgeInput, TypedOutputError> {
        self.validate()?;
        let action = self.action.clone();
        let goal = self.trusted_goal.clone();
        let destination = self.destination.clone();
        let features = match judge {
            JudgeKind::TaskAlignment => JudgeFeatures::TaskAlignment { goal, action },
            JudgeKind::PrivilegeScope => JudgeFeatures::PrivilegeScope {
                goal,
                action,
                scope: self.scope.clone(),
            },
            JudgeKind::Destination => JudgeFeatures::Destination {
                goal,
                action,
                destination,
            },
            JudgeKind::DataFlow => JudgeFeatures::DataFlow {
                action,
                destination,
                data_class: self.data_class,
                provenance: self.provenance,
                argument_summary: self.argument_summary.clone(),
            },
        };
        Ok(JudgeInput {
            schema_version: 1,
            features,
        })
    }
}
