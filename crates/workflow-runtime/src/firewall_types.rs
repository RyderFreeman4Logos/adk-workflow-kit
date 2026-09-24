//! Data-only Firewall v1 contracts. No document, rationale, or approval input.
use crate::{SandboxCapability, TrustDomain};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Firewall schema and hard-policy implementation identity.
pub const FIREWALL_SCHEMA_VERSION: u32 = 1;
pub const FIREWALL_IMPLEMENTATION_VERSION: &str = "firewall-hard-policy-v1";

/// Authority supplied by the trusted application, never by a proposal or model.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedGoal {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub capabilities: BTreeSet<SandboxCapability>,
    pub scopes: BTreeSet<String>,
    pub destinations: BTreeSet<String>,
}

/// Closed side-effect classes, independent of model claims about safety.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    None,
    Read,
    Write,
    Destructive,
}

/// Versioned proposal claim; the registered policy must independently agree.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SideEffectDescriptor {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub class: SideEffectClass,
}

/// Opaque exact revision supplied independently by a trusted target reader.
#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct TargetVersion {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub revision: String,
}

/// Snapshot identity includes the destination and scope, not only an object ID.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetState {
    pub scope: String,
    pub destination: String,
    pub resource: String,
    pub version: TargetVersion,
}

/// Canonical action claim, containing identifiers rather than natural-language context.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolIntent {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub goal_id: String,
    pub tool_id: String,
    pub tool_version: String,
    pub capabilities: BTreeSet<SandboxCapability>,
    pub scope: String,
    pub destination: String,
    pub resource: String,
    pub effect: SideEffectDescriptor,
    pub target_version: TargetVersion,
}

/// Scalar-only arguments. Nested documents, arrays, nulls, and floats are excluded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ToolArgument {
    Integer(i64),
    Boolean(bool),
    Token(
        #[schemars(length(min = 1, max = 256), regex(pattern = r"^[A-Za-z0-9._/:@#-]+$"))] String,
    ),
}

impl<'de> Deserialize<'de> for ToolArgument {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::Bool(value) => Ok(Self::Boolean(value)),
            serde_json::Value::Number(value) => value
                .as_i64()
                .map(Self::Integer)
                .ok_or_else(|| serde::de::Error::custom("argument must be an integer")),
            serde_json::Value::String(value) if crate::firewall::token(&value, 256) => {
                Ok(Self::Token(value))
            }
            _ => Err(serde::de::Error::custom(
                "argument must be a bounded scalar token",
            )),
        }
    }
}

/// A content reference and argument binding; provenance never upgrades authority.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalProvenance {
    pub source_digest: String,
    pub arguments_digest: String,
    pub trust_domain: TrustDomain,
}

/// The entire untrusted Firewall request. TrustedGoal and policy are injected separately.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolProposal {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub intent: ToolIntent,
    #[serde(deserialize_with = "unique_map")]
    pub arguments: BTreeMap<String, ToolArgument>,
    pub provenance: ProposalProvenance,
}

/// Exact argument constraints; all registered arguments are required and extras denied.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArgumentRule {
    Integer { min: i64, max: i64 },
    Boolean,
    Token { max_bytes: usize },
    Choice { values: BTreeSet<String> },
}

/// Binds asserted metadata to actual arguments or immutable registration-owned literals.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArgumentBinding {
    Literal { value: String },
    Argument { name: String },
}

/// Automatic allow is opt-in and only applies to no-effect/read-only registrations.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolAdmission {
    LowRisk,
    HumanApproval,
}

/// Trusted registration. These facts are not copied from ToolIntent.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    pub version: String,
    pub capabilities: BTreeSet<SandboxCapability>,
    pub scopes: BTreeSet<String>,
    pub destinations: BTreeSet<String>,
    pub effect: SideEffectClass,
    pub admission: ToolAdmission,
    pub arguments: BTreeMap<String, ArgumentRule>,
    pub scope: ArgumentBinding,
    pub destination: ArgumentBinding,
    pub resource: ArgumentBinding,
}

/// Injected trusted configuration; absent tool entries deny, never default allow.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallPolicy {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub version: String,
    pub tools: BTreeMap<String, ToolRule>,
    pub targets: BTreeSet<TargetState>,
    /// Synthetic markers or application-supplied prohibited substrings. Never logged.
    pub forbidden_markers: BTreeSet<String>,
}

fn unique_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Unique<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Unique<T> {
        type Value = BTreeMap<String, T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique argument keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry()? {
                if map.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate argument key"));
                }
            }
            Ok(map)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

/// Stable compact hard-policy reason registry. No free-form error payloads.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, schemars::JsonSchema)]
pub enum FirewallReason {
    #[serde(rename = "sch")]
    Schema,
    #[serde(rename = "pol")]
    Policy,
    #[serde(rename = "prv")]
    Provenance,
    #[serde(rename = "gol")]
    Goal,
    #[serde(rename = "tol")]
    Tool,
    #[serde(rename = "cap")]
    Capability,
    #[serde(rename = "scp")]
    Scope,
    #[serde(rename = "dst")]
    Destination,
    #[serde(rename = "arg")]
    Arguments,
    #[serde(rename = "sec")]
    Secret,
    #[serde(rename = "eff")]
    SideEffect,
    #[serde(rename = "stl")]
    StaleTarget,
    #[serde(rename = "low")]
    LowRisk,
    #[serde(rename = "smt")]
    Semantic,
    #[serde(rename = "hum")]
    HumanApproval,
}
