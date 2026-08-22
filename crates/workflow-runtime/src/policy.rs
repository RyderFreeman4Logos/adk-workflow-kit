//! Context identity and network policy layered over POLICY-001 capabilities.

use super::{
    intersect_policy_capabilities, CapabilityPolicyDenied, EffectiveCapabilities,
    PolicyCapabilities, RequestedCapabilities, SandboxCapability,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::{collections::HashSet, fmt};

/// A validated non-empty tenant identifier.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TenantId(String);

impl TenantId {
    /// Creates a tenant identifier from a non-empty string.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidPolicyToken> {
        let value = value.into();
        if value.is_empty() {
            Err(InvalidPolicyToken)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl From<String> for TenantId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl<'a> From<&'a str> for TenantId {
    fn from(value: &'a str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TenantId(<redacted>)")
    }
}

/// A validated non-empty authorization role token.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RoleToken(String);

impl RoleToken {
    /// Creates a role token from a non-empty string.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidPolicyToken> {
        let value = value.into();
        if value.is_empty() {
            Err(InvalidPolicyToken)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RoleToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl From<String> for RoleToken {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl<'a> From<&'a str> for RoleToken {
    fn from(value: &'a str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for RoleToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RoleToken(<redacted>)")
    }
}

/// An invalid empty policy token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPolicyToken;

impl fmt::Display for InvalidPolicyToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("policy token must not be empty")
    }
}

impl std::error::Error for InvalidPolicyToken {}

/// The closed data-classification ordering used by context policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Public data.
    Public,
    /// Internal data.
    Internal,
    /// Confidential data.
    Confidential,
    /// Restricted data.
    Restricted,
}

/// Identity and classification supplied for one policy decision.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySubject {
    tenant_id: TenantId,
    role: RoleToken,
    classification: Classification,
}

impl PolicySubject {
    /// Creates a subject with required tenant and role tokens.
    pub fn new(
        tenant_id: impl Into<String>,
        role: impl Into<String>,
        classification: Classification,
    ) -> Result<Self, InvalidPolicyToken> {
        Ok(Self {
            tenant_id: TenantId::new(tenant_id)?,
            role: RoleToken::new(role)?,
            classification,
        })
    }

    /// Returns the tenant identifier.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the authorization role token.
    pub fn role(&self) -> &RoleToken {
        &self.role
    }

    /// Returns the subject classification.
    pub fn classification(&self) -> Classification {
        self.classification
    }
}

impl fmt::Debug for PolicySubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PolicySubject(<redacted>)")
    }
}

/// An exact network destination tuple.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDestination {
    host: String,
    port: u16,
}

impl NetworkDestination {
    /// Creates an exact non-wildcard host and port tuple.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, InvalidNetworkDestination> {
        let host = host.into();
        if host.is_empty() || host.contains('*') || port == 0 {
            Err(InvalidNetworkDestination)
        } else {
            Ok(Self { host, port })
        }
    }

    /// Returns the exact host string.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the exact port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// An invalid network destination tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidNetworkDestination;

impl fmt::Display for InvalidNetworkDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("network destination is invalid")
    }
}

impl std::error::Error for InvalidNetworkDestination {}

/// The closed network profile vocabulary.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProfile {
    /// No network access.
    #[default]
    None,
    /// Loopback-only network access.
    LoopbackOnly,
    /// Access to approved service aliases.
    ServiceAlias,
    /// Access to exact brokered destination tuples.
    BrokeredAllowlist,
    /// Full network access, never inferred by intersection.
    Full,
}

impl NetworkProfile {
    fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::LoopbackOnly => 1,
            Self::ServiceAlias => 2,
            Self::BrokeredAllowlist => 3,
            Self::Full => 4,
        }
    }
}

/// One contextual grant layered over POLICY-001 capabilities.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLayer {
    allowed_tenants: HashSet<TenantId>,
    allowed_roles: HashSet<RoleToken>,
    max_classification: Classification,
    network_profile: NetworkProfile,
    brokered_destinations: Vec<NetworkDestination>,
    capabilities: PolicyCapabilities,
}

impl PolicyLayer {
    /// Creates one grant layer from its allowlists and capability grant.
    pub fn new<T, R>(
        allowed_tenants: impl IntoIterator<Item = T>,
        allowed_roles: impl IntoIterator<Item = R>,
        max_classification: Classification,
        network_profile: NetworkProfile,
        brokered_destinations: impl IntoIterator<Item = NetworkDestination>,
        capabilities: PolicyCapabilities,
    ) -> Self
    where
        T: Into<TenantId>,
        R: Into<RoleToken>,
    {
        Self {
            allowed_tenants: allowed_tenants.into_iter().map(Into::into).collect(),
            allowed_roles: allowed_roles.into_iter().map(Into::into).collect(),
            max_classification,
            network_profile,
            brokered_destinations: brokered_destinations.into_iter().collect(),
            capabilities,
        }
    }

    /// Returns this layer's network profile.
    pub fn network_profile(&self) -> NetworkProfile {
        self.network_profile
    }

    /// Returns this layer's brokered destination allowlist.
    pub fn brokered_destinations(&self) -> &[NetworkDestination] {
        &self.brokered_destinations
    }
}

impl fmt::Debug for PolicyLayer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyLayer")
            .field("max_classification", &self.max_classification)
            .field("network_profile", &self.network_profile)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

/// The effective context policy after every layer is intersected.
#[derive(Clone, Eq, PartialEq)]
pub struct EffectivePolicy {
    capabilities: EffectiveCapabilities,
    network_profile: NetworkProfile,
    brokered_destinations: Vec<NetworkDestination>,
}

impl EffectivePolicy {
    /// Returns the effective capability classes.
    pub fn capabilities(&self) -> &EffectiveCapabilities {
        &self.capabilities
    }

    /// Returns the effective network profile.
    pub fn network_profile(&self) -> NetworkProfile {
        self.network_profile
    }

    /// Returns the effective brokered destination allowlist.
    pub fn brokered_destinations(&self) -> &[NetworkDestination] {
        &self.brokered_destinations
    }
}

impl fmt::Debug for EffectivePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectivePolicy")
            .field("capabilities", &self.capabilities)
            .field("network_profile", &self.network_profile)
            .finish()
    }
}

/// Closed reasons for contextual policy denial.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextPolicyDeniedKind {
    /// The request did not provide a valid subject.
    MissingSubject,
    /// The role is absent from at least one layer.
    RoleDenied,
    /// The tenant is absent from at least one layer.
    TenantMismatch,
    /// The subject classification exceeds a layer maximum.
    ClassificationDenied,
    /// Network was requested without an approved non-none profile.
    NetworkProfileRequired,
    /// A requested destination is outside the intersected allowlist.
    DestinationDenied,
    /// A requested capability is absent from the capability intersection.
    CapabilityDenied,
    /// The policy input is structurally invalid or empty.
    InvalidPolicy,
}

impl fmt::Display for ContextPolicyDeniedKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingSubject => "missing_subject",
            Self::RoleDenied => "role_denied",
            Self::TenantMismatch => "tenant_mismatch",
            Self::ClassificationDenied => "classification_denied",
            Self::NetworkProfileRequired => "network_profile_required",
            Self::DestinationDenied => "destination_denied",
            Self::CapabilityDenied => "capability_denied",
            Self::InvalidPolicy => "invalid_policy",
        })
    }
}

/// A privacy-safe contextual policy denial.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextPolicyDenied {
    kind: ContextPolicyDeniedKind,
    missing: Vec<SandboxCapability>,
}

impl ContextPolicyDenied {
    fn new(kind: ContextPolicyDeniedKind) -> Self {
        Self {
            kind,
            missing: Vec::new(),
        }
    }

    fn capability(missing: Vec<SandboxCapability>) -> Self {
        Self {
            kind: ContextPolicyDeniedKind::CapabilityDenied,
            missing,
        }
    }

    /// Returns the closed denial kind.
    pub fn kind(&self) -> ContextPolicyDeniedKind {
        self.kind
    }

    /// Returns missing capabilities for a capability denial.
    pub fn missing_capabilities(&self) -> &[SandboxCapability] {
        &self.missing
    }
}

impl fmt::Display for ContextPolicyDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("context policy denied: ")?;
        formatter.write_str(&self.kind.to_string())?;
        if self.kind == ContextPolicyDeniedKind::CapabilityDenied {
            for capability in &self.missing {
                formatter.write_str(" ")?;
                formatter.write_str(capability.as_str())?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ContextPolicyDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ContextPolicyDenied {}

/// Evaluates contextual grants before the existing capability intersection.
pub fn evaluate_context_policy(
    subject: &PolicySubject,
    requested: &RequestedCapabilities,
    policy_layers: &[PolicyLayer],
) -> Result<EffectivePolicy, ContextPolicyDenied> {
    if policy_layers.is_empty() {
        return Err(ContextPolicyDenied::new(
            ContextPolicyDeniedKind::InvalidPolicy,
        ));
    }

    if !policy_layers
        .iter()
        .all(|layer| layer.allowed_tenants.contains(subject.tenant_id()))
    {
        return Err(ContextPolicyDenied::new(
            ContextPolicyDeniedKind::TenantMismatch,
        ));
    }

    if !policy_layers
        .iter()
        .all(|layer| layer.allowed_roles.contains(subject.role()))
    {
        return Err(ContextPolicyDenied::new(
            ContextPolicyDeniedKind::RoleDenied,
        ));
    }

    if !policy_layers
        .iter()
        .all(|layer| subject.classification() <= layer.max_classification)
    {
        return Err(ContextPolicyDenied::new(
            ContextPolicyDeniedKind::ClassificationDenied,
        ));
    }

    let (network_profile, brokered_destinations) = intersect_network_policy(policy_layers);
    if requested.contains(SandboxCapability::Network) {
        if network_profile == NetworkProfile::None {
            return Err(ContextPolicyDenied::new(
                ContextPolicyDeniedKind::NetworkProfileRequired,
            ));
        }
        if let Some(destination) = requested.network_destination() {
            if network_profile == NetworkProfile::BrokeredAllowlist
                && !brokered_destinations.contains(destination)
            {
                return Err(ContextPolicyDenied::new(
                    ContextPolicyDeniedKind::DestinationDenied,
                ));
            }
        }
    }

    let capabilities = intersect_policy_capabilities(
        requested,
        &policy_layers
            .iter()
            .map(|layer| layer.capabilities.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(context_capability_denial)?;

    Ok(EffectivePolicy {
        capabilities,
        network_profile,
        brokered_destinations,
    })
}

fn context_capability_denial(denied: CapabilityPolicyDenied) -> ContextPolicyDenied {
    ContextPolicyDenied::capability(denied.missing().to_vec())
}

fn intersect_network_policy(
    policy_layers: &[PolicyLayer],
) -> (NetworkProfile, Vec<NetworkDestination>) {
    let profile = policy_layers
        .iter()
        .map(|layer| layer.network_profile)
        .min_by_key(|profile| profile.rank())
        .unwrap_or(NetworkProfile::None);

    if profile != NetworkProfile::BrokeredAllowlist {
        return (profile, Vec::new());
    }

    let mut destinations: Option<Vec<NetworkDestination>> = None;
    for layer in policy_layers
        .iter()
        .filter(|layer| layer.network_profile == NetworkProfile::BrokeredAllowlist)
    {
        if let Some(current) = &mut destinations {
            current.retain(|destination| layer.brokered_destinations.contains(destination));
        } else {
            destinations = Some(layer.brokered_destinations.clone());
        }
    }

    (profile, destinations.unwrap_or_default())
}
