use std::{
    collections::BTreeSet,
    error::Error,
    fmt::{self, Display, Formatter},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SECURITY_MODEL_VERSION: &str = "security-threat-model-v1";
pub const SECRET_POLICY_VERSION: &str = "synthetic-secret-policy-v1";
pub const SYNTHETIC_HONEYTOKEN_PREFIX: &str = "synthetic-honeytoken-v1:";

/// Security provenance is attached to each object, not inherited from its container.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustDomain {
    TrustedPolicy,
    TrustedGoal,
    ConditionallyTrustedContent,
    UntrustedContent,
    SyntheticTrap,
}

impl TrustDomain {
    pub const fn cache_salt(self) -> &'static str {
        match self {
            Self::TrustedPolicy => "trust-domain:policy:v1",
            Self::TrustedGoal => "trust-domain:goal:v1",
            Self::ConditionallyTrustedContent => "trust-domain:conditional-content:v1",
            Self::UntrustedContent => "trust-domain:untrusted-content:v1",
            Self::SyntheticTrap => "trust-domain:synthetic-trap:v1",
        }
    }

    pub fn cache_key(self, content: &[u8]) -> CacheKey {
        let mut hasher = Sha256::new();
        hasher.update(SECURITY_MODEL_VERSION.as_bytes());
        hasher.update([0]);
        hasher.update(SECRET_POLICY_VERSION.as_bytes());
        hasher.update([0]);
        hasher.update(self.cache_salt().as_bytes());
        hasher.update([0]);
        hasher.update(content);
        CacheKey(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentObjectKind {
    IssueBody,
    Comment,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ContentProvenance {
    kind: ContentObjectKind,
    object_id: String,
    author: String,
    domain: TrustDomain,
}

impl ContentProvenance {
    pub fn kind(&self) -> ContentObjectKind {
        self.kind
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn author(&self) -> &str {
        &self.author
    }

    pub fn domain(&self) -> TrustDomain {
        self.domain
    }

    pub fn cache_key(&self, content: &[u8]) -> CacheKey {
        self.domain.cache_key(content)
    }
}

pub enum ContentObject<'a> {
    IssueBody { object_id: &'a str, author: &'a str },
    Comment { object_id: &'a str, author: &'a str },
}

#[derive(Clone, Debug, Default)]
pub struct TrustPolicy {
    allowlisted_authors: BTreeSet<String>,
}

impl TrustPolicy {
    pub fn new<I, S>(allowlisted_authors: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowlisted_authors: allowlisted_authors.into_iter().map(Into::into).collect(),
        }
    }

    pub fn classify(&self, object: ContentObject<'_>) -> ContentProvenance {
        let (kind, object_id, author) = match object {
            ContentObject::IssueBody { object_id, author } => {
                (ContentObjectKind::IssueBody, object_id, author)
            }
            ContentObject::Comment { object_id, author } => {
                (ContentObjectKind::Comment, object_id, author)
            }
        };
        let domain = if self.allowlisted_authors.contains(author) {
            TrustDomain::ConditionallyTrustedContent
        } else {
            TrustDomain::UntrustedContent
        };
        ContentProvenance {
            kind,
            object_id: object_id.to_owned(),
            author: author.to_owned(),
            domain,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CacheKey([u8; 32]);

impl CacheKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorTarget {
    Simulated,
    Production,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeBindingError {
    ProductionExecutorForbidden,
}

impl Display for ProbeBindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProductionExecutorForbidden => {
                formatter.write_str("sentinel probes require a simulated executor")
            }
        }
    }
}

impl Error for ProbeBindingError {}

#[derive(Debug)]
pub struct SentinelProbe;

impl SentinelProbe {
    pub fn bind(target: ExecutorTarget) -> Result<Self, ProbeBindingError> {
        match target {
            ExecutorTarget::Simulated => Ok(Self),
            ExecutorTarget::Production => Err(ProbeBindingError::ProductionExecutorForbidden),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticHoneytoken {
    value: String,
}

impl SyntheticHoneytoken {
    pub fn for_scope(scope: &str, nonce: &str) -> Result<Self, SecretPolicyError> {
        if scope.is_empty() {
            return Err(SecretPolicyError::EmptyScope);
        }
        if nonce.is_empty() {
            return Err(SecretPolicyError::EmptyNonce);
        }
        let mut hasher = Sha256::new();
        hasher.update(scope.as_bytes());
        hasher.update([0]);
        hasher.update(nonce.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            value: format!("{SYNTHETIC_HONEYTOKEN_PREFIX}{suffix}"),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn is_synthetic(value: &str) -> bool {
        value.starts_with(SYNTHETIC_HONEYTOKEN_PREFIX)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretPolicyError {
    EmptyScope,
    EmptyNonce,
    RealSecretFixtureRejected,
}

impl Display for SecretPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScope => formatter.write_str("synthetic token scope must not be empty"),
            Self::EmptyNonce => formatter.write_str("synthetic token nonce must not be empty"),
            Self::RealSecretFixtureRejected => {
                formatter.write_str("secret-shaped fixture rejected from ordinary logs")
            }
        }
    }
}

impl Error for SecretPolicyError {}

#[derive(Clone, Debug, Default)]
pub struct SyntheticSecretPolicy {
    tokens: BTreeSet<String>,
}

impl SyntheticSecretPolicy {
    pub fn issue(
        &mut self,
        scope: &str,
        nonce: &str,
    ) -> Result<SyntheticHoneytoken, SecretPolicyError> {
        let token = SyntheticHoneytoken::for_scope(scope, nonce)?;
        self.tokens.insert(token.value.clone());
        Ok(token)
    }

    pub fn sanitize_log(&self, line: &str) -> Result<String, SecretPolicyError> {
        let redacted = self.tokens.iter().fold(line.to_owned(), |line, token| {
            line.replace(token, "[REDACTED_SYNTHETIC]")
        });
        if contains_secret_fixture_pattern(&redacted) {
            return Err(SecretPolicyError::RealSecretFixtureRejected);
        }
        Ok(redacted)
    }
}

fn contains_secret_fixture_pattern(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if ["real-secret-fixture", "fixture-placeholder"]
        .into_iter()
        .any(|pattern| lower.contains(pattern))
    {
        return true;
    }
    [
        "api_key=",
        "apikey=",
        "secret=",
        "secret_key=",
        "secret_access_key=",
        "access_token=",
        "auth_token=",
        "private_key=",
        "password=",
    ]
    .into_iter()
    .any(|pattern| {
        lower
            .split_once(pattern)
            .is_some_and(|(_, value)| !value.starts_with("[redacted_synthetic]"))
    })
}
