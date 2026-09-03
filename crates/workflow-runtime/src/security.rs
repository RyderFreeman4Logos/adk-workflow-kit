use std::{
    collections::BTreeSet,
    error::Error,
    fmt::{self, Display, Formatter},
};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentObjectKind {
    IssueBody,
    Comment,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ContentProvenance {
    kind: ContentObjectKind,
    scope: String,
    object_id: String,
    author: String,
    domain: TrustDomain,
    policy_digest: [u8; 32],
}

impl ContentProvenance {
    fn from_parts(
        kind: ContentObjectKind,
        scope: String,
        object_id: String,
        author: String,
        domain: TrustDomain,
        policy_digest: [u8; 32],
    ) -> Result<Self, TrustPolicyError> {
        validate_non_blank(&scope, TrustPolicyError::EmptyScope)?;
        validate_non_blank(&object_id, TrustPolicyError::EmptyObjectId)?;
        validate_non_blank(&author, TrustPolicyError::EmptyAuthor)?;
        Ok(Self {
            kind,
            scope,
            object_id,
            author,
            domain,
            policy_digest,
        })
    }

    pub fn kind(&self) -> ContentObjectKind {
        self.kind
    }

    pub fn scope(&self) -> &str {
        &self.scope
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
        let mut hasher = Sha256::new();
        update_field(&mut hasher, SECURITY_MODEL_VERSION.as_bytes());
        update_field(&mut hasher, SECRET_POLICY_VERSION.as_bytes());
        update_field(&mut hasher, &self.policy_digest);
        update_field(&mut hasher, self.scope.as_bytes());
        update_field(&mut hasher, self.kind.cache_tag().as_bytes());
        update_field(&mut hasher, self.object_id.as_bytes());
        update_field(&mut hasher, self.author.as_bytes());
        update_field(&mut hasher, self.domain.cache_salt().as_bytes());
        update_field(&mut hasher, content);
        CacheKey(hasher.finalize().into())
    }

    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }
}

impl<'de> Deserialize<'de> for ContentProvenance {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(D::Error::custom(
            "content provenance must be reclassified from a TrustPolicy",
        ))
    }
}

pub enum ContentObject<'a> {
    IssueBody { object_id: &'a str, author: &'a str },
    Comment { object_id: &'a str, author: &'a str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustPolicyError {
    EmptyScope,
    EmptyAllowlistedAuthor,
    EmptyObjectId,
    EmptyAuthor,
}

impl Display for TrustPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyScope => "trust scope must not be empty or blank",
            Self::EmptyAllowlistedAuthor => "allowlisted author must not be empty or blank",
            Self::EmptyObjectId => "object ID must not be empty or blank",
            Self::EmptyAuthor => "author must not be empty or blank",
        };
        formatter.write_str(message)
    }
}

impl Error for TrustPolicyError {}

#[derive(Clone, Debug)]
pub struct TrustPolicy {
    scope: String,
    allowlisted_authors: BTreeSet<String>,
    policy_digest: [u8; 32],
}

impl TrustPolicy {
    pub fn new<I, S, A>(scope: S, allowlisted_authors: I) -> Result<Self, TrustPolicyError>
    where
        I: IntoIterator<Item = A>,
        S: Into<String>,
        A: Into<String>,
    {
        let scope = scope.into();
        validate_non_blank(&scope, TrustPolicyError::EmptyScope)?;
        let mut authors = BTreeSet::new();
        for author in allowlisted_authors {
            let author = author.into();
            validate_non_blank(&author, TrustPolicyError::EmptyAllowlistedAuthor)?;
            authors.insert(author);
        }
        let policy_digest = canonical_policy_digest(&authors);
        Ok(Self {
            scope,
            allowlisted_authors: authors,
            policy_digest,
        })
    }

    pub fn classify(
        &self,
        object: ContentObject<'_>,
    ) -> Result<ContentProvenance, TrustPolicyError> {
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
        ContentProvenance::from_parts(
            kind,
            self.scope.clone(),
            object_id.to_owned(),
            author.to_owned(),
            domain,
            self.policy_digest,
        )
    }
}

fn validate_non_blank(value: &str, error: TrustPolicyError) -> Result<(), TrustPolicyError> {
    if value.trim().is_empty() {
        Err(error)
    } else {
        Ok(())
    }
}

fn canonical_policy_digest(allowlisted_authors: &BTreeSet<String>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, SECURITY_MODEL_VERSION.as_bytes());
    update_field(&mut hasher, SECRET_POLICY_VERSION.as_bytes());
    update_field(&mut hasher, b"trust-policy-allowlist-v1");
    for author in allowlisted_authors {
        update_field(&mut hasher, author.as_bytes());
    }
    hasher.finalize().into()
}

fn update_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

impl ContentObjectKind {
    fn cache_tag(self) -> &'static str {
        match self {
            Self::IssueBody => "issue_body",
            Self::Comment => "comment",
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
        if scope.trim().is_empty() {
            return Err(SecretPolicyError::EmptyScope);
        }
        if nonce.trim().is_empty() {
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
    _private: (),
}

impl SyntheticSecretPolicy {
    pub fn issue(
        &mut self,
        scope: &str,
        nonce: &str,
    ) -> Result<SyntheticHoneytoken, SecretPolicyError> {
        SyntheticHoneytoken::for_scope(scope, nonce)
    }

    pub fn sanitize_log(&self, line: &str) -> Result<String, SecretPolicyError> {
        let redacted = redact_synthetic_markers(line);
        if contains_unknown_secret_like_structure(&redacted) {
            return Err(SecretPolicyError::RealSecretFixtureRejected);
        }
        Ok(redacted)
    }
}

const REDACTION_MARKER: &str = "[REDACTED_SYNTHETIC]";
const SECRET_LIKE_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "secret_access_key",
    "access_token",
    "auth_token",
    "private_key",
    "password",
    "credential",
    "credentials",
    "token",
];

fn redact_synthetic_markers(line: &str) -> String {
    let mut redacted = String::with_capacity(line.len());
    let mut cursor = 0;
    while let Some(offset) = line[cursor..].find(SYNTHETIC_HONEYTOKEN_PREFIX) {
        let start = cursor + offset;
        redacted.push_str(&line[cursor..start]);
        redacted.push_str(REDACTION_MARKER);
        cursor = start + SYNTHETIC_HONEYTOKEN_PREFIX.len();
        while cursor < line.len() {
            let byte = line.as_bytes()[cursor];
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
                cursor += 1;
            } else {
                break;
            }
        }
    }
    redacted.push_str(&line[cursor..]);
    redacted
}

fn contains_unknown_secret_like_structure(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if ["real-secret-fixture", "fixture-placeholder"]
        .into_iter()
        .any(|pattern| lower.contains(pattern))
    {
        return true;
    }
    SECRET_LIKE_KEYS.iter().any(|key| {
        let mut search_from = 0;
        while let Some(offset) = lower[search_from..].find(key) {
            let start = search_from + offset;
            let end = start + key.len();
            let mut key_end = end;
            while lower
                .as_bytes()
                .get(key_end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                key_end += 1;
            }
            if is_key_boundary(&lower, start, key_end) {
                if is_single_quoted_key(&lower, start, key_end) {
                    return true;
                }
                let mut value_start = key_end;
                if lower.as_bytes().get(value_start) == Some(&b'"') {
                    value_start += 1;
                }
                while lower
                    .as_bytes()
                    .get(value_start)
                    .is_some_and(u8::is_ascii_whitespace)
                {
                    value_start += 1;
                }
                if lower.as_bytes().get(value_start) == Some(&b'=')
                    || lower.as_bytes().get(value_start) == Some(&b':')
                {
                    value_start += 1;
                    while lower
                        .as_bytes()
                        .get(value_start)
                        .is_some_and(u8::is_ascii_whitespace)
                    {
                        value_start += 1;
                    }
                    if !is_redaction_value(line, value_start) {
                        return true;
                    }
                }
            }
            search_from = end;
        }
        false
    })
}

fn is_key_boundary(line: &str, start: usize, end: usize) -> bool {
    let is_key_byte = |byte: u8| byte.is_ascii_alphanumeric();
    line.as_bytes()
        .get(start.wrapping_sub(1))
        .is_none_or(|byte| !is_key_byte(*byte))
        && line
            .as_bytes()
            .get(end)
            .is_none_or(|byte| !is_key_byte(*byte))
}

fn is_single_quoted_key(line: &str, start: usize, end: usize) -> bool {
    line.as_bytes().get(start.wrapping_sub(1)) == Some(&b'\'')
        || line.as_bytes().get(end) == Some(&b'\'')
}

fn is_redaction_value(line: &str, value_start: usize) -> bool {
    let value = &line[value_start..];
    if let Some(suffix) = value.strip_prefix(REDACTION_MARKER) {
        return is_redaction_suffix(suffix);
    }
    let Some(value) = value.strip_prefix('"') else {
        return false;
    };
    let Some(value) = value.strip_prefix(REDACTION_MARKER) else {
        return false;
    };
    let Some(suffix) = value.strip_prefix('"') else {
        return false;
    };
    is_redaction_suffix(suffix)
}

fn is_redaction_suffix(suffix: &str) -> bool {
    matches!(
        suffix.trim_start().as_bytes().first(),
        None | Some(b',') | Some(b'}') | Some(b']')
    )
}
