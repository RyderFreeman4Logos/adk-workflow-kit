use std::{
    fmt,
    fs::{self, File},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};

use super::{
    ByteSource, DatasetDistribution, DatasetEntry, DatasetError, DatasetErrorKind, EvalSuite,
    digest_bytes,
};

impl DatasetEntry {
    /// Dataset family used for split discipline.
    pub fn family(&self) -> &str {
        &self.family
    }

    /// Dataset language used for split discipline.
    pub fn language(&self) -> &str {
        &self.language
    }

    /// Pinned source URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Provenance kind carried by a resolved source identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatasetProvenance {
    /// Bytes were resolved from an upstream immutable object ID.
    Upstream,
    /// Bytes came from a local synthetic/fixture source and are content-addressed.
    LocalFixture,
    /// Bytes were supplied through the operator's manual import boundary.
    Manual,
}

/// Identity resolved by the selected source, never synthesized from a manifest label.
#[derive(Clone, Eq, PartialEq)]
pub enum DatasetSourceIdentity {
    /// Upstream origin bound to a full object ID.
    Upstream { origin: String, revision: String },
    /// Local fixture origin bound to the observed content digest.
    LocalFixture {
        origin: String,
        content_sha256: String,
    },
    /// Manual import bound to the observed content digest.
    Manual { content_sha256: String },
}

impl DatasetSourceIdentity {
    /// Constructs an upstream identity; preparation validates its object-ID syntax.
    pub fn upstream(origin: impl Into<String>, revision: impl Into<String>) -> Self {
        Self::Upstream {
            origin: origin.into(),
            revision: revision.into(),
        }
    }

    /// Constructs a content-addressed local fixture identity.
    pub fn local_fixture(origin: impl Into<String>, content_sha256: impl Into<String>) -> Self {
        Self::LocalFixture {
            origin: origin.into(),
            content_sha256: content_sha256.into(),
        }
    }

    /// Constructs a content-addressed manual identity.
    pub fn manual(content_sha256: impl Into<String>) -> Self {
        Self::Manual {
            content_sha256: content_sha256.into(),
        }
    }

    /// Returns the provenance kind.
    pub const fn provenance(&self) -> DatasetProvenance {
        match self {
            Self::Upstream { .. } => DatasetProvenance::Upstream,
            Self::LocalFixture { .. } => DatasetProvenance::LocalFixture,
            Self::Manual { .. } => DatasetProvenance::Manual,
        }
    }

    /// Returns the resolved origin when the identity has one.
    pub fn origin(&self) -> Option<&str> {
        match self {
            Self::Upstream { origin, .. } | Self::LocalFixture { origin, .. } => Some(origin),
            Self::Manual { .. } => None,
        }
    }

    /// Returns the resolved object ID or content digest.
    pub fn source_revision(&self) -> &str {
        match self {
            Self::Upstream { revision, .. } => revision,
            Self::LocalFixture { content_sha256, .. } | Self::Manual { content_sha256 } => {
                content_sha256
            }
        }
    }

    pub(super) fn cache_bytes(&self) -> String {
        let (kind, origin, revision) = match self {
            Self::Upstream { origin, revision } => ("upstream", origin.as_str(), revision.as_str()),
            Self::LocalFixture {
                origin,
                content_sha256,
            } => ("local_fixture", origin.as_str(), content_sha256.as_str()),
            Self::Manual { content_sha256 } => ("manual", "manual", content_sha256.as_str()),
        };
        format!(
            "dataset-identity-v1\\nKIND_BYTES:{}\\n{}\\nORIGIN_BYTES:{}\\n{}\\nREVISION_BYTES:{}\\n{}\\n",
            kind.len(),
            kind,
            origin.len(),
            origin,
            revision.len(),
            revision,
        )
    }
}

impl fmt::Debug for DatasetSourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatasetSourceIdentity")
            .field("provenance", &self.provenance())
            .field("origin", &"<redacted>")
            .field("source_revision", &"<redacted>")
            .finish()
    }
}

/// Provenance listed in evaluation reports.
#[derive(Clone, Eq, PartialEq)]
pub struct DatasetReport {
    pub(super) source_identity: DatasetSourceIdentity,
    pub(super) checksum: String,
    pub(super) adapter_version: String,
    pub(super) derivation_hash: String,
}

impl DatasetReport {
    /// Resolved source revision or content identity.
    pub fn source_revision(&self) -> &str {
        self.source_identity.source_revision()
    }

    /// Resolved identity, including provenance kind and source origin.
    pub fn source_identity(&self) -> &DatasetSourceIdentity {
        &self.source_identity
    }

    /// Artifact SHA-256.
    pub fn checksum(&self) -> &str {
        &self.checksum
    }

    /// Adapter version from the manifest.
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }

    /// Hash of adapter version, derivation recipe, and artifact checksum.
    pub fn derivation_hash(&self) -> &str {
        &self.derivation_hash
    }
}

impl fmt::Debug for DatasetReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatasetReport")
            .field("source_identity", &self.source_identity)
            .field("adapter_version", &self.adapter_version)
            .field("checksum", &"<redacted>")
            .field("derivation_hash", &"<redacted>")
            .finish()
    }
}

/// Verified local dataset ready for an eval suite.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedDataset {
    pub(super) checksum: String,
    pub(super) source_identity: DatasetSourceIdentity,
    pub(super) adapter_version: String,
    pub(super) derivation_hash: String,
    pub(super) from_cache: bool,
    pub(super) case_ids: Vec<String>,
}

impl PreparedDataset {
    /// Artifact SHA-256.
    pub fn checksum(&self) -> &str {
        &self.checksum
    }

    /// Resolved source revision or content identity.
    pub fn source_revision(&self) -> &str {
        self.source_identity.source_revision()
    }

    /// Resolved identity, including provenance kind and source origin.
    pub fn source_identity(&self) -> &DatasetSourceIdentity {
        &self.source_identity
    }

    /// Hash of the adapter recipe and artifact.
    pub fn derivation_hash(&self) -> &str {
        &self.derivation_hash
    }

    /// Whether the artifact was reused from a verified cache entry.
    pub fn from_cache(&self) -> bool {
        self.from_cache
    }

    /// Deterministic case identities for split discipline.
    pub fn case_ids(&self) -> &[String] {
        &self.case_ids
    }

    /// Report fields: revision, checksum, adapter version, derivation hash.
    pub fn report(&self) -> DatasetReport {
        DatasetReport {
            source_identity: self.source_identity.clone(),
            checksum: self.checksum.clone(),
            adapter_version: self.adapter_version.clone(),
            derivation_hash: self.derivation_hash.clone(),
        }
    }
}

impl fmt::Debug for PreparedDataset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDataset")
            .field("from_cache", &self.from_cache)
            .field("case_count", &self.case_ids.len())
            .field("checksum", &"<redacted>")
            .finish()
    }
}

/// Local file source used by production local/fixture preparation paths.
pub struct LocalFileSource {
    path: PathBuf,
    length: u64,
    identity: DatasetSourceIdentity,
}

impl LocalFileSource {
    /// Opens a local fixture and resolves its content identity from observed bytes.
    pub fn new(path: impl AsRef<Path>, origin: impl Into<String>) -> Result<Self, DatasetError> {
        let path = path.as_ref().to_owned();
        let bytes = fs::read(&path).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let length =
            u64::try_from(bytes.len()).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        Ok(Self {
            path,
            length,
            identity: DatasetSourceIdentity::local_fixture(origin, digest_bytes(&bytes)),
        })
    }
}

impl ByteSource for LocalFileSource {
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        Ok(self.identity.clone())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        File::open(&self.path)
            .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?
            .read_at(buf, offset)
            .map_err(|_| DatasetError::new(DatasetErrorKind::Io))
    }

    fn len(&self) -> Result<u64, DatasetError> {
        Ok(self.length)
    }
}

pub(super) fn is_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(super::SHA256_PREFIX) else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_immutable_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
}

fn is_local_fixture(entry: &DatasetEntry) -> bool {
    entry.url.starts_with("memory://")
}

pub(super) fn is_pinned_entry(entry: &DatasetEntry, suite: EvalSuite) -> bool {
    if entry.distribution == DatasetDistribution::Manual
        || (suite == EvalSuite::Regression && is_local_fixture(entry))
    {
        is_sha256(&entry.sha256)
    } else {
        is_immutable_object_id(&entry.revision)
    }
}

pub(super) fn expected_identity(entry: &DatasetEntry) -> DatasetSourceIdentity {
    if entry.distribution == DatasetDistribution::Manual {
        DatasetSourceIdentity::manual(entry.sha256.clone())
    } else if is_local_fixture(entry) {
        DatasetSourceIdentity::local_fixture(entry.url.clone(), entry.sha256.clone())
    } else {
        DatasetSourceIdentity::upstream(entry.url.clone(), entry.revision.clone())
    }
}

pub(super) fn valid_source_identity(identity: &DatasetSourceIdentity, suite: EvalSuite) -> bool {
    match identity {
        DatasetSourceIdentity::Upstream { origin, revision } => {
            !origin.is_empty()
                && !origin.bytes().any(|byte| byte == b'\n' || byte == b'\0')
                && (!suite.requires_pin() || is_immutable_object_id(revision))
        }
        DatasetSourceIdentity::LocalFixture {
            origin,
            content_sha256,
        } => !origin.is_empty() && is_sha256(content_sha256),
        DatasetSourceIdentity::Manual { content_sha256 } => is_sha256(content_sha256),
    }
}
