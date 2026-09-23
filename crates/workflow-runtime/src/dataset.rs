//! Pinned dataset registry, resumable fetch, checksums, and license gates.

use std::{
    collections::{HashSet, hash_map::RandomState},
    fmt,
    fs::{self, OpenOptions},
    hash::BuildHasher,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encode_hex;

const SCHEMA_VERSION: u32 = 1;
const SHA256_PREFIX: &str = "sha256:";
const ARTIFACT_NAME: &str = "artifact";
const O_NOFOLLOW: i32 = 0o400000;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Fail-closed dataset registry and fetch errors.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum DatasetErrorKind {
    /// Manifest text is not a valid v1 registry.
    InvalidManifest,
    /// No dataset with the requested id exists.
    UnknownDataset,
    /// Formal suites reject moving branches such as `main`.
    UnpinnedRevision,
    /// Requested eval suite is absent from the dataset's admitted suites.
    SuiteNotAdmitted,
    /// License-gated datasets require explicit acceptance.
    LicenseRequired,
    /// Non-distributable sources must be supplied on a local path.
    ManualPathRequired,
    /// Bytes do not match the pinned SHA-256.
    ChecksumMismatch,
    /// Offline mode found no verified cache entry.
    OfflineMiss,
    /// The source stopped before the artifact was complete.
    Interrupted,
    /// The source could not provide an immutable identity.
    SourceIdentityRequired,
    /// The requested and resolved source identities differ.
    SourceIdentityMismatch,
    /// Cache metadata does not describe the stored artifact.
    InvalidCacheIdentity,
    /// Cache or source IO failed.
    Io,
}

/// Privacy-safe dataset diagnostic.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DatasetError {
    kind: DatasetErrorKind,
}

impl DatasetError {
    pub(crate) const fn new(kind: DatasetErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable typed failure category.
    pub const fn kind(self) -> DatasetErrorKind {
        self.kind
    }
}

impl From<DatasetErrorKind> for DatasetError {
    fn from(kind: DatasetErrorKind) -> Self {
        Self::new(kind)
    }
}

impl fmt::Debug for DatasetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatasetError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Debug for DatasetErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidManifest => "InvalidManifest",
            Self::UnknownDataset => "UnknownDataset",
            Self::UnpinnedRevision => "UnpinnedRevision",
            Self::SuiteNotAdmitted => "SuiteNotAdmitted",
            Self::LicenseRequired => "LicenseRequired",
            Self::ManualPathRequired => "ManualPathRequired",
            Self::ChecksumMismatch => "ChecksumMismatch",
            Self::OfflineMiss => "OfflineMiss",
            Self::Interrupted => "Interrupted",
            Self::SourceIdentityRequired => "SourceIdentityRequired",
            Self::SourceIdentityMismatch => "SourceIdentityMismatch",
            Self::InvalidCacheIdentity => "InvalidCacheIdentity",
            Self::Io => "Io",
        })
    }
}

impl fmt::Display for DatasetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            DatasetErrorKind::InvalidManifest => "dataset manifest is invalid",
            DatasetErrorKind::UnknownDataset => "dataset is unknown",
            DatasetErrorKind::UnpinnedRevision => "dataset revision is unpinned",
            DatasetErrorKind::SuiteNotAdmitted => "dataset is not admitted to the requested suite",
            DatasetErrorKind::LicenseRequired => "dataset license acceptance is required",
            DatasetErrorKind::ManualPathRequired => "dataset requires a manual path",
            DatasetErrorKind::ChecksumMismatch => "dataset checksum mismatch",
            DatasetErrorKind::OfflineMiss => "dataset cache miss in offline mode",
            DatasetErrorKind::Interrupted => "dataset fetch interrupted",
            DatasetErrorKind::SourceIdentityRequired => "dataset source identity is required",
            DatasetErrorKind::SourceIdentityMismatch => "dataset source identity mismatch",
            DatasetErrorKind::InvalidCacheIdentity => "dataset cache identity is invalid",
            DatasetErrorKind::Io => "dataset storage failed",
        })
    }
}

impl std::error::Error for DatasetError {}

/// How a dataset may enter the local cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetDistribution {
    /// Bytes may be fetched through a [`ByteSource`].
    Fetch,
    /// Bytes must be supplied on a local path.
    Manual,
}

/// Suite that consumes a prepared dataset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvalSuite {
    /// Tiny smoke subset.
    Smoke,
    /// Local regression subset.
    Regression,
    /// Formal regression or final evaluation.
    Formal,
}

impl EvalSuite {
    const fn requires_pin(self) -> bool {
        matches!(self, Self::Regression | Self::Formal)
    }

    const fn manifest_name(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Regression => "regression",
            Self::Formal => "final",
        }
    }
}

use dataset_cache_security::{validate_cache_entry_ancestors, validate_root_link_chain};
pub use dataset_http::HttpByteSource;
pub use dataset_identity::{
    DatasetProvenance, DatasetReport, DatasetSourceIdentity, LocalFileSource, PreparedDataset,
};
use dataset_identity::{expected_identity, is_pinned_entry, is_sha256, valid_source_identity};
pub use dataset_parquet::{DatasetCase, ParquetCaseError, decode_parquet_cases};

#[path = "dataset_cache_security.rs"]
mod dataset_cache_security;
#[path = "dataset_http.rs"]
mod dataset_http;
#[path = "dataset_identity.rs"]
mod dataset_identity;
#[path = "dataset_parquet.rs"]
mod dataset_parquet;

/// Byte source used by fetch. Implementations must attest the selected source identity.
pub trait ByteSource {
    /// Returns the identity resolved by this source/provider.
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        Err(DatasetError::new(DatasetErrorKind::SourceIdentityRequired))
    }
    /// Reads up to `buf.len()` bytes starting at `offset`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError>;
    /// Returns the total source length in bytes.
    fn len(&self) -> Result<u64, DatasetError>;
    /// Optional transport pin, checked against the manifest before egress.
    fn expected_sha256(&self) -> Option<&str> {
        None
    }
    /// Returns whether the source is empty.
    fn is_empty(&self) -> Result<bool, DatasetError> {
        Ok(self.len()? == 0)
    }
}

/// Inputs to [`prepare_dataset`].
pub struct PrepareRequest<'a> {
    /// Local cache root. Layout is `<cache>/<id>/<revision>/artifact`.
    pub cache_dir: &'a Path,
    /// Fetch source; ignored for verified cache hits and manual paths.
    pub source: &'a dyn ByteSource,
    /// Consuming evaluation suite.
    pub suite: EvalSuite,
    /// When true, never call the fetch source.
    pub offline: bool,
    /// Explicit license acceptance for gated datasets.
    pub license_accepted: bool,
    /// Operator-supplied path for `distribution = "manual"`.
    pub manual_path: Option<&'a Path>,
}

/// One pinned dataset from `config/datasets.toml`.
#[derive(Clone, Eq, PartialEq)]
pub struct DatasetEntry {
    id: String,
    family: String,
    language: String,
    revision: String,
    url: String,
    sha256: String,
    license: String,
    license_acceptance_required: bool,
    distribution: DatasetDistribution,
    adapter_version: String,
    derivation: String,
    suites: Vec<String>,
}

impl DatasetEntry {
    /// Dataset identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Pinned revision token.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Pinned SHA-256 (`sha256:` + hex).
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Adapter version recorded in the manifest.
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }

    /// Whether fetch requires explicit license acceptance.
    pub fn license_acceptance_required(&self) -> bool {
        self.license_acceptance_required
    }
}

impl fmt::Debug for DatasetEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatasetEntry")
            .field("id", &"<redacted>")
            .field("family", &self.family)
            .field("language", &self.language)
            .field(
                "license_acceptance_required",
                &self.license_acceptance_required,
            )
            .field("distribution", &self.distribution)
            .finish()
    }
}

/// Versioned dataset registry.
#[derive(Clone, Eq, PartialEq)]
pub struct DatasetManifest {
    schema_version: u32,
    datasets: Vec<DatasetEntry>,
}

impl DatasetManifest {
    /// Parses a v1 `datasets.toml` document.
    pub fn parse_str(text: &str) -> Result<Self, DatasetError> {
        let raw: RawManifest = toml::from_str(text)
            .map_err(|_| DatasetError::new(DatasetErrorKind::InvalidManifest))?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(DatasetError::new(DatasetErrorKind::InvalidManifest));
        }
        let mut datasets = Vec::with_capacity(raw.datasets.len());
        let mut ids = HashSet::with_capacity(raw.datasets.len());
        for item in raw.datasets {
            let entry = DatasetEntry::from_raw(item)?;
            if !ids.insert(entry.id.clone()) {
                return Err(DatasetError::new(DatasetErrorKind::InvalidManifest));
            }
            datasets.push(entry);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            datasets,
        })
    }

    /// Encodes the registry as TOML.
    pub fn to_toml(&self) -> Result<String, DatasetError> {
        let raw = RawManifest {
            schema_version: self.schema_version,
            datasets: self.datasets.iter().map(DatasetEntry::to_raw).collect(),
        };
        toml::to_string(&raw).map_err(|_| DatasetError::new(DatasetErrorKind::InvalidManifest))
    }

    /// Returns the named dataset.
    pub fn dataset(&self, id: &str) -> Option<&DatasetEntry> {
        self.datasets.iter().find(|entry| entry.id == id)
    }
}

impl fmt::Debug for DatasetManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatasetManifest")
            .field("schema_version", &self.schema_version)
            .field("dataset_count", &self.datasets.len())
            .finish()
    }
}

/// Fetches or reuses a pinned dataset. Independent of live model execution.
pub fn prepare_dataset(
    manifest: &DatasetManifest,
    id: &str,
    request: &PrepareRequest<'_>,
) -> Result<PreparedDataset, DatasetError> {
    let entry = manifest
        .dataset(id)
        .ok_or(DatasetError::new(DatasetErrorKind::UnknownDataset))?;
    if !entry
        .suites
        .iter()
        .any(|suite| suite == request.suite.manifest_name())
    {
        return Err(DatasetError::new(DatasetErrorKind::SuiteNotAdmitted));
    }
    if entry.license_acceptance_required && !request.license_accepted {
        return Err(DatasetError::new(DatasetErrorKind::LicenseRequired));
    }
    if request.suite.requires_pin() && !is_pinned_entry(entry, request.suite) {
        return Err(DatasetError::new(DatasetErrorKind::UnpinnedRevision));
    }
    let cache_root = validated_dataset_cache_root(request.cache_dir)?;
    let expected_identity = expected_identity(entry);
    let dest = artifact_path(&cache_root, entry)?;
    validate_cache_entry_ancestors(&cache_root, &dest)?;
    if let Some(prepared) = load_verified(entry, &dest, &cache_root, &expected_identity)? {
        return Ok(prepared);
    }
    match entry.distribution {
        DatasetDistribution::Manual => {
            let path = request
                .manual_path
                .ok_or(DatasetError::new(DatasetErrorKind::ManualPathRequired))?;
            copy_manual(entry, path, &dest, &cache_root, &expected_identity)
        }
        DatasetDistribution::Fetch => {
            if request.offline {
                return Err(DatasetError::new(DatasetErrorKind::OfflineMiss));
            }
            fetch_resumable(
                entry,
                request.source,
                &dest,
                &cache_root,
                &expected_identity,
                request.suite,
            )
        }
    }
}

#[derive(Deserialize, Serialize)]
struct RawManifest {
    schema_version: u32,
    datasets: Vec<RawDataset>,
}

#[derive(Deserialize, Serialize)]
struct RawDataset {
    id: String,
    family: String,
    language: String,
    revision: String,
    url: String,
    sha256: String,
    license: String,
    license_acceptance_required: bool,
    distribution: DatasetDistribution,
    adapter_version: String,
    derivation: String,
    suites: Vec<String>,
}

impl DatasetEntry {
    fn from_raw(raw: RawDataset) -> Result<Self, DatasetError> {
        for value in [
            &raw.id,
            &raw.family,
            &raw.language,
            &raw.revision,
            &raw.url,
            &raw.license,
            &raw.adapter_version,
            &raw.derivation,
        ] {
            if value.is_empty() {
                return Err(DatasetError::new(DatasetErrorKind::InvalidManifest));
            }
        }
        if !is_safe_token(&raw.id) || !is_safe_token(&raw.revision) {
            return Err(DatasetError::new(DatasetErrorKind::InvalidManifest));
        }
        if !is_sha256(&raw.sha256) {
            return Err(DatasetError::new(DatasetErrorKind::InvalidManifest));
        }
        Ok(Self {
            id: raw.id,
            family: raw.family,
            language: raw.language,
            revision: raw.revision,
            url: raw.url,
            sha256: raw.sha256,
            license: raw.license,
            license_acceptance_required: raw.license_acceptance_required,
            distribution: raw.distribution,
            adapter_version: raw.adapter_version,
            derivation: raw.derivation,
            suites: raw.suites,
        })
    }

    fn to_raw(&self) -> RawDataset {
        RawDataset {
            id: self.id.clone(),
            family: self.family.clone(),
            language: self.language.clone(),
            revision: self.revision.clone(),
            url: self.url.clone(),
            sha256: self.sha256.clone(),
            license: self.license.clone(),
            license_acceptance_required: self.license_acceptance_required,
            distribution: self.distribution,
            adapter_version: self.adapter_version.clone(),
            derivation: self.derivation.clone(),
            suites: self.suites.clone(),
        }
    }
}

fn is_safe_token(value: &str) -> bool {
    !matches!(value, "." | "..")
        && !value.is_empty()
        && value.bytes().all(
            |byte| matches!(byte, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'.' | b'_' | b'-'),
        )
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{SHA256_PREFIX}{}", encode_hex(&Sha256::digest(bytes)))
}

fn frame(label: &str, value: &str) -> String {
    format!("{label}_BYTES:{}\n{value}", value.len())
}

fn derivation_hash(entry: &DatasetEntry) -> String {
    let framed = [
        frame("ADAPTER_VERSION", &entry.adapter_version),
        frame("DERIVATION", &entry.derivation),
        frame("SHA256", &entry.sha256),
        frame("FAMILY", &entry.family),
        frame("LANGUAGE", &entry.language),
    ]
    .join("\n");
    digest_bytes(framed.as_bytes())
}

fn case_id(entry: &DatasetEntry) -> String {
    format!("{}/{}/{}/0000", entry.id, entry.family, entry.language)
}

fn prepared(
    entry: &DatasetEntry,
    source_identity: &DatasetSourceIdentity,
    from_cache: bool,
) -> PreparedDataset {
    PreparedDataset {
        checksum: entry.sha256.clone(),
        source_identity: source_identity.clone(),
        adapter_version: entry.adapter_version.clone(),
        derivation_hash: derivation_hash(entry),
        from_cache,
        case_ids: vec![case_id(entry)],
    }
}

fn artifact_path(cache_dir: &Path, entry: &DatasetEntry) -> Result<PathBuf, DatasetError> {
    if !is_safe_token(&entry.id) || !is_safe_token(&entry.revision) {
        return Err(DatasetError::new(DatasetErrorKind::InvalidManifest));
    }
    let relative = Path::new(&entry.id)
        .join(&entry.revision)
        .join(ARTIFACT_NAME);
    let dest = cache_dir.join(&relative);
    if dest.strip_prefix(cache_dir) != Ok(relative.as_path()) {
        return Err(DatasetError::new(DatasetErrorKind::Io));
    }
    Ok(dest)
}

fn safe_directory_metadata(metadata: &fs::Metadata) -> bool {
    let mode = metadata.mode();
    metadata.is_dir() && mode & 0o020 == 0 && (mode & 0o002 == 0 || mode & 0o1000 != 0)
}

fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn validate_directory_ancestry(path: &Path) -> Result<(), DatasetError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        if metadata.file_type().is_symlink() || !safe_directory_metadata(&metadata) {
            return Err(DatasetError::new(DatasetErrorKind::Io));
        }
    }
    Ok(())
}

/// Validates the configured cache root and binds later paths to its checked target.
/// Callers publishing reports must use the returned path, not reopen the root link.
pub fn validated_dataset_cache_root(cache_dir: &Path) -> Result<PathBuf, DatasetError> {
    let root = validate_cache_root(cache_dir)?;
    match fs::symlink_metadata(cache_dir) {
        Ok(_) => validate_root_link_chain(cache_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
    }
    validate_cache_entry_ancestors(cache_dir, &cache_dir.join(ARTIFACT_NAME))?;
    Ok(root)
}

fn validate_cache_root(cache_dir: &Path) -> Result<PathBuf, DatasetError> {
    let metadata = match fs::symlink_metadata(cache_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            reject_symlink_components(cache_dir, None)?;
            return Ok(cache_dir.to_owned());
        }
        Err(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
    };
    if metadata.file_type().is_symlink() {
        let link_target =
            fs::read_link(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let canonical_target =
            fs::canonicalize(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let before =
            fs::metadata(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        validate_directory_ancestry(&canonical_target)?;
        let canonical_again =
            fs::canonicalize(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let after = fs::metadata(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let link_target_again =
            fs::read_link(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        if canonical_target != canonical_again
            || link_target != link_target_again
            || !same_identity(&before, &after)
        {
            return Err(DatasetError::new(DatasetErrorKind::Io));
        }
        return Ok(canonical_target);
    }
    let canonical_root =
        fs::canonicalize(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    validate_directory_ancestry(&canonical_root)?;
    let after = fs::metadata(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    if !same_identity(&metadata, &after) {
        return Err(DatasetError::new(DatasetErrorKind::Io));
    }
    Ok(canonical_root)
}

fn reject_symlink_components(path: &Path, allowed_root: Option<&Path>) -> Result<(), DatasetError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata)
                if metadata.file_type().is_symlink() && allowed_root != Some(current.as_path()) =>
            {
                return Err(DatasetError::new(DatasetErrorKind::Io));
            }
            Ok(metadata)
                if current != path
                    && !metadata.is_dir()
                    && allowed_root != Some(current.as_path()) =>
            {
                return Err(DatasetError::new(DatasetErrorKind::Io));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
        }
    }
    Ok(())
}

fn temp_prefix(dest: &Path) -> Result<String, DatasetError> {
    Ok(format!(
        ".tmp-{}-",
        dest.file_name()
            .ok_or(DatasetError::new(DatasetErrorKind::Io))?
            .to_string_lossy()
    ))
}

fn partial_path(dest: &Path) -> Result<PathBuf, DatasetError> {
    let name = dest
        .file_name()
        .ok_or(DatasetError::new(DatasetErrorKind::Io))?;
    let mut leaf = name.to_os_string();
    leaf.push(".partial");
    Ok(dest.with_file_name(leaf))
}

fn identity_path(dest: &Path) -> PathBuf {
    dest.with_file_name(format!(
        "{}.identity",
        dest.file_name().unwrap_or_default().to_string_lossy()
    ))
}

fn load_verified(
    entry: &DatasetEntry,
    dest: &Path,
    cache_dir: &Path,
    expected_identity: &DatasetSourceIdentity,
) -> Result<Option<PreparedDataset>, DatasetError> {
    reject_symlink_components(dest, Some(cache_dir))?;
    let identity = identity_path(dest);
    reject_symlink_components(&identity, Some(cache_dir))?;
    match fs::read(dest) {
        Ok(bytes) => {
            if digest_bytes(&bytes) != entry.sha256 {
                return Err(DatasetError::new(DatasetErrorKind::ChecksumMismatch));
            }
            let stored = match fs::read(&identity) {
                Ok(stored) => stored,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
            };
            if stored != expected_identity.cache_bytes().into_bytes() {
                return Ok(None);
            }
            Ok(Some(prepared(entry, expected_identity, true)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(DatasetError::new(DatasetErrorKind::Io)),
    }
}

fn ensure_parent(dest: &Path, cache_dir: &Path) -> Result<(), DatasetError> {
    reject_symlink_components(dest, Some(cache_dir))?;
    let parent = dest
        .parent()
        .ok_or(DatasetError::new(DatasetErrorKind::Io))?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(parent)
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    reject_symlink_components(dest, Some(cache_dir))?;
    validate_cache_entry_ancestors(cache_dir, dest)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    validate_directory_ancestry(&canonical_parent)
}

fn publish(dest: &Path, bytes: &[u8], cache_dir: &Path) -> Result<(), DatasetError> {
    ensure_parent(dest, cache_dir)?;
    let parent = dest
        .parent()
        .ok_or(DatasetError::new(DatasetErrorKind::Io))?;
    let prefix = temp_prefix(dest)?;
    for entry in fs::read_dir(parent).map_err(|_| DatasetError::new(DatasetErrorKind::Io))? {
        let entry = entry.map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            return Err(DatasetError::new(DatasetErrorKind::Io));
        }
    }
    let nonce = RandomState::new().hash_one((
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
    ));
    let tmp = parent.join(format!("{prefix}{nonce:016x}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&tmp)
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&tmp);
        return Err(DatasetError::new(DatasetErrorKind::Io));
    }
    drop(file);
    reject_symlink_components(&tmp, Some(cache_dir))?;
    reject_symlink_components(dest, Some(cache_dir))?;
    fs::rename(&tmp, dest).map_err(|_| {
        let _ = fs::remove_file(&tmp);
        DatasetError::new(DatasetErrorKind::Io)
    })
}

fn copy_manual(
    entry: &DatasetEntry,
    path: &Path,
    dest: &Path,
    cache_dir: &Path,
    expected_identity: &DatasetSourceIdentity,
) -> Result<PreparedDataset, DatasetError> {
    reject_symlink_components(path, None)?;
    let bytes = fs::read(path).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    if digest_bytes(&bytes) != entry.sha256 {
        return Err(DatasetError::new(DatasetErrorKind::ChecksumMismatch));
    }
    if !valid_source_identity(expected_identity, EvalSuite::Smoke) {
        return Err(DatasetError::new(DatasetErrorKind::SourceIdentityMismatch));
    }
    publish(dest, &bytes, cache_dir)?;
    publish(
        &identity_path(dest),
        expected_identity.cache_bytes().as_bytes(),
        cache_dir,
    )?;
    Ok(prepared(entry, expected_identity, false))
}

fn fetch_resumable(
    entry: &DatasetEntry,
    source: &dyn ByteSource,
    dest: &Path,
    cache_dir: &Path,
    expected_identity: &DatasetSourceIdentity,
    suite: EvalSuite,
) -> Result<PreparedDataset, DatasetError> {
    let actual_identity = source.identity()?;
    if &actual_identity != expected_identity || !valid_source_identity(&actual_identity, suite) {
        return Err(DatasetError::new(DatasetErrorKind::SourceIdentityMismatch));
    }
    if source
        .expected_sha256()
        .is_some_and(|pin| pin != entry.sha256)
    {
        return Err(DatasetError::new(DatasetErrorKind::ChecksumMismatch));
    }
    ensure_parent(dest, cache_dir)?;
    let partial = partial_path(dest)?;
    let partial_identity = identity_path(&partial);
    reject_symlink_components(&partial, Some(cache_dir))?;
    reject_symlink_components(&partial_identity, Some(cache_dir))?;
    let identity_bytes = expected_identity.cache_bytes().into_bytes();
    match fs::read(&partial_identity) {
        Ok(stored) if stored != identity_bytes => {
            return Err(DatasetError::new(DatasetErrorKind::SourceIdentityMismatch));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if fs::symlink_metadata(&partial).is_ok() {
                return Err(DatasetError::new(DatasetErrorKind::SourceIdentityMismatch));
            }
            publish(&partial_identity, &identity_bytes, cache_dir)?;
        }
        Err(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
    }
    let expected = source.len()?;
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .custom_flags(O_NOFOLLOW)
        .open(&partial)
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    let metadata = file
        .metadata()
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(DatasetError::new(DatasetErrorKind::Io));
    }
    let mut offset = file
        .seek(SeekFrom::End(0))
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    let mut buf = [0_u8; 4096];
    while offset < expected {
        let read = source.read_at(offset, &mut buf)?;
        if read == 0 {
            file.flush()
                .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
            return Err(DatasetError::new(DatasetErrorKind::Interrupted));
        }
        file.write_all(&buf[..read])
            .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        offset += u64::try_from(read).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    }
    file.flush()
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    drop(file);
    reject_symlink_components(&partial, Some(cache_dir))?;
    let bytes = fs::read(&partial).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    if digest_bytes(&bytes) != entry.sha256 {
        fs::remove_file(&partial).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let _ = fs::remove_file(&partial_identity);
        return Err(DatasetError::new(DatasetErrorKind::ChecksumMismatch));
    }
    reject_symlink_components(dest, Some(cache_dir))?;
    fs::rename(&partial, dest).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    publish(&identity_path(dest), &identity_bytes, cache_dir)?;
    let _ = fs::remove_file(&partial_identity);
    Ok(prepared(entry, expected_identity, false))
}
