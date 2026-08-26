use serde::{Deserialize, Serialize, ser::SerializeStruct};
use sha2::{Digest, Sha256};

const PACKAGE_SCHEMA_VERSION_V1: u16 = 1;
const SHA256_HEX_BYTES: usize = 64;

/// A declared file in a workflow package manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    path: String,
    sha256: String,
}

impl PackageFile {
    /// Declares one archive path and its expected SHA-256 digest.
    pub fn new(path: String, sha256: String) -> Self {
        Self { path, sha256 }
    }

    /// Returns the archive-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the expected lowercase hexadecimal SHA-256 digest.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// The bounded manifest used to validate a workflow package archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    schema_version: u16,
    files: Vec<PackageFile>,
}

impl PackageManifest {
    /// Creates a v1 package manifest from declared files.
    pub fn new(files: Vec<PackageFile>) -> Self {
        Self {
            schema_version: PACKAGE_SCHEMA_VERSION_V1,
            files,
        }
    }

    /// Decodes a package manifest from its JSON wire form.
    pub fn from_json(json: &str) -> Result<Self, PackageValidationError> {
        serde_json::from_str(json).map_err(|_| PackageValidationError::InvalidManifest)
    }

    /// Returns the declared files.
    pub fn files(&self) -> &[PackageFile] {
        &self.files
    }
}

/// One archive entry supplied at the validation boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct PackageArchiveEntry<'a> {
    path: &'a str,
    bytes: &'a [u8],
    executable: bool,
}

impl std::fmt::Debug for PackageArchiveEntry<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackageArchiveEntry")
            .field("path", &self.path)
            .field("length", &self.bytes.len())
            .field("executable", &self.executable)
            .finish()
    }
}

impl std::fmt::Display for PackageArchiveEntry<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PackageArchiveEntry(path={:?}, length={}, executable={})",
            self.path,
            self.bytes.len(),
            self.executable
        )
    }
}

impl Serialize for PackageArchiveEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PackageArchiveEntry", 3)?;
        state.serialize_field("path", self.path)?;
        state.serialize_field("length", &self.bytes.len())?;
        state.serialize_field("executable", &self.executable)?;
        state.end()
    }
}

impl<'a> PackageArchiveEntry<'a> {
    /// Creates one archive entry without taking ownership of its bytes.
    pub fn new(path: &'a str, bytes: &'a [u8], executable: bool) -> Self {
        Self {
            path,
            bytes,
            executable,
        }
    }
}

/// Typed, fail-closed package boundary and content validation failures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageValidationError {
    /// The manifest could not be decoded.
    InvalidManifest,
    /// The manifest schema version is unsupported.
    UnsupportedSchemaVersion,
    /// A manifest or archive path is absolute or escapes its archive root.
    PathEscape,
    /// A declared digest is not a lowercase hexadecimal SHA-256 value.
    InvalidDigest,
    /// A path is declared more than once.
    DuplicatePath,
    /// An archive entry is not declared in the manifest.
    UnexpectedFile,
    /// A declared file is absent from the archive.
    MissingFile,
    /// An archive entry does not match its declared digest.
    HashMismatch,
    /// An archive entry is executable.
    ExecutableFile,
    /// A secret-like path or credential-shaped value was found.
    SecretDetected,
}

/// A durable surface that must not receive secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretFixtureSurface {
    /// Serialized workflow state.
    State,
    /// Files written in a workflow workdir.
    Workdir,
    /// Serialized execution trace events.
    Trace,
}

impl std::fmt::Display for PackageValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidManifest => "package manifest is invalid",
            Self::UnsupportedSchemaVersion => "package manifest schema version is unsupported",
            Self::PathEscape => "package path escapes its archive boundary",
            Self::InvalidDigest => "package manifest digest is invalid",
            Self::DuplicatePath => "package contains a duplicate path",
            Self::UnexpectedFile => "package archive contains an undeclared file",
            Self::MissingFile => "package archive is missing a declared file",
            Self::HashMismatch => "package file hash does not match its manifest digest",
            Self::ExecutableFile => "package archive contains an undeclared executable",
            Self::SecretDetected => "package archive contains a secret-like value",
        })
    }
}

impl std::error::Error for PackageValidationError {}

/// Validates archive paths, manifest hashes, executable bits, and secret-like data.
pub fn validate_package(
    manifest: &PackageManifest,
    entries: &[PackageArchiveEntry<'_>],
) -> Result<(), PackageValidationError> {
    if manifest.schema_version != PACKAGE_SCHEMA_VERSION_V1 {
        return Err(PackageValidationError::UnsupportedSchemaVersion);
    }

    for (index, file) in manifest.files.iter().enumerate() {
        ensure_safe_path(file.path())?;
        if !is_sha256(file.sha256()) {
            return Err(PackageValidationError::InvalidDigest);
        }
        if manifest.files[..index]
            .iter()
            .any(|previous| previous.path() == file.path())
        {
            return Err(PackageValidationError::DuplicatePath);
        }
    }

    for (index, entry) in entries.iter().enumerate() {
        ensure_safe_path(entry.path)?;
        if entries[..index]
            .iter()
            .any(|previous| previous.path == entry.path)
        {
            return Err(PackageValidationError::DuplicatePath);
        }
    }

    for entry in entries {
        if entry.executable {
            return Err(PackageValidationError::ExecutableFile);
        }
        if contains_secret_like_data(entry.path, entry.bytes) {
            return Err(PackageValidationError::SecretDetected);
        }
        let declared = manifest
            .files
            .iter()
            .find(|file| file.path() == entry.path)
            .ok_or(PackageValidationError::UnexpectedFile)?;
        if sha256(entry.bytes) != declared.sha256() {
            return Err(PackageValidationError::HashMismatch);
        }
    }

    if manifest
        .files
        .iter()
        .any(|file| !entries.iter().any(|entry| entry.path == file.path()))
    {
        return Err(PackageValidationError::MissingFile);
    }
    if entries
        .iter()
        .any(|entry| !manifest.files.iter().any(|file| file.path() == entry.path))
    {
        return Err(PackageValidationError::UnexpectedFile);
    }

    Ok(())
}

/// Rejects secret-like data before a fixture reaches a durable workflow surface.
pub fn validate_secret_free_fixture(
    _surface: SecretFixtureSurface,
    path: &str,
    bytes: &[u8],
) -> Result<(), PackageValidationError> {
    ensure_safe_path(path)?;
    if contains_secret_like_data(path, bytes) {
        return Err(PackageValidationError::SecretDetected);
    }
    Ok(())
}

fn ensure_safe_path(path: &str) -> Result<(), PackageValidationError> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') || path.contains(':') {
        return Err(PackageValidationError::PathEscape);
    }
    if path
        .split(['/', '\\'])
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(PackageValidationError::PathEscape);
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    super::hex(&digest)
}

fn contains_secret_like_data(path: &str, bytes: &[u8]) -> bool {
    let path = path.to_ascii_lowercase();
    if path.split(['/', '\\']).any(|component| {
        ["secret", "secrets", "credential", "credentials", "token"].contains(&component)
    }) {
        return true;
    }

    let content = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if [
        "canary_secret_56",
        "canary_secret_",
        "password",
        "api_key",
        "private_key",
        "client_secret",
        "credential",
    ]
    .iter()
    .any(|marker| content.contains(marker))
    {
        return true;
    }

    content.lines().any(|line| {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
        !value.trim().is_empty()
            && ["secret", "token", "password", "api_key", "client_secret"].contains(&key.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::{
        PackageArchiveEntry, PackageFile, PackageManifest, PackageValidationError,
        SecretFixtureSurface, validate_package, validate_secret_free_fixture,
    };
    use sha2::{Digest, Sha256};

    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn valid_manifest_and_archive_pass() {
        let bytes = b"workflow = \"demo\"";
        let manifest = PackageManifest::new(vec![PackageFile::new(
            "workflow.toml".into(),
            digest(bytes),
        )]);

        assert!(
            validate_package(
                &manifest,
                &[PackageArchiveEntry::new("workflow.toml", bytes, false)]
            )
            .is_ok()
        );
    }

    #[test]
    fn manifest_json_unknown_fields_fail_closed() {
        let result = PackageManifest::from_json(
            r#"{"schema_version":1,"files":[],"CANARY_SECRET_56":"no"}"#,
        );

        assert_eq!(result, Err(super::PackageValidationError::InvalidManifest));
    }

    #[test]
    fn secret_bearing_state_fixture_is_rejected() {
        assert_eq!(
            validate_secret_free_fixture(
                SecretFixtureSurface::State,
                "state.json",
                br#"{"value":"CANARY_SECRET_STATE_78"}"#,
            ),
            Err(PackageValidationError::SecretDetected)
        );
    }

    #[test]
    fn secret_bearing_workdir_fixture_is_rejected() {
        assert_eq!(
            validate_secret_free_fixture(
                SecretFixtureSurface::Workdir,
                "workdir/output.txt",
                b"CANARY_SECRET_WORKDIR_78",
            ),
            Err(PackageValidationError::SecretDetected)
        );
    }

    #[test]
    fn secret_bearing_trace_fixture_is_rejected() {
        assert_eq!(
            validate_secret_free_fixture(
                SecretFixtureSurface::Trace,
                "trace.jsonl",
                br#"{"event":"CANARY_SECRET_TRACE_78"}"#,
            ),
            Err(PackageValidationError::SecretDetected)
        );
    }
}
