use serde::{Deserialize, Serialize};
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageArchiveEntry<'a> {
    path: &'a str,
    bytes: &'a [u8],
    executable: bool,
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

    for entry in entries {
        ensure_safe_path(entry.path)?;
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
    use super::{validate_package, PackageArchiveEntry, PackageFile, PackageManifest};
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

        assert!(validate_package(
            &manifest,
            &[PackageArchiveEntry::new("workflow.toml", bytes, false)]
        )
        .is_ok());
    }

    #[test]
    fn manifest_json_unknown_fields_fail_closed() {
        let result = PackageManifest::from_json(
            r#"{"schema_version":1,"files":[],"CANARY_SECRET_56":"no"}"#,
        );

        assert_eq!(result, Err(super::PackageValidationError::InvalidManifest));
    }
}
