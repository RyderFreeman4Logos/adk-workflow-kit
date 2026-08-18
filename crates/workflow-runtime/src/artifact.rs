use std::{
    collections::HashMap,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    num::NonZeroU64,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use sha2::{Digest, Sha256};

use crate::encode_hex;

/// An opaque content identifier derived from stored bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// Returns the lowercase hexadecimal SHA-256 content identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded byte-page request for an artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageRequest {
    offset: u64,
    limit: NonZeroU64,
}

impl PageRequest {
    /// Creates a page request at `offset` with a positive byte limit.
    pub fn new(offset: u64, limit: NonZeroU64) -> Self {
        Self { offset, limit }
    }

    /// Returns the requested byte offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the requested positive byte limit.
    pub fn limit(&self) -> NonZeroU64 {
        self.limit
    }
}

/// One bounded page of opaque artifact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactPage {
    bytes: Vec<u8>,
    next_offset: Option<u64>,
}

impl ArtifactPage {
    /// Returns the page bytes without interpreting them.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns ownership of the opaque page bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the offset for the next page when unread bytes remain.
    pub fn next_offset(&self) -> Option<u64> {
        self.next_offset
    }
}

/// Metadata that records artifact retention without enforcing expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionPolicy {
    /// Retains the artifact until a later policy update.
    Retain,
    /// Records a caller-supplied expiration time without deleting the artifact.
    ExpiresAt(SystemTime),
}

/// A stable artifact operation failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactErrorKind {
    /// Content was empty.
    EmptyContent,
    /// Content exceeded the store's configured limit.
    ContentTooLarge,
    /// A page offset exceeded the stored content length.
    PageOutOfBounds,
    /// The requested artifact was absent.
    NotFound,
    /// Matching content IDs referred to different bytes.
    ContentIdCollision,
    /// The underlying storage failed while reading or writing content.
    Io,
}

/// A categorized artifact failure with a privacy-safe message.
#[derive(Debug)]
pub struct ArtifactError {
    kind: ArtifactErrorKind,
}

impl ArtifactError {
    fn new(kind: ArtifactErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    pub fn kind(&self) -> ArtifactErrorKind {
        self.kind
    }
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ArtifactErrorKind::EmptyContent => "artifact content must not be empty",
            ArtifactErrorKind::ContentTooLarge => "artifact content exceeds the configured limit",
            ArtifactErrorKind::PageOutOfBounds => "artifact page offset is out of bounds",
            ArtifactErrorKind::NotFound => "artifact was not found",
            ArtifactErrorKind::ContentIdCollision => "artifact content ID collision",
            ArtifactErrorKind::Io => "storage I/O error",
        })
    }
}

impl std::error::Error for ArtifactError {}

/// Stores and retrieves opaque artifacts with explicit retention metadata.
pub trait ArtifactStore {
    /// Stores `bytes` and returns their content identifier.
    fn put(&mut self, bytes: &[u8]) -> Result<ArtifactId, ArtifactError>;

    /// Reads one bounded page of an artifact.
    fn read_page(
        &self,
        id: &ArtifactId,
        request: PageRequest,
    ) -> Result<ArtifactPage, ArtifactError>;

    /// Records the retention policy for an existing artifact.
    fn set_retention(
        &mut self,
        id: &ArtifactId,
        policy: RetentionPolicy,
    ) -> Result<(), ArtifactError>;

    /// Returns the recorded retention policy for an existing artifact.
    fn retention(&self, id: &ArtifactId) -> Result<RetentionPolicy, ArtifactError>;
}

struct Entry {
    bytes: Vec<u8>,
    retention: RetentionPolicy,
}

/// An in-memory implementation of [`ArtifactStore`].
pub struct InMemoryArtifactStore {
    entries: HashMap<ArtifactId, Entry>,
    max_content_bytes: NonZeroU64,
    max_page_bytes: NonZeroU64,
}

impl InMemoryArtifactStore {
    /// Creates an empty store with public positive content and page limits.
    pub fn new(max_content_bytes: NonZeroU64, max_page_bytes: NonZeroU64) -> Self {
        Self {
            entries: HashMap::new(),
            max_content_bytes,
            max_page_bytes,
        }
    }
}

impl ArtifactStore for InMemoryArtifactStore {
    fn put(&mut self, bytes: &[u8]) -> Result<ArtifactId, ArtifactError> {
        if bytes.is_empty() {
            return Err(ArtifactError::new(ArtifactErrorKind::EmptyContent));
        }
        if u64::try_from(bytes.len()).map_or(true, |length| length > self.max_content_bytes.get()) {
            return Err(ArtifactError::new(ArtifactErrorKind::ContentTooLarge));
        }

        let id = ArtifactId(encode_hex(&Sha256::digest(bytes)));
        match self.entries.get(&id) {
            Some(entry) if entry.bytes.as_slice() == bytes => Ok(id),
            Some(_) => Err(ArtifactError::new(ArtifactErrorKind::ContentIdCollision)),
            None => {
                self.entries.insert(
                    id.clone(),
                    Entry {
                        bytes: bytes.to_vec(),
                        retention: RetentionPolicy::Retain,
                    },
                );
                Ok(id)
            }
        }
    }

    fn read_page(
        &self,
        id: &ArtifactId,
        request: PageRequest,
    ) -> Result<ArtifactPage, ArtifactError> {
        let entry = self
            .entries
            .get(id)
            .ok_or_else(|| ArtifactError::new(ArtifactErrorKind::NotFound))?;
        let content_len = u64::try_from(entry.bytes.len())
            .map_err(|_| ArtifactError::new(ArtifactErrorKind::ContentTooLarge))?;
        if request.offset > content_len {
            return Err(ArtifactError::new(ArtifactErrorKind::PageOutOfBounds));
        }

        let page_len = request
            .limit
            .get()
            .min(self.max_page_bytes.get())
            .min(content_len - request.offset);
        let end_offset = request
            .offset
            .checked_add(page_len)
            .ok_or_else(|| ArtifactError::new(ArtifactErrorKind::PageOutOfBounds))?;
        let start = usize::try_from(request.offset)
            .map_err(|_| ArtifactError::new(ArtifactErrorKind::PageOutOfBounds))?;
        let end = usize::try_from(end_offset)
            .map_err(|_| ArtifactError::new(ArtifactErrorKind::PageOutOfBounds))?;

        Ok(ArtifactPage {
            bytes: entry.bytes[start..end].to_vec(),
            next_offset: (end_offset < content_len).then_some(end_offset),
        })
    }

    fn set_retention(
        &mut self,
        id: &ArtifactId,
        policy: RetentionPolicy,
    ) -> Result<(), ArtifactError> {
        let entry = self
            .entries
            .get_mut(id)
            .ok_or_else(|| ArtifactError::new(ArtifactErrorKind::NotFound))?;
        entry.retention = policy;
        Ok(())
    }

    fn retention(&self, id: &ArtifactId) -> Result<RetentionPolicy, ArtifactError> {
        self.entries
            .get(id)
            .map(|entry| entry.retention)
            .ok_or_else(|| ArtifactError::new(ArtifactErrorKind::NotFound))
    }
}

/// Stores and retrieves opaque artifacts as content-addressed files on disk.
///
/// Each stored artifact is one file named by its lowercase hex SHA-256 ID,
/// so hostile bytes never reach the filesystem path. Writes are atomic
/// (temp + fsync + rename); retention is metadata kept alongside the store
/// and never triggers deletion.
pub struct FilesystemArtifactStore {
    root: PathBuf,
    retention: HashMap<ArtifactId, RetentionPolicy>,
    max_content_bytes: NonZeroU64,
    max_page_bytes: NonZeroU64,
}

impl FilesystemArtifactStore {
    /// Creates an empty store rooted at `root`, creating the directory if needed.
    pub fn new(
        root: impl AsRef<Path>,
        max_content_bytes: NonZeroU64,
        max_page_bytes: NonZeroU64,
    ) -> Self {
        fs::create_dir_all(root.as_ref()).expect("configured store root must be created");
        Self {
            root: root.as_ref().to_path_buf(),
            retention: HashMap::new(),
            max_content_bytes,
            max_page_bytes,
        }
    }

    /// Removes the entire store directory; later reads become `NotFound`.
    pub fn remove_all(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }

    fn path_for(&self, id: &ArtifactId) -> PathBuf {
        self.root.join(id.as_str())
    }

    fn storage_error(error: io::Error) -> ArtifactError {
        ArtifactError::new(if error.kind() == io::ErrorKind::NotFound {
            ArtifactErrorKind::NotFound
        } else {
            ArtifactErrorKind::Io
        })
    }
}

impl ArtifactStore for FilesystemArtifactStore {
    fn put(&mut self, bytes: &[u8]) -> Result<ArtifactId, ArtifactError> {
        if bytes.is_empty() {
            return Err(ArtifactError::new(ArtifactErrorKind::EmptyContent));
        }
        if u64::try_from(bytes.len()).map_or(true, |length| length > self.max_content_bytes.get()) {
            return Err(ArtifactError::new(ArtifactErrorKind::ContentTooLarge));
        }

        let id = ArtifactId(encode_hex(&Sha256::digest(bytes)));
        let final_path = self.path_for(&id);
        match fs::read(&final_path) {
            Ok(existing) => {
                if existing.as_slice() != bytes {
                    return Err(ArtifactError::new(ArtifactErrorKind::ContentIdCollision));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Fresh content: atomic write, mirroring workdir.rs publication.
                let temporary = self.root.join(format!(".tmp-{}", id.as_str()));
                let result = (|| {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&temporary)
                        .map_err(Self::storage_error)?;
                    file.write_all(bytes).map_err(Self::storage_error)?;
                    file.sync_all().map_err(Self::storage_error)?;
                    drop(file);
                    fs::rename(&temporary, &final_path).map_err(Self::storage_error)
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&temporary);
                }
                result?;
            }
            Err(error) => return Err(Self::storage_error(error)),
        }

        self.retention
            .entry(id.clone())
            .or_insert(RetentionPolicy::Retain);
        Ok(id)
    }

    fn read_page(
        &self,
        id: &ArtifactId,
        request: PageRequest,
    ) -> Result<ArtifactPage, ArtifactError> {
        let bytes = fs::read(self.path_for(id)).map_err(Self::storage_error)?;
        let content_len = u64::try_from(bytes.len())
            .map_err(|_| ArtifactError::new(ArtifactErrorKind::ContentTooLarge))?;
        if request.offset > content_len {
            return Err(ArtifactError::new(ArtifactErrorKind::PageOutOfBounds));
        }

        let page_len = request
            .limit
            .get()
            .min(self.max_page_bytes.get())
            .min(content_len - request.offset);
        let end_offset = request
            .offset
            .checked_add(page_len)
            .ok_or_else(|| ArtifactError::new(ArtifactErrorKind::PageOutOfBounds))?;
        let start = usize::try_from(request.offset)
            .map_err(|_| ArtifactError::new(ArtifactErrorKind::PageOutOfBounds))?;
        let end = usize::try_from(end_offset)
            .map_err(|_| ArtifactError::new(ArtifactErrorKind::PageOutOfBounds))?;

        Ok(ArtifactPage {
            bytes: bytes[start..end].to_vec(),
            next_offset: (end_offset < content_len).then_some(end_offset),
        })
    }

    fn set_retention(
        &mut self,
        id: &ArtifactId,
        policy: RetentionPolicy,
    ) -> Result<(), ArtifactError> {
        match fs::metadata(self.path_for(id)) {
            Ok(_) => self.retention.insert(id.clone(), policy),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ArtifactError::new(ArtifactErrorKind::NotFound))
            }
            Err(error) => return Err(Self::storage_error(error)),
        };
        Ok(())
    }

    fn retention(&self, id: &ArtifactId) -> Result<RetentionPolicy, ArtifactError> {
        match fs::metadata(self.path_for(id)) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ArtifactError::new(ArtifactErrorKind::NotFound))
            }
            Err(error) => return Err(Self::storage_error(error)),
        }
        self.retention
            .get(id)
            .copied()
            .ok_or_else(|| ArtifactError::new(ArtifactErrorKind::NotFound))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use sha2::{Digest, Sha256};

    use super::{
        ArtifactErrorKind, ArtifactId, ArtifactStore, Entry, InMemoryArtifactStore, RetentionPolicy,
    };
    use crate::encode_hex;

    #[test]
    fn content_id_collisions_fail_closed_without_replacing_bytes() {
        let mut store = InMemoryArtifactStore::new(
            NonZeroU64::new(16).expect("test content limit must be positive"),
            NonZeroU64::new(16).expect("test page limit must be positive"),
        );
        let id = ArtifactId(encode_hex(&Sha256::digest(b"expected")));
        store.entries.insert(
            id.clone(),
            Entry {
                bytes: b"existing".to_vec(),
                retention: RetentionPolicy::Retain,
            },
        );

        let error = store
            .put(b"expected")
            .expect_err("a mismatched entry with the same content ID must fail closed");

        assert_eq!(error.kind(), ArtifactErrorKind::ContentIdCollision);
        assert_eq!(error.to_string(), "artifact content ID collision");
        assert_eq!(
            store
                .entries
                .get(&id)
                .expect("the colliding entry must remain")
                .bytes,
            b"existing"
        );
    }
}
