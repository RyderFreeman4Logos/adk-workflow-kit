use std::{collections::HashMap, fmt, num::NonZeroU64, time::SystemTime};

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
