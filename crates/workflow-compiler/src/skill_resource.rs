use std::{
    collections::BTreeMap,
    fmt,
    num::{NonZeroU64, NonZeroUsize},
};

use workflow_runtime::{
    ArtifactErrorKind, ArtifactId, ArtifactPage, ArtifactStore, EffectiveCapabilities,
    InMemoryArtifactStore, PageRequest, SandboxCapability,
};

use crate::{SkillActivationReceipt, SkillId};

const MAX_RESOURCE_ID_BYTES: usize = 1_024;

/// A validated logical path to a non-executable Skill resource.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SkillResourceId(String);

impl SkillResourceId {
    /// Validates and owns one canonical `references/` or `assets/` resource path.
    pub fn new(raw: &str) -> Result<Self, SkillResourceIdError> {
        if raw.is_empty() {
            return Err(SkillResourceIdError::Empty);
        }
        if raw.len() > MAX_RESOURCE_ID_BYTES {
            return Err(SkillResourceIdError::TooLong);
        }
        if raw.starts_with('/') {
            return Err(SkillResourceIdError::Absolute);
        }
        if raw.chars().any(char::is_control) {
            return Err(SkillResourceIdError::ControlCharacter);
        }

        let mut components = raw.split('/');
        let prefix = match components.next() {
            Some(prefix) => prefix,
            None => return Err(SkillResourceIdError::Empty),
        };
        if prefix != "references" && prefix != "assets" {
            return Err(SkillResourceIdError::DisallowedPrefix);
        }

        let mut has_resource_component = false;
        for component in components {
            if component == ".." {
                return Err(SkillResourceIdError::Traversal);
            }
            if component.is_empty() || component == "." {
                return Err(SkillResourceIdError::InvalidComponent);
            }
            has_resource_component = true;
        }
        if !has_resource_component {
            return Err(SkillResourceIdError::InvalidComponent);
        }

        Ok(Self(raw.to_owned()))
    }

    /// Returns the validated canonical resource path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A stable failure while validating a Skill resource identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillResourceIdError {
    /// The resource identifier is empty.
    Empty,
    /// The resource identifier exceeds its byte limit.
    TooLong,
    /// The resource identifier is absolute.
    Absolute,
    /// The resource identifier contains a parent component.
    Traversal,
    /// The resource identifier contains an invalid component.
    InvalidComponent,
    /// The resource identifier contains a control character.
    ControlCharacter,
    /// The resource identifier is not under an allowed resource prefix.
    DisallowedPrefix,
}

impl fmt::Display for SkillResourceIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "skill resource ID is empty",
            Self::TooLong => "skill resource ID is too long",
            Self::Absolute => "skill resource ID is absolute",
            Self::Traversal => "skill resource ID contains traversal",
            Self::InvalidComponent => "skill resource ID has an invalid component",
            Self::ControlCharacter => "skill resource ID contains a control character",
            Self::DisallowedPrefix => "skill resource ID has a disallowed prefix",
        })
    }
}

impl std::error::Error for SkillResourceIdError {}

/// One logical resource presented for an already activated Skill.
pub enum SkillResourceInput {
    File { id: SkillResourceId, bytes: Vec<u8> },
    Symlink { id: SkillResourceId, target: String },
}

impl SkillResourceInput {
    /// Creates one regular-file resource with opaque bytes.
    pub fn file(id: SkillResourceId, bytes: Vec<u8>) -> Self {
        Self::File { id, bytes }
    }

    /// Creates one logical symlink resource, which activation always rejects.
    pub fn symlink(id: SkillResourceId, target: String) -> Self {
        Self::Symlink { id, target }
    }
}

/// Fixed bounds for one activated Skill's logical resources.
#[derive(Clone, Copy, Debug)]
pub struct SkillResourceLimits {
    max_resources: NonZeroUsize,
    max_resource_bytes: NonZeroU64,
    max_page_bytes: NonZeroU64,
    max_total_read_bytes: NonZeroU64,
}

impl SkillResourceLimits {
    /// Creates positive resource count, payload, page, and cumulative-read limits.
    pub fn new(
        max_resources: NonZeroUsize,
        max_resource_bytes: NonZeroU64,
        max_page_bytes: NonZeroU64,
        max_total_read_bytes: NonZeroU64,
    ) -> Self {
        Self {
            max_resources,
            max_resource_bytes,
            max_page_bytes,
            max_total_read_bytes,
        }
    }
}

/// Stable metadata for one activated Skill resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillResourceMetadata {
    id: SkillResourceId,
    byte_len: u64,
    artifact_id: ArtifactId,
}

impl SkillResourceMetadata {
    /// Returns the validated logical resource path.
    pub fn id(&self) -> &SkillResourceId {
        &self.id
    }

    /// Returns the resource's opaque byte length.
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Returns the SHA-256 content identity for the resource bytes.
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }
}

/// Metadata-only listing for an activated Skill's bounded resources.
pub struct SkillResourceList<'a> {
    resources: Vec<&'a SkillResourceMetadata>,
}

impl<'a> SkillResourceList<'a> {
    /// Returns resources in deterministic logical-ID order without any resource bytes.
    pub fn resources(&self) -> &[&'a SkillResourceMetadata] {
        &self.resources
    }
}

/// One explicit paged read of an activated Skill resource.
pub struct SkillResourceRead {
    metadata: SkillResourceMetadata,
    page: ArtifactPage,
}

impl SkillResourceRead {
    /// Returns stable metadata for the resource whose bytes were read.
    pub fn metadata(&self) -> &SkillResourceMetadata {
        &self.metadata
    }

    /// Returns the opaque bounded artifact page.
    pub fn page(&self) -> &ArtifactPage {
        &self.page
    }

    /// Returns ownership of the opaque bounded artifact page.
    pub fn into_page(self) -> ArtifactPage {
        self.page
    }
}

/// Stable failure while attaching or reading activated Skill resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillResourceError {
    /// Policy did not authorize filesystem resource reads.
    CapabilityDenied,
    /// The supplied resource count exceeded its fixed limit.
    TooManyResources,
    /// More than one resource used the same logical ID.
    DuplicateResource,
    /// A symlink resource was supplied.
    SymlinkRejected,
    /// A resource payload was empty.
    EmptyPayload,
    /// A resource payload exceeded its fixed byte limit.
    PayloadTooLarge,
    /// Stored bytes did not retain their expected content identity.
    ContentIdentityFailure,
    /// The requested resource was absent.
    ResourceNotFound,
    /// The requested page offset was out of bounds.
    PageOutOfBounds,
    /// The explicit read would exceed the cumulative byte budget.
    TotalReadExceeded,
    /// The underlying storage failed while reading or writing content.
    Io,
}

impl fmt::Display for SkillResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CapabilityDenied => "skill resource capability denied",
            Self::TooManyResources => "skill resource count exceeds the configured limit",
            Self::DuplicateResource => "skill resource ID is duplicated",
            Self::SymlinkRejected => "skill resource symlink is rejected",
            Self::EmptyPayload => "skill resource payload is empty",
            Self::PayloadTooLarge => "skill resource payload exceeds the configured limit",
            Self::ContentIdentityFailure => "skill resource content identity failed",
            Self::ResourceNotFound => "skill resource was not found",
            Self::PageOutOfBounds => "skill resource page is out of bounds",
            Self::TotalReadExceeded => "skill resource total read budget exceeded",
            Self::Io => "skill resource storage I/O error",
        })
    }
}

impl std::error::Error for SkillResourceError {}

/// Activation-bound in-memory resources for one exact Skill ID and version.
pub struct ActivatedSkillResources<'a> {
    _skill_id: &'a SkillId,
    _skill_version: &'a str,
    metadata: BTreeMap<SkillResourceId, SkillResourceMetadata>,
    store: InMemoryArtifactStore,
    max_total_read_bytes: NonZeroU64,
    total_read_bytes: u64,
}

impl<'a> ActivatedSkillResources<'a> {
    /// Returns only deterministic metadata for the resources attached at activation.
    pub fn list_skill_resources(&self) -> SkillResourceList<'_> {
        SkillResourceList {
            resources: self.metadata.values().collect(),
        }
    }

    /// Reads one bounded page and consumes only the returned page length from the total budget.
    pub fn read_skill_resource(
        &mut self,
        id: &SkillResourceId,
        request: PageRequest,
    ) -> Result<SkillResourceRead, SkillResourceError> {
        let metadata = match self.metadata.get(id) {
            Some(metadata) => metadata,
            None => return Err(SkillResourceError::ResourceNotFound),
        };
        let page = self
            .store
            .read_page(metadata.artifact_id(), request)
            .map_err(map_artifact_error)?;
        let page_len =
            u64::try_from(page.bytes().len()).map_err(|_| SkillResourceError::TotalReadExceeded)?;
        let next_total = self
            .total_read_bytes
            .checked_add(page_len)
            .ok_or(SkillResourceError::TotalReadExceeded)?;
        if next_total > self.max_total_read_bytes.get() {
            return Err(SkillResourceError::TotalReadExceeded);
        }
        self.total_read_bytes = next_total;

        Ok(SkillResourceRead {
            metadata: metadata.clone(),
            page,
        })
    }
}

impl<'a> SkillActivationReceipt<'a> {
    /// Attaches bounded, non-executable logical resources to this exact activation receipt.
    pub fn attach_resources(
        &self,
        capabilities: &EffectiveCapabilities,
        limits: SkillResourceLimits,
        resources: impl IntoIterator<Item = SkillResourceInput>,
    ) -> Result<ActivatedSkillResources<'_>, SkillResourceError> {
        if !capabilities
            .capabilities()
            .contains(&SandboxCapability::FilesystemRead)
        {
            return Err(SkillResourceError::CapabilityDenied);
        }

        let mut metadata = BTreeMap::new();
        let mut store =
            InMemoryArtifactStore::new(limits.max_resource_bytes, limits.max_page_bytes);
        let mut remaining_resources = limits.max_resources.get();
        for input in resources {
            if remaining_resources == 0 {
                return Err(SkillResourceError::TooManyResources);
            }
            remaining_resources -= 1;
            let (id, bytes) = match input {
                SkillResourceInput::File { id, bytes } => (id, bytes),
                SkillResourceInput::Symlink { id: _, target: _ } => {
                    return Err(SkillResourceError::SymlinkRejected)
                }
            };
            if bytes.is_empty() {
                return Err(SkillResourceError::EmptyPayload);
            }
            if u64::try_from(bytes.len())
                .map_or(true, |length| length > limits.max_resource_bytes.get())
            {
                return Err(SkillResourceError::PayloadTooLarge);
            }
            if metadata.contains_key(&id) {
                return Err(SkillResourceError::DuplicateResource);
            }

            let artifact_id = store.put(&bytes).map_err(map_artifact_error)?;
            let byte_len =
                u64::try_from(bytes.len()).map_err(|_| SkillResourceError::PayloadTooLarge)?;
            metadata.insert(
                id.clone(),
                SkillResourceMetadata {
                    id,
                    byte_len,
                    artifact_id,
                },
            );
        }

        Ok(ActivatedSkillResources {
            _skill_id: self.id(),
            _skill_version: self.version(),
            metadata,
            store,
            max_total_read_bytes: limits.max_total_read_bytes,
            total_read_bytes: 0,
        })
    }
}

fn map_artifact_error(kind: workflow_runtime::ArtifactError) -> SkillResourceError {
    match kind.kind() {
        ArtifactErrorKind::EmptyContent => SkillResourceError::EmptyPayload,
        ArtifactErrorKind::ContentTooLarge => SkillResourceError::PayloadTooLarge,
        ArtifactErrorKind::PageOutOfBounds => SkillResourceError::PageOutOfBounds,
        ArtifactErrorKind::NotFound => SkillResourceError::ResourceNotFound,
        ArtifactErrorKind::ContentIdCollision => SkillResourceError::ContentIdentityFailure,
        ArtifactErrorKind::Io => SkillResourceError::Io,
    }
}
