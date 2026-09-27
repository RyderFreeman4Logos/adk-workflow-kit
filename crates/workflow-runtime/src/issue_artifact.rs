//! Offline canonical admitted-issue artifact. No network, Distiller, or compiler.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    ArtifactId, ArtifactRef, ArtifactStore, ContentObject, GitHubIssueMetadata, NodeCacheKey,
    NodeCacheKeyError, NodeCacheKeyMaterial, SourceSpan, TrustDomain, TrustPolicy,
    TrustPolicyError, encode_hex,
};

pub const ISSUE_ARTIFACT_SCHEMA_VERSION: u16 = 1;
const SCHEMA_ID: &str = "admitted-issue-artifact-v1";
const MAX_TEXT: usize = 65_536;
const MAX_COMMENTS: usize = 1_024;
const MAX_IDENTITY: usize = 256;
const MAX_SNAPSHOT: usize = 256;
const MAX_INPUT_BYTES: usize = 262_144;
const MAX_DIRECT_COMMENTS: usize = 64;
const TITLE_OBJECT_ID: &str = "issue-title";
const BODY_OBJECT_ID: &str = "issue-body";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueArtifactErrorKind {
    InvalidInput,
    NotRouted,
    Store,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssueArtifactError {
    kind: IssueArtifactErrorKind,
}

impl IssueArtifactError {
    const fn new(kind: IssueArtifactErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> IssueArtifactErrorKind {
        self.kind
    }
}

impl fmt::Display for IssueArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            IssueArtifactErrorKind::InvalidInput => "admitted issue content is invalid",
            IssueArtifactErrorKind::NotRouted => "long-thread distillation is not routed",
            IssueArtifactErrorKind::Store => "artifact store rejected canonical content",
        })
    }
}

impl std::error::Error for IssueArtifactError {}

#[derive(Clone, Eq, PartialEq)]
pub struct OfflineComment {
    object_id: String,
    author: String,
    order: u32,
    revision: u64,
    deleted: bool,
    bytes: Vec<u8>,
}

impl fmt::Debug for OfflineComment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineComment")
            .field("object_id", &self.object_id)
            .field("author", &self.author)
            .field("order", &self.order)
            .field("revision", &self.revision)
            .field("deleted", &self.deleted)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl OfflineComment {
    /// Creates a validated comment record.
    ///
    /// Comment IDs `issue-title` and `issue-body` are reserved. Revisions must
    /// be nonzero; deleted comments must have empty bytes, and live comments
    /// must have nonempty bytes.
    pub fn new(
        object_id: impl Into<String>,
        author: impl Into<String>,
        order: u32,
        revision: u64,
        deleted: bool,
        bytes: Vec<u8>,
    ) -> Result<Self, IssueArtifactError> {
        let object_id = object_id.into();
        let author = author.into();
        if object_id.trim().is_empty()
            || object_id.len() > MAX_IDENTITY
            || matches!(object_id.as_str(), TITLE_OBJECT_ID | BODY_OBJECT_ID)
            || author.trim().is_empty()
            || author.len() > MAX_IDENTITY
            || revision == 0
            || (!deleted && bytes.is_empty())
            || (deleted && !bytes.is_empty())
            || bytes.len() > MAX_TEXT
        {
            return Err(IssueArtifactError::new(
                IssueArtifactErrorKind::InvalidInput,
            ));
        }
        Ok(Self {
            object_id,
            author,
            order,
            revision,
            deleted,
            bytes,
        })
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OfflineIssueContent {
    metadata: GitHubIssueMetadata,
    snapshot: String,
    title: Vec<u8>,
    body: Vec<u8>,
    comments: Vec<OfflineComment>,
}

impl fmt::Debug for OfflineIssueContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineIssueContent")
            .field("metadata", &self.metadata)
            .field("snapshot", &self.snapshot)
            .field("title_len", &self.title.len())
            .field("body_len", &self.body.len())
            .field("comments", &self.comments)
            .finish()
    }
}

impl OfflineIssueContent {
    /// Creates a validated offline snapshot.
    ///
    /// The nonempty `snapshot` identifier is retained verbatim in the
    /// manifest. Comment IDs must be unique and their order values strictly
    /// increasing; each comment revision is validated by [`OfflineComment::new`].
    pub fn new(
        metadata: GitHubIssueMetadata,
        snapshot: impl Into<String>,
        title: Vec<u8>,
        body: Vec<u8>,
        comments: Vec<OfflineComment>,
    ) -> Result<Self, IssueArtifactError> {
        let snapshot = snapshot.into();
        if snapshot.trim().is_empty()
            || snapshot.len() > MAX_SNAPSHOT
            || title.is_empty()
            || body.is_empty()
            || title.len() > MAX_TEXT
            || body.len() > MAX_TEXT
            || comments.len() > MAX_COMMENTS
            || metadata.is_pull_request()
        {
            return Err(IssueArtifactError::new(
                IssueArtifactErrorKind::InvalidInput,
            ));
        }
        let mut input_bytes = snapshot
            .len()
            .checked_add(title.len())
            .and_then(|size| size.checked_add(body.len()))
            .and_then(|size| size.checked_add(metadata.author().len()))
            .ok_or_else(|| IssueArtifactError::new(IssueArtifactErrorKind::InvalidInput))?;
        let mut seen = BTreeSet::new();
        let mut last_order = None;
        for comment in &comments {
            input_bytes = input_bytes
                .checked_add(comment.object_id.len())
                .and_then(|size| size.checked_add(comment.author.len()))
                .and_then(|size| size.checked_add(comment.bytes.len()))
                .ok_or_else(|| IssueArtifactError::new(IssueArtifactErrorKind::InvalidInput))?;
            if input_bytes > MAX_INPUT_BYTES
                || !seen.insert(comment.object_id.as_str())
                || last_order.is_some_and(|order| comment.order <= order)
            {
                return Err(IssueArtifactError::new(
                    IssueArtifactErrorKind::InvalidInput,
                ));
            }
            last_order = Some(comment.order);
        }
        if input_bytes > MAX_INPUT_BYTES {
            return Err(IssueArtifactError::new(
                IssueArtifactErrorKind::InvalidInput,
            ));
        }
        Ok(Self {
            metadata,
            snapshot,
            title,
            body,
            comments,
        })
    }

    pub fn comments(&self) -> &[OfflineComment] {
        &self.comments
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IssueOmission {
    object_id: String,
    reason: String,
}

impl IssueOmission {
    pub fn new(object_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            object_id: object_id.into(),
            reason: reason.into(),
        }
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ManifestObject {
    object_id: String,
    kind: &'static str,
    order: u64,
    revision: u64,
    author: String,
    domain: TrustDomain,
    digest: String,
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ManifestRecord {
    object_id: String,
    order: u64,
    revision: u64,
    author: String,
    status: &'static str,
    reason: Option<String>,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Manifest {
    schema: &'static str,
    schema_version: u16,
    issue: u64,
    snapshot: String,
    objects: Vec<ManifestObject>,
    omissions: Vec<IssueOmission>,
    records: Vec<ManifestRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncludedObject {
    object_id: String,
    digest: String,
    span: SourceSpan,
}

impl IncludedObject {
    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectChange {
    Unchanged,
    Appended,
    Edited,
    Deleted,
    NewlyOmitted,
    NewlyPermitted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObjectDiffEntry {
    object_id: String,
    change: ObjectChange,
}

impl ObjectDiffEntry {
    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn change(&self) -> ObjectChange {
        self.change
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ObjectStatus {
    Included { digest: String },
    Omitted { reason: String, digest: String },
    Deleted { digest: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectState {
    object_id: String,
    order: u64,
    revision: u64,
    author: String,
    status: ObjectStatus,
}

impl ObjectState {
    fn digest(&self) -> &str {
        match &self.status {
            ObjectStatus::Included { digest }
            | ObjectStatus::Omitted { digest, .. }
            | ObjectStatus::Deleted { digest } => digest,
        }
    }

    fn manifest_record(&self) -> ManifestRecord {
        let (status, reason) = match &self.status {
            ObjectStatus::Included { .. } => ("included", None),
            ObjectStatus::Omitted { reason, .. } => ("omitted", Some(reason.clone())),
            ObjectStatus::Deleted { .. } => ("deleted", Some("deleted".to_owned())),
        };
        ManifestRecord {
            object_id: self.object_id.clone(),
            order: self.order,
            revision: self.revision,
            author: self.author.clone(),
            status,
            reason,
            digest: self.digest().to_owned(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanonicalIssueArtifact {
    content_id: ArtifactId,
    content_ref: ArtifactRef,
    manifest_bytes: Vec<u8>,
    included: Vec<IncludedObject>,
    omissions: Vec<IssueOmission>,
    states: Vec<ObjectState>,
    policy_digest: String,
    aggregate_digest: String,
}

impl CanonicalIssueArtifact {
    pub fn content_id(&self) -> &ArtifactId {
        &self.content_id
    }

    pub fn content_ref(&self) -> &ArtifactRef {
        &self.content_ref
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn included(&self) -> &[IncludedObject] {
        &self.included
    }

    pub fn omissions(&self) -> &[IssueOmission] {
        &self.omissions
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn aggregate_digest(&self) -> &str {
        &self.aggregate_digest
    }

    /// Binds caller cache material to this canonical artifact.
    ///
    /// The artifact content hash is appended to the supplied input hashes;
    /// the request-input and policy digests are replaced with this artifact's
    /// aggregate and policy digests. Other cache material is preserved.
    pub fn cache_key(
        &self,
        material: NodeCacheKeyMaterial<'_>,
    ) -> Result<NodeCacheKey, NodeCacheKeyError> {
        let mut hashes = material.input_artifact_hashes.to_vec();
        hashes.push(self.content_ref.sha256().to_owned());
        NodeCacheKey::bind(NodeCacheKeyMaterial {
            input_artifact_hashes: &hashes,
            request_input_digest: self.aggregate_digest.as_str(),
            policy_digest: self.policy_digest.as_str(),
            ..material
        })
    }

    /// Returns object transitions from `previous`.
    ///
    /// On a first inventory, included objects are `Appended` and omitted or
    /// deleted records are `NewlyOmitted`.
    pub fn diff_from(&self, previous: Option<&Self>) -> Vec<ObjectDiffEntry> {
        let Some(previous) = previous else {
            return self
                .states
                .iter()
                .map(|state| ObjectDiffEntry {
                    object_id: state.object_id.clone(),
                    change: match state.status {
                        ObjectStatus::Included { .. } => ObjectChange::Appended,
                        ObjectStatus::Omitted { .. } | ObjectStatus::Deleted { .. } => {
                            ObjectChange::NewlyOmitted
                        }
                    },
                })
                .collect();
        };

        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        for prior in &previous.states {
            seen.insert(prior.object_id.as_str());
            let change = match self
                .states
                .iter()
                .find(|current| current.object_id == prior.object_id)
            {
                None => ObjectChange::Deleted,
                Some(current) => classify_change(prior, current),
            };
            entries.push(ObjectDiffEntry {
                object_id: prior.object_id.clone(),
                change,
            });
        }
        for current in &self.states {
            if seen.contains(current.object_id.as_str()) {
                continue;
            }
            entries.push(ObjectDiffEntry {
                object_id: current.object_id.clone(),
                change: match current.status {
                    ObjectStatus::Included { .. } => ObjectChange::Appended,
                    ObjectStatus::Omitted { .. } | ObjectStatus::Deleted { .. } => {
                        ObjectChange::NewlyOmitted
                    }
                },
            });
        }
        entries
    }
}

fn classify_change(previous: &ObjectState, current: &ObjectState) -> ObjectChange {
    match (&previous.status, &current.status) {
        (ObjectStatus::Included { .. }, ObjectStatus::Included { .. }) => {
            if previous == current {
                ObjectChange::Unchanged
            } else {
                ObjectChange::Edited
            }
        }
        (ObjectStatus::Included { .. }, ObjectStatus::Omitted { .. }) => ObjectChange::NewlyOmitted,
        (ObjectStatus::Included { .. }, ObjectStatus::Deleted { .. })
        | (ObjectStatus::Omitted { .. }, ObjectStatus::Deleted { .. }) => ObjectChange::Deleted,
        (ObjectStatus::Omitted { .. }, ObjectStatus::Included { .. })
        | (ObjectStatus::Deleted { .. }, ObjectStatus::Included { .. }) => {
            ObjectChange::NewlyPermitted
        }
        (ObjectStatus::Omitted { .. }, ObjectStatus::Omitted { .. }) => {
            if previous == current {
                ObjectChange::Unchanged
            } else {
                ObjectChange::Edited
            }
        }
        (ObjectStatus::Deleted { .. }, ObjectStatus::Omitted { .. }) => ObjectChange::NewlyOmitted,
        (ObjectStatus::Deleted { .. }, ObjectStatus::Deleted { .. }) => {
            if previous == current {
                ObjectChange::Unchanged
            } else {
                ObjectChange::Deleted
            }
        }
    }
}

impl fmt::Debug for CanonicalIssueArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalIssueArtifact")
            .field("content_id", &self.content_id)
            .field("omissions", &self.omissions)
            .field("aggregate_digest", &self.aggregate_digest)
            .finish()
    }
}

struct Classified<'a> {
    object_id: &'a str,
    kind: &'static str,
    order: u64,
    revision: u64,
    author: &'a str,
    domain: TrustDomain,
    bytes: &'a [u8],
    digest: String,
}

/// Builds the canonical artifact for an admitted issue snapshot.
///
/// The direct path accepts at most 64 comments; larger inventories return
/// [`IssueArtifactErrorKind::NotRouted`]. Title and body digests retain their
/// shared policy provenance while remaining distinct by local object role.
pub fn build_canonical_issue_artifact(
    policy: &TrustPolicy,
    admitted: &OfflineIssueContent,
    store: &mut impl ArtifactStore,
) -> Result<CanonicalIssueArtifact, IssueArtifactError> {
    if admitted.comments.len() > MAX_DIRECT_COMMENTS {
        return Err(IssueArtifactError::new(IssueArtifactErrorKind::NotRouted));
    }

    let issue_id = admitted.metadata.number().to_string();
    let body = policy
        .classify(ContentObject::IssueBody {
            object_id: &issue_id,
            author: admitted.metadata.author(),
        })
        .map_err(map_policy)?;
    if body.domain() != TrustDomain::ConditionallyTrustedContent {
        return Err(IssueArtifactError::new(
            IssueArtifactErrorKind::InvalidInput,
        ));
    }
    let policy_digest = encode_hex(body.policy_digest());
    let title_digest = digest_object(
        &body.cache_key(&admitted.title).as_hex(),
        Some(TITLE_OBJECT_ID),
        1,
    );
    let body_digest = digest_object(
        &body.cache_key(&admitted.body).as_hex(),
        Some(BODY_OBJECT_ID),
        1,
    );
    let title = Classified {
        object_id: TITLE_OBJECT_ID,
        kind: "issue_title",
        order: 0,
        revision: 1,
        author: admitted.metadata.author(),
        domain: body.domain(),
        bytes: &admitted.title,
        digest: title_digest.clone(),
    };
    let issue_body = Classified {
        object_id: BODY_OBJECT_ID,
        kind: "issue_body",
        order: 1,
        revision: 1,
        author: admitted.metadata.author(),
        domain: body.domain(),
        bytes: &admitted.body,
        digest: body_digest.clone(),
    };
    let mut classified = vec![title, issue_body];
    let mut states = vec![
        ObjectState {
            object_id: TITLE_OBJECT_ID.to_owned(),
            order: 0,
            revision: 1,
            author: admitted.metadata.author().to_owned(),
            status: ObjectStatus::Included {
                digest: title_digest,
            },
        },
        ObjectState {
            object_id: BODY_OBJECT_ID.to_owned(),
            order: 1,
            revision: 1,
            author: admitted.metadata.author().to_owned(),
            status: ObjectStatus::Included {
                digest: body_digest,
            },
        },
    ];
    let mut omissions = Vec::new();
    for comment in &admitted.comments {
        let provenance = policy
            .classify(ContentObject::Comment {
                object_id: &comment.object_id,
                author: &comment.author,
            })
            .map_err(map_policy)?;
        let digest = digest_object(
            &provenance.cache_key(&comment.bytes).as_hex(),
            None,
            comment.revision,
        );
        let order = u64::from(comment.order) + 2;
        let status = if comment.deleted {
            omissions.push(IssueOmission::new(&comment.object_id, "deleted"));
            ObjectStatus::Deleted { digest }
        } else if provenance.domain() != TrustDomain::ConditionallyTrustedContent {
            omissions.push(IssueOmission::new(
                &comment.object_id,
                "author_not_allowlisted",
            ));
            ObjectStatus::Omitted {
                reason: "author_not_allowlisted".to_owned(),
                digest,
            }
        } else {
            classified.push(Classified {
                object_id: &comment.object_id,
                kind: "comment",
                order,
                revision: comment.revision,
                author: &comment.author,
                domain: provenance.domain(),
                bytes: &comment.bytes,
                digest: digest.clone(),
            });
            ObjectStatus::Included { digest }
        };
        states.push(ObjectState {
            object_id: comment.object_id.clone(),
            order,
            revision: comment.revision,
            author: comment.author.clone(),
            status,
        });
    }

    let mut content = Vec::new();
    let mut objects = Vec::new();
    let mut included = Vec::new();
    for item in &classified {
        let start = u64::try_from(content.len()).map_err(|_| store_error())?;
        content.extend_from_slice(item.bytes);
        let end = u64::try_from(content.len()).map_err(|_| store_error())?;
        if end <= start {
            return Err(IssueArtifactError::new(
                IssueArtifactErrorKind::InvalidInput,
            ));
        }
        content.push(0);
        objects.push(ManifestObject {
            object_id: item.object_id.to_owned(),
            kind: item.kind,
            order: item.order,
            revision: item.revision,
            author: item.author.to_owned(),
            domain: item.domain,
            digest: item.digest.clone(),
            start,
            end,
        });
    }
    let records = states.iter().map(ObjectState::manifest_record).collect();
    let manifest = Manifest {
        schema: SCHEMA_ID,
        schema_version: ISSUE_ARTIFACT_SCHEMA_VERSION,
        issue: admitted.metadata.number(),
        snapshot: admitted.snapshot.clone(),
        objects,
        omissions: omissions.clone(),
        records,
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| store_error())?;

    let staged = store.stage(&content).map_err(|_| store_error())?;
    let content_id = staged.id().clone();
    let content_ref = ArtifactRef::new(
        content_id.as_str(),
        format!("sha256:{}", content_id.as_str()),
    )
    .map_err(|_| store_error())?;
    for (item, manifest_object) in classified.iter().zip(manifest.objects.iter()) {
        let span = SourceSpan::new(
            content_id.as_str(),
            manifest_object.start,
            manifest_object.end,
        )
        .map_err(|_| store_error())?;
        let start = usize::try_from(span.start()).map_err(|_| store_error())?;
        let end = usize::try_from(span.end()).map_err(|_| store_error())?;
        if end > content.len() || start >= end || content[start..end] != *item.bytes {
            return Err(store_error());
        }
        included.push(IncludedObject {
            object_id: item.object_id.to_owned(),
            digest: item.digest.clone(),
            span,
        });
    }
    let committed_id = store.commit(staged).map_err(|_| store_error())?;
    if committed_id != content_id {
        return Err(store_error());
    }

    let mut aggregate = Sha256::new();
    aggregate.update(SCHEMA_ID.as_bytes());
    aggregate.update(policy_digest.as_bytes());
    aggregate.update(&manifest_bytes);
    Ok(CanonicalIssueArtifact {
        content_id,
        content_ref,
        manifest_bytes,
        included,
        omissions,
        states,
        policy_digest,
        aggregate_digest: encode_hex(&aggregate.finalize()),
    })
}

fn digest_object(content_digest: &str, local_role: Option<&str>, revision: u64) -> String {
    let mut hasher = Sha256::new();
    if let Some(local_role) = local_role {
        hasher.update(b"issue-object-role-v1");
        hasher.update([0]);
        hasher.update(local_role.as_bytes());
        hasher.update([0]);
    }
    hasher.update(content_digest.as_bytes());
    hasher.update(revision.to_be_bytes());
    encode_hex(&hasher.finalize())
}

fn map_policy(error: TrustPolicyError) -> IssueArtifactError {
    let _ = error;
    IssueArtifactError::new(IssueArtifactErrorKind::InvalidInput)
}

fn store_error() -> IssueArtifactError {
    IssueArtifactError::new(IssueArtifactErrorKind::Store)
}
