//! Offline canonical admitted-issue artifact. No network, Distiller, or compiler.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    ArtifactId, ArtifactRef, ArtifactStore, ContentObject, GitHubIssueMetadata, NodeCacheKey,
    NodeCacheKeyError, NodeCacheKeyMaterial, PageRequest, SourceSpan, TrustDomain, TrustPolicy,
    TrustPolicyError, encode_hex,
};

pub const ISSUE_ARTIFACT_SCHEMA_VERSION: u16 = 1;
const SCHEMA_ID: &str = "admitted-issue-artifact-v1";
const MAX_TEXT: usize = 65_536;
const MAX_COMMENTS: usize = 1_024;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineComment {
    object_id: String,
    author: String,
    order: u32,
    revision: u64,
    deleted: bool,
    bytes: Vec<u8>,
}

impl OfflineComment {
    pub fn new(
        object_id: impl Into<String>,
        author: impl Into<String>,
        order: u32,
        revision: u64,
        deleted: bool,
        bytes: Vec<u8>,
    ) -> Result<Self, IssueArtifactError> {
        let comment = Self {
            object_id: object_id.into(),
            author: author.into(),
            order,
            revision,
            deleted,
            bytes,
        };
        if comment.object_id.trim().is_empty()
            || comment.author.trim().is_empty()
            || comment.revision == 0
            || comment.bytes.is_empty()
            || comment.bytes.len() > MAX_TEXT
        {
            return Err(IssueArtifactError::new(
                IssueArtifactErrorKind::InvalidInput,
            ));
        }
        Ok(comment)
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineIssueContent {
    metadata: GitHubIssueMetadata,
    snapshot: String,
    title: Vec<u8>,
    body: Vec<u8>,
    comments: Vec<OfflineComment>,
}

impl OfflineIssueContent {
    pub fn new(
        metadata: GitHubIssueMetadata,
        snapshot: impl Into<String>,
        title: Vec<u8>,
        body: Vec<u8>,
        comments: Vec<OfflineComment>,
    ) -> Result<Self, IssueArtifactError> {
        let content = Self {
            metadata,
            snapshot: snapshot.into(),
            title,
            body,
            comments,
        };
        if content.snapshot.trim().is_empty()
            || content.title.is_empty()
            || content.body.is_empty()
            || content.title.len() > MAX_TEXT
            || content.body.len() > MAX_TEXT
            || content.comments.len() > MAX_COMMENTS
            || content.metadata.is_pull_request()
        {
            return Err(IssueArtifactError::new(
                IssueArtifactErrorKind::InvalidInput,
            ));
        }
        let mut seen = BTreeSet::new();
        let mut last_order = None;
        for comment in &content.comments {
            if !seen.insert(comment.object_id.clone())
                || last_order.is_some_and(|order| comment.order <= order)
            {
                return Err(IssueArtifactError::new(
                    IssueArtifactErrorKind::InvalidInput,
                ));
            }
            last_order = Some(comment.order);
        }
        Ok(content)
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
    revision: u64,
    author: String,
    domain: TrustDomain,
    digest: String,
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Manifest {
    schema: &'static str,
    schema_version: u16,
    issue: u64,
    snapshot: String,
    objects: Vec<ManifestObject>,
    omissions: Vec<IssueOmission>,
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

#[derive(Clone, Eq, PartialEq)]
pub struct CanonicalIssueArtifact {
    content_id: ArtifactId,
    content_ref: ArtifactRef,
    manifest_bytes: Vec<u8>,
    included: Vec<IncludedObject>,
    omissions: Vec<IssueOmission>,
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

    pub fn diff_from(&self, previous: Option<&Self>) -> Vec<ObjectDiffEntry> {
        let Some(previous) = previous else {
            return self
                .included
                .iter()
                .map(|object| ObjectDiffEntry {
                    object_id: object.object_id.clone(),
                    change: ObjectChange::Appended,
                })
                .chain(self.omissions.iter().map(|omission| ObjectDiffEntry {
                    object_id: omission.object_id.clone(),
                    change: ObjectChange::NewlyOmitted,
                }))
                .collect();
        };
        let mut entries = Vec::new();
        for object in &previous.included {
            match self
                .included
                .iter()
                .find(|next| next.object_id == object.object_id)
            {
                Some(next) if next.digest == object.digest => entries.push(ObjectDiffEntry {
                    object_id: object.object_id.clone(),
                    change: ObjectChange::Unchanged,
                }),
                Some(_) => entries.push(ObjectDiffEntry {
                    object_id: object.object_id.clone(),
                    change: ObjectChange::Edited,
                }),
                None if self
                    .omissions
                    .iter()
                    .any(|item| item.object_id == object.object_id) =>
                {
                    entries.push(ObjectDiffEntry {
                        object_id: object.object_id.clone(),
                        change: ObjectChange::NewlyOmitted,
                    });
                }
                None => entries.push(ObjectDiffEntry {
                    object_id: object.object_id.clone(),
                    change: ObjectChange::Deleted,
                }),
            }
        }
        for object in &self.included {
            if previous
                .included
                .iter()
                .any(|prior| prior.object_id == object.object_id)
            {
                continue;
            }
            let change = if previous
                .omissions
                .iter()
                .any(|item| item.object_id == object.object_id)
            {
                ObjectChange::NewlyPermitted
            } else {
                ObjectChange::Appended
            };
            entries.push(ObjectDiffEntry {
                object_id: object.object_id.clone(),
                change,
            });
        }
        for omission in &self.omissions {
            if previous
                .included
                .iter()
                .any(|object| object.object_id == omission.object_id)
                || previous
                    .omissions
                    .iter()
                    .any(|prior| prior.object_id == omission.object_id)
            {
                continue;
            }
            entries.push(ObjectDiffEntry {
                object_id: omission.object_id.clone(),
                change: ObjectChange::NewlyOmitted,
            });
        }
        entries
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
    revision: u64,
    author: &'a str,
    domain: TrustDomain,
    bytes: &'a [u8],
    digest: String,
}

pub fn build_canonical_issue_artifact(
    policy: &TrustPolicy,
    admitted: &OfflineIssueContent,
    store: &mut impl ArtifactStore,
) -> Result<CanonicalIssueArtifact, IssueArtifactError> {
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
    let mut classified = vec![Classified {
        object_id: "issue-body",
        kind: "issue_body",
        revision: 1,
        author: admitted.metadata.author(),
        domain: body.domain(),
        bytes: &admitted.body,
        digest: digest_object(&body.cache_key(&admitted.body).as_hex(), 1),
    }];
    let mut omissions = Vec::new();
    for comment in &admitted.comments {
        let provenance = policy
            .classify(ContentObject::Comment {
                object_id: &comment.object_id,
                author: &comment.author,
            })
            .map_err(map_policy)?;
        if comment.deleted {
            omissions.push(IssueOmission::new(&comment.object_id, "deleted"));
        } else if provenance.domain() != TrustDomain::ConditionallyTrustedContent {
            omissions.push(IssueOmission::new(
                &comment.object_id,
                "author_not_allowlisted",
            ));
        } else {
            classified.push(Classified {
                object_id: &comment.object_id,
                kind: "comment",
                revision: comment.revision,
                author: &comment.author,
                domain: provenance.domain(),
                bytes: &comment.bytes,
                digest: digest_object(
                    &provenance.cache_key(&comment.bytes).as_hex(),
                    comment.revision,
                ),
            });
        }
    }

    let mut content = admitted.title.clone();
    content.push(0);
    let mut objects = Vec::new();
    let mut included = Vec::new();
    for item in &classified {
        let start = u64::try_from(content.len()).map_err(|_| store_error())?;
        content.extend_from_slice(item.bytes);
        content.push(0);
        let end = u64::try_from(content.len()).map_err(|_| store_error())? - 1;
        if end <= start {
            return Err(IssueArtifactError::new(
                IssueArtifactErrorKind::InvalidInput,
            ));
        }
        objects.push(ManifestObject {
            object_id: item.object_id.to_owned(),
            kind: item.kind,
            revision: item.revision,
            author: item.author.to_owned(),
            domain: item.domain,
            digest: item.digest.clone(),
            start,
            end,
        });
    }
    let manifest = Manifest {
        schema: SCHEMA_ID,
        schema_version: ISSUE_ARTIFACT_SCHEMA_VERSION,
        issue: admitted.metadata.number(),
        snapshot: admitted.snapshot.clone(),
        objects,
        omissions: omissions.clone(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| store_error())?;
    let content_id = store.put(&content).map_err(|_| store_error())?;
    let content_ref = ArtifactRef::new(
        content_id.as_str(),
        format!("sha256:{}", content_id.as_str()),
    )
    .map_err(|_| store_error())?;
    for item in &manifest.objects {
        let span = SourceSpan::new(content_id.as_str(), item.start, item.end)
            .map_err(|_| store_error())?;
        let page = store
            .read_page(
                &content_id,
                PageRequest::new(
                    span.start(),
                    std::num::NonZeroU64::new(span.end() - span.start()).ok_or_else(store_error)?,
                ),
            )
            .map_err(|_| store_error())?;
        let expected = classified
            .iter()
            .find(|candidate| candidate.object_id == item.object_id)
            .ok_or_else(store_error)?;
        if page.bytes() != expected.bytes {
            return Err(store_error());
        }
        included.push(IncludedObject {
            object_id: item.object_id.clone(),
            digest: item.digest.clone(),
            span,
        });
    }
    let mut aggregate = Sha256::new();
    aggregate.update(SCHEMA_ID.as_bytes());
    aggregate.update(&manifest_bytes);
    Ok(CanonicalIssueArtifact {
        content_id,
        content_ref,
        manifest_bytes,
        included,
        omissions,
        policy_digest: encode_hex(body.policy_digest()),
        aggregate_digest: encode_hex(&aggregate.finalize()),
    })
}

pub fn refuse_long_thread() -> Result<CanonicalIssueArtifact, IssueArtifactError> {
    Err(IssueArtifactError::new(IssueArtifactErrorKind::NotRouted))
}

fn digest_object(content_digest: &str, revision: u64) -> String {
    let mut hasher = Sha256::new();
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
