//! Metadata-only GitHub intake. Typed Sentinel/hybrid content admission is deferred to #235.

use std::collections::BTreeSet;

use crate::security::TrustPolicy;

const MAX_REPOSITORY_LENGTH: usize = 256;
const MAX_SNAPSHOT_LENGTH: usize = 256;
const MAX_METADATA_TEXT_LENGTH: usize = 512;
const MAX_PAGES: u32 = 1_000;
const MAX_PER_PAGE: u16 = 100;
const MAX_ITEMS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubIssueState {
    Open,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubIssueMetadata {
    number: u64,
    author: String,
    author_association: String,
    state: GitHubIssueState,
    updated_at: String,
    is_pull_request: bool,
}

impl GitHubIssueMetadata {
    pub fn new(
        number: u64,
        author: impl Into<String>,
        author_association: impl Into<String>,
        state: GitHubIssueState,
        updated_at: impl Into<String>,
        is_pull_request: bool,
    ) -> Result<Self, GitHubIntakeError> {
        if number == 0 {
            return Err(GitHubIntakeError::invalid_metadata());
        }
        Ok(Self {
            number,
            author: valid_text(author.into(), MAX_METADATA_TEXT_LENGTH)?,
            author_association: valid_text(author_association.into(), MAX_METADATA_TEXT_LENGTH)?,
            state,
            updated_at: valid_text(updated_at.into(), MAX_METADATA_TEXT_LENGTH)?,
            is_pull_request,
        })
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn author(&self) -> &str {
        &self.author
    }

    pub fn author_association(&self) -> &str {
        &self.author_association
    }

    pub fn state(&self) -> GitHubIssueState {
        self.state
    }

    pub fn updated_at(&self) -> &str {
        &self.updated_at
    }

    pub fn is_pull_request(&self) -> bool {
        self.is_pull_request
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitHubRateLimit {
    remaining: u32,
    reset_at_unix_seconds: Option<u64>,
}

impl GitHubRateLimit {
    pub const fn new(remaining: u32, reset_at_unix_seconds: Option<u64>) -> Self {
        Self {
            remaining,
            reset_at_unix_seconds,
        }
    }

    pub fn remaining(self) -> u32 {
        self.remaining
    }

    pub fn reset_at_unix_seconds(self) -> Option<u64> {
        self.reset_at_unix_seconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubMetadataPage {
    snapshot: String,
    issues: Vec<GitHubIssueMetadata>,
    has_next_page: bool,
    rate_limit: GitHubRateLimit,
}

impl GitHubMetadataPage {
    pub fn new(
        snapshot: impl Into<String>,
        issues: Vec<GitHubIssueMetadata>,
        has_next_page: bool,
        rate_limit: GitHubRateLimit,
    ) -> Result<Self, GitHubIntakeError> {
        Ok(Self {
            snapshot: valid_text(snapshot.into(), MAX_SNAPSHOT_LENGTH)?,
            issues,
            has_next_page,
            rate_limit,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubMetadataPageRequest {
    repository: String,
    page: u32,
    per_page: u16,
    snapshot: Option<String>,
}

impl GitHubMetadataPageRequest {
    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn page(&self) -> u32 {
        self.page
    }

    pub fn per_page(&self) -> u16 {
        self.per_page
    }

    pub fn snapshot(&self) -> Option<&str> {
        self.snapshot.as_deref()
    }
}

pub trait GitHubMetadataSource {
    fn list_page(
        &mut self,
        request: &GitHubMetadataPageRequest,
    ) -> Result<GitHubMetadataPage, GitHubIntakeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubIntakeLimits {
    max_pages: u32,
    per_page: u16,
    max_items: usize,
}

impl GitHubIntakeLimits {
    pub fn new(max_pages: u32, per_page: u16, max_items: usize) -> Result<Self, GitHubIntakeError> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || per_page == 0
            || per_page > MAX_PER_PAGE
            || max_items == 0
            || max_items > MAX_ITEMS
        {
            return Err(GitHubIntakeError::invalid_request());
        }
        Ok(Self {
            max_pages,
            per_page,
            max_items,
        })
    }
}

impl Default for GitHubIntakeLimits {
    fn default() -> Self {
        Self {
            max_pages: 100,
            per_page: 100,
            max_items: 10_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubMetadataProvenance {
    repository: String,
    snapshot: String,
}

impl GitHubMetadataProvenance {
    pub fn source(&self) -> &'static str {
        "github"
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn snapshot(&self) -> &str {
        &self.snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubMetadataSnapshot {
    repository: String,
    snapshot: String,
    issues: Vec<GitHubIssueMetadata>,
    pages: u32,
    provenance: GitHubMetadataProvenance,
}

impl GitHubMetadataSnapshot {
    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn snapshot(&self) -> &str {
        &self.snapshot
    }

    pub fn issues(&self) -> &[GitHubIssueMetadata] {
        &self.issues
    }

    pub fn pages(&self) -> u32 {
        self.pages
    }

    pub fn provenance(&self) -> &GitHubMetadataProvenance {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubIntakeErrorKind {
    InvalidRequest,
    InvalidMetadata,
    SnapshotChanged,
    DuplicateIssue,
    PageOverflow,
    PageLimitExceeded,
    ItemLimitExceeded,
    SourceUnavailable,
    RateLimited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubIntakeError {
    kind: GitHubIntakeErrorKind,
    retry_after_seconds: Option<u64>,
}

impl GitHubIntakeError {
    fn invalid_request() -> Self {
        Self {
            kind: GitHubIntakeErrorKind::InvalidRequest,
            retry_after_seconds: None,
        }
    }

    fn invalid_metadata() -> Self {
        Self {
            kind: GitHubIntakeErrorKind::InvalidMetadata,
            retry_after_seconds: None,
        }
    }

    pub fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self {
            kind: GitHubIntakeErrorKind::RateLimited,
            retry_after_seconds,
        }
    }

    /// Refuses a metadata request when the source cannot provide a page.
    pub fn source_unavailable() -> Self {
        Self {
            kind: GitHubIntakeErrorKind::SourceUnavailable,
            retry_after_seconds: None,
        }
    }

    pub fn kind(&self) -> GitHubIntakeErrorKind {
        self.kind
    }

    pub fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }
}

pub fn collect_github_metadata<S>(
    repository: impl Into<String>,
    source: &mut S,
    limits: GitHubIntakeLimits,
) -> Result<GitHubMetadataSnapshot, GitHubIntakeError>
where
    S: GitHubMetadataSource,
{
    let repository = valid_text(repository.into(), MAX_REPOSITORY_LENGTH)?;
    let mut page_number = 1;
    let mut expected_snapshot = None;
    let mut issues = Vec::new();
    let mut seen_numbers = BTreeSet::new();

    loop {
        let request = GitHubMetadataPageRequest {
            repository: repository.clone(),
            page: page_number,
            per_page: limits.per_page,
            snapshot: expected_snapshot.clone(),
        };
        let page = source.list_page(&request)?;
        if page.issues.len() > limits.per_page as usize {
            return Err(GitHubIntakeError {
                kind: GitHubIntakeErrorKind::PageOverflow,
                retry_after_seconds: None,
            });
        }

        if let Some(expected) = &expected_snapshot {
            if expected != &page.snapshot {
                return Err(GitHubIntakeError {
                    kind: GitHubIntakeErrorKind::SnapshotChanged,
                    retry_after_seconds: None,
                });
            }
        } else {
            expected_snapshot = Some(page.snapshot.clone());
        }

        for issue in page.issues {
            if issue.is_pull_request {
                continue;
            }
            if !seen_numbers.insert(issue.number) {
                return Err(GitHubIntakeError {
                    kind: GitHubIntakeErrorKind::DuplicateIssue,
                    retry_after_seconds: None,
                });
            }
            if issues.len() >= limits.max_items {
                return Err(GitHubIntakeError {
                    kind: GitHubIntakeErrorKind::ItemLimitExceeded,
                    retry_after_seconds: None,
                });
            }
            issues.push(issue);
        }

        if !page.has_next_page {
            let snapshot = expected_snapshot.expect("a source page always establishes a snapshot");
            return Ok(GitHubMetadataSnapshot {
                repository: repository.clone(),
                snapshot: snapshot.clone(),
                issues,
                pages: page_number,
                provenance: GitHubMetadataProvenance {
                    repository,
                    snapshot,
                },
            });
        }
        if page.rate_limit.remaining == 0 {
            return Err(GitHubIntakeError::rate_limited(None));
        }
        if page_number >= limits.max_pages {
            return Err(GitHubIntakeError {
                kind: GitHubIntakeErrorKind::PageLimitExceeded,
                retry_after_seconds: None,
            });
        }
        page_number += 1;
    }
}

pub trait GitHubContentFetcher {
    type Content;
    type Error;

    fn fetch_content(
        &mut self,
        metadata: &GitHubIssueMetadata,
    ) -> Result<Self::Content, Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum GitHubContentFetchError<E> {
    AllowlistRefused,
    PullRequestExcluded,
    Source(E),
}

pub fn fetch_allowlisted_content<F>(
    policy: &TrustPolicy,
    metadata: &GitHubIssueMetadata,
    fetcher: &mut F,
) -> Result<F::Content, GitHubContentFetchError<F::Error>>
where
    F: GitHubContentFetcher,
{
    if metadata.is_pull_request {
        return Err(GitHubContentFetchError::PullRequestExcluded);
    }
    if !policy.allows_author(&metadata.author) {
        return Err(GitHubContentFetchError::AllowlistRefused);
    }
    fetcher
        .fetch_content(metadata)
        .map_err(GitHubContentFetchError::Source)
}

fn valid_text(value: String, max_length: usize) -> Result<String, GitHubIntakeError> {
    if value.is_empty() || value.len() > max_length || value.chars().any(char::is_control) {
        return Err(GitHubIntakeError::invalid_metadata());
    }
    Ok(value)
}
