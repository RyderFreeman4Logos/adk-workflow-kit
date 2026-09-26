use std::collections::VecDeque;

use workflow_runtime::{
    GitHubContentFetchError, GitHubContentFetcher, GitHubIntakeError, GitHubIntakeErrorKind,
    GitHubIntakeLimits, GitHubIssueMetadata, GitHubIssueState, GitHubMetadataPage,
    GitHubMetadataPageRequest, GitHubMetadataSource, GitHubRateLimit, TrustPolicy,
    collect_github_metadata, fetch_allowlisted_content,
};

struct FakeMetadataSource {
    pages: VecDeque<Result<GitHubMetadataPage, GitHubIntakeError>>,
    requests: Vec<(u32, Option<String>)>,
}

impl FakeMetadataSource {
    fn new(pages: impl IntoIterator<Item = Result<GitHubMetadataPage, GitHubIntakeError>>) -> Self {
        Self {
            pages: pages.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl GitHubMetadataSource for FakeMetadataSource {
    fn list_page(
        &mut self,
        request: &GitHubMetadataPageRequest,
    ) -> Result<GitHubMetadataPage, GitHubIntakeError> {
        self.requests
            .push((request.page(), request.snapshot().map(str::to_owned)));
        self.pages.pop_front().expect("fake page fixture")
    }
}

fn issue(number: u64, author: &str, is_pull_request: bool) -> GitHubIssueMetadata {
    GitHubIssueMetadata::new(
        number,
        author,
        "MEMBER",
        GitHubIssueState::Open,
        "2026-09-26T00:00:00Z",
        is_pull_request,
    )
    .expect("valid issue metadata")
}

fn page(
    snapshot: &str,
    issues: Vec<GitHubIssueMetadata>,
    has_next_page: bool,
    remaining: u32,
) -> GitHubMetadataPage {
    GitHubMetadataPage::new(
        snapshot,
        issues,
        has_next_page,
        GitHubRateLimit::new(remaining, Some(1_800_000_000)),
    )
    .expect("valid metadata page")
}

#[test]
fn metadata_listing_is_bounded_snapshot_pinned_and_excludes_pull_requests() {
    let mut source = FakeMetadataSource::new([
        Ok(page(
            "snapshot-1",
            vec![issue(1, "trusted", false), issue(2, "trusted", true)],
            true,
            1,
        )),
        Ok(page(
            "snapshot-1",
            vec![issue(3, "other", false), issue(4, "other", true)],
            false,
            0,
        )),
    ]);

    let snapshot = collect_github_metadata(
        "owner/repository",
        &mut source,
        GitHubIntakeLimits::new(2, 2, 2).expect("limits"),
    )
    .expect("metadata snapshot");

    assert_eq!(snapshot.repository(), "owner/repository");
    assert_eq!(snapshot.snapshot(), "snapshot-1");
    assert_eq!(snapshot.pages(), 2);
    assert_eq!(
        snapshot
            .issues()
            .iter()
            .map(GitHubIssueMetadata::number)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(snapshot.provenance().source(), "github");
    assert_eq!(
        source.requests,
        vec![(1, None), (2, Some(String::from("snapshot-1")))]
    );
}

#[test]
fn changed_snapshot_and_page_bound_stop_without_another_request() {
    let mut changed = FakeMetadataSource::new([
        Ok(page(
            "snapshot-1",
            vec![issue(1, "trusted", false)],
            true,
            1,
        )),
        Ok(page(
            "snapshot-2",
            vec![issue(2, "trusted", false)],
            false,
            1,
        )),
    ]);
    let error = collect_github_metadata(
        "owner/repository",
        &mut changed,
        GitHubIntakeLimits::new(3, 1, 3).expect("limits"),
    )
    .expect_err("snapshot drift must refuse the result");
    assert_eq!(error.kind(), GitHubIntakeErrorKind::SnapshotChanged);
    assert_eq!(changed.requests.len(), 2);

    let mut over_bound = FakeMetadataSource::new([Ok(page(
        "snapshot-1",
        vec![issue(1, "trusted", false)],
        true,
        1,
    ))]);
    let error = collect_github_metadata(
        "owner/repository",
        &mut over_bound,
        GitHubIntakeLimits::new(1, 1, 1).expect("limits"),
    )
    .expect_err("pagination must have a hard bound");
    assert_eq!(error.kind(), GitHubIntakeErrorKind::PageLimitExceeded);
    assert_eq!(over_bound.requests.len(), 1);
}

#[test]
fn exhausted_rate_limit_stops_before_following_page() {
    let mut source = FakeMetadataSource::new([Ok(page(
        "snapshot-1",
        vec![issue(1, "trusted", false)],
        true,
        0,
    ))]);
    let error = collect_github_metadata(
        "owner/repository",
        &mut source,
        GitHubIntakeLimits::new(2, 1, 2).expect("limits"),
    )
    .expect_err("known exhausted rate limit must refuse continuation");
    assert_eq!(error.kind(), GitHubIntakeErrorKind::RateLimited);
    assert_eq!(source.requests.len(), 1);
}

#[derive(Debug, Eq, PartialEq)]
struct FakeContentError;

struct FakeContentFetcher {
    calls: usize,
}

impl GitHubContentFetcher for FakeContentFetcher {
    type Content = &'static str;
    type Error = FakeContentError;

    fn fetch_content(
        &mut self,
        _metadata: &GitHubIssueMetadata,
    ) -> Result<Self::Content, Self::Error> {
        self.calls += 1;
        Ok("untrusted content stays outside metadata")
    }
}

#[test]
fn allowlist_refuses_before_content_fetch_and_allows_only_non_pr_issue() {
    let policy = TrustPolicy::new("owner/repository", ["trusted"]).expect("policy");
    let mut fetcher = FakeContentFetcher { calls: 0 };

    let error = fetch_allowlisted_content(&policy, &issue(1, "untrusted", false), &mut fetcher)
        .expect_err("unallowlisted content must be refused");
    assert_eq!(error, GitHubContentFetchError::AllowlistRefused);
    assert_eq!(fetcher.calls, 0);

    let error = fetch_allowlisted_content(&policy, &issue(2, "trusted", true), &mut fetcher)
        .expect_err("pull requests are excluded before content fetch");
    assert_eq!(error, GitHubContentFetchError::PullRequestExcluded);
    assert_eq!(fetcher.calls, 0);

    let content = fetch_allowlisted_content(&policy, &issue(3, "trusted", false), &mut fetcher)
        .expect("allowlisted issue content");
    assert_eq!(content, "untrusted content stays outside metadata");
    assert_eq!(fetcher.calls, 1);
}

#[test]
fn source_rate_limit_error_is_returned_without_retrying() {
    let mut source = FakeMetadataSource::new([Err(GitHubIntakeError::rate_limited(Some(30)))]);
    let error = collect_github_metadata(
        "owner/repository",
        &mut source,
        GitHubIntakeLimits::new(2, 1, 2).expect("limits"),
    )
    .expect_err("source rate-limit errors must be surfaced");
    assert_eq!(error.kind(), GitHubIntakeErrorKind::RateLimited);
    assert_eq!(error.retry_after_seconds(), Some(30));
    assert_eq!(source.requests.len(), 1);
}

#[test]
fn source_failure_on_later_page_discards_partial_snapshot_and_stops() {
    let mut source = FakeMetadataSource::new([
        Ok(page(
            "snapshot-1",
            vec![issue(1, "trusted", false)],
            true,
            1,
        )),
        Err(GitHubIntakeError::source_unavailable()),
        Ok(page(
            "snapshot-1",
            vec![issue(2, "trusted", false)],
            false,
            1,
        )),
    ]);

    let error = collect_github_metadata(
        "owner/repository",
        &mut source,
        GitHubIntakeLimits::new(3, 1, 3).expect("limits"),
    )
    .expect_err("source failure must refuse the partial snapshot");

    assert_eq!(error.kind(), GitHubIntakeErrorKind::SourceUnavailable);
    assert_eq!(error.retry_after_seconds(), None);
    assert_eq!(
        source.requests,
        vec![(1, None), (2, Some(String::from("snapshot-1")))]
    );
}
