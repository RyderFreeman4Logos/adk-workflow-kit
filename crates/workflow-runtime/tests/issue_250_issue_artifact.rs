use std::num::NonZeroU64;

use workflow_runtime::{
    ArtifactStore, GitHubIssueMetadata, GitHubIssueState, InMemoryArtifactStore, IssueOmission,
    NodeCacheKey, NodeCacheKeyMaterial, ObjectChange, OfflineComment, OfflineIssueContent,
    PageRequest, TrustPolicy, build_canonical_issue_artifact, refuse_long_thread,
};

const OMITTED: &[u8] = b"OMITTED-COMMENT-BYTES-250";

fn content(comments: Vec<OfflineComment>) -> OfflineIssueContent {
    OfflineIssueContent::new(
        issue(),
        "snapshot-250",
        b"trusted title".to_vec(),
        b"trusted body".to_vec(),
        comments,
    )
    .expect("content")
}

fn comment(id: &str, author: &str, order: u32, revision: u64, bytes: &[u8]) -> OfflineComment {
    OfflineComment::new(id, author, order, revision, false, bytes.to_vec()).expect("comment")
}

fn store() -> InMemoryArtifactStore {
    InMemoryArtifactStore::new(
        NonZeroU64::new(65_536).unwrap(),
        NonZeroU64::new(65_536).unwrap(),
    )
}

fn policy(authors: &[&str]) -> TrustPolicy {
    TrustPolicy::new("owner/repo", authors.iter().copied()).expect("policy")
}

fn key<'a>(
    artifact: &'a workflow_runtime::CanonicalIssueArtifact,
    schema: &'a str,
    trust: &'a str,
) -> NodeCacheKey {
    artifact
        .cache_key(NodeCacheKeyMaterial {
            workflow_id: "issue-artifact",
            workflow_version: schema,
            node_id: "canonical-issue",
            node_version: "1",
            invocation_identity: trust,
            input_artifact_hashes: &[],
            request_input_digest: "replaced",
            policy_digest: "replaced",
        })
        .expect("cache key")
}

fn issue() -> GitHubIssueMetadata {
    GitHubIssueMetadata::new(
        250,
        "trusted-author",
        "MEMBER",
        GitHubIssueState::Open,
        "2026-09-26T00:00:00Z",
        false,
    )
    .expect("metadata")
}

#[test]
fn unallowlisted_comment_bytes_are_absent_from_artifact_and_errors() {
    let policy = TrustPolicy::new("owner/repo", ["trusted-author"]).expect("policy");
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(65_536).unwrap(),
        NonZeroU64::new(65_536).unwrap(),
    );
    let content = workflow_runtime::OfflineIssueContent::new(
        issue(),
        "snapshot-250",
        b"trusted title".to_vec(),
        b"trusted body".to_vec(),
        vec![
            workflow_runtime::OfflineComment::new(
                "comment-omitted",
                "stranger",
                1,
                1,
                false,
                OMITTED.to_vec(),
            )
            .expect("comment"),
        ],
    )
    .expect("content");

    let built = build_canonical_issue_artifact(&policy, &content, &mut store);
    let rendered = format!("{built:?}");
    assert!(
        !rendered.contains("OMITTED-COMMENT-BYTES-250"),
        "omitted comment bytes must not appear in success or error output"
    );
    let artifact = built.expect("canonical artifact");
    assert!(
        !format!("{artifact:?}").contains("OMITTED-COMMENT-BYTES-250"),
        "canonical artifact debug output must not retain omitted bytes"
    );
    let page = store
        .read_page(
            artifact.content_id(),
            workflow_runtime::PageRequest::new(0, NonZeroU64::new(65_536).unwrap()),
        )
        .expect("stored content");
    assert!(
        !page
            .bytes()
            .windows(OMITTED.len())
            .any(|window| window == OMITTED),
        "artifact store must not retain omitted comment bytes"
    );
    assert_eq!(
        artifact.omissions(),
        &[IssueOmission::new(
            "comment-omitted",
            "author_not_allowlisted"
        )]
    );
    let span = artifact.included()[0].span();
    let spanned = store
        .read_page(
            artifact.content_id(),
            PageRequest::new(
                span.start(),
                NonZeroU64::new(span.end() - span.start()).unwrap(),
            ),
        )
        .expect("span");
    assert_eq!(spanned.bytes(), b"trusted body");
}

#[test]
fn invalid_records_fail_before_store_visibility() {
    assert!(OfflineComment::new(" ", "author", 1, 1, false, b"x".to_vec()).is_err());
    assert!(OfflineComment::new("id", "author", 1, 0, false, b"x".to_vec()).is_err());
    assert!(
        OfflineIssueContent::new(
            issue(),
            "snapshot-250",
            b"title".to_vec(),
            b"body".to_vec(),
            vec![
                comment("same", "trusted-author", 2, 1, b"later"),
                comment("same", "trusted-author", 1, 1, b"earlier"),
            ],
        )
        .is_err()
    );
}

#[test]
fn identical_inputs_reuse_identity_and_policy_change_misses() {
    let admitted = content(vec![comment("kept", "trusted-author", 1, 1, b"kept-bytes")]);
    let mut first_store = store();
    let mut second_store = store();
    let trusted = policy(&["trusted-author"]);
    let first =
        build_canonical_issue_artifact(&trusted, &admitted, &mut first_store).expect("first");
    let second =
        build_canonical_issue_artifact(&trusted, &admitted, &mut second_store).expect("second");
    assert_eq!(first.manifest_bytes(), second.manifest_bytes());
    assert_eq!(first.content_id(), second.content_id());
    assert_eq!(
        key(&first, "1", "allowlist"),
        key(&second, "1", "allowlist")
    );
    assert_ne!(key(&first, "1", "allowlist"), key(&first, "2", "allowlist"));
    assert_ne!(
        key(&first, "1", "allowlist"),
        key(&first, "1", "other-domain")
    );
}

#[test]
fn append_preserves_unchanged_digest_and_edit_does_not() {
    let base = content(vec![comment("kept", "trusted-author", 1, 1, b"kept")]);
    let appended = content(vec![
        comment("kept", "trusted-author", 1, 1, b"kept"),
        comment("added", "trusted-author", 2, 1, b"added"),
    ]);
    let edited = content(vec![comment("kept", "trusted-author", 1, 2, b"changed")]);
    let mut artifact_store = store();
    let trusted = policy(&["trusted-author"]);
    let before =
        build_canonical_issue_artifact(&trusted, &base, &mut artifact_store).expect("base");
    let after =
        build_canonical_issue_artifact(&trusted, &appended, &mut artifact_store).expect("append");
    let changed =
        build_canonical_issue_artifact(&trusted, &edited, &mut artifact_store).expect("edit");
    assert_eq!(before.included()[0].digest(), after.included()[0].digest());
    assert_ne!(before.aggregate_digest(), after.aggregate_digest());
    assert!(
        after.diff_from(Some(&before)).iter().any(|entry| {
            entry.object_id() == "added" && entry.change() == ObjectChange::Appended
        })
    );
    assert_ne!(
        before.included()[1].digest(),
        changed.included()[1].digest()
    );
}

#[test]
fn long_thread_request_is_not_routed() {
    let error = refuse_long_thread().expect_err("distiller route is absent");
    assert_eq!(
        error.kind(),
        workflow_runtime::IssueArtifactErrorKind::NotRouted
    );
    assert!(!error.to_string().contains("trusted body"));
}
