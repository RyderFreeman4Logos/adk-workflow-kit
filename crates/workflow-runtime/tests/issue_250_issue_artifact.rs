use std::num::NonZeroU64;

use workflow_runtime::{
    ArtifactStore, GitHubIssueMetadata, GitHubIssueState, InMemoryArtifactStore, IssueOmission,
    NodeCacheKey, NodeCacheKeyMaterial, ObjectChange, OfflineComment, OfflineIssueContent,
    PageRequest, TrustPolicy, build_canonical_issue_artifact,
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
fn raw_input_debug_never_exposes_decimal_payload_bytes() {
    let payload = b"raw-payload-debug-250".to_vec();
    let comment = comment("hidden", "stranger", 1, 1, &payload);
    let admitted = content(vec![comment.clone()]);
    let raw_bytes = format!("{payload:?}");

    assert!(!format!("{comment:?}").contains(&raw_bytes));
    assert!(!format!("{admitted:?}").contains(&raw_bytes));
}

#[test]
fn unallowlisted_comment_bytes_are_absent_from_artifact_and_errors() {
    let policy = TrustPolicy::new("owner/repo", ["trusted-author"]).expect("policy");
    let mut store = store();
    let content = content(vec![comment("comment-omitted", "stranger", 1, 1, OMITTED)]);

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
            PageRequest::new(0, NonZeroU64::new(65_536).unwrap()),
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
    let span = artifact
        .included()
        .iter()
        .find(|object| object.object_id() == "issue-body")
        .expect("body object")
        .span();
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
}

#[test]
fn duplicate_ids_are_rejected_even_when_order_increases() {
    assert!(
        OfflineIssueContent::new(
            issue(),
            "snapshot-250",
            b"title".to_vec(),
            b"body".to_vec(),
            vec![
                comment("same", "trusted-author", 1, 1, b"first"),
                comment("same", "trusted-author", 2, 1, b"second"),
            ],
        )
        .is_err()
    );
}

#[test]
fn non_increasing_orders_are_rejected_for_unique_ids() {
    assert!(
        OfflineIssueContent::new(
            issue(),
            "snapshot-250",
            b"title".to_vec(),
            b"body".to_vec(),
            vec![
                comment("later", "trusted-author", 2, 1, b"later"),
                comment("earlier", "trusted-author", 1, 1, b"earlier"),
            ],
        )
        .is_err()
    );
}

#[test]
fn identical_inputs_reuse_identity_and_policy_change_misses() {
    let admitted = content(vec![comment("kept", "other-author", 1, 1, b"kept-bytes")]);
    let mut first_store = store();
    let mut second_store = store();
    let trusted = policy(&["trusted-author", "other-author"]);
    let omitting = policy(&["trusted-author"]);
    let first =
        build_canonical_issue_artifact(&trusted, &admitted, &mut first_store).expect("first");
    let second =
        build_canonical_issue_artifact(&trusted, &admitted, &mut second_store).expect("second");
    let retargeted =
        build_canonical_issue_artifact(&omitting, &admitted, &mut second_store).expect("policy");
    assert_eq!(first.manifest_bytes(), second.manifest_bytes());
    assert_eq!(first.content_id(), second.content_id());
    assert_ne!(first.policy_digest(), retargeted.policy_digest());
    assert_ne!(first.aggregate_digest(), retargeted.aggregate_digest());
    assert_eq!(
        retargeted.omissions(),
        &[IssueOmission::new("kept", "author_not_allowlisted")]
    );
    assert!(
        retargeted
            .included()
            .iter()
            .all(|object| object.object_id() != "kept")
    );
    assert!(retargeted.diff_from(Some(&first)).iter().any(|entry| {
        entry.object_id() == "kept" && entry.change() == ObjectChange::NewlyOmitted
    }));
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
    let unchanged_before = before
        .included()
        .iter()
        .find(|object| object.object_id() == "kept")
        .expect("unchanged before");
    let unchanged_after = after
        .included()
        .iter()
        .find(|object| object.object_id() == "kept")
        .expect("unchanged after");
    assert_eq!(unchanged_before.digest(), unchanged_after.digest());
    assert_ne!(before.aggregate_digest(), after.aggregate_digest());
    assert!(
        after.diff_from(Some(&before)).iter().any(|entry| {
            entry.object_id() == "added" && entry.change() == ObjectChange::Appended
        })
    );
    let changed_kept = changed
        .included()
        .iter()
        .find(|object| object.object_id() == "kept")
        .expect("changed kept");
    assert_ne!(unchanged_before.digest(), changed_kept.digest());
}

#[test]
fn title_is_a_tracked_included_object() {
    let old = content(vec![comment("kept", "trusted-author", 1, 1, b"kept")]);
    let new = OfflineIssueContent::new(
        issue(),
        "snapshot-250",
        b"new title".to_vec(),
        b"trusted body".to_vec(),
        vec![comment("kept", "trusted-author", 1, 1, b"kept")],
    )
    .expect("content");
    let trusted = policy(&["trusted-author"]);
    let mut store = store();
    let before = build_canonical_issue_artifact(&trusted, &old, &mut store).expect("old");
    let after = build_canonical_issue_artifact(&trusted, &new, &mut store).expect("new");
    let old_title = before
        .included()
        .iter()
        .find(|object| object.object_id() == "issue-title")
        .expect("title object");
    let new_title = after
        .included()
        .iter()
        .find(|object| object.object_id() == "issue-title")
        .expect("title object");
    assert_ne!(old_title.digest(), new_title.digest());
    assert_ne!(before.manifest_bytes(), after.manifest_bytes());
    assert_ne!(before.aggregate_digest(), after.aggregate_digest());
    assert!(after.diff_from(Some(&before)).iter().any(|entry| {
        entry.object_id() == "issue-title" && entry.change() == ObjectChange::Edited
    }));
    let span = new_title.span();
    let page = store
        .read_page(
            after.content_id(),
            PageRequest::new(
                span.start(),
                NonZeroU64::new(span.end() - span.start()).unwrap(),
            ),
        )
        .expect("title span");
    assert_eq!(page.bytes(), b"new title");
}

#[test]
fn equal_title_and_body_bytes_have_distinct_stable_role_digests() {
    let admitted = OfflineIssueContent::new(
        issue(),
        "snapshot-250",
        b"same title and body".to_vec(),
        b"same title and body".to_vec(),
        Vec::new(),
    )
    .expect("content");
    let trusted = policy(&["trusted-author"]);
    let mut first_store = store();
    let mut second_store = store();
    let first =
        build_canonical_issue_artifact(&trusted, &admitted, &mut first_store).expect("first");
    let second =
        build_canonical_issue_artifact(&trusted, &admitted, &mut second_store).expect("second");
    let first_title = first
        .included()
        .iter()
        .find(|object| object.object_id() == "issue-title")
        .expect("first title");
    let first_body = first
        .included()
        .iter()
        .find(|object| object.object_id() == "issue-body")
        .expect("first body");
    let second_title = second
        .included()
        .iter()
        .find(|object| object.object_id() == "issue-title")
        .expect("second title");
    let second_body = second
        .included()
        .iter()
        .find(|object| object.object_id() == "issue-body")
        .expect("second body");
    assert_ne!(first_title.digest(), first_body.digest());
    assert_eq!(first_title.digest(), second_title.digest());
    assert_eq!(first_body.digest(), second_body.digest());
}

#[test]
fn mixed_permitted_and_omitted_source_order_changes_identity() {
    let first = content(vec![
        comment("permitted", "trusted-author", 1, 1, b"kept"),
        comment("omitted", "stranger", 2, 1, b"hidden"),
    ]);
    let second = content(vec![
        comment("omitted", "stranger", 1, 1, b"hidden"),
        comment("permitted", "trusted-author", 2, 1, b"kept"),
    ]);
    let trusted = policy(&["trusted-author"]);
    let mut store = store();
    let before = build_canonical_issue_artifact(&trusted, &first, &mut store).expect("first");
    let after = build_canonical_issue_artifact(&trusted, &second, &mut store).expect("second");
    assert_ne!(before.manifest_bytes(), after.manifest_bytes());
    assert_ne!(before.aggregate_digest(), after.aggregate_digest());
}

#[test]
fn reserved_object_ids_and_unbounded_input_strings_are_rejected() {
    assert!(
        OfflineComment::new("issue-body", "trusted-author", 1, 1, false, b"x".to_vec()).is_err()
    );
    assert!(
        OfflineComment::new("issue-title", "trusted-author", 1, 1, false, b"x".to_vec()).is_err()
    );
    assert!(OfflineComment::new("x".repeat(257), "author", 1, 1, false, b"x".to_vec()).is_err());
    assert!(OfflineComment::new("id", "author".repeat(257), 1, 1, false, b"x".to_vec()).is_err());
    assert!(
        OfflineIssueContent::new(
            issue(),
            "s".repeat(257),
            b"title".to_vec(),
            b"body".to_vec(),
            Vec::new(),
        )
        .is_err()
    );
}

#[test]
fn bounded_pages_do_not_reject_valid_content() {
    let trusted = policy(&["trusted-author"]);
    let admitted = content(vec![comment(
        "kept",
        "trusted-author",
        1,
        1,
        b"body larger than one page",
    )]);
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(65_536).unwrap(),
        NonZeroU64::new(1).unwrap(),
    );
    let artifact = build_canonical_issue_artifact(&trusted, &admitted, &mut store)
        .expect("valid content must not depend on one-page readback");
    assert!(
        artifact
            .included()
            .iter()
            .any(|object| object.object_id() == "kept")
    );
    assert!(store.retention(artifact.content_id()).is_ok());
}

#[test]
fn deleted_comments_are_payload_free_and_diff_as_deleted() {
    assert!(OfflineComment::new("deleted", "trusted-author", 1, 1, true, Vec::new()).is_ok());
    assert!(OfflineComment::new("deleted", "trusted-author", 1, 1, true, b"old".to_vec()).is_err());

    let trusted = policy(&["trusted-author"]);
    let previous = content(vec![comment("deleted", "trusted-author", 1, 1, b"old")]);
    let current = OfflineIssueContent::new(
        issue(),
        "snapshot-250",
        b"trusted title".to_vec(),
        b"trusted body".to_vec(),
        vec![
            OfflineComment::new("deleted", "trusted-author", 1, 2, true, Vec::new())
                .expect("tombstone"),
        ],
    )
    .expect("content");
    let omitted = content(vec![comment("vanished", "stranger", 1, 1, b"old omitted")]);
    let disappeared = content(Vec::new());
    let mut store = store();
    let before = build_canonical_issue_artifact(&trusted, &previous, &mut store).expect("before");
    let after = build_canonical_issue_artifact(&trusted, &current, &mut store).expect("after");
    let omitted_before =
        build_canonical_issue_artifact(&trusted, &omitted, &mut store).expect("omitted before");
    let disappeared_after = build_canonical_issue_artifact(&trusted, &disappeared, &mut store)
        .expect("disappeared after");
    assert!(after.diff_from(Some(&before)).iter().any(|entry| {
        entry.object_id() == "deleted" && entry.change() == ObjectChange::Deleted
    }));
    assert!(disappeared_after
        .diff_from(Some(&omitted_before))
        .iter()
        .any(|entry| entry.object_id() == "vanished" && entry.change() == ObjectChange::Deleted));

    let omitted_current = OfflineIssueContent::new(
        issue(),
        "snapshot-250",
        b"trusted title".to_vec(),
        b"trusted body".to_vec(),
        vec![
            OfflineComment::new("vanished", "stranger", 1, 2, true, Vec::new()).expect("tombstone"),
        ],
    )
    .expect("content");
    let deleted_after = build_canonical_issue_artifact(&trusted, &omitted_current, &mut store)
        .expect("deleted after omission");
    assert!(deleted_after
        .diff_from(Some(&omitted_before))
        .iter()
        .any(|entry| entry.object_id() == "vanished" && entry.change() == ObjectChange::Deleted));
    assert!(!format!("{after:?}").contains("old"));
}

#[test]
fn long_thread_is_not_routed_by_the_builder() {
    let comments = (0..65)
        .map(|index| {
            comment(
                &format!("comment-{index}"),
                "trusted-author",
                index + 1,
                1,
                b"comment",
            )
        })
        .collect();
    let admitted = content(comments);
    let trusted = policy(&["trusted-author"]);
    let mut store = store();
    let error = build_canonical_issue_artifact(&trusted, &admitted, &mut store)
        .expect_err("large threads must not use the direct path");
    assert_eq!(
        error.kind(),
        workflow_runtime::IssueArtifactErrorKind::NotRouted
    );
}
