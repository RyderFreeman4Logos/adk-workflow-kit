use workflow_runtime::{
    ContentObject, ContentProvenance, ExecutorTarget, SYNTHETIC_HONEYTOKEN_PREFIX,
    SecretPolicyError, SentinelProbe, SyntheticSecretPolicy, TrustDomain, TrustPolicy,
    TrustPolicyError,
};

#[test]
fn sentinel_probe_rejects_production_executor_at_startup() {
    let error = SentinelProbe::bind(ExecutorTarget::Production)
        .expect_err("a sentinel probe must never bind to production");

    assert_eq!(
        error.to_string(),
        "sentinel probes require a simulated executor"
    );
}

#[test]
fn comment_trust_is_independent_from_issue_author_trust() {
    let policy = TrustPolicy::new("tenant-a/workflow-a", ["trusted-issue-author"])
        .expect("valid trust policy");
    let issue = policy
        .classify(ContentObject::IssueBody {
            object_id: "issue-225",
            author: "trusted-issue-author",
        })
        .expect("valid issue identity");
    let comment = policy
        .classify(ContentObject::Comment {
            object_id: "comment-225-1",
            author: "untrusted-comment-author",
        })
        .expect("valid comment identity");

    assert_eq!(issue.domain(), TrustDomain::ConditionallyTrustedContent);
    assert_eq!(comment.domain(), TrustDomain::UntrustedContent);
    assert_eq!(issue.object_id(), "issue-225");
    assert_eq!(comment.object_id(), "comment-225-1");
    assert_ne!(issue.author(), comment.author());
}

#[test]
fn cache_keys_bind_scope_object_kind_author_and_policy_identity() {
    let content = b"identical fixture content";
    let policy = TrustPolicy::new("tenant-a/workflow-a", ["author-a", "author-b"])
        .expect("valid trust policy");
    let same_object = policy
        .classify(ContentObject::IssueBody {
            object_id: "object-a",
            author: "author-a",
        })
        .expect("valid identity");
    let other_object = policy
        .classify(ContentObject::IssueBody {
            object_id: "object-b",
            author: "author-a",
        })
        .expect("valid identity");
    let other_kind = policy
        .classify(ContentObject::Comment {
            object_id: "object-a",
            author: "author-a",
        })
        .expect("valid identity");
    let other_author = policy
        .classify(ContentObject::IssueBody {
            object_id: "object-a",
            author: "author-b",
        })
        .expect("valid identity");
    let other_scope = TrustPolicy::new("tenant-b/workflow-a", ["author-a", "author-b"])
        .expect("valid trust policy")
        .classify(ContentObject::IssueBody {
            object_id: "object-a",
            author: "author-a",
        })
        .expect("valid identity");
    let other_policy = TrustPolicy::new("tenant-a/workflow-a", ["author-a", "author-c"])
        .expect("valid trust policy")
        .classify(ContentObject::IssueBody {
            object_id: "object-a",
            author: "author-a",
        })
        .expect("valid identity");

    assert_ne!(
        same_object.cache_key(content),
        other_object.cache_key(content)
    );
    assert_ne!(
        same_object.cache_key(content),
        other_kind.cache_key(content)
    );
    assert_ne!(
        same_object.cache_key(content),
        other_author.cache_key(content)
    );
    assert_ne!(
        same_object.cache_key(content),
        other_scope.cache_key(content)
    );
    assert_ne!(
        same_object.cache_key(content),
        other_policy.cache_key(content)
    );
    assert_ne!(
        TrustDomain::ConditionallyTrustedContent.cache_salt(),
        TrustDomain::UntrustedContent.cache_salt()
    );
}

#[test]
fn logs_redact_synthetic_honeytokens_and_reject_secret_fixture_patterns() {
    let mut policy = SyntheticSecretPolicy::default();
    let token = policy
        .issue("sentinel-probe-225", "case-a")
        .expect("synthetic token fixture");
    assert!(token.as_str().starts_with(SYNTHETIC_HONEYTOKEN_PREFIX));
    let line = format!("probe token={}", token.as_str());
    let redacted = policy
        .sanitize_log(&line)
        .expect("synthetic token is log-safe");

    assert_eq!(redacted, "probe token=[REDACTED_SYNTHETIC]");
    assert!(!redacted.contains(token.as_str()));

    let error = policy
        .sanitize_log("API_KEY : \"opaque-value\"")
        .expect_err("real-secret-shaped fixtures must be rejected");
    assert_eq!(error, SecretPolicyError::RealSecretFixtureRejected);
    assert!(!error.to_string().contains("api_key"));
}

#[test]
fn sanitizer_redacts_foreign_markers_and_structured_variants() {
    let mut first_policy = SyntheticSecretPolicy::default();
    let foreign_token = first_policy
        .issue("probe-a", "nonce-a")
        .expect("synthetic token fixture");
    let mut second_policy = SyntheticSecretPolicy::default();
    let local_token = second_policy
        .issue("probe-b", "nonce-b")
        .expect("synthetic token fixture");

    let line = format!(
        "{{\n  \"credential\" : \"{}\",\n  \"other\": \"{}\"\n}}",
        foreign_token.as_str(),
        local_token.as_str()
    );
    let redacted = second_policy
        .sanitize_log(&line)
        .expect("all synthetic markers are log-safe");

    assert_eq!(redacted.matches("[REDACTED_SYNTHETIC]").count(), 2);
    assert!(!redacted.contains(SYNTHETIC_HONEYTOKEN_PREFIX));
}

#[test]
fn sanitizer_rejects_unknown_secret_like_whitespace_structure() {
    let policy = SyntheticSecretPolicy::default();
    let error = policy
        .sanitize_log("{\n  \"access_token\"\n : \"opaque-value\"\n}")
        .expect_err("unknown secret-shaped values must fail closed");

    assert_eq!(error, SecretPolicyError::RealSecretFixtureRejected);

    let error = policy
        .sanitize_log("secret_value : opaque-value")
        .expect_err("unknown secret-like keys must fail closed");
    assert_eq!(error, SecretPolicyError::RealSecretFixtureRejected);
}

#[test]
fn trust_policy_rejects_blank_scope_allowlist_and_object_identity() {
    assert_eq!(
        TrustPolicy::new(" \t", ["trusted-author"]).expect_err("blank scope must be rejected"),
        TrustPolicyError::EmptyScope
    );
    assert_eq!(
        TrustPolicy::new("tenant-a", [" \n "]).expect_err("blank allowlist entry must be rejected"),
        TrustPolicyError::EmptyAllowlistedAuthor
    );

    let policy = TrustPolicy::new("tenant-a", ["trusted-author"]).expect("valid trust policy");
    assert_eq!(
        policy
            .classify(ContentObject::Comment {
                object_id: "\n",
                author: "trusted-author",
            })
            .expect_err("blank object ID must be rejected"),
        TrustPolicyError::EmptyObjectId
    );
    assert_eq!(
        policy
            .classify(ContentObject::Comment {
                object_id: "comment-1",
                author: " \t",
            })
            .expect_err("blank author must be rejected"),
        TrustPolicyError::EmptyAuthor
    );
}

#[test]
fn deserialized_provenance_rejects_blank_identity() {
    let policy = TrustPolicy::new("tenant-a", ["trusted-author"]).expect("valid trust policy");
    let provenance = policy
        .classify(ContentObject::Comment {
            object_id: "comment-1",
            author: "trusted-author",
        })
        .expect("valid identity");
    let json = serde_json::to_string(&provenance).expect("serialize provenance");
    let invalid_object_id = json.replace("comment-1", " ");
    let invalid_author = json.replace("trusted-author", "\t");

    assert!(serde_json::from_str::<ContentProvenance>(&invalid_object_id).is_err());
    assert!(serde_json::from_str::<ContentProvenance>(&invalid_author).is_err());
}
