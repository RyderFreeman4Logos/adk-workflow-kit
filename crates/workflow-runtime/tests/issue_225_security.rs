use workflow_runtime::{
    ContentObject, ExecutorTarget, SYNTHETIC_HONEYTOKEN_PREFIX, SecretPolicyError, SentinelProbe,
    SyntheticSecretPolicy, TrustDomain, TrustPolicy,
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
    let policy = TrustPolicy::new(["trusted-issue-author"]);
    let issue = policy.classify(ContentObject::IssueBody {
        object_id: "issue-225",
        author: "trusted-issue-author",
    });
    let comment = policy.classify(ContentObject::Comment {
        object_id: "comment-225-1",
        author: "untrusted-comment-author",
    });

    assert_eq!(issue.domain(), TrustDomain::ConditionallyTrustedContent);
    assert_eq!(comment.domain(), TrustDomain::UntrustedContent);
    assert_eq!(issue.object_id(), "issue-225");
    assert_eq!(comment.object_id(), "comment-225-1");
    assert_ne!(issue.author(), comment.author());
}

#[test]
fn cache_keys_and_salts_differ_for_identical_content_across_trust_domains() {
    let content = b"identical fixture content";
    let trusted = TrustDomain::ConditionallyTrustedContent;
    let untrusted = TrustDomain::UntrustedContent;

    assert_ne!(trusted.cache_salt(), untrusted.cache_salt());
    assert_ne!(trusted.cache_key(content), untrusted.cache_key(content));
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
        .sanitize_log("api_key=fixture-placeholder")
        .expect_err("real-secret-shaped fixtures must be rejected");
    assert_eq!(error, SecretPolicyError::RealSecretFixtureRejected);
    assert!(!error.to_string().contains("api_key"));
}
