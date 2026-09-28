use std::num::NonZeroU64;

use workflow_runtime::{
    Actionability, AmbiguityReasonCode, CapabilityId, ComponentId, GitHubIssueMetadata,
    GitHubIssueState, InMemoryArtifactStore, IssueCardCacheIdentity, IssueCardV1, OfflineComment,
    OfflineIssueContent, PriorityDependency, PriorityEffort, PriorityImpact, PriorityInputs,
    PriorityReasonCode, PriorityScore, PriorityUrgency, RiskCode, TrustPolicy, UnableReasonCode,
    build_canonical_issue_artifact,
};

fn issue() -> GitHubIssueMetadata {
    GitHubIssueMetadata::new(
        251,
        "trusted-author",
        "MEMBER",
        GitHubIssueState::Open,
        "2026-09-26T00:00:00Z",
        false,
    )
    .expect("metadata")
}

fn artifact() -> workflow_runtime::CanonicalIssueArtifact {
    let content = OfflineIssueContent::new(
        issue(),
        "snapshot-251",
        b"trusted title".to_vec(),
        b"trusted body".to_vec(),
        vec![
            OfflineComment::new(
                "comment-1",
                "stranger",
                1,
                1,
                false,
                b"omitted comment".to_vec(),
            )
            .expect("comment"),
        ],
    )
    .expect("content");
    let policy = TrustPolicy::new("owner/repo", ["trusted-author"]).expect("policy");
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(65_536).expect("page size"),
        NonZeroU64::new(65_536).expect("artifact size"),
    );
    build_canonical_issue_artifact(&policy, &content, &mut store).expect("artifact")
}

fn inputs(impact: PriorityImpact) -> PriorityInputs {
    PriorityInputs::new(
        impact,
        PriorityUrgency::High,
        PriorityEffort::Small,
        PriorityDependency::Blocks,
    )
}

fn card(id: &str, impact: PriorityImpact) -> IssueCardV1 {
    IssueCardV1::from_artifact(
        id,
        "runtime-foundation",
        Actionability::Actionable,
        inputs(impact),
        &artifact(),
        "model:none",
        "prompt-v1",
    )
    .expect("card")
}

#[test]
fn source_binding_preserves_only_included_spans() {
    let artifact = artifact();
    let card = IssueCardV1::from_artifact(
        "issue-251",
        "runtime-foundation",
        Actionability::Actionable,
        inputs(PriorityImpact::High),
        &artifact,
        "model:none",
        "prompt-v1",
    )
    .expect("card");

    assert_eq!(
        card.source().content_hash(),
        artifact.content_ref().sha256()
    );
    assert_eq!(card.source().policy_digest(), artifact.policy_digest());
    assert_eq!(card.source().evidence().len(), artifact.included().len());
    assert!(
        card.source()
            .evidence()
            .iter()
            .all(|evidence| evidence.object_id() != "comment-1")
    );
    for (evidence, included) in card.source().evidence().iter().zip(artifact.included()) {
        assert_eq!(evidence.object_id(), included.object_id());
        assert_eq!(evidence.digest(), included.digest());
        assert_eq!(evidence.span(), included.span());
    }
}

#[test]
fn actionability_exposes_typed_negative_states() {
    let ambiguous = Actionability::Ambiguous {
        reason: AmbiguityReasonCode::ConflictingSignals,
    };
    let unable = Actionability::Unable {
        reason: UnableReasonCode::MissingTrustedSource,
    };

    assert!(!ambiguous.is_actionable());
    assert!(!unable.is_actionable());
    assert_eq!(ambiguous.reason_code(), Some("conflicting_signals"));
    assert_eq!(unable.reason_code(), Some("missing_trusted_source"));
}

#[test]
fn priority_is_inspectable_but_not_claimed_calibrated() {
    let low = card("issue-low", PriorityImpact::Low);
    let high = card("issue-high", PriorityImpact::Critical);

    assert_eq!(low.priority_score(), PriorityScore::NotCalibrated);
    assert_eq!(high.priority_score(), PriorityScore::NotCalibrated);
    assert_eq!(low.priority_reasons(), &[PriorityReasonCode::NotCalibrated]);
    assert!(high.priority_order_key() > low.priority_order_key());
    assert_eq!(high.priority_order_key().version(), 1);
}

#[test]
fn cache_identity_binds_all_execution_inputs() {
    let artifact = artifact();
    let first = IssueCardCacheIdentity::from_artifact(&artifact, "model:none", "prompt-v1")
        .expect("cache identity");
    let same = IssueCardCacheIdentity::from_artifact(&artifact, "model:none", "prompt-v1")
        .expect("cache identity");
    let other_model = IssueCardCacheIdentity::from_artifact(&artifact, "model:other", "prompt-v1")
        .expect("cache identity");
    let other_prompt = IssueCardCacheIdentity::from_artifact(&artifact, "model:none", "prompt-v2")
        .expect("cache identity");

    assert_eq!(first, same);
    assert_eq!(first.schema_version(), 1);
    assert_eq!(first.priority_order_version(), 1);
    assert_ne!(first.digest(), other_model.digest());
    assert_ne!(first.digest(), other_prompt.digest());
}

#[test]
fn renderer_is_stable_field_only_and_sorts_identifiers() {
    let first = card("issue-251", PriorityImpact::High)
        .with_components([
            ComponentId::new("runtime").expect("component"),
            ComponentId::new("compiler").expect("component"),
        ])
        .with_prerequisites([ComponentId::new("trusted-intake").expect("component")])
        .with_capabilities([CapabilityId::new("read-source").expect("capability")])
        .with_risks([RiskCode::UncalibratedPriority]);
    let second = card("issue-251", PriorityImpact::High)
        .with_components([ComponentId::new("compiler").expect("component")])
        .with_components([ComponentId::new("runtime").expect("component")])
        .with_prerequisites([ComponentId::new("trusted-intake").expect("component")])
        .with_capabilities([CapabilityId::new("read-source").expect("capability")])
        .with_risks([RiskCode::UncalibratedPriority]);

    let rendered = first.render_markdown();
    assert_eq!(rendered, second.render_markdown());
    assert!(rendered.contains("schema: issue-card-v1"));
    assert!(rendered.contains("actionability: actionable"));
    assert!(rendered.contains("priority_score: not_calibrated"));
    assert!(rendered.contains("components: [compiler, runtime]"));
    assert!(rendered.contains("risks: [uncalibrated_priority]"));
    assert!(!rendered.contains("because"));
    assert!(!rendered.contains("omitted comment"));
}
