use std::num::NonZeroU64;

use workflow_runtime::{
    Actionability, AmbiguityReasonCode, CapabilityId, ComponentId, GitHubIssueMetadata,
    GitHubIssueState, ISSUE_CARD_MAX_COLLECTION_ITEMS, ISSUE_CARD_MAX_OBJECTIVE_BYTES,
    ISSUE_CARD_MAX_RENDERED_BYTES, InMemoryArtifactStore, IssueCardCacheIdentity,
    IssueCardCollectionInputs, IssueCardError, IssueCardV1, OfflineComment, OfflineIssueContent,
    PriorityDependency, PriorityEffort, PriorityImpact, PriorityInputs, PriorityReasonCode,
    PriorityScore, PriorityUrgency, RiskCode, TrustPolicy, UnableReasonCode,
    build_canonical_issue_artifact,
};

fn issue(number: u64) -> GitHubIssueMetadata {
    GitHubIssueMetadata::new(
        number,
        "trusted-author",
        "MEMBER",
        GitHubIssueState::Open,
        "2026-09-26T00:00:00Z",
        false,
    )
    .expect("metadata")
}

fn artifact_for(
    number: u64,
    snapshot: &str,
    repository: &str,
) -> workflow_runtime::CanonicalIssueArtifact {
    let content = OfflineIssueContent::new(
        issue(number),
        snapshot,
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
    let policy = TrustPolicy::new(repository, ["trusted-author"]).expect("policy");
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(65_536).expect("page size"),
        NonZeroU64::new(65_536).expect("artifact size"),
    );
    build_canonical_issue_artifact(&policy, &content, &mut store).expect("artifact")
}

fn artifact() -> workflow_runtime::CanonicalIssueArtifact {
    artifact_for(251, "snapshot-251", "owner/repo")
}

fn inputs(impact: PriorityImpact) -> PriorityInputs {
    PriorityInputs::new(
        impact,
        PriorityUrgency::High,
        PriorityEffort::Small,
        PriorityDependency::Blocks,
    )
}

fn card_from(
    artifact: &workflow_runtime::CanonicalIssueArtifact,
    id: &str,
    objective: &str,
    impact: PriorityImpact,
) -> IssueCardV1 {
    IssueCardV1::from_artifact(
        id,
        objective,
        Actionability::Actionable,
        inputs(impact),
        artifact,
        "model:none",
        "prompt-v1",
    )
    .expect("card")
}

fn card(id: &str, impact: PriorityImpact) -> IssueCardV1 {
    card_from(&artifact(), id, "runtime-foundation", impact)
}

#[test]
fn source_binding_preserves_only_included_spans() {
    let artifact = artifact();
    let card = card_from(
        &artifact,
        "issue-251",
        "runtime-foundation",
        PriorityImpact::High,
    );

    assert_eq!(
        card.source().content_hash(),
        artifact.content_ref().sha256()
    );
    assert_eq!(
        card.source().aggregate_digest(),
        artifact.aggregate_digest()
    );
    assert_eq!(card.source().policy_digest(), artifact.policy_digest());
    assert_eq!(card.source().evidence().len(), artifact.included().len());
    assert_eq!(card.references(), card.source().evidence());
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
    assert_eq!(high.priority_inputs().impact(), PriorityImpact::Critical);
    assert!(high.priority_order_key() > low.priority_order_key());
    assert_eq!(high.priority_order_key().version(), 1);
    assert_eq!(high.priority_order_key().impact_rank(), 4);
}

#[test]
fn cache_identity_binds_the_canonical_aggregate_and_execution_inputs() {
    let artifact = artifact();
    let first = IssueCardCacheIdentity::from_artifact(&artifact, "model:none", "prompt-v1")
        .expect("cache identity");
    let same = IssueCardCacheIdentity::from_artifact(&artifact, "model:none", "prompt-v1")
        .expect("cache identity");
    let other_model = IssueCardCacheIdentity::from_artifact(&artifact, "model:other", "prompt-v1")
        .expect("cache identity");
    let other_prompt = IssueCardCacheIdentity::from_artifact(&artifact, "model:none", "prompt-v2")
        .expect("cache identity");
    let other_issue = artifact_for(252, "snapshot-252", "owner/repo");
    let other_aggregate =
        IssueCardCacheIdentity::from_artifact(&other_issue, "model:none", "prompt-v1")
            .expect("cache identity");

    assert_eq!(first, same);
    assert_eq!(first.cache_schema_version(), 3);
    assert_eq!(first.schema_version(), 1);
    assert_eq!(first.priority_order_version(), 1);
    assert_eq!(first.aggregate_digest(), artifact.aggregate_digest());
    assert_ne!(first.digest(), other_model.digest());
    assert_ne!(first.digest(), other_prompt.digest());
    assert_ne!(first.aggregate_digest(), other_aggregate.aggregate_digest());
    assert_ne!(first.digest(), other_aggregate.digest());
}

#[test]
fn public_cards_with_the_same_artifact_model_and_prompt_do_not_share_cache_identity() {
    let artifact = artifact();
    let low = card_from(&artifact, "issue-low", "objective-low", PriorityImpact::Low);
    let high = card_from(
        &artifact,
        "issue-high",
        "objective-high",
        PriorityImpact::Critical,
    );
    let same = card_from(&artifact, "issue-low", "objective-low", PriorityImpact::Low);

    assert_eq!(
        low.cache_identity().digest(),
        same.cache_identity().digest()
    );
    assert_ne!(
        low.cache_identity().digest(),
        high.cache_identity().digest()
    );
    assert_ne!(
        serde_json::to_string(low.cache_identity()).expect("serialize cache"),
        serde_json::to_string(high.cache_identity()).expect("serialize cache")
    );

    let reordered = low
        .clone()
        .with_components([
            ComponentId::new("runtime").expect("component"),
            ComponentId::new("compiler").expect("component"),
        ])
        .expect("components");
    let ordered = low
        .clone()
        .with_components([ComponentId::new("compiler").expect("component")])
        .expect("components")
        .with_components([ComponentId::new("runtime").expect("component")])
        .expect("components");
    assert_eq!(
        reordered.cache_identity().digest(),
        ordered.cache_identity().digest()
    );
    let other_collection = low
        .clone()
        .with_components([ComponentId::new("runtime").expect("component")])
        .expect("components");
    assert_ne!(
        reordered.cache_identity().digest(),
        other_collection.cache_identity().digest()
    );

    let ambiguous = IssueCardV1::from_artifact(
        "issue-low",
        "objective-low",
        Actionability::ambiguous(AmbiguityReasonCode::ConflictingSignals),
        inputs(PriorityImpact::Low),
        &artifact,
        "model:none",
        "prompt-v1",
    )
    .expect("card");
    assert_ne!(
        low.cache_identity().digest(),
        ambiguous.cache_identity().digest()
    );

    let other_inputs = IssueCardV1::from_artifact(
        "issue-low",
        "objective-low",
        Actionability::Actionable,
        PriorityInputs::new(
            PriorityImpact::Low,
            PriorityUrgency::Unknown,
            PriorityEffort::Large,
            PriorityDependency::None,
        ),
        &artifact,
        "model:none",
        "prompt-v1",
    )
    .expect("card");
    assert_ne!(
        low.cache_identity().digest(),
        other_inputs.cache_identity().digest()
    );

    let rehydrated = IssueCardV1::rehydrate(
        high.id(),
        high.objective(),
        high.actionability(),
        high.priority_inputs(),
        &artifact,
        (high.source().clone(), high.cache_identity().clone()),
        IssueCardCollectionInputs::new(
            high.components().to_vec(),
            high.prerequisites().to_vec(),
            high.capabilities().to_vec(),
            high.risks().to_vec(),
        ),
    )
    .expect("rehydrate matching card");
    assert_eq!(
        rehydrated.cache_identity().digest(),
        high.cache_identity().digest()
    );
    let rejected = IssueCardV1::rehydrate(
        low.id(),
        low.objective(),
        low.actionability(),
        low.priority_inputs(),
        &artifact,
        (high.source().clone(), high.cache_identity().clone()),
        IssueCardCollectionInputs::new(
            low.components().to_vec(),
            low.prerequisites().to_vec(),
            low.capabilities().to_vec(),
            low.risks().to_vec(),
        ),
    );
    assert_eq!(
        rejected.expect_err("stale card cache"),
        IssueCardError::InvalidIdentity
    );
}

#[test]
fn cache_digest_frames_collection_boundaries_through_public_card_builders() {
    let artifact = artifact();
    let components = card_from(&artifact, "issue-251", "objective", PriorityImpact::High)
        .with_components([
            ComponentId::new("a").expect("component"),
            ComponentId::new("b").expect("component"),
        ])
        .expect("components");
    let split = card_from(&artifact, "issue-251", "objective", PriorityImpact::High)
        .with_components([ComponentId::new("a").expect("component")])
        .expect("components")
        .with_prerequisites([ComponentId::new("b").expect("component")])
        .expect("prerequisites");

    assert_ne!(
        components.cache_identity().digest(),
        split.cache_identity().digest(),
        "different typed collections must not share cache identity"
    );
}

#[test]
fn public_rehydrate_preserves_enriched_collections_and_rejects_stale_digest() {
    let artifact = artifact();
    let card = card_from(&artifact, "issue-251", "objective", PriorityImpact::High)
        .with_components([ComponentId::new("component-a").expect("component")])
        .expect("components")
        .with_prerequisites([ComponentId::new("prerequisite-a").expect("prerequisite")])
        .expect("prerequisites")
        .with_capabilities([CapabilityId::new("capability-a").expect("capability")])
        .expect("capabilities")
        .with_risks([RiskCode::ExternalDependency])
        .expect("risks");
    let rehydrated = IssueCardV1::rehydrate(
        card.id(),
        card.objective(),
        card.actionability(),
        card.priority_inputs(),
        &artifact,
        (card.source().clone(), card.cache_identity().clone()),
        IssueCardCollectionInputs::new(
            card.components().to_vec(),
            card.prerequisites().to_vec(),
            card.capabilities().to_vec(),
            card.risks().to_vec(),
        ),
    )
    .expect("enriched card must rehydrate");

    assert_eq!(rehydrated.components(), card.components());
    assert_eq!(rehydrated.prerequisites(), card.prerequisites());
    assert_eq!(rehydrated.capabilities(), card.capabilities());
    assert_eq!(rehydrated.risks(), card.risks());
    assert_eq!(
        rehydrated.cache_identity().digest(),
        card.cache_identity().digest()
    );

    let stale = card
        .clone()
        .with_components([ComponentId::new("component-b").expect("component")])
        .expect("component");
    assert_eq!(
        IssueCardV1::rehydrate(
            card.id(),
            card.objective(),
            card.actionability(),
            card.priority_inputs(),
            &artifact,
            (card.source().clone(), stale.cache_identity().clone()),
            IssueCardCollectionInputs::new(
                card.components().to_vec(),
                card.prerequisites().to_vec(),
                card.capabilities().to_vec(),
                card.risks().to_vec(),
            ),
        )
        .expect_err("digest mismatch must reject tampered collection"),
        IssueCardError::InvalidIdentity
    );
}

#[test]
fn rehydration_rejects_cross_artifact_policy_material() {
    let artifact_a = artifact();
    let artifact_b = artifact_for(251, "snapshot-251", "other/repo");
    let card_a = card_from(
        &artifact_a,
        "issue-251",
        "runtime-foundation",
        PriorityImpact::High,
    );
    let card_b = card_from(
        &artifact_b,
        "issue-251",
        "runtime-foundation",
        PriorityImpact::High,
    );

    let error = IssueCardV1::rehydrate(
        "issue-251",
        "runtime-foundation",
        Actionability::Actionable,
        inputs(PriorityImpact::High),
        &artifact_a,
        (card_b.source().clone(), card_b.cache_identity().clone()),
        IssueCardCollectionInputs::new(
            card_b.components().to_vec(),
            card_b.prerequisites().to_vec(),
            card_b.capabilities().to_vec(),
            card_b.risks().to_vec(),
        ),
    )
    .expect_err("cross-artifact source must be rejected");
    assert_eq!(error, IssueCardError::InvalidIdentity);

    let error = IssueCardV1::rehydrate(
        "issue-251",
        "runtime-foundation",
        Actionability::Actionable,
        inputs(PriorityImpact::High),
        &artifact_a,
        (card_a.source().clone(), card_b.cache_identity().clone()),
        IssueCardCollectionInputs::new(
            card_a.components().to_vec(),
            card_a.prerequisites().to_vec(),
            card_a.capabilities().to_vec(),
            card_a.risks().to_vec(),
        ),
    )
    .expect_err("mismatched policy cache must be rejected");
    assert_eq!(error, IssueCardError::InvalidIdentity);
}

#[test]
fn renderer_is_stable_escaped_and_collection_framing_is_unambiguous() {
    let first = card("issue-251", PriorityImpact::High)
        .with_components([
            ComponentId::new("runtime").expect("component"),
            ComponentId::new("compiler").expect("component"),
            ComponentId::new("compiler, runtime").expect("component"),
        ])
        .expect("components")
        .with_prerequisites([ComponentId::new("trusted-intake").expect("component")])
        .expect("prerequisites")
        .with_capabilities([CapabilityId::new("read-source").expect("capability")])
        .expect("capabilities")
        .with_risks([RiskCode::UncalibratedPriority])
        .expect("risks");
    let second = card("issue-251", PriorityImpact::High)
        .with_components([ComponentId::new("compiler").expect("component")])
        .expect("components")
        .with_components([ComponentId::new("runtime").expect("component")])
        .expect("components")
        .with_components([ComponentId::new("compiler, runtime").expect("component")])
        .expect("components")
        .with_prerequisites([ComponentId::new("trusted-intake").expect("component")])
        .expect("prerequisites")
        .with_capabilities([CapabilityId::new("read-source").expect("capability")])
        .expect("capabilities")
        .with_risks([RiskCode::UncalibratedPriority])
        .expect("risks");

    let rendered = first.render_markdown().expect("render");
    assert_eq!(rendered, second.render_markdown().expect("render"));
    assert!(rendered.contains("schema: issue-card-v1"));
    assert!(rendered.contains("actionability: \"actionable\""));
    assert!(rendered.contains("priority_score: \"not\\_calibrated\""));
    assert!(rendered.contains("components: [\"compiler\", \"compiler\\, runtime\", \"runtime\"]"));
    assert!(rendered.contains("risks: [\"uncalibrated\\_priority\"]"));

    let dangerous = card_from(
        &artifact(),
        "![card](javascript:alert(1))",
        "![objective](javascript:alert(2)) <img src=x>",
        PriorityImpact::High,
    )
    .render_markdown()
    .expect("render");
    assert!(
        dangerous.contains("\\!\\[objective\\]\\(javascript\\:alert\\(2\\)\\) \\<img src\\=x\\>")
    );
    assert!(!dangerous.contains("<img src=x>"));
}

#[test]
fn public_renderer_keeps_free_text_literal_for_gfm_and_lists_framed() {
    let objective = r#"~~do not deploy~~; see https://example.invalid/item; a*b _c_ [d](e) `f` #g +h -i !j <k> |l ^m ~n"#;
    let rendered = card_from(&artifact(), "issue-251", objective, PriorityImpact::High)
        .with_components([ComponentId::new("compiler, runtime").expect("component")])
        .expect("components")
        .render_markdown()
        .expect("render");

    assert!(rendered.contains(r#"\~\~do not deploy\~\~"#));
    assert!(rendered.contains(r#"see https\:\/\/example\.invalid\/item"#));
    assert!(rendered.contains(r#"a\*b \_c\_ \[d\]\(e\) \`f\` \#g \+h \-i \!j \<k\> \|l \^m \~n"#));
    assert!(!rendered.contains("~~do not deploy~~"));
    assert!(!rendered.contains("https://example.invalid/item"));
    assert!(rendered.contains(r#"components: ["compiler\, runtime"]"#));

    let backslashes = card_from(
        &artifact(),
        "issue-251",
        r#"literal \* and \\ path"#,
        PriorityImpact::High,
    )
    .render_markdown()
    .expect("render");
    assert!(backslashes.contains(r#"objective: "literal \\\* and \\\\ path""#));
}

#[test]
fn debug_output_redacts_semantic_text_and_nested_identity_material() {
    let card = card_from(
        &artifact(),
        "issue-secret-id",
        "objective-secret-text",
        PriorityImpact::High,
    )
    .with_components([ComponentId::new("component-secret").expect("component")])
    .expect("components");
    let debug = format!("{card:?}");
    let source_debug = format!("{:?}", card.source());
    let cache_debug = format!("{:?}", card.cache_identity());

    for secret in [
        "issue-secret-id",
        "objective-secret-text",
        "component-secret",
        "model:none",
        "prompt-v1",
    ] {
        assert!(!debug.contains(secret), "card debug leaked {secret}");
        assert!(
            !source_debug.contains(secret),
            "source debug leaked {secret}"
        );
        assert!(!cache_debug.contains(secret), "cache debug leaked {secret}");
    }
    assert!(debug.contains("component_count: 1"));
    assert!(source_debug.contains("evidence_count"));
    assert!(cache_debug.contains("<redacted>"));
}

#[test]
fn public_card_path_rejects_oversized_objectives_and_collection_growth() {
    let oversized = "x".repeat(ISSUE_CARD_MAX_OBJECTIVE_BYTES + 1);
    let error = IssueCardV1::from_artifact(
        "issue-251",
        oversized,
        Actionability::Actionable,
        inputs(PriorityImpact::High),
        &artifact(),
        "model:none",
        "prompt-v1",
    )
    .expect_err("oversized objective must be rejected");
    assert_eq!(error, IssueCardError::FieldTooLong);

    let too_many = (0..=ISSUE_CARD_MAX_COLLECTION_ITEMS)
        .map(|index| ComponentId::new(format!("component-{index}")).expect("component"));
    let error = card("issue-251", PriorityImpact::High)
        .with_components(too_many)
        .expect_err("collection growth must be rejected");
    assert_eq!(error, IssueCardError::CollectionTooLarge);
}

#[test]
fn public_card_path_accepts_existing_items_at_the_collection_limit() {
    let components = (0..ISSUE_CARD_MAX_COLLECTION_ITEMS)
        .map(|index| ComponentId::new(format!("component-{index}")).expect("component"))
        .collect::<Vec<_>>();
    let component = card("issue-251", PriorityImpact::High)
        .with_components(components)
        .expect("64 components");
    let component = component
        .clone()
        .with_components([ComponentId::new("component-0").expect("component")])
        .expect("existing component at limit");
    assert_eq!(
        component.components().len(),
        ISSUE_CARD_MAX_COLLECTION_ITEMS
    );

    let prerequisites = (0..ISSUE_CARD_MAX_COLLECTION_ITEMS)
        .map(|index| ComponentId::new(format!("prerequisite-{index}")).expect("prerequisite"))
        .collect::<Vec<_>>();
    let prerequisite = card("issue-251", PriorityImpact::High)
        .with_prerequisites(prerequisites)
        .expect("64 prerequisites")
        .with_prerequisites([ComponentId::new("prerequisite-0").expect("prerequisite")])
        .expect("existing prerequisite at limit");
    assert_eq!(
        prerequisite.prerequisites().len(),
        ISSUE_CARD_MAX_COLLECTION_ITEMS
    );

    let capabilities = (0..ISSUE_CARD_MAX_COLLECTION_ITEMS)
        .map(|index| CapabilityId::new(format!("capability-{index}")).expect("capability"))
        .collect::<Vec<_>>();
    let capability = card("issue-251", PriorityImpact::High)
        .with_capabilities(capabilities)
        .expect("64 capabilities")
        .with_capabilities([CapabilityId::new("capability-0").expect("capability")])
        .expect("existing capability at limit");
    assert_eq!(
        capability.capabilities().len(),
        ISSUE_CARD_MAX_COLLECTION_ITEMS
    );

    let risk = card("issue-251", PriorityImpact::High)
        .with_risks([RiskCode::ExternalDependency])
        .expect("risk");
    let risk = risk
        .with_risks([RiskCode::ExternalDependency])
        .expect("duplicate risk");
    assert_eq!(risk.risks().len(), 2);
    assert!(risk.risks().contains(&RiskCode::ExternalDependency));
}

#[test]
fn public_card_rendering_stays_within_the_offline_bound() {
    let card = card_from(
        &artifact(),
        "issue-251",
        &"objective ".repeat(ISSUE_CARD_MAX_OBJECTIVE_BYTES / 10),
        PriorityImpact::High,
    );
    let rendered = card.render_markdown().expect("bounded render");
    assert!(rendered.len() <= ISSUE_CARD_MAX_RENDERED_BYTES);
}
