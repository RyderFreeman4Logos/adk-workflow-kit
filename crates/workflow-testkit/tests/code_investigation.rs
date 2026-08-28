use workflow_review::ReviewVerdict;
use workflow_testkit::code_investigation::{
    DiagnosticCode, FixtureRepo, InvestigationStage, InvestigationStatus, LiveDogfood,
    ReadOnlyTool, SyntheticInvestigation, validate_answer,
};

#[test]
fn synthetic_repo_has_expected_grounded_answer() {
    let result = SyntheticInvestigation::new(FixtureRepo::synthetic())
        .run_fake()
        .expect("deterministic fake model should complete");
    assert_eq!(result.status(), InvestigationStatus::Published);
    assert!(result.answer().claims().iter().any(|claim| {
        claim.text().contains("retry")
            && claim.evidence().iter().any(|evidence| {
                evidence.path().ends_with("retry.rs") && evidence.snippet().contains("retry")
            })
    }));
    assert!(result.trace().llm_requests() >= 1);
    assert!(result.trace().tool_calls().iter().any(|call| {
        call.tool() == ReadOnlyTool::SearchCode
            && call.route() == "search_code"
            && call.query() == "retry"
            && call.path() == Some("src")
    }));
    assert_eq!(result.trace().adk_terminal(), Some("publish"));
    assert!(
        result
            .trace()
            .routes()
            .iter()
            .any(|route| route == "adk:retry_coverage_decision:sufficient")
    );
}

#[test]
fn evidence_digest_mismatch_fails_closed() {
    let result = SyntheticInvestigation::new(FixtureRepo::synthetic())
        .run_fake()
        .expect("fake run should complete");
    let mut answer = result.answer().clone();
    answer.claims_mut()[0].evidence_mut()[0].set_digest("00".repeat(32));
    let error = validate_answer(&answer, result.snapshot()).expect_err("digest must be checked");
    assert_eq!(error.code(), DiagnosticCode::EvidenceDigestMismatch);
}

#[test]
fn public_stage_api_rejects_illegal_jump_and_binds_semantic_ids() {
    let mut session = SyntheticInvestigation::new(FixtureRepo::synthetic()).session();
    let error = session
        .advance(InvestigationStage::InspectEvidence)
        .expect_err("planner must precede inspection");
    assert_eq!(error.code(), DiagnosticCode::IllegalStageTransition);

    let result = SyntheticInvestigation::new(FixtureRepo::synthetic())
        .run_fake()
        .expect("fake run should complete");
    let mut answer = result.answer().clone();
    answer.claims_mut()[0].evidence_mut()[0].set_claim_id("different-claim");
    let error = validate_answer(&answer, result.snapshot()).expect_err("claim IDs are semantic");
    assert_eq!(error.code(), DiagnosticCode::EvidenceClaimBinding);
}

#[test]
fn kill_resume_inspect_and_replay_are_deterministic() {
    let investigation = SyntheticInvestigation::new(FixtureRepo::synthetic());
    let killed = investigation
        .run_until_kill(3)
        .expect("kill point is checkpointed");
    assert_eq!(killed.status(), InvestigationStatus::Killed);
    assert!(killed.checkpoint().is_some());

    let resumed = SyntheticInvestigation::new(FixtureRepo::synthetic())
        .resume(killed.checkpoint().expect("checkpoint"))
        .expect("fresh-process resume should complete");
    assert_eq!(resumed.status(), InvestigationStatus::Published);
    assert!(
        resumed
            .trace()
            .routes()
            .iter()
            .any(|route| route == "resume:search_code")
    );
    assert!(resumed.trace().tool_calls().iter().any(|call| {
        call.tool() == ReadOnlyTool::SearchCode
            && call.query() == "retry"
            && call.path() == Some("src")
    }));
    let inspected = resumed.inspect_artifact(0).expect("artifact page exists");
    assert!(!inspected.is_empty());
    assert!(resumed.replay_validate().is_ok());
}

#[test]
fn resume_rejects_a_forged_partial_trace_digest() {
    let investigation = SyntheticInvestigation::new(FixtureRepo::synthetic());
    let killed = investigation
        .run_until_kill(3)
        .expect("kill point is checkpointed");
    let mut forged = serde_json::to_value(killed.checkpoint().expect("checkpoint"))
        .expect("checkpoint is serializable");
    forged["state_digest"] = serde_json::json!("sha256:forged");
    let forged = serde_json::from_value(forged).expect("checkpoint shape remains valid");

    let error = SyntheticInvestigation::new(FixtureRepo::synthetic())
        .resume(&forged)
        .expect_err("resume must bind the real partial trace");
    assert_eq!(error.code(), DiagnosticCode::CheckpointInvalid);
}

#[test]
fn live_dogfood_is_opt_in_and_safe_to_skip() {
    let live = LiveDogfood::default().run();
    assert!(live.is_skipped());
    assert!(live.diagnostic().is_none_or(|diagnostic| {
        !diagnostic.debug_string().contains("sk-") && !diagnostic.display_string().contains("sk-")
    }));
}

#[test]
fn fixture_package_resources_load_with_workflow() {
    let package = SyntheticInvestigation::fixture_package().expect("fixture package loads");
    assert_eq!(package.skill_id(), "code-investigation");
    assert_eq!(package.resource_count(), 6);
}

#[test]
fn review_loop_publishes_from_structured_pass_verdict() {
    let result = SyntheticInvestigation::new(FixtureRepo::synthetic())
        .run_fake()
        .expect("review loop should complete");
    assert!(
        result
            .trace()
            .routes()
            .iter()
            .any(|route| route == "review_loop_pass")
    );
    assert!(
        !result
            .trace()
            .routes()
            .iter()
            .any(|route| route == "revise")
    );
}

#[test]
fn opt_in_without_constructable_profile_abstains_fail_closed() {
    let live = LiveDogfood::opt_in().run();
    assert!(live.is_abstained());
    assert!(!live.is_published());
    assert_eq!(
        live.diagnostic().map(|diagnostic| diagnostic.code()),
        Some(DiagnosticCode::LiveProfileUnavailable)
    );
}

#[test]
fn review_revise_and_abstain_are_terminal_dogfood_routes() {
    let investigation = SyntheticInvestigation::new(FixtureRepo::synthetic());
    let revised = investigation
        .run_fake_with_review(ReviewVerdict::Revise)
        .expect("structured revision route should terminate safely");
    assert_eq!(revised.status(), InvestigationStatus::Abstained);
    assert_eq!(revised.trace().adk_terminal(), Some("abstain"));

    let abstained = investigation
        .run_fake_with_review(ReviewVerdict::Abstain)
        .expect("structured abstention should be a terminal result");
    assert_eq!(abstained.status(), InvestigationStatus::Abstained);
    assert_eq!(abstained.trace().adk_terminal(), Some("abstain"));
}
