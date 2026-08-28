use std::{
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use serde_json::json;
use workflow_review::{
    CandidateArtifact, ReviewCost, ReviewDefect, ReviewLoopConfig, ReviewLoopDiagnosticCode,
    ReviewLoopOutcome, ReviewSeverity, ReviewVerdict, ReviewerExecutionBoundary, ReviewerResponse,
    RevisionResponse, SelectedEvidence, ValidationReport, run_bounded_review_loop,
};
use workflow_runtime::{
    CapabilityIntersection, ChildSandbox, RunContext, RunId, RunLimits, RunSandbox, ToolBridge,
    ToolBridgeError, ToolCallContext, ToolEnvelope, ToolFlags, ToolProvenance, ToolRegistration,
    WorkdirManager,
};

const RUBRIC: &str = "publish only complete, evidenced candidates";

fn valid() -> ValidationReport {
    ValidationReport::valid()
}

fn invalid(code: &str) -> ValidationReport {
    ValidationReport::invalid(vec![ReviewDefect::new(
        code.to_owned(),
        ReviewSeverity::Error,
        Some("/claims/0".to_owned()),
        vec!["evidence:claim-0".to_owned()],
        "candidate is missing required evidence".to_owned(),
        Some("add the cited evidence".to_owned()),
    )])
}

fn pass() -> ReviewerResponse {
    ReviewerResponse::new(
        workflow_review::ReviewResult::new(
            workflow_review::REVIEW_SCHEMA_VERSION_V1,
            ReviewVerdict::Pass,
            "candidate is acceptable".to_owned(),
            Vec::new(),
            0.9,
        )
        .expect("fixture review must be valid"),
        ReviewCost::default(),
    )
}

fn revise(code: &str) -> ReviewerResponse {
    ReviewerResponse::new(
        workflow_review::ReviewResult::new(
            workflow_review::REVIEW_SCHEMA_VERSION_V1,
            ReviewVerdict::Revise,
            "candidate needs repair".to_owned(),
            vec![ReviewDefect::new(
                code.to_owned(),
                ReviewSeverity::Error,
                Some("/claims/0".to_owned()),
                vec!["evidence:claim-0".to_owned()],
                "repair the candidate".to_owned(),
                None,
            )],
            0.8,
        )
        .expect("fixture review must be valid"),
        ReviewCost::default(),
    )
}

fn artifact(value: &str) -> CandidateArtifact {
    CandidateArtifact::new(value.as_bytes().to_vec())
}

fn config() -> ReviewLoopConfig {
    ReviewLoopConfig::default()
        .with_rubric(RUBRIC)
        .with_evidence(vec![SelectedEvidence::new(
            "evidence:claim-0".to_owned(),
            "source supports the claim".to_owned(),
        )])
}

#[test]
fn fixture_matrix_repairs_correct_and_abstains() {
    let mut validator_rounds = 0;
    let repairable = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("draft-v1")),
        |candidate| {
            validator_rounds += 1;
            if candidate.bytes() == b"draft-v1" {
                Ok(invalid("missing_evidence"))
            } else {
                Ok(valid())
            }
        },
        |_| Ok(pass()),
        |request| {
            assert_eq!(request.validation().defects().len(), 1);
            Ok(RevisionResponse::new(
                artifact("draft-v2"),
                ReviewCost::default(),
            ))
        },
        config(),
    )
    .expect("repairable fixture must complete");
    assert!(matches!(repairable, ReviewLoopOutcome::Published { .. }));
    assert_eq!(repairable.metrics().revisions(), 1);
    assert_eq!(
        validator_rounds, 3,
        "initial, repaired, and final validation"
    );

    let mut reviser_calls = 0;
    let correct = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("already-correct")),
        |_| Ok(valid()),
        |_| Ok(pass()),
        |_| {
            reviser_calls += 1;
            Ok(RevisionResponse::new(
                artifact("unused"),
                ReviewCost::default(),
            ))
        },
        config(),
    )
    .expect("correct fixture must complete");
    assert!(matches!(correct, ReviewLoopOutcome::Published { .. }));
    assert_eq!(correct.metrics().revisions(), 0);
    assert_eq!(reviser_calls, 0);

    let unrepairable = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("broken")),
        |_| Ok(invalid("missing_evidence")),
        |_| panic!("invalid candidates must not reach the reviewer"),
        |request| {
            Ok(RevisionResponse::new(
                request.candidate().clone(),
                ReviewCost::default(),
            ))
        },
        config(),
    )
    .expect("unrepairable fixture must abstain, not error");
    assert_eq!(
        unrepairable
            .diagnostic()
            .map(|diagnostic| diagnostic.code()),
        Some(ReviewLoopDiagnosticCode::RepeatedOutputHash)
    );
}

#[test]
fn oscillation_and_same_hash_stop_before_another_review() {
    let mut revisions = vec![artifact("draft-b"), artifact("draft-a")];
    let oscillating = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("draft-a")),
        |_| Ok(valid()),
        |_| Ok(revise("semantic_gap")),
        |_| {
            Ok(RevisionResponse::new(
                revisions.remove(0),
                ReviewCost::default(),
            ))
        },
        config(),
    )
    .expect("oscillation must abstain");
    assert_eq!(
        oscillating.diagnostic().map(|diagnostic| diagnostic.code()),
        Some(ReviewLoopDiagnosticCode::OscillationDetected)
    );
    assert_eq!(oscillating.metrics().reviewer_attempts(), 2);

    let same_hash = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("same")),
        |_| Ok(valid()),
        |_| Ok(revise("semantic_gap")),
        |request| {
            Ok(RevisionResponse::new(
                request.candidate().clone(),
                ReviewCost::default(),
            ))
        },
        config(),
    )
    .expect("same output must abstain");
    assert_eq!(
        same_hash.diagnostic().map(|diagnostic| diagnostic.code()),
        Some(ReviewLoopDiagnosticCode::RepeatedOutputHash)
    );
}

#[test]
fn reviewer_is_narrowed_to_an_isolated_read_only_request() {
    let mut saw_request = false;
    let result = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("candidate")),
        |_| Ok(valid()),
        |request| {
            saw_request = true;
            assert_ne!(request.session_id(), request.producer_session_id());
            assert!(request.authority().is_read_only());
            assert!(!request.authority().can_write());
            assert!(!request.authority().can_change_sandbox());
            assert!(!request.authority().can_increase_limits());
            assert_eq!(request.rubric(), RUBRIC);
            assert_eq!(request.selected_evidence()[0].id(), "evidence:claim-0");
            Ok(pass())
        },
        |_| panic!("a passing review does not need a reviser"),
        config(),
    )
    .expect("narrow reviewer request must complete");
    assert!(saw_request);
    assert!(matches!(result, ReviewLoopOutcome::Published { .. }));
}

#[test]
fn leaked_reviewer_authority_is_closed_after_review_settles() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let provenance = ToolProvenance::new("review.inspect", "1");
    let registration = ToolRegistration::for_types::<serde_json::Value, serde_json::Value>(
        "inspect",
        provenance.clone(),
        ToolFlags::new(true, true, true),
    )
    .expect("fixture registration");
    let mut bridge = ToolBridge::new(reviewer_sandbox());
    let calls = Arc::clone(&handler_calls);
    bridge
        .register(
            registration,
            move |_: &ChildSandbox<'_>,
                  _: &ToolCallContext,
                  _: &serde_json::Value|
                  -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(ToolEnvelope::success(
                    json!({"ok": true}),
                    provenance.clone(),
                ))
            },
        )
        .expect("fixture tool registration");
    let boundary =
        ReviewerExecutionBoundary::new(bridge, CapabilityIntersection::all_for_tool("inspect", []));
    let leaked = Arc::new(Mutex::new(None));
    let leaked_for_reviewer = Arc::clone(&leaked);

    let result = run_bounded_review_loop(
        || Ok::<_, ToolBridgeError>(artifact("candidate")),
        |_| Ok(valid()),
        move |request| {
            *leaked_for_reviewer.lock().expect("authority slot lock") =
                Some(request.authority().clone());
            request
                .authority()
                .invoke_tool("in-review", "inspect", json!({}))
                .expect("in-review tool call must execute");
            Ok(ReviewerResponse::new(
                pass().review().clone(),
                ReviewCost::new(1, 0),
            ))
        },
        |_| panic!("a passing review does not need a reviser"),
        config()
            .with_max_tool_calls(2)
            .with_read_only_tools(vec!["inspect".to_owned()])
            .with_execution_boundary(boundary),
    )
    .expect("review must publish");

    assert_eq!(result.metrics().cost().tool_calls(), 1);
    let leaked = leaked
        .lock()
        .expect("authority slot lock")
        .take()
        .expect("reviewer must leak a clone for the regression test");
    let error = leaked
        .invoke_tool("after-review", "inspect", json!({}))
        .expect_err("closed authority must reject post-review calls");
    assert_eq!(
        error.kind(),
        workflow_runtime::ToolBridgeErrorKind::CapabilityDenied
    );
    assert_eq!(result.metrics().cost().tool_calls(), 1);
    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn semantic_evidence_binding_and_final_validation_are_fail_closed() {
    let hostile = "secret-token=/etc/shadow";
    let bad_review = ReviewerResponse::new(
        workflow_review::ReviewResult::new(
            workflow_review::REVIEW_SCHEMA_VERSION_V1,
            ReviewVerdict::Revise,
            hostile.to_owned(),
            vec![ReviewDefect::new(
                "unsupported_claim".to_owned(),
                ReviewSeverity::Error,
                Some("/claims/2".to_owned()),
                vec!["evidence:not-selected".to_owned()],
                hostile.to_owned(),
                None,
            )],
            0.8,
        )
        .expect("review fixture must be schema-valid"),
        ReviewCost::default(),
    );
    let rejected = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("candidate")),
        |_| Ok(valid()),
        |_| Ok(bad_review.clone()),
        |_| panic!("invalid evidence binding must not revise"),
        config(),
    )
    .expect("invalid review output must abstain");
    assert_eq!(
        rejected.diagnostic().map(|diagnostic| diagnostic.code()),
        Some(ReviewLoopDiagnosticCode::ReviewerOutputRejected)
    );
    assert!(!format!("{rejected:?}").contains(hostile));
    assert!(!rejected.to_string().contains(hostile));

    let mut final_validation = false;
    let no_bypass = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("candidate")),
        |_| {
            if final_validation {
                Ok(invalid("late_failure"))
            } else {
                final_validation = true;
                Ok(valid())
            }
        },
        |_| Ok(pass()),
        |_| panic!("final deterministic failure must not be bypassed"),
        config(),
    )
    .expect("final validation failure must abstain");
    assert_eq!(
        no_bypass.diagnostic().map(|diagnostic| diagnostic.code()),
        Some(ReviewLoopDiagnosticCode::FinalValidationFailed)
    );
    assert_eq!(
        no_bypass.stages(),
        &[
            workflow_review::ReviewLoopStage::Producer,
            workflow_review::ReviewLoopStage::Validate,
            workflow_review::ReviewLoopStage::Reviewer,
            workflow_review::ReviewLoopStage::FinalValidate,
            workflow_review::ReviewLoopStage::Abstain,
        ]
    );
}

#[test]
fn digest_mismatch_budget_and_attempts_are_recorded() {
    let mismatch = CandidateArtifact::from_declared_hash(b"candidate", "00");
    let mismatch_error = mismatch.expect_err("mismatched digest must fail");
    assert!(!mismatch_error.to_string().contains("secret-token"));
    assert!(!mismatch_error.to_string().contains("/etc/shadow"));

    let mut reviser_calls = 0;
    let exhausted = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("candidate")),
        |_| Ok(valid()),
        |_| {
            Ok(ReviewerResponse::new(
                revise("still_wrong").review().clone(),
                ReviewCost::new(1, 0),
            ))
        },
        |_| {
            reviser_calls += 1;
            Ok(RevisionResponse::new(
                artifact("revised"),
                ReviewCost::default(),
            ))
        },
        config().with_max_model_turns(1),
    )
    .expect("budget exhaustion must abstain");
    assert_eq!(
        exhausted.diagnostic().map(|diagnostic| diagnostic.code()),
        Some(ReviewLoopDiagnosticCode::BudgetExhausted)
    );
    assert_eq!(exhausted.metrics().reviewer_attempts(), 1);
    assert_eq!(exhausted.metrics().cost().model_turns(), 1);
    assert_eq!(
        reviser_calls, 0,
        "zero remaining budget must block revision"
    );
}

#[test]
fn callback_failures_have_static_diagnostics() {
    let hostile = "secret-token=/etc/shadow";
    let error = run_bounded_review_loop(
        || Err::<CandidateArtifact, _>(hostile),
        |_| Ok(valid()),
        |_| Ok(pass()),
        |_| panic!("producer failed"),
        config(),
    )
    .expect_err("producer error must be returned");
    assert!(!format!("{error:?}").contains(hostile));
    assert!(!error.to_string().contains(hostile));
}

#[test]
fn public_path_accepts_multiline_rubric_and_evidence() {
    let result = run_bounded_review_loop(
        || Ok::<_, &'static str>(artifact("candidate")),
        |_| Ok(valid()),
        |request| {
            assert_eq!(
                request.rubric(),
                "line one\nline two\tline three\rline four"
            );
            assert_eq!(
                request.selected_evidence()[0].content(),
                "evidence\ncontinues"
            );
            Ok(pass())
        },
        |_| panic!("a passing review does not need a reviser"),
        config()
            .with_rubric("line one\nline two\tline three\rline four")
            .with_evidence(vec![SelectedEvidence::new(
                "evidence:claim-0".to_owned(),
                "evidence\ncontinues".to_owned(),
            )]),
    )
    .expect("ordinary multiline review text must be accepted");
    assert!(matches!(result, ReviewLoopOutcome::Published { .. }));
}

fn reviewer_sandbox() -> RunSandbox {
    let run_id = RunId::new("review-boundary-test".to_owned()).expect("valid fixture run ID");
    let limits = RunLimits::new(
        NonZeroU64::new(4).expect("positive"),
        NonZeroU64::new(4).expect("positive"),
        NonZeroU64::new(4).expect("positive"),
        NonZeroU64::new(2_000).expect("positive"),
        NonZeroU64::new(2_000).expect("positive"),
        NonZeroU64::new(2_000).expect("positive"),
        NonZeroU64::new(64 * 1024).expect("positive"),
    );
    let context = RunContext::new(run_id.clone(), limits);
    let base = std::env::temp_dir().join(format!("workflow-review-{}", std::process::id()));
    std::fs::create_dir_all(&base).expect("fixture base must exist");
    let workdir = WorkdirManager::new(&base)
        .expect("fixture workdir manager")
        .allocate(&run_id)
        .expect("fixture workdir");
    RunSandbox::new(context, workdir, []).expect("fixture sandbox")
}

#[test]
fn reviewer_execution_boundary_rejects_write_tools_without_running_them() {
    let handler_called = Arc::new(AtomicBool::new(false));
    let registration = ToolRegistration::for_types::<String, String>(
        "write-tool",
        ToolProvenance::new("fixture.write", "1"),
        ToolFlags::new(false, false, false),
    )
    .expect("fixture registration");
    let mut bridge = ToolBridge::new(reviewer_sandbox());
    let called = Arc::clone(&handler_called);
    bridge
        .register(
            registration,
            move |_: &ChildSandbox<'_>,
                  _: &ToolCallContext,
                  _: &serde_json::Value|
                  -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
                called.store(true, Ordering::SeqCst);
                Ok(ToolEnvelope::success(
                    serde_json::Value::String("executed".to_owned()),
                    ToolProvenance::new("fixture.write", "1"),
                ))
            },
        )
        .expect("fixture tool registration");
    let boundary = ReviewerExecutionBoundary::new(
        bridge,
        CapabilityIntersection::all_for_tool("write-tool", []),
    );

    let error = run_bounded_review_loop(
        || Ok::<_, ToolBridgeError>(artifact("candidate")),
        |_| Ok(valid()),
        |request| {
            assert_ne!(request.session_id(), request.producer_session_id());
            let error = request
                .authority()
                .invoke_tool("write-call", "write-tool", json!("side effect"))
                .expect_err("reviewer write must be denied at dispatch");
            assert_eq!(
                error.kind(),
                workflow_runtime::ToolBridgeErrorKind::CapabilityDenied
            );
            Err(error)
        },
        |_| panic!("denied reviewer tool must not reach the reviser"),
        config().with_execution_boundary(boundary),
    )
    .expect_err("write-tool denial must reach the reviewer boundary");
    assert!(matches!(
        error,
        workflow_review::ReviewLoopError::Reviewer(_)
    ));
    assert!(!handler_called.load(Ordering::SeqCst));
}
