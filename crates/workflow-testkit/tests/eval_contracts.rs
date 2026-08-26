//! EVAL-001 (issue #51): bind adk-eval behind the platform test API.
//!
//! One trajectory fixture and one rubric fixture must run through the public
//! bind path as distinct typed dispositions. A failed boundary cannot report
//! that both fixtures ran. Fixture payloads stay out of Debug/Display/serde.

use workflow_testkit::{
    EvalDiagnosticKind, EvalEnvelope, EvalError, EvalFixture, EvalInput, compile_eval,
};

const CANARY_TRAJECTORY_51: &str = "CANARY_TRAJECTORY_51";
const CANARY_RUBRIC_51: &str = "CANARY_RUBRIC_51";
const CANARY_EVAL_BOUNDARY_51: &str = "CANARY_EVAL_BOUNDARY_51";

fn trajectory_fixture() -> EvalFixture {
    EvalFixture::new(
        String::from("canary-trajectory-51"),
        String::from(CANARY_TRAJECTORY_51),
    )
}

fn rubric_fixture() -> EvalFixture {
    EvalFixture::new(
        String::from("canary-rubric-51"),
        String::from(CANARY_RUBRIC_51),
    )
}

fn assert_payload_redacted(value: &impl std::fmt::Debug, canary: &str) {
    assert!(!format!("{value:?}").contains(canary));
}

#[test]
fn canary_trajectory_runs_as_typed_trajectory_not_rubric() {
    let result = compile_eval(EvalInput::trajectory(trajectory_fixture()))
        .expect("trajectory canary must run through the platform test API");

    match &result {
        EvalEnvelope::Trajectory { acknowledgement } => {
            assert_eq!(acknowledgement.fixture_name(), "canary-trajectory-51");
            assert_eq!(acknowledgement.fixture_count(), 1);
        }
        EvalEnvelope::Rubric { .. } => {
            panic!("trajectory canary must not be reported as a rubric-only success")
        }
        EvalEnvelope::TrajectoryAndRubric { .. } => {
            panic!("trajectory-only canary must not report that both fixtures ran")
        }
    }
    assert!(!result.to_string().contains(CANARY_TRAJECTORY_51));
    assert_payload_redacted(&result, CANARY_TRAJECTORY_51);
    assert!(
        !serde_json::to_string(&result)
            .expect("trajectory envelope must serialize")
            .contains(CANARY_TRAJECTORY_51)
    );
}

#[test]
fn canary_rubric_runs_as_typed_rubric_not_trajectory() {
    let result = compile_eval(EvalInput::rubric(rubric_fixture()))
        .expect("rubric canary must run through the platform test API");

    match &result {
        EvalEnvelope::Rubric { acknowledgement } => {
            assert_eq!(acknowledgement.fixture_name(), "canary-rubric-51");
            assert_eq!(acknowledgement.fixture_count(), 1);
        }
        EvalEnvelope::Trajectory { .. } => {
            panic!("rubric canary must not be reported as a trajectory-only success")
        }
        EvalEnvelope::TrajectoryAndRubric { .. } => {
            panic!("rubric-only canary must not report that both fixtures ran")
        }
    }
    assert!(!result.to_string().contains(CANARY_RUBRIC_51));
    assert_payload_redacted(&result, CANARY_RUBRIC_51);
    assert!(
        !serde_json::to_string(&result)
            .expect("rubric envelope must serialize")
            .contains(CANARY_RUBRIC_51)
    );
}

#[test]
fn canary_eval_boundary_takes_typed_path_and_cannot_report_both_ran() {
    let result = compile_eval(EvalInput::trajectory(EvalFixture::new(
        String::new(),
        String::from(CANARY_EVAL_BOUNDARY_51),
    )));

    let error = match result {
        Ok(EvalEnvelope::TrajectoryAndRubric { .. }) => {
            panic!("boundary canary must not report that a trajectory and rubric fixture ran")
        }
        Ok(_) => panic!("boundary canary must not report a successful fixture run"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), EvalDiagnosticKind::BoundaryMiss);
    assert_eq!(error.code(), "eval.boundary_miss");
    assert!(!format!("{error}").contains(CANARY_EVAL_BOUNDARY_51));
    assert_payload_redacted(&error, CANARY_EVAL_BOUNDARY_51);
    assert!(
        !serde_json::to_string(&error)
            .expect("boundary error must serialize")
            .contains(CANARY_EVAL_BOUNDARY_51)
    );
    let _typed: EvalError = error;
}

#[test]
fn one_trajectory_and_rubric_fixture_runs() {
    let result = compile_eval(EvalInput::both(trajectory_fixture(), rubric_fixture()))
        .expect("one trajectory and one rubric fixture must run");

    match &result {
        EvalEnvelope::TrajectoryAndRubric { trajectory, rubric } => {
            assert_eq!(trajectory.fixture_name(), "canary-trajectory-51");
            assert_eq!(rubric.fixture_name(), "canary-rubric-51");
            assert_eq!(trajectory.fixture_count(), 1);
            assert_eq!(rubric.fixture_count(), 1);
            assert_ne!(trajectory.disposition(), rubric.disposition());
        }
        EvalEnvelope::Trajectory { .. } => panic!("combined run must not drop the rubric fixture"),
        EvalEnvelope::Rubric { .. } => panic!("combined run must not drop the trajectory fixture"),
    }
    assert_payload_redacted(&result, CANARY_TRAJECTORY_51);
    assert_payload_redacted(&result, CANARY_RUBRIC_51);
    let serialized = serde_json::to_string(&result).expect("combined envelope must serialize");
    assert!(!serialized.contains(CANARY_TRAJECTORY_51));
    assert!(!serialized.contains(CANARY_RUBRIC_51));
}
