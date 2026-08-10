use std::{error::Error, fmt::Debug, num::NonZeroU64};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use workflow_runtime::{
    InvalidRunId, RunContext, RunId, RunLimitKind, RunLimits, RunOutcome, RunResult, RunStatus,
    RunTimeoutKind,
};

#[test]
fn run_id_preserves_nonempty_input_exactly() {
    for source in [String::from("run-1"), String::from("  ../../run\0🔥  ")] {
        let run_id = RunId::new(source.clone()).expect("non-empty run IDs must be valid");
        assert_eq!(run_id.as_str(), source);

        let json = serde_json::to_string(&run_id).expect("run ID serialization must succeed");
        let decoded: RunId = serde_json::from_str(&json).expect("serialized run IDs must decode");
        assert_eq!(decoded, run_id);
        assert_eq!(decoded.as_str(), source);
    }
}

#[test]
fn empty_run_ids_are_rejected_without_echoing_input() {
    let error: InvalidRunId = RunId::new(String::new()).expect_err("empty run IDs must be invalid");
    let as_error: &dyn Error = &error;

    assert_eq!(as_error.to_string(), "run ID must not be empty");
    assert!(as_error.source().is_none());
    assert!(serde_json::from_str::<RunId>(r#""""#).is_err());
}

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("test limits are positive")
}

fn run_limits() -> RunLimits {
    RunLimits::new(
        nonzero(1),
        nonzero(2),
        nonzero(3),
        nonzero(4),
        nonzero(5),
        nonzero(6),
        nonzero(7),
    )
}

const LIMITS_JSON: &str = r#"{"max_model_turns":1,"max_tool_calls":2,"max_calls_per_tool":3,"max_wall_time_ms":4,"max_idle_time_ms":5,"max_tool_time_ms":6,"max_tool_output_bytes":7}"#;

#[test]
fn limits_and_context_match_exact_json_contract() {
    let limits = run_limits();
    assert_eq!(limits.max_model_turns(), nonzero(1));
    assert_eq!(limits.max_tool_calls(), nonzero(2));
    assert_eq!(limits.max_calls_per_tool(), nonzero(3));
    assert_eq!(limits.max_wall_time_ms(), nonzero(4));
    assert_eq!(limits.max_idle_time_ms(), nonzero(5));
    assert_eq!(limits.max_tool_time_ms(), nonzero(6));
    assert_eq!(limits.max_tool_output_bytes(), nonzero(7));
    assert_eq!(
        serde_json::to_string(&limits).expect("limits serialization must succeed"),
        LIMITS_JSON
    );

    let decoded_limits: RunLimits =
        serde_json::from_str(LIMITS_JSON).expect("valid limits must decode");
    assert_eq!(decoded_limits, limits);

    let context = RunContext::new(
        RunId::new(String::from("run-1")).expect("fixture run ID is valid"),
        limits,
    );
    let context_json = format!(r#"{{"run_id":"run-1","limits":{LIMITS_JSON}}}"#);
    assert_eq!(context.run_id().as_str(), "run-1");
    assert_eq!(context.limits(), &run_limits());
    assert_eq!(
        serde_json::to_string(&context).expect("context serialization must succeed"),
        context_json
    );
    assert_eq!(
        serde_json::from_str::<RunContext>(&context_json).expect("valid context must decode"),
        context
    );
}

#[test]
fn limits_and_context_reject_malformed_envelopes() {
    const FIELDS: [&str; 7] = [
        "max_model_turns",
        "max_tool_calls",
        "max_calls_per_tool",
        "max_wall_time_ms",
        "max_idle_time_ms",
        "max_tool_time_ms",
        "max_tool_output_bytes",
    ];
    let valid: serde_json::Value =
        serde_json::from_str(LIMITS_JSON).expect("limits fixture must be valid JSON");

    for field in FIELDS {
        for invalid in [serde_json::json!(0), serde_json::json!(-1)] {
            let mut malformed = valid.clone();
            malformed[field] = invalid;
            assert!(
                serde_json::from_value::<RunLimits>(malformed).is_err(),
                "{field} must reject zero and negative values"
            );
        }

        let mut missing = valid.clone();
        missing
            .as_object_mut()
            .expect("limits fixture is an object")
            .remove(field);
        assert!(
            serde_json::from_value::<RunLimits>(missing).is_err(),
            "{field} must be required"
        );
    }

    let mut unknown_limit = valid;
    unknown_limit["unexpected"] = serde_json::json!(1);
    assert!(serde_json::from_value::<RunLimits>(unknown_limit).is_err());

    let context_with_unknown =
        format!(r#"{{"run_id":"run-1","limits":{LIMITS_JSON},"unexpected":true}}"#);
    assert!(serde_json::from_str::<RunContext>(&context_with_unknown).is_err());
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TestOutput {
    answer: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TestDiagnostic {
    code: String,
}

fn output() -> TestOutput {
    TestOutput { answer: 42 }
}

fn diagnostic() -> TestDiagnostic {
    TestDiagnostic {
        code: String::from("runtime.test"),
    }
}

fn assert_enum_json<T>(value: T, name: &str)
where
    T: Debug + DeserializeOwned + Eq + Serialize,
{
    let json = format!(r#""{name}""#);
    assert_eq!(
        serde_json::to_string(&value).expect("enum serialization must succeed"),
        json
    );
    assert_eq!(
        serde_json::from_str::<T>(&json).expect("known enum value must decode"),
        value
    );
}

#[test]
fn terminal_enums_use_exact_snake_case_json() {
    for (value, name) in [
        (RunStatus::Completed, "completed"),
        (RunStatus::Abstained, "abstained"),
        (RunStatus::Incomplete, "incomplete"),
        (RunStatus::Failed, "failed"),
        (RunStatus::Cancelled, "cancelled"),
        (RunStatus::TimedOut, "timed_out"),
        (RunStatus::LimitExceeded, "limit_exceeded"),
        (RunStatus::PolicyDenied, "policy_denied"),
    ] {
        assert_enum_json(value, name);
    }

    for (value, name) in [
        (RunTimeoutKind::WallTime, "wall_time"),
        (RunTimeoutKind::IdleTime, "idle_time"),
        (RunTimeoutKind::ToolTime, "tool_time"),
    ] {
        assert_enum_json(value, name);
    }

    for (value, name) in [
        (RunLimitKind::ModelTurns, "model_turns"),
        (RunLimitKind::TotalToolCalls, "total_tool_calls"),
        (RunLimitKind::ToolCallsPerTool, "tool_calls_per_tool"),
        (RunLimitKind::ToolOutputBytes, "tool_output_bytes"),
    ] {
        assert_enum_json(value, name);
    }

    assert!(serde_json::from_str::<RunStatus>(r#""running""#).is_err());
    assert!(serde_json::from_str::<RunTimeoutKind>(r#""deadline""#).is_err());
    assert!(serde_json::from_str::<RunLimitKind>(r#""wall_time""#).is_err());
}

#[test]
fn every_outcome_derives_its_terminal_status() {
    let cases: [(RunOutcome<TestOutput, TestDiagnostic>, RunStatus); 8] = [
        (
            RunOutcome::Completed { output: output() },
            RunStatus::Completed,
        ),
        (
            RunOutcome::Abstained {
                diagnostic: diagnostic(),
            },
            RunStatus::Abstained,
        ),
        (
            RunOutcome::Incomplete {
                diagnostic: diagnostic(),
            },
            RunStatus::Incomplete,
        ),
        (
            RunOutcome::Failed {
                diagnostic: diagnostic(),
            },
            RunStatus::Failed,
        ),
        (
            RunOutcome::Cancelled {
                diagnostic: diagnostic(),
            },
            RunStatus::Cancelled,
        ),
        (
            RunOutcome::TimedOut {
                timeout: RunTimeoutKind::WallTime,
                diagnostic: diagnostic(),
            },
            RunStatus::TimedOut,
        ),
        (
            RunOutcome::LimitExceeded {
                limit: RunLimitKind::ModelTurns,
                diagnostic: diagnostic(),
            },
            RunStatus::LimitExceeded,
        ),
        (
            RunOutcome::PolicyDenied {
                diagnostic: diagnostic(),
            },
            RunStatus::PolicyDenied,
        ),
    ];

    for (outcome, expected) in cases {
        assert_eq!(outcome.status(), expected);
    }
}

fn test_run_id() -> RunId {
    RunId::new(String::from("run-1")).expect("fixture run ID is valid")
}

#[test]
fn every_typed_result_has_exact_json_and_round_trips() {
    let cases: [(RunOutcome<TestOutput, TestDiagnostic>, RunStatus, &str); 8] = [
        (
            RunOutcome::Completed { output: output() },
            RunStatus::Completed,
            r#"{"run_id":"run-1","outcome":{"status":"completed","output":{"answer":42}}}"#,
        ),
        (
            RunOutcome::Abstained {
                diagnostic: diagnostic(),
            },
            RunStatus::Abstained,
            r#"{"run_id":"run-1","outcome":{"status":"abstained","diagnostic":{"code":"runtime.test"}}}"#,
        ),
        (
            RunOutcome::Incomplete {
                diagnostic: diagnostic(),
            },
            RunStatus::Incomplete,
            r#"{"run_id":"run-1","outcome":{"status":"incomplete","diagnostic":{"code":"runtime.test"}}}"#,
        ),
        (
            RunOutcome::Failed {
                diagnostic: diagnostic(),
            },
            RunStatus::Failed,
            r#"{"run_id":"run-1","outcome":{"status":"failed","diagnostic":{"code":"runtime.test"}}}"#,
        ),
        (
            RunOutcome::Cancelled {
                diagnostic: diagnostic(),
            },
            RunStatus::Cancelled,
            r#"{"run_id":"run-1","outcome":{"status":"cancelled","diagnostic":{"code":"runtime.test"}}}"#,
        ),
        (
            RunOutcome::TimedOut {
                timeout: RunTimeoutKind::WallTime,
                diagnostic: TestDiagnostic {
                    code: String::from("runtime.wall_time"),
                },
            },
            RunStatus::TimedOut,
            r#"{"run_id":"run-1","outcome":{"status":"timed_out","timeout":"wall_time","diagnostic":{"code":"runtime.wall_time"}}}"#,
        ),
        (
            RunOutcome::LimitExceeded {
                limit: RunLimitKind::ModelTurns,
                diagnostic: diagnostic(),
            },
            RunStatus::LimitExceeded,
            r#"{"run_id":"run-1","outcome":{"status":"limit_exceeded","limit":"model_turns","diagnostic":{"code":"runtime.test"}}}"#,
        ),
        (
            RunOutcome::PolicyDenied {
                diagnostic: diagnostic(),
            },
            RunStatus::PolicyDenied,
            r#"{"run_id":"run-1","outcome":{"status":"policy_denied","diagnostic":{"code":"runtime.test"}}}"#,
        ),
    ];

    for (outcome, status, expected_json) in cases {
        let result = RunResult::new(test_run_id(), outcome);
        assert_eq!(result.run_id().as_str(), "run-1");
        assert_eq!(result.outcome().status(), status);
        assert_eq!(result.status(), status);
        assert_eq!(
            serde_json::to_string(&result).expect("result serialization must succeed"),
            expected_json
        );
        assert_eq!(
            serde_json::from_str::<RunResult<TestOutput, TestDiagnostic>>(expected_json)
                .expect("valid result must decode"),
            result
        );
    }
}

#[test]
fn malformed_results_fail_closed() {
    type TestResult = RunResult<TestOutput, TestDiagnostic>;

    let malformed = [
        r#"{"run_id":"run-1","outcome":{"status":"completed"}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"abstained"}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"incomplete"}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"failed"}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"cancelled"}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"timed_out","timeout":"wall_time"}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"limit_exceeded","limit":"model_turns"}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"policy_denied"}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"timed_out","limit":"model_turns","diagnostic":{"code":"runtime.test"}}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"limit_exceeded","timeout":"wall_time","diagnostic":{"code":"runtime.test"}}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"timed_out","diagnostic":{"code":"runtime.test"}}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"limit_exceeded","diagnostic":{"code":"runtime.test"}}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"completed","output":{"answer":42},"diagnostic":{"code":"runtime.test"}}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"abstained","diagnostic":{"code":"runtime.test"},"output":{"answer":42}}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"running","diagnostic":{"code":"runtime.test"}}}"#,
        r#"{"run_id":"","outcome":{"status":"completed","output":{"answer":42}}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"completed","output":{"answer":42},"unexpected":true}}"#,
        r#"{"run_id":"run-1","outcome":{"status":"completed","output":{"answer":42}},"unexpected":true}"#,
        r#"{"outcome":{"status":"completed","output":{"answer":42}}}"#,
        r#"{"run_id":"run-1"}"#,
    ];

    for json in malformed {
        assert!(
            serde_json::from_str::<TestResult>(json).is_err(),
            "malformed result decoded: {json}"
        );
    }
}

#[test]
fn contexts_and_results_own_caller_inputs() {
    let mut id_source = String::from("run-owned");
    let context = RunContext::new(
        RunId::new(id_source.clone()).expect("fixture run ID is valid"),
        run_limits(),
    );
    id_source.clear();
    assert_eq!(context.run_id().as_str(), "run-owned");

    let mut diagnostic_source = String::from("runtime.owned");
    let result: RunResult<TestOutput, TestDiagnostic> = RunResult::new(
        test_run_id(),
        RunOutcome::Failed {
            diagnostic: TestDiagnostic {
                code: diagnostic_source.clone(),
            },
        },
    );
    diagnostic_source.clear();

    match result.outcome() {
        RunOutcome::Failed { diagnostic } => assert_eq!(diagnostic.code, "runtime.owned"),
        _ => panic!("fixture outcome must remain failed"),
    }
}
