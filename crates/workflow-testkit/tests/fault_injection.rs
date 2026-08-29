//! TESTKIT-003 (issue #50): deterministic fault-injection fixtures.
//!
//! Each fixture composes the TESTKIT-001 scripted harness and the RUN-002
//! host-enforced run limits into one bounded in-process failure scenario and
//! asserts the fail-closed typed diagnostic. No network, no live model, no
//! scheduler: every signal fires deterministically from explicit ceilings.

use std::{num::NonZeroU64, time::Duration};

use adk_rust::{Content, Llm, LlmRequest};
use serde_json::Value;
use workflow_compiler::ToolRegistry;
use workflow_runtime::{
    RunContext, RunController, RunId, RunLimitKind, RunLimits, RunTerminalCause, RunTimeoutKind,
};
use workflow_testkit::{
    FakeTool, FakeToolRegistry, FaultDiagnostic, FaultSignal, ScriptedLlm, inject_context_limit,
    inject_invalid_output, inject_output_flood, inject_rate_limit, inject_timeout,
};

/// One relaxed 7-ceiling run limit set; individual ceilings are overridden per fixture.
fn limits(ceiling: [u64; 7]) -> RunLimits {
    RunLimits::new(
        NonZeroU64::new(ceiling[0]).expect("fixture ceiling is positive"),
        NonZeroU64::new(ceiling[1]).expect("fixture ceiling is positive"),
        NonZeroU64::new(ceiling[2]).expect("fixture ceiling is positive"),
        NonZeroU64::new(ceiling[3]).expect("fixture ceiling is positive"),
        NonZeroU64::new(ceiling[4]).expect("fixture ceiling is positive"),
        NonZeroU64::new(ceiling[5]).expect("fixture ceiling is positive"),
        NonZeroU64::new(ceiling[6]).expect("fixture ceiling is positive"),
    )
}

fn context(ceiling: [u64; 7]) -> RunContext {
    RunContext::new(
        RunId::new(String::from("testkit-003")).expect("fixture run ID is valid"),
        limits(ceiling),
    )
}

/// Fixture 1: a host deadline elapses and the run must terminalize as a typed
/// timeout diagnostic with static text only.
#[adk_rust::tokio::test]
async fn timeout_fixture_fails_closed_with_typed_diagnostic() {
    let model = ScriptedLlm::new(Vec::new());
    assert_eq!(
        model
            .remaining_steps()
            .expect("new scripted model state is available"),
        0
    );
    assert!(
        model
            .generate_content(
                LlmRequest::new(
                    "scripted-llm",
                    vec![Content::new("user").with_text("fixture")],
                ),
                false,
            )
            .await
            .is_err()
    );
    assert!(
        !model
            .requests()
            .expect("new scripted model request ledger is available")
            .is_empty()
    );
    let registry = FakeToolRegistry::new(
        "fixture-tool",
        "1",
        FakeTool::new("fixture-tool", "fault fixture tool", Value::Null),
    );
    let resolved = registry
        .resolve("fixture-tool", "1")
        .expect("fixture tool resolves by its exact registry identity");
    assert!(
        resolved
            .implementation()
            .calls()
            .expect("new fake tool call ledger is available")
            .is_empty()
    );
    let run_context = context([10, 10, 10, 5, 100, 100, 100]);
    let mut controller = RunController::new(&run_context);

    let diagnostic: FaultDiagnostic = inject_timeout(
        &mut controller,
        Duration::from_millis(5),
        RunTimeoutKind::WallTime,
    );

    assert_eq!(
        diagnostic.signal(),
        FaultSignal::Timeout(RunTimeoutKind::WallTime)
    );
    assert_eq!(
        controller.terminal_cause(),
        Some(RunTerminalCause::TimedOut(RunTimeoutKind::WallTime))
    );

    let rendered = format!("{diagnostic} {diagnostic:?}");
    assert!(!rendered.contains("payload"));
    assert!(!rendered.contains("flood"));
    assert_eq!(
        diagnostic.to_string(),
        "injected fault: run timed out (wall time)"
    );
}

/// Fixture 2: model-turn quota exhaustion must fail closed as a typed
/// rate-limit diagnostic.
#[adk_rust::tokio::test]
async fn rate_limit_fixture_fails_closed_on_quota_exhaustion() {
    let model = ScriptedLlm::new(Vec::new());
    assert_eq!(
        model
            .remaining_steps()
            .expect("new scripted model state is available"),
        0
    );
    assert!(
        model
            .generate_content(
                LlmRequest::new(
                    "scripted-llm",
                    vec![Content::new("user").with_text("fixture")],
                ),
                false,
            )
            .await
            .is_err()
    );
    assert!(
        !model
            .requests()
            .expect("new scripted model request ledger is available")
            .is_empty()
    );
    let registry = FakeToolRegistry::new(
        "fixture-tool",
        "1",
        FakeTool::new("fixture-tool", "fault fixture tool", Value::Null),
    );
    let resolved = registry
        .resolve("fixture-tool", "1")
        .expect("fixture tool resolves by its exact registry identity");
    assert!(
        resolved
            .implementation()
            .calls()
            .expect("new fake tool call ledger is available")
            .is_empty()
    );
    let run_context = context([1, 10, 10, 100, 100, 100, 100]);
    let mut controller = RunController::new(&run_context);
    controller
        .admit_model_turn(Duration::ZERO)
        .expect("first turn is under quota");

    let diagnostic: FaultDiagnostic = inject_rate_limit(&mut controller, Duration::from_millis(1));

    assert_eq!(
        diagnostic.signal(),
        FaultSignal::RateLimit(RunLimitKind::ModelTurns)
    );
    assert_eq!(
        controller.terminal_cause(),
        Some(RunTerminalCause::LimitExceeded(RunLimitKind::ModelTurns))
    );
    assert_eq!(
        diagnostic.to_string(),
        "injected fault: quota exhausted (model turns)"
    );
}

#[test]
fn context_limit_fixture_fails_closed_without_retaining_request_content() {
    let diagnostic = inject_context_limit(4_097, 4_096);
    assert_eq!(diagnostic.signal(), FaultSignal::ContextLimit);
    assert_eq!(
        diagnostic.to_string(),
        "injected fault: context limit exceeded"
    );
}

/// Fixture 3: malformed tool output must fail closed as a typed invalid-output
/// diagnostic that never echoes the offending bytes.
#[adk_rust::tokio::test]
async fn invalid_output_fixture_fails_closed_without_echoing_bytes() {
    let model = ScriptedLlm::new(Vec::new());
    assert_eq!(
        model
            .remaining_steps()
            .expect("new scripted model state is available"),
        0
    );
    assert!(
        model
            .generate_content(
                LlmRequest::new(
                    "scripted-llm",
                    vec![Content::new("user").with_text("fixture")],
                ),
                false,
            )
            .await
            .is_err()
    );
    assert!(
        !model
            .requests()
            .expect("new scripted model request ledger is available")
            .is_empty()
    );
    let registry = FakeToolRegistry::new(
        "fixture-tool",
        "1",
        FakeTool::new("fixture-tool", "fault fixture tool", Value::Null),
    );
    let resolved = registry
        .resolve("fixture-tool", "1")
        .expect("fixture tool resolves by its exact registry identity");
    assert!(
        resolved
            .implementation()
            .calls()
            .expect("new fake tool call ledger is available")
            .is_empty()
    );
    let run_context = context([10, 10, 10, 100, 100, 100, 100]);
    let mut controller = RunController::new(&run_context);
    controller
        .admit_model_turn(Duration::ZERO)
        .expect("fixture turn is admitted under the relaxed quota");
    assert_eq!(controller.terminal_cause(), None);
    let malformed = br#"{"status":"success","payload":{"value":"SENTINEL_FLOOD_BYTES"}"#;

    let diagnostic: FaultDiagnostic = inject_invalid_output::<Value>(malformed, 4096);

    assert_eq!(diagnostic.signal(), FaultSignal::InvalidOutput);
    let rendered = format!("{diagnostic} {diagnostic:?}");
    assert!(!rendered.contains("SENTINEL_FLOOD_BYTES"));
    assert!(!rendered.contains("success"));
    assert_eq!(diagnostic.to_string(), "injected fault: invalid output");
}

/// Fixture 4: a tool stream that crosses the byte ceiling must fail closed as
/// a typed output-flood diagnostic carrying only the accepted byte count.
#[adk_rust::tokio::test]
async fn output_flood_fixture_fails_closed_at_byte_ceiling() {
    let model = ScriptedLlm::new(Vec::new());
    assert_eq!(
        model
            .remaining_steps()
            .expect("new scripted model state is available"),
        0
    );
    assert!(
        model
            .generate_content(
                LlmRequest::new(
                    "scripted-llm",
                    vec![Content::new("user").with_text("fixture")],
                ),
                false,
            )
            .await
            .is_err()
    );
    assert!(
        !model
            .requests()
            .expect("new scripted model request ledger is available")
            .is_empty()
    );
    let registry = FakeToolRegistry::new(
        "fixture-tool",
        "1",
        FakeTool::new("fixture-tool", "fault fixture tool", Value::Null),
    );
    let resolved = registry
        .resolve("fixture-tool", "1")
        .expect("fixture tool resolves by its exact registry identity");
    assert!(
        resolved
            .implementation()
            .calls()
            .expect("new fake tool call ledger is available")
            .is_empty()
    );
    let run_context = context([10, 10, 10, 100, 100, 100, 3]);
    let mut controller = RunController::new(&run_context);
    controller
        .begin_tool_call(Duration::ZERO, "SENTINEL_FLOOD_BYTES", "1")
        .expect("tool call is admitted");
    controller
        .accept_tool_output(Duration::ZERO, 2)
        .expect("chunk under the ceiling is accepted");

    let diagnostic: FaultDiagnostic =
        inject_output_flood(&mut controller, Duration::from_millis(1), 2);

    assert_eq!(
        diagnostic.signal(),
        FaultSignal::OutputFlood { accepted_bytes: 2 }
    );
    assert_eq!(
        controller.terminal_cause(),
        Some(RunTerminalCause::LimitExceeded(
            RunLimitKind::ToolOutputBytes
        ))
    );
    let rendered = format!("{diagnostic} {diagnostic:?}");
    assert!(!rendered.contains("payload"));
    assert!(!rendered.contains("flood"));
    assert_eq!(
        diagnostic.to_string(),
        "injected fault: output byte ceiling rejected (accepted 2 bytes)"
    );
}
