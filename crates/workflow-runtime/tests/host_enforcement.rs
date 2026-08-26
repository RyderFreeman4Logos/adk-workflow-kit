use std::{num::NonZeroU64, time::Duration};

use workflow_runtime::{
    RunContext, RunControlError, RunController, RunId, RunLimitKind, RunLimits, RunOutcome,
    RunStatus, RunTerminalCause, RunTermination, RunTimeoutKind, ToolCallCleanup,
};

const RELAXED: [u64; 7] = [100; 7];

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("test limits are positive")
}

fn run_context(values: [u64; 7]) -> RunContext {
    let [model, total, per_tool, wall, idle, tool, output] = values;
    RunContext::new(
        RunId::new(String::from("run-002")).expect("fixture run ID is valid"),
        RunLimits::new(
            nonzero(model),
            nonzero(total),
            nonzero(per_tool),
            nonzero(wall),
            nonzero(idle),
            nonzero(tool),
            nonzero(output),
        ),
    )
}

fn elapsed(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

fn pass(result: Result<(), RunTermination>) {
    result.expect("boundary must proceed");
}

fn expect_cause(result: Result<(), RunTermination>, expected: RunTerminalCause) -> RunTermination {
    let termination = result.expect_err("boundary must terminate");
    assert_eq!(termination.cause(), expected);
    termination
}

fn assert_cleanup(termination: &RunTermination, tool_id: &str, version: &str) {
    let cleanup = termination
        .cleanup()
        .expect("active tool termination must request cleanup");
    assert_eq!(cleanup.exact_tool_id(), tool_id);
    assert_eq!(cleanup.exact_version(), version);
}

fn complete_tool(controller: &mut RunController<'_>, tool_id: &str, version: &str) {
    pass(controller.begin_tool_call(Duration::ZERO, tool_id, version));
    pass(controller.finish_tool_call(Duration::ZERO));
}

fn fresh_timeout(values: [u64; 7], at: u64, expected: RunTimeoutKind) {
    let context = run_context(values);
    let mut controller = RunController::new(&context);
    expect_cause(
        controller.poll(elapsed(at)),
        RunTerminalCause::TimedOut(expected),
    );
}

fn active_timeout(values: [u64; 7], start: u64, at: u64, expected: RunTimeoutKind) {
    let context = run_context(values);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(elapsed(start), "tool", "1"));
    expect_cause(
        controller.poll(elapsed(at)),
        RunTerminalCause::TimedOut(expected),
    );
}

#[test]
fn count_ceilings_are_inclusive_transactional_and_exact() {
    let context = run_context([2, 10, 10, 100, 100, 100, 100]);
    let mut controller = RunController::new(&context);
    pass(controller.admit_model_turn(elapsed(1)));
    pass(controller.admit_model_turn(elapsed(2)));
    expect_cause(
        controller.admit_model_turn(elapsed(3)),
        RunTerminalCause::LimitExceeded(RunLimitKind::ModelTurns),
    );
    assert_eq!(controller.model_turn_count(), 2);

    let context = run_context([10, 2, 10, 100, 100, 100, 100]);
    let mut controller = RunController::new(&context);
    complete_tool(&mut controller, "tool-a", "1.0.0");
    complete_tool(&mut controller, "tool-b", "1.0.0");
    expect_cause(
        controller.begin_tool_call(Duration::ZERO, "tool-c", "1.0.0"),
        RunTerminalCause::LimitExceeded(RunLimitKind::TotalToolCalls),
    );
    assert_eq!(controller.total_tool_call_count(), 2);
    assert_eq!(controller.tool_call_count("tool-c", "1.0.0"), 0);

    let context = run_context([10, 10, 2, 100, 100, 100, 100]);
    let mut controller = RunController::new(&context);
    for (tool_id, version) in [
        ("tool-a", "1.0.0"),
        ("tool-a", "1.0.0"),
        ("tool-a", "2.0.0"),
        ("tool-a", "2.0.0"),
        ("tool-b", "1.0.0"),
    ] {
        complete_tool(&mut controller, tool_id, version);
    }
    expect_cause(
        controller.begin_tool_call(Duration::ZERO, "tool-a", "1.0.0"),
        RunTerminalCause::LimitExceeded(RunLimitKind::ToolCallsPerTool),
    );
    assert_eq!(controller.total_tool_call_count(), 5);
    assert_eq!(controller.tool_call_count("tool-a", "1.0.0"), 2);
    assert_eq!(controller.tool_call_count("tool-a", "2.0.0"), 2);
    assert_eq!(controller.tool_call_count("tool-b", "1.0.0"), 1);
}

#[test]
fn total_limit_wins_collisions_and_maximum_ceilings_do_not_overflow() {
    let context = run_context([10, 1, 1, 100, 100, 100, 100]);
    let mut controller = RunController::new(&context);
    complete_tool(&mut controller, "tool-a", "1.0.0");
    expect_cause(
        controller.begin_tool_call(Duration::ZERO, "tool-a", "1.0.0"),
        RunTerminalCause::LimitExceeded(RunLimitKind::TotalToolCalls),
    );
    assert_eq!(controller.total_tool_call_count(), 1);
    assert_eq!(controller.tool_call_count("tool-a", "1.0.0"), 1);

    let context = run_context([u64::MAX; 7]);
    let mut controller = RunController::new(&context);
    pass(controller.admit_model_turn(Duration::ZERO));
    pass(controller.begin_tool_call(Duration::ZERO, "tool", "v"));
    assert_eq!(controller.model_turn_count(), 1);
    assert_eq!(controller.total_tool_call_count(), 1);
    assert_eq!(controller.tool_call_count("tool", "v"), 1);
}

#[test]
fn output_is_charged_before_acceptance_without_partial_mutation() {
    let context = run_context([10, 10, 10, 100, 100, 100, 5]);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(Duration::ZERO, "stream", "1"));
    pass(controller.accept_tool_output(elapsed(1), 2));
    pass(controller.accept_tool_output(elapsed(2), 3));
    assert_eq!(controller.accepted_tool_output_bytes(), 5);
    let termination = expect_cause(
        controller.accept_tool_output(elapsed(3), 1),
        RunTerminalCause::LimitExceeded(RunLimitKind::ToolOutputBytes),
    );
    assert_eq!(controller.accepted_tool_output_bytes(), 5);
    assert_cleanup(&termination, "stream", "1");

    let context = run_context([10, 10, 10, 100, 100, 100, 5]);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(Duration::ZERO, "oversized", "1"));
    expect_cause(
        controller.accept_tool_output(Duration::ZERO, u64::MAX),
        RunTerminalCause::LimitExceeded(RunLimitKind::ToolOutputBytes),
    );
    assert_eq!(controller.accepted_tool_output_bytes(), 0);

    let context = run_context([u64::MAX; 7]);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(Duration::ZERO, "maximum", "1"));
    pass(controller.accept_tool_output(Duration::ZERO, u64::MAX));
    assert_eq!(controller.accepted_tool_output_bytes(), u64::MAX);
    expect_cause(
        controller.accept_tool_output(Duration::ZERO, 1),
        RunTerminalCause::LimitExceeded(RunLimitKind::ToolOutputBytes),
    );
    assert_eq!(controller.accepted_tool_output_bytes(), u64::MAX);

    let context = run_context([10, 10, 10, 100, 5, 100, 10]);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(Duration::ZERO, "idle", "1"));
    pass(controller.accept_tool_output(elapsed(4), 0));
    assert_eq!(controller.accepted_tool_output_bytes(), 0);
    expect_cause(
        controller.poll(elapsed(5)),
        RunTerminalCause::TimedOut(RunTimeoutKind::IdleTime),
    );
}

#[test]
fn automatic_progress_events_reset_idle_to_the_exact_boundary() {
    type ProgressEvent = for<'limits> fn(&mut RunController<'limits>) -> Result<(), RunTermination>;

    let cases: [(&str, ProgressEvent); 4] = [
        ("model admission", |controller| {
            controller.admit_model_turn(elapsed(4))
        }),
        ("tool admission", |controller| {
            controller.begin_tool_call(elapsed(4), "tool", "1")
        }),
        ("positive tool output", |controller| {
            pass(controller.begin_tool_call(Duration::ZERO, "tool", "1"));
            controller.accept_tool_output(elapsed(4), 1)
        }),
        ("tool completion", |controller| {
            pass(controller.begin_tool_call(Duration::ZERO, "tool", "1"));
            controller.finish_tool_call(elapsed(4))
        }),
    ];

    for (name, progress) in cases {
        let context = run_context([10, 10, 10, 100, 5, 100, 100]);
        let mut controller = RunController::new(&context);
        progress(&mut controller).unwrap_or_else(|termination| {
            panic!("{name} must succeed at 4 ms: {:?}", termination.cause())
        });
        controller.poll(elapsed(8)).unwrap_or_else(|termination| {
            panic!(
                "{name} must keep the run alive through 8 ms: {:?}",
                termination.cause()
            )
        });
        let termination = controller
            .poll(elapsed(9))
            .expect_err("renewed idle deadline must terminate at 9 ms");
        assert_eq!(
            termination.cause(),
            RunTerminalCause::TimedOut(RunTimeoutKind::IdleTime),
            "{name}"
        );
    }
}

#[test]
fn duration_boundaries_reset_only_on_progress_and_choose_earliest_deadline() {
    for (values, kind) in [
        ([10, 10, 10, 10, 100, 100, 100], RunTimeoutKind::WallTime),
        ([10, 10, 10, 100, 10, 100, 100], RunTimeoutKind::IdleTime),
    ] {
        let context = run_context(values);
        let mut controller = RunController::new(&context);
        pass(controller.poll(elapsed(9)));
        expect_cause(
            controller.poll(elapsed(10)),
            RunTerminalCause::TimedOut(kind),
        );
        fresh_timeout(values, 11, kind);
    }

    let context = run_context([10, 10, 10, 100, 10, 100, 100]);
    let mut controller = RunController::new(&context);
    pass(controller.mark_progress(elapsed(9)));
    pass(controller.poll(elapsed(18)));
    expect_cause(
        controller.poll(elapsed(19)),
        RunTerminalCause::TimedOut(RunTimeoutKind::IdleTime),
    );

    let context = run_context([10, 10, 10, 100, 100, 10, 100]);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(elapsed(5), "tool", "1"));
    pass(controller.poll(elapsed(14)));
    expect_cause(
        controller.finish_tool_call(elapsed(15)),
        RunTerminalCause::TimedOut(RunTimeoutKind::ToolTime),
    );
    active_timeout(
        [10, 10, 10, 100, 100, 10, 100],
        5,
        16,
        RunTimeoutKind::ToolTime,
    );

    fresh_timeout([10, 10, 10, 20, 10, 100, 100], 20, RunTimeoutKind::IdleTime);
    active_timeout(
        [10, 10, 10, 20, 100, 5, 100],
        2,
        20,
        RunTimeoutKind::ToolTime,
    );
    fresh_timeout([10, 10, 10, 10, 10, 100, 100], 10, RunTimeoutKind::WallTime);
    active_timeout([10, 10, 10, 100, 5, 5, 100], 0, 5, RunTimeoutKind::IdleTime);
    active_timeout([10, 10, 10, 5, 5, 5, 100], 0, 5, RunTimeoutKind::WallTime);
}

#[test]
fn equal_elapsed_is_valid_and_regression_fails_before_event_mutation() {
    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    pass(controller.poll(elapsed(5)));
    pass(controller.admit_model_turn(elapsed(5)));
    pass(controller.begin_tool_call(elapsed(5), "tool", "1"));
    pass(controller.accept_tool_output(elapsed(5), 0));
    pass(controller.finish_tool_call(elapsed(5)));
    pass(controller.finish(elapsed(5)));

    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    pass(controller.admit_model_turn(elapsed(5)));
    expect_cause(
        controller.admit_model_turn(elapsed(4)),
        RunTerminalCause::Failed(RunControlError::ClockRegressed),
    );
    assert_eq!(controller.model_turn_count(), 1);

    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(elapsed(5), "tool", "1"));
    let termination = expect_cause(
        controller.accept_tool_output(elapsed(4), 1),
        RunTerminalCause::Failed(RunControlError::ClockRegressed),
    );
    assert_eq!(controller.accepted_tool_output_bytes(), 0);
    assert_cleanup(&termination, "tool", "1");
}

#[test]
fn one_active_tool_lifecycle_accepts_only_legal_transitions() {
    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    pass(controller.poll(Duration::ZERO));
    pass(controller.admit_model_turn(Duration::ZERO));
    pass(controller.begin_tool_call(Duration::ZERO, "tool", "1"));
    pass(controller.accept_tool_output(Duration::ZERO, 1));
    pass(controller.mark_progress(Duration::ZERO));
    pass(controller.finish_tool_call(Duration::ZERO));
    pass(controller.admit_model_turn(Duration::ZERO));
    pass(controller.finish(Duration::ZERO));

    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(Duration::ZERO, "original", "1"));
    let termination = expect_cause(
        controller.begin_tool_call(Duration::ZERO, "nested", "2"),
        RunTerminalCause::Failed(RunControlError::ToolCallAlreadyActive),
    );
    assert_cleanup(&termination, "original", "1");
    assert_eq!(controller.total_tool_call_count(), 1);
    assert_eq!(controller.tool_call_count("nested", "2"), 0);

    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(Duration::ZERO, "tool", "1"));
    let termination = expect_cause(
        controller.admit_model_turn(Duration::ZERO),
        RunTerminalCause::Failed(RunControlError::ModelTurnWhileToolCallActive),
    );
    assert_cleanup(&termination, "tool", "1");
    assert_eq!(controller.model_turn_count(), 0);

    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    assert!(
        expect_cause(
            controller.accept_tool_output(Duration::ZERO, 1),
            RunTerminalCause::Failed(RunControlError::ToolOutputWithoutActiveCall),
        )
        .cleanup()
        .is_none()
    );

    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    assert!(
        expect_cause(
            controller.finish_tool_call(Duration::ZERO),
            RunTerminalCause::Failed(RunControlError::ToolFinishWithoutActiveCall),
        )
        .cleanup()
        .is_none()
    );

    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(Duration::ZERO, "tool", "1"));
    let termination = expect_cause(
        controller.finish(Duration::ZERO),
        RunTerminalCause::Failed(RunControlError::RunFinishWithActiveToolCall),
    );
    assert_cleanup(&termination, "tool", "1");
}

#[test]
fn cancellation_and_first_terminal_cause_are_idempotent_and_latched() {
    let context = run_context(RELAXED);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(elapsed(1), "tool", "1"));
    let first = controller.request_cancel(elapsed(2));
    assert_eq!(first.cause(), RunTerminalCause::Cancelled);
    assert_cleanup(&first, "tool", "1");
    assert_eq!(
        controller.terminal_cause(),
        Some(RunTerminalCause::Cancelled)
    );

    let repeated = controller.request_cancel(Duration::ZERO);
    assert_eq!(repeated.cause(), RunTerminalCause::Cancelled);
    assert!(repeated.cleanup().is_none());
    assert!(
        expect_cause(
            controller.admit_model_turn(elapsed(100)),
            RunTerminalCause::Cancelled,
        )
        .cleanup()
        .is_none()
    );
    assert_eq!(controller.model_turn_count(), 0);

    let context = run_context([10, 10, 10, 5, 100, 100, 100]);
    let mut controller = RunController::new(&context);
    assert_eq!(
        controller.request_cancel(elapsed(5)).cause(),
        RunTerminalCause::TimedOut(RunTimeoutKind::WallTime)
    );

    let context = run_context([1, 10, 10, 100, 100, 100, 100]);
    let mut controller = RunController::new(&context);
    pass(controller.admit_model_turn(elapsed(2)));
    expect_cause(
        controller.admit_model_turn(elapsed(3)),
        RunTerminalCause::LimitExceeded(RunLimitKind::ModelTurns),
    );
    assert_eq!(
        controller.request_cancel(Duration::ZERO).cause(),
        RunTerminalCause::LimitExceeded(RunLimitKind::ModelTurns)
    );
    assert_eq!(controller.model_turn_count(), 1);

    let context = run_context(RELAXED);
    pass(RunController::new(&context).finish(Duration::ZERO));
}

#[test]
fn every_control_cause_maps_to_existing_status_and_outcome() {
    let diagnostic = "runtime.run_002";
    let cause = RunTerminalCause::Cancelled;
    assert_eq!(cause.status(), RunStatus::Cancelled);
    assert_eq!(
        cause.into_outcome::<(), _>(diagnostic),
        RunOutcome::Cancelled { diagnostic }
    );

    for timeout in [
        RunTimeoutKind::WallTime,
        RunTimeoutKind::IdleTime,
        RunTimeoutKind::ToolTime,
    ] {
        let cause = RunTerminalCause::TimedOut(timeout);
        assert_eq!(cause.status(), RunStatus::TimedOut);
        assert_eq!(
            cause.into_outcome::<(), _>(diagnostic),
            RunOutcome::TimedOut {
                timeout,
                diagnostic
            }
        );
    }
    for limit in [
        RunLimitKind::ModelTurns,
        RunLimitKind::TotalToolCalls,
        RunLimitKind::ToolCallsPerTool,
        RunLimitKind::ToolOutputBytes,
    ] {
        let cause = RunTerminalCause::LimitExceeded(limit);
        assert_eq!(cause.status(), RunStatus::LimitExceeded);
        assert_eq!(
            cause.into_outcome::<(), _>(diagnostic),
            RunOutcome::LimitExceeded { limit, diagnostic }
        );
    }
    for error in [
        RunControlError::ClockRegressed,
        RunControlError::ModelTurnWhileToolCallActive,
        RunControlError::ToolCallAlreadyActive,
        RunControlError::ToolOutputWithoutActiveCall,
        RunControlError::ToolFinishWithoutActiveCall,
        RunControlError::RunFinishWithActiveToolCall,
    ] {
        let cause = RunTerminalCause::Failed(error);
        assert_eq!(cause.status(), RunStatus::Failed);
        assert_eq!(
            cause.into_outcome::<(), _>(diagnostic),
            RunOutcome::Failed { diagnostic }
        );
    }
}

struct FakeActiveResource {
    active: bool,
    cleanup_count: u64,
}

impl FakeActiveResource {
    fn consume_cleanup(&mut self, cleanup: Option<&ToolCallCleanup>) {
        if let Some(cleanup) = cleanup {
            assert!(self.active, "cleanup intent must be one-shot");
            assert_eq!(cleanup.exact_tool_id(), "runaway");
            assert_eq!(cleanup.exact_version(), "1");
            self.active = false;
            self.cleanup_count += 1;
        }
    }
}

#[test]
fn cooperative_runaway_exits_at_ceiling_and_cleans_active_resource_once() {
    let context = run_context([10, 10, 10, 100, 100, 100, 3]);
    let mut controller = RunController::new(&context);
    pass(controller.begin_tool_call(Duration::ZERO, "runaway", "1"));
    let mut resource = FakeActiveResource {
        active: true,
        cleanup_count: 0,
    };
    let mut accepted_chunks = 0;

    let termination = loop {
        match controller.accept_tool_output(Duration::ZERO, 1) {
            Ok(()) => accepted_chunks += 1,
            Err(termination) => break termination,
        }
    };

    assert_eq!(accepted_chunks, 3);
    assert_eq!(
        termination.cause(),
        RunTerminalCause::LimitExceeded(RunLimitKind::ToolOutputBytes)
    );
    resource.consume_cleanup(termination.cleanup());
    resource.consume_cleanup(controller.request_cancel(Duration::ZERO).cleanup());
    assert!(!resource.active);
    assert_eq!(resource.cleanup_count, 1);
}
