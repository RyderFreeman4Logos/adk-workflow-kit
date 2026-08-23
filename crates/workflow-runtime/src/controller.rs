use std::{collections::HashMap, time::Duration};

use crate::{RunContext, RunId, RunLimitKind, RunLimits, RunOutcome, RunStatus, RunTimeoutKind};

/// A fail-closed host-controller error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunControlError {
    /// A supplied elapsed sample was lower than the previous sample.
    ClockRegressed,
    /// A model turn was requested while a tool call was active.
    ModelTurnWhileToolCallActive,
    /// A tool call was requested while another tool call was active.
    ToolCallAlreadyActive,
    /// Tool output arrived without an active tool call.
    ToolOutputWithoutActiveCall,
    /// Tool completion arrived without an active tool call.
    ToolFinishWithoutActiveCall,
    /// The run was finished while a tool call was active.
    RunFinishWithActiveToolCall,
}

/// The immutable cause of a controller terminal transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunTerminalCause {
    /// The trusted host cancelled the run.
    Cancelled,
    /// A time ceiling was reached.
    TimedOut(RunTimeoutKind),
    /// A count or byte ceiling was exceeded.
    LimitExceeded(RunLimitKind),
    /// A controller invariant was violated.
    Failed(RunControlError),
}

impl RunTerminalCause {
    /// Returns the existing terminal classifier for this cause.
    pub const fn status(self) -> RunStatus {
        match self {
            Self::Cancelled => RunStatus::Cancelled,
            Self::TimedOut(_) => RunStatus::TimedOut,
            Self::LimitExceeded(_) => RunStatus::LimitExceeded,
            Self::Failed(_) => RunStatus::Failed,
        }
    }

    /// Converts this cause into the existing typed outcome with a caller diagnostic.
    pub fn into_outcome<T, D>(self, diagnostic: D) -> RunOutcome<T, D> {
        match self {
            Self::Cancelled => RunOutcome::Cancelled { diagnostic },
            Self::TimedOut(timeout) => RunOutcome::TimedOut {
                timeout,
                diagnostic,
            },
            Self::LimitExceeded(limit) => RunOutcome::LimitExceeded { limit, diagnostic },
            Self::Failed(_) => RunOutcome::Failed { diagnostic },
        }
    }
}

/// The exact active tool identity that requires host cleanup.
#[derive(Debug, Eq, PartialEq)]
pub struct ToolCallCleanup {
    exact_tool_id: String,
    exact_version: String,
}

impl ToolCallCleanup {
    /// Returns the exact resolved tool identifier.
    pub fn exact_tool_id(&self) -> &str {
        &self.exact_tool_id
    }

    /// Returns the exact resolved tool version.
    pub fn exact_version(&self) -> &str {
        &self.exact_version
    }
}

/// A terminal cause and its optional one-shot active-tool cleanup intent.
#[derive(Debug, Eq, PartialEq)]
pub struct RunTermination {
    cause: RunTerminalCause,
    cleanup: Option<ToolCallCleanup>,
}

impl RunTermination {
    /// Returns the immutable terminal cause.
    pub const fn cause(&self) -> RunTerminalCause {
        self.cause
    }

    /// Returns the active-tool cleanup intent, when this transition owns it.
    pub fn cleanup(&self) -> Option<&ToolCallCleanup> {
        self.cleanup.as_ref()
    }
}

struct ActiveToolCall {
    cleanup: ToolCallCleanup,
    started_at: Duration,
}

/// Synchronous cooperative enforcement for one trusted host run.
pub struct RunController<'limits> {
    run_id: &'limits RunId,
    limits: &'limits RunLimits,
    model_turn_count: u64,
    total_tool_call_count: u64,
    tool_call_counts: HashMap<String, HashMap<String, u64>>,
    accepted_tool_output_bytes: u64,
    last_elapsed: Duration,
    idle_started_at: Duration,
    active_tool_call: Option<ActiveToolCall>,
    terminal_cause: Option<RunTerminalCause>,
}

impl<'limits> RunController<'limits> {
    /// Starts a controller at elapsed zero using immutable context limits.
    pub fn new(context: &'limits RunContext) -> Self {
        Self {
            run_id: context.run_id(),
            limits: context.limits(),
            model_turn_count: 0,
            total_tool_call_count: 0,
            tool_call_counts: HashMap::new(),
            accepted_tool_output_bytes: 0,
            last_elapsed: Duration::ZERO,
            idle_started_at: Duration::ZERO,
            active_tool_call: None,
            terminal_cause: None,
        }
    }

    /// Checks clocks and deadlines without reporting progress.
    pub fn poll(&mut self, elapsed: Duration) -> Result<(), RunTermination> {
        self.check_boundary(elapsed)
    }

    pub(crate) fn belongs_to(&self, run_id: &RunId) -> bool {
        self.run_id == run_id
    }

    pub(crate) fn preflight_finish(&mut self, elapsed: Duration) -> Result<(), RunTermination> {
        self.check_boundary(elapsed)?;
        if self.active_tool_call.is_some() {
            return Err(self.terminate(RunTerminalCause::Failed(
                RunControlError::RunFinishWithActiveToolCall,
            )));
        }
        Ok(())
    }

    /// Admits and charges one model turn before dispatch.
    pub fn admit_model_turn(&mut self, elapsed: Duration) -> Result<(), RunTermination> {
        self.check_boundary(elapsed)?;
        if self.active_tool_call.is_some() {
            return Err(self.terminate(RunTerminalCause::Failed(
                RunControlError::ModelTurnWhileToolCallActive,
            )));
        }
        if self.model_turn_count >= self.limits.max_model_turns().get() {
            return Err(self.terminate(RunTerminalCause::LimitExceeded(RunLimitKind::ModelTurns)));
        }

        self.model_turn_count += 1;
        self.idle_started_at = elapsed;
        Ok(())
    }

    /// Reserves and charges one exact tool call before invocation.
    pub fn begin_tool_call(
        &mut self,
        elapsed: Duration,
        exact_tool_id: &str,
        exact_version: &str,
    ) -> Result<(), RunTermination> {
        self.check_boundary(elapsed)?;
        if self.active_tool_call.is_some() {
            return Err(self.terminate(RunTerminalCause::Failed(
                RunControlError::ToolCallAlreadyActive,
            )));
        }
        if self.total_tool_call_count >= self.limits.max_tool_calls().get() {
            return Err(self.terminate(RunTerminalCause::LimitExceeded(
                RunLimitKind::TotalToolCalls,
            )));
        }
        let pair_count = self.tool_call_count(exact_tool_id, exact_version);
        if pair_count >= self.limits.max_calls_per_tool().get() {
            return Err(self.terminate(RunTerminalCause::LimitExceeded(
                RunLimitKind::ToolCallsPerTool,
            )));
        }

        self.total_tool_call_count += 1;
        *self
            .tool_call_counts
            .entry(String::from(exact_tool_id))
            .or_default()
            .entry(String::from(exact_version))
            .or_default() += 1;
        self.active_tool_call = Some(ActiveToolCall {
            cleanup: ToolCallCleanup {
                exact_tool_id: String::from(exact_tool_id),
                exact_version: String::from(exact_version),
            },
            started_at: elapsed,
        });
        self.idle_started_at = elapsed;
        Ok(())
    }

    /// Charges a tool-output chunk before the host exposes it.
    pub fn accept_tool_output(
        &mut self,
        elapsed: Duration,
        bytes: u64,
    ) -> Result<(), RunTermination> {
        self.check_boundary(elapsed)?;
        if self.active_tool_call.is_none() {
            return Err(self.terminate(RunTerminalCause::Failed(
                RunControlError::ToolOutputWithoutActiveCall,
            )));
        }

        let remaining = self.limits.max_tool_output_bytes().get() - self.accepted_tool_output_bytes;
        if bytes > remaining {
            return Err(self.terminate(RunTerminalCause::LimitExceeded(
                RunLimitKind::ToolOutputBytes,
            )));
        }

        self.accepted_tool_output_bytes += bytes;
        if bytes != 0 {
            self.idle_started_at = elapsed;
        }
        Ok(())
    }

    /// Closes the active tool call after either tool success or failure.
    pub fn finish_tool_call(&mut self, elapsed: Duration) -> Result<(), RunTermination> {
        self.check_boundary(elapsed)?;
        if self.active_tool_call.is_none() {
            return Err(self.terminate(RunTerminalCause::Failed(
                RunControlError::ToolFinishWithoutActiveCall,
            )));
        }

        self.active_tool_call = None;
        self.idle_started_at = elapsed;
        Ok(())
    }

    /// Records trusted-host forward progress and resets idle time.
    pub fn mark_progress(&mut self, elapsed: Duration) -> Result<(), RunTermination> {
        self.check_boundary(elapsed)?;
        self.idle_started_at = elapsed;
        Ok(())
    }

    /// Requests cancellation after applying clock and deadline precedence.
    pub fn request_cancel(&mut self, elapsed: Duration) -> RunTermination {
        if let Err(termination) = self.check_boundary(elapsed) {
            return termination;
        }
        self.terminate(RunTerminalCause::Cancelled)
    }

    /// Finishes a healthy run with no active tool call.
    ///
    /// Completion consumes controller authority, so contradictory later control is impossible.
    ///
    /// ```compile_fail
    /// use std::{num::NonZeroU64, time::Duration};
    /// use workflow_runtime::{RunContext, RunController, RunId, RunLimits};
    /// let one = NonZeroU64::new(1).unwrap();
    /// let context = RunContext::new(
    ///     RunId::new(String::from("one-shot")).unwrap(),
    ///     RunLimits::new(one, one, one, one, one, one, one),
    /// );
    /// let mut controller = RunController::new(&context);
    /// controller.finish(Duration::ZERO).unwrap();
    /// let _ = controller.request_cancel(Duration::ZERO);
    /// ```
    pub fn finish(mut self, elapsed: Duration) -> Result<(), RunTermination> {
        self.preflight_finish(elapsed)
    }

    /// Returns the number of admitted model turns.
    pub const fn model_turn_count(&self) -> u64 {
        self.model_turn_count
    }

    /// Returns the number of admitted tool calls across exact identities.
    pub const fn total_tool_call_count(&self) -> u64 {
        self.total_tool_call_count
    }

    /// Returns the number of admitted calls for one exact tool identity.
    pub fn tool_call_count(&self, exact_tool_id: &str, exact_version: &str) -> u64 {
        self.tool_call_counts
            .get(exact_tool_id)
            .and_then(|versions| versions.get(exact_version))
            .copied()
            .unwrap_or(0)
    }

    /// Returns the cumulative accepted tool-output bytes.
    pub const fn accepted_tool_output_bytes(&self) -> u64 {
        self.accepted_tool_output_bytes
    }

    /// Returns the first terminal cause, if the run has terminalized.
    pub const fn terminal_cause(&self) -> Option<RunTerminalCause> {
        self.terminal_cause
    }

    fn check_boundary(&mut self, elapsed: Duration) -> Result<(), RunTermination> {
        if let Some(cause) = self.terminal_cause {
            return Err(RunTermination {
                cause,
                cleanup: None,
            });
        }
        if elapsed < self.last_elapsed {
            return Err(self.terminate(RunTerminalCause::Failed(RunControlError::ClockRegressed)));
        }
        self.last_elapsed = elapsed;
        if let Some(timeout) = self.reached_timeout(elapsed) {
            return Err(self.terminate(RunTerminalCause::TimedOut(timeout)));
        }
        Ok(())
    }

    fn reached_timeout(&self, elapsed: Duration) -> Option<RunTimeoutKind> {
        let mut winner = None;
        let mut consider = |deadline: Duration, kind| {
            if elapsed >= deadline
                && match winner {
                    Some((earliest, _)) => deadline < earliest,
                    None => true,
                }
            {
                winner = Some((deadline, kind));
            }
        };

        consider(
            Duration::from_millis(self.limits.max_wall_time_ms().get()),
            RunTimeoutKind::WallTime,
        );
        if let Some(deadline) = self
            .idle_started_at
            .checked_add(Duration::from_millis(self.limits.max_idle_time_ms().get()))
        {
            consider(deadline, RunTimeoutKind::IdleTime);
        }
        if let Some(active) = &self.active_tool_call {
            if let Some(deadline) = active
                .started_at
                .checked_add(Duration::from_millis(self.limits.max_tool_time_ms().get()))
            {
                consider(deadline, RunTimeoutKind::ToolTime);
            }
        }

        winner.map(|(_, kind)| kind)
    }

    fn terminate(&mut self, cause: RunTerminalCause) -> RunTermination {
        if let Some(latched) = self.terminal_cause {
            return RunTermination {
                cause: latched,
                cleanup: None,
            };
        }

        self.terminal_cause = Some(cause);
        let cleanup = self.active_tool_call.take().map(|active| active.cleanup);
        RunTermination { cause, cleanup }
    }
}
