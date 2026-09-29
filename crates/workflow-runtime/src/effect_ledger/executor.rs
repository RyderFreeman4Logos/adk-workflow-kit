//! Capability-scoped executor binding and conservative remote recovery.
use super::{ApprovalRequest, EffectLedger, EffectState, LedgerError};
use crate::{
    argument_fingerprint,
    firewall::{ToolRule, token},
};
use std::{collections::BTreeMap, time::Instant};

/// Read-only remote lookup by the exact idempotency key. Absence must be authoritative.
/// Absent is a snapshot, not a fence: an earlier in-flight request may still commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteObservation {
    Absent,
    Committed,
    Unknown,
}
/// Outcome of one dispatch, not finality of the logical effect key.
/// A request error/timeout/uncertain response is Unknown, never Rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionOutcome {
    Committed,
    /// This dispatch cannot cause an effect; an earlier dispatch may still commit.
    Rejected,
    Unknown,
}
/// Read-only postcondition observation; unknown never becomes success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Postcondition {
    Satisfied,
    Violated,
    Unknown,
}

/// Trusted host implementation, never dynamically selected from proposal text.
/// Implementations MUST bound IO, atomically deduplicate `effect_key`, and condition
/// mutations on the exact target version in `proposal`. A service without these
/// guarantees must return Unknown and require manual reconciliation, not retry.
/// Lookup/verify MUST be read-only and bind observations to this exact action/key.
/// Rejected rules out an effect only from this dispatch, not all requests sharing
/// `effect_key`. Neither rejection nor snapshot absence fences earlier requests.
pub trait EffectExecutor: Send {
    fn reconcile(&mut self, request: &ApprovalRequest) -> RemoteObservation;
    fn execute(&mut self, request: &ApprovalRequest) -> ExecutionOutcome;
    fn verify(&mut self, request: &ApprovalRequest) -> Postcondition;
}

/// Explicit host registry binds implementation to the whole capability/scoping rule.
/// Registering trusted code is not an OS sandbox; hosts retain that responsibility.
#[derive(Default)]
pub struct ExecutorRegistry {
    entries: BTreeMap<(String, String), (String, Box<dyn EffectExecutor>)>,
}
impl ExecutorRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    /// Duplicate registrations are rejected, never silently replaced.
    pub fn register(
        &mut self,
        tool_id: &str,
        rule: ToolRule,
        executor: impl EffectExecutor + 'static,
    ) -> Result<(), LedgerError> {
        if !token(tool_id, 128) || !token(&rule.version, 128) {
            return Err(LedgerError::InvalidInput);
        }
        let key = (tool_id.to_owned(), rule.version.clone());
        if self.entries.contains_key(&key) {
            return Err(LedgerError::ExecutorMismatch);
        }
        let digest = argument_fingerprint(
            &serde_json::to_value(rule).map_err(|_| LedgerError::InvalidInput)?,
        );
        self.entries.insert(key, (digest, Box::new(executor)));
        Ok(())
    }
    fn get(
        &mut self,
        request: &ApprovalRequest,
    ) -> Result<&mut Box<dyn EffectExecutor>, LedgerError> {
        let intent = &request.proposal.intent;
        self.entries
            .get_mut(&(intent.tool_id.clone(), intent.tool_version.clone()))
            .filter(|(digest, _)| digest == &request.rule_digest)
            .map(|(_, executor)| executor)
            .ok_or(LedgerError::ExecutorMismatch)
    }
}
impl EffectLedger {
    /// Advances one durable phase, never an unbounded workflow loop. The caller
    /// reconstructs the request from current trusted goal/policy/lock on resume.
    /// Started is committed before IO. Every uncertain request reconciles remotely
    /// before retry; committed effects only verify, even after approval expiry.
    /// `now_unix_ms` is the host's trusted wall clock at entry; elapsed IO time is
    /// included in the final dispatch-expiry check. Clock rollback handling belongs
    /// to the host clock. Terminal replay performs no remote IO.
    pub fn advance(
        &mut self,
        request: &ApprovalRequest,
        registry: &mut ExecutorRegistry,
        now_unix_ms: u64,
    ) -> Result<EffectState, LedgerError> {
        let entered = Instant::now();
        let state = self.state(request)?;
        if matches!(state, EffectState::Verified | EffectState::Failed) {
            return Ok(state);
        }
        if state == EffectState::Proposed {
            return Err(LedgerError::ApprovalRequired);
        }
        let executor = registry.get(request)?;
        let next = match state {
            EffectState::Approved => {
                if now_unix_ms >= request.context.expires_at_unix_ms {
                    EffectState::Failed
                } else {
                    EffectState::Started
                }
            }
            EffectState::Started | EffectState::Indeterminate => {
                match executor.reconcile(request) {
                    RemoteObservation::Committed => EffectState::Committed,
                    RemoteObservation::Unknown => EffectState::Indeterminate,
                    RemoteObservation::Absent => {
                        let elapsed =
                            u64::try_from(entered.elapsed().as_millis()).unwrap_or(u64::MAX);
                        if now_unix_ms.saturating_add(elapsed) >= request.context.expires_at_unix_ms
                        {
                            // Expiry forbids retry, but does not cancel a prior remote request.
                            EffectState::Indeterminate
                        } else {
                            match executor.execute(request) {
                                ExecutionOutcome::Committed => EffectState::Committed,
                                // B's rejection cannot rule out A's commit for the same key.
                                ExecutionOutcome::Rejected | ExecutionOutcome::Unknown => {
                                    EffectState::Indeterminate
                                }
                            }
                        }
                    }
                }
            }
            EffectState::Committed => match executor.verify(request) {
                Postcondition::Satisfied => EffectState::Verified,
                Postcondition::Violated => EffectState::Failed,
                // A known commit must never return to a request-capable state.
                Postcondition::Unknown => EffectState::Committed,
            },
            EffectState::Proposed | EffectState::Verified | EffectState::Failed => {
                unreachable!("handled above")
            }
        };
        if state == next {
            Ok(state)
        } else {
            self.append(request, next)
        }
    }
}
