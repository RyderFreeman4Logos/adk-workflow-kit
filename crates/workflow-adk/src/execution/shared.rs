//! Shared turns use the existing loop-ledger/checkpoint generation and visit owner.

use super::*;
use crate::shared_session::{History, Turn};
#[cfg(test)]
#[path = "shared_tests.rs"]
mod tests;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    step: usize,
    ordinal: usize,
    input: Content,
    history_digest: String,
}

fn invalid() -> ExecutionError {
    ExecutionError::new(ExecutionErrorKind::InvalidRunState)
}

fn same_input(left: &Content, right: &Content) -> Result<bool, ExecutionError> {
    Ok(serde_json::to_vec(left).map_err(|_| invalid())?
        == serde_json::to_vec(right).map_err(|_| invalid())?)
}

fn digest(turns: &[Turn]) -> Result<String, ExecutionError> {
    let bytes = serde_json::to_vec(turns).map_err(|_| invalid())?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(invalid());
    }
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn history(nodes: &BTreeMap<String, LoopState>) -> Result<History, ExecutionError> {
    let mut turns: Vec<_> = nodes
        .values()
        .flat_map(|state| state.shared_turns.clone())
        .collect();
    turns.sort_by_key(|turn| turn.ordinal);
    for (ordinal, turn) in turns.iter().enumerate() {
        let state = nodes.get(&turn.node).ok_or_else(invalid)?;
        let owner = state.invocation.as_ref().ok_or_else(invalid)?;
        if turn.ordinal != ordinal
            || turn.step > owner.step
            || turn.input.role != "user"
            || turn
                .input
                .parts
                .iter()
                .any(|part| !matches!(part, adk_rust::Part::Text { .. }))
            || (turn.step == owner.step
                && (!state.finish_admitted
                    || state.finish_successor.as_ref() != Some(&turn.output)))
        {
            return Err(invalid());
        }
    }
    let history_digest = digest(&turns)?;
    let mut pending = None;
    for (node, state) in nodes {
        if state.shared_turns.iter().any(|turn| &turn.node != node)
            || state
                .shared_turns
                .windows(2)
                .any(|pair| pair[0].step >= pair[1].step)
        {
            return Err(invalid());
        }
        if !state.shared_turns.is_empty() || state.shared_pending.is_some() {
            let finishes = state
                .conversation
                .iter()
                .filter_map(|content| admitted_finish(content).ok().flatten())
                .collect::<Vec<_>>();
            let pending_finish =
                usize::from(state.shared_pending.is_some() && state.finish_admitted);
            if finishes.len() != state.shared_turns.len() + pending_finish
                || state
                    .shared_turns
                    .iter()
                    .zip(&finishes)
                    .any(|(turn, output)| &turn.output != output)
            {
                return Err(invalid());
            }
        }
        if let Some(prepared) = &state.shared_pending
            && (pending.replace(node.clone()).is_some()
                || state.invocation.as_ref().map(|owner| owner.step) != Some(prepared.step)
                || prepared.ordinal != turns.len()
                || prepared.history_digest != history_digest
                || state
                    .shared_turns
                    .last()
                    .is_some_and(|turn| turn.step >= prepared.step))
        {
            return Err(invalid());
        }
    }
    Ok(History::new(turns, pending))
}

pub(super) fn validate(
    ledger: &LoopLedgerStore,
    contracts: &BTreeMap<String, RuntimeAgentContract>,
) -> Result<(), ExecutionError> {
    let nodes = ledger.nodes.lock().map_err(|_| invalid())?;
    history(&nodes)?;
    for (node, state) in nodes.iter() {
        let shared = contracts
            .get(node)
            .is_some_and(|contract| !contract.isolated);
        if !shared && (!state.shared_turns.is_empty() || state.shared_pending.is_some()) {
            return Err(invalid());
        }
        if shared
            && state
                .invocation
                .as_ref()
                .is_some_and(|owner| state.model_iterations > owner.model_iteration_start)
            && state.shared_pending.is_none()
            && state.shared_turns.last().map(|turn| turn.step)
                != state.invocation.as_ref().map(|owner| owner.step)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn recoverable(
    contracts: &BTreeMap<String, RuntimeAgentContract>,
    raw_history: bool,
) -> Result<(), ExecutionError> {
    if !raw_history && contracts.values().any(|contract| !contract.isolated) {
        return Err(ExecutionError::new(ExecutionErrorKind::InvalidProfile));
    }
    Ok(())
}

impl LoopLedgerStore {
    pub(crate) fn shared_history(&self) -> Result<History, ExecutionError> {
        history(&*self.nodes.lock().map_err(|_| invalid())?)
    }

    pub(crate) fn prepare_shared(
        &self,
        node: &str,
        input: &Content,
        expected: &[Turn],
    ) -> Result<(), ExecutionError> {
        if !self.persist_raw_loop_state {
            return Err(invalid());
        }
        let mut nodes = self.nodes.lock().map_err(|_| invalid())?;
        let current = history(&nodes)?;
        if digest(expected)? != digest(&current.turns)? {
            return Err(invalid());
        }
        let mut next = nodes.clone();
        let state = next.get_mut(node).ok_or_else(invalid)?;
        let step = state.invocation.as_ref().ok_or_else(invalid)?.step;
        if let Some(turn) = state.shared_turns.last().filter(|turn| turn.step == step) {
            return if same_input(&turn.input, input)? {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if let Some(prepared) = &state.shared_pending {
            return if same_input(&prepared.input, input)? {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if current.pending.is_some() {
            return Err(invalid());
        }
        state.shared_pending = Some(Prepared {
            step,
            ordinal: expected.len(),
            input: input.clone(),
            history_digest: digest(expected)?,
        });
        self.persist_generation(&next, None)?;
        *nodes = next;
        Ok(())
    }

    pub(crate) fn accept_shared(
        &self,
        node: &str,
        input: &Content,
        output: Value,
    ) -> Result<(), ExecutionError> {
        let mut nodes = self.nodes.lock().map_err(|_| invalid())?;
        let mut next = nodes.clone();
        let state = next.get_mut(node).ok_or_else(invalid)?;
        let step = state.invocation.as_ref().ok_or_else(invalid)?.step;
        if !state.finish_admitted || state.finish_successor.as_ref() != Some(&output) {
            return Err(invalid());
        }
        if let Some(turn) = state.shared_turns.last().filter(|turn| turn.step == step) {
            return if same_input(&turn.input, input)? && turn.output == output {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        let prepared = state.shared_pending.take().ok_or_else(invalid)?;
        if prepared.step != step || !same_input(&prepared.input, input)? {
            return Err(invalid());
        }
        state.shared_turns.push(Turn {
            node: node.to_owned(),
            step,
            ordinal: prepared.ordinal,
            input: input.clone(),
            output,
        });
        history(&next)?;
        self.persist_generation(&next, None)?;
        *nodes = next;
        Ok(())
    }
}
