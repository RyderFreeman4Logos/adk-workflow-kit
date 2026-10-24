//! Run-owned ADK projections of accepted public turns, never tool transcripts.

use crate::{AdkGraphError, execution::LoopLedgerStore, session_context::HistoryContext};
use adk_rust::{
    Content, Event, InvocationContext,
    session::{AppendEventRequest, CreateRequest, InMemorySessionService, SessionService},
    tokio::sync::{Mutex as AsyncMutex, Notify},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Turn {
    pub(crate) node: String,
    pub(crate) step: usize,
    pub(crate) ordinal: usize,
    pub(crate) input: Content,
    pub(crate) output: Value,
}

#[derive(Default)]
pub(crate) struct History {
    pub(crate) turns: Vec<Turn>,
    pub(crate) pending: Option<String>,
}

impl History {
    pub(crate) fn new(turns: Vec<Turn>, pending: Option<String>) -> Self {
        Self { turns, pending }
    }
}

struct Run {
    failed: AtomicBool,
    history: AsyncMutex<History>,
    changed: Notify,
    ledger: Option<Arc<LoopLedgerStore>>,
}

/// This map belongs to one compiled graph, not the process. A guard removes the
/// run on completion, error or cancellation; session-id reuse never grants history.
#[derive(Default)]
pub(super) struct Sessions {
    runs: Mutex<BTreeMap<String, Arc<Run>>>,
    enabled: bool,
    checkpointed: bool,
}

pub(super) struct RunGuard<'a> {
    sessions: &'a Sessions,
    id: String,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut runs) = self.sessions.runs.lock() {
            runs.remove(&self.id);
        }
    }
}

fn invalid() -> adk_rust::AdkError {
    adk_rust::AdkError::agent("workflow.loop.invalid_state")
}

impl Sessions {
    pub(super) fn new(enabled: bool, checkpointed: bool) -> Self {
        Self {
            runs: Mutex::default(),
            enabled,
            checkpointed,
        }
    }
    pub(super) fn begin(
        &self,
        id: &str,
        ledger: Option<Arc<LoopLedgerStore>>,
    ) -> Result<Option<RunGuard<'_>>, AdkGraphError> {
        if !self.enabled {
            return Ok(None);
        }
        // Generic SDK checkpointers do not contain the Kit's accepted history.
        if self.checkpointed && ledger.is_none() {
            return Err(AdkGraphError::Failed);
        }
        let history = ledger
            .as_ref()
            .map(|ledger| ledger.shared_history())
            .transpose()
            .map_err(|_| AdkGraphError::Failed)?
            .unwrap_or_default();
        let mut runs = self.runs.lock().map_err(|_| AdkGraphError::Failed)?;
        if runs.contains_key(id) {
            return Err(AdkGraphError::Failed);
        }
        runs.insert(
            id.to_owned(),
            Arc::new(Run {
                failed: AtomicBool::new(false),
                history: AsyncMutex::new(history),
                changed: Notify::new(),
                ledger,
            }),
        );
        Ok(Some(RunGuard {
            sessions: self,
            id: id.to_owned(),
        }))
    }

    pub(super) async fn invoke(
        &self,
        node: &str,
        agent: &dyn adk_rust::Agent,
        ctx: Arc<dyn InvocationContext>,
    ) -> adk_rust::Result<Vec<Event>> {
        use adk_rust::futures::TryStreamExt as _;
        let run = self
            .runs
            .lock()
            .map_err(|_| invalid())?
            .get(ctx.session_id())
            .cloned()
            .ok_or_else(invalid)?;
        let mut failure = FailureGuard {
            run: &run,
            accepted: false,
        };
        let work = async {
            let mut history = loop {
                let notified = run.changed.notified();
                // Register before releasing the lock to avoid missing the recovery
                // owner's completion when multiple shared nodes resume together.
                adk_rust::tokio::pin!(notified);
                notified.as_mut().enable();
                let history = run.history.lock().await;
                if run.failed.load(Ordering::Acquire) || ctx.is_cancelled() {
                    return Err(invalid());
                }
                if history
                    .pending
                    .as_deref()
                    .is_none_or(|pending| pending == node)
                {
                    break history;
                }
                drop(history);
                notified.await;
            };
            let result = async {
                if let Some(ledger) = &run.ledger {
                    ledger
                        .prepare_shared(node, ctx.user_content(), &history.turns)
                        .map_err(|_| invalid())?;
                }
                let input = ctx.user_content().clone();
                let projection = project(&history.turns, ctx.as_ref()).await?;
                let projected: Arc<dyn InvocationContext> = Arc::new(HistoryContext {
                    inner: ctx.clone(),
                    history: projection,
                });
                let events: Vec<Event> = agent.run(projected).await?.try_collect().await?;
                if events
                    .iter()
                    .any(|event| event.actions.tool_confirmation.is_some())
                {
                    // Confirmation is not a completed turn. The public Kit graph
                    // does not expose SDK confirmation resume; durable execution
                    // must release any waiting owner rather than hang or approve.
                    if run.ledger.is_some() {
                        run.failed.store(true, Ordering::Release);
                    }
                    return Ok(events);
                }
                let text = super::final_agent_text(&events)
                    .ok_or_else(super::agent_admission::invalid_output)?;
                let value = serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!(text));
                let output = value.get("output").cloned().unwrap_or(value);
                if let Some(ledger) = &run.ledger {
                    ledger
                        .accept_shared(node, &input, output)
                        .map_err(|_| invalid())?;
                    *history = ledger.shared_history().map_err(|_| invalid())?;
                } else {
                    let ordinal = history.turns.len();
                    history.turns.push(Turn {
                        node: node.to_owned(),
                        step: ordinal,
                        ordinal,
                        input,
                        output,
                    });
                }
                Ok(events)
            }
            .await;
            drop(history);
            run.changed.notify_waiters();
            result
        };
        // The pinned public context exposes cancellation as a predicate, not a
        // notification. Poll only that predicate while awaiting shared admission;
        // the execution backend still owns its absolute wall/idle deadlines.
        let cancelled = async {
            loop {
                if ctx.is_cancelled() {
                    break;
                }
                adk_rust::tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        let result = adk_rust::tokio::select! {
            biased;
            () = cancelled => Err(adk_rust::AdkError::agent("workflow.loop.cancelled")),
            result = work => result,
        };
        failure.accepted = result.is_ok();
        result
    }
}

struct FailureGuard<'a> {
    run: &'a Run,
    accepted: bool,
}
impl Drop for FailureGuard<'_> {
    fn drop(&mut self) {
        if !self.accepted {
            self.run.failed.store(true, Ordering::Release);
            self.run.changed.notify_waiters();
        }
    }
}

async fn project(
    turns: &[Turn],
    ctx: &dyn InvocationContext,
) -> adk_rust::Result<adk_rust::runner::MutableSession> {
    let bytes = serde_json::to_vec(&(turns, ctx.user_content())).map_err(|_| invalid())?;
    if bytes.len() > crate::execution::MAX_STATE_BYTES {
        return Err(invalid());
    }
    let service = InMemorySessionService::new();
    let snapshot = service
        .create(CreateRequest {
            app_name: ctx.app_name().to_owned(),
            user_id: ctx.user_id().to_owned(),
            session_id: Some(ctx.session_id().to_owned()),
            state: Default::default(),
        })
        .await?;
    let identity = snapshot.try_identity()?;
    for turn in turns {
        for (author, content) in [
            ("user", turn.input.clone()),
            (
                "model",
                Content::new("model").with_text(json!({"output":turn.output}).to_string()),
            ),
        ] {
            let mut event = Event::new(ctx.invocation_id());
            event.author = author.to_owned();
            event.set_content(content);
            service
                .append_event_for_identity(AppendEventRequest {
                    identity: identity.clone(),
                    event,
                })
                .await?;
        }
    }
    // LlmAgent replaces the last user with the current mapped input. Give that
    // substitution its own turn, so it never overwrites an accepted earlier user.
    let mut event = Event::new(ctx.invocation_id());
    event.author = "user".to_owned();
    event.set_content(ctx.user_content().clone());
    service
        .append_event_for_identity(AppendEventRequest {
            identity: identity.clone(),
            event,
        })
        .await?;
    Ok(adk_rust::runner::MutableSession::new(Arc::from(
        service.get_for_identity(&identity).await?,
    )))
}
