//! Admits one complete agent response before the SDK can publish node updates.

use std::sync::Arc;

use adk_rust::{
    AdkError, Agent, AgentCapabilities, AgentInteractionMode, AgentTopology, AgentTransferDecision,
    AgentTransferRequest, Event, EventStream, InvocationContext, RunConfig, async_trait,
    futures::TryStreamExt as _,
};

pub(super) fn admit(agent: Arc<dyn Agent>) -> Arc<dyn Agent> {
    Arc::new(OutputAdmission {
        agent,
        replay: None,
    })
}

pub(super) fn replay_current(
    agent: Arc<dyn Agent>,
    replay: impl Fn() -> adk_rust::Result<Option<Event>> + Send + Sync + 'static,
) -> Arc<dyn Agent> {
    Arc::new(OutputAdmission {
        agent,
        replay: Some(Box::new(replay)),
    })
}

fn invalid_output() -> AdkError {
    AdkError::agent("workflow.node.invalid_output")
}

pub(super) fn is_invalid_output(node: &str, message: &str) -> bool {
    // AgentNode attaches the node once; Executor wraps its failure once more.
    // Compare that exact SDK representation using the trusted failing node.
    message
        == adk_rust::graph::GraphError::NodeExecutionFailed {
            node: node.to_owned(),
            message: invalid_output().to_string(),
        }
        .to_string()
}

struct OutputAdmission {
    agent: Arc<dyn Agent>,
    replay: Option<Box<dyn Fn() -> adk_rust::Result<Option<Event>> + Send + Sync>>,
}

#[async_trait]
impl Agent for OutputAdmission {
    fn name(&self) -> &str {
        self.agent.name()
    }

    fn description(&self) -> &str {
        self.agent.description()
    }

    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        self.agent.sub_agents()
    }

    fn interaction_mode(&self) -> AgentInteractionMode {
        self.agent.interaction_mode()
    }

    fn supports_agent_transfer(&self) -> bool {
        self.agent.supports_agent_transfer()
    }

    fn capabilities(&self) -> AgentCapabilities {
        self.agent.capabilities()
    }

    fn topology(&self) -> Option<AgentTopology> {
        self.agent.topology()
    }

    fn configure_run(&self, agent_name: &str, config: &mut RunConfig) {
        self.agent.configure_run(agent_name, config);
    }

    fn transfer_targets_for(&self, agent_name: &str) -> Option<Vec<String>> {
        self.agent.transfer_targets_for(agent_name)
    }

    fn strict_transfer_policy(&self) -> bool {
        self.agent.strict_transfer_policy()
    }

    async fn govern_transfer(
        &self,
        request: &AgentTransferRequest,
    ) -> adk_rust::Result<AgentTransferDecision> {
        self.agent.govern_transfer(request).await
    }

    async fn run(&self, ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        if let Some(event) = self
            .replay
            .as_ref()
            .map(|replay| replay())
            .transpose()?
            .flatten()
        {
            return Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])));
        }
        // Match AgentNode's complete-stream boundary: real errors win, and a
        // confirmation remains the SDK's interrupt rather than an empty answer.
        let events: Vec<Event> = self.agent.run(ctx).await?.try_collect().await?;
        if !events
            .iter()
            .any(|event| event.actions.tool_confirmation.is_some())
            && super::final_agent_text(&events).is_none()
        {
            return Err(invalid_output());
        }
        Ok(Box::pin(adk_rust::futures::stream::iter(
            events.into_iter().map(Ok),
        )))
    }
}
