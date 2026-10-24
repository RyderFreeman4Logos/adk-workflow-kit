//! Changes only the history view; identity, graph state and authority remain local.

use adk_rust::{
    Agent, Artifacts, CallbackContext, Content, InvocationContext, Memory, ReadonlyContext,
    RunConfig, SecretRequest, Session, SharedState, State, ToolOutcome, async_trait,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

pub(super) struct HistoryContext {
    pub(super) inner: Arc<dyn InvocationContext>,
    pub(super) history: adk_rust::runner::MutableSession,
}

impl ReadonlyContext for HistoryContext {
    fn invocation_id(&self) -> &str {
        self.inner.invocation_id()
    }
    fn agent_name(&self) -> &str {
        self.inner.agent_name()
    }
    fn user_id(&self) -> &str {
        self.inner.user_id()
    }
    fn app_name(&self) -> &str {
        self.inner.app_name()
    }
    fn session_id(&self) -> &str {
        self.inner.session_id()
    }
    fn branch(&self) -> &str {
        self.inner.branch()
    }
    fn user_content(&self) -> &Content {
        self.inner.user_content()
    }
    fn state(&self) -> Option<&dyn State> {
        self.inner.state()
    }
}

#[async_trait]
impl CallbackContext for HistoryContext {
    fn artifacts(&self) -> Option<Arc<dyn Artifacts>> {
        self.inner.artifacts()
    }
    fn tool_outcome(&self) -> Option<ToolOutcome> {
        self.inner.tool_outcome()
    }
    fn tool_name(&self) -> Option<&str> {
        self.inner.tool_name()
    }
    fn tool_input(&self) -> Option<&Value> {
        self.inner.tool_input()
    }
    fn shared_state(&self) -> Option<Arc<SharedState>> {
        self.inner.shared_state()
    }
}

impl Session for HistoryContext {
    fn id(&self) -> &str {
        self.inner.session().id()
    }
    fn app_name(&self) -> &str {
        self.inner.session().app_name()
    }
    fn user_id(&self) -> &str {
        self.inner.session().user_id()
    }
    fn state(&self) -> &dyn State {
        self.inner.session().state()
    }
    fn conversation_history(&self) -> Vec<Content> {
        self.history.conversation_history()
    }
    // Only explicitly admitted public turns inhabit this projection. Authored
    // Shared grants their visibility across node branches and agent names.
    fn conversation_history_scoped(&self, _: Option<&str>, _: &str) -> Vec<Content> {
        self.history.conversation_history()
    }
}

#[async_trait]
impl InvocationContext for HistoryContext {
    fn agent(&self) -> Arc<dyn Agent> {
        self.inner.agent()
    }
    fn memory(&self) -> Option<Arc<dyn Memory>> {
        self.inner.memory()
    }
    fn session(&self) -> &dyn Session {
        self
    }
    fn run_config(&self) -> &RunConfig {
        self.inner.run_config()
    }
    fn end_invocation(&self) {
        self.inner.end_invocation();
    }
    fn ended(&self) -> bool {
        self.inner.ended()
    }
    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
    fn user_scopes(&self) -> Vec<String> {
        self.inner.user_scopes()
    }
    fn request_metadata(&self) -> HashMap<String, Value> {
        self.inner.request_metadata()
    }
    fn authoritative_transfer_targets(&self) -> bool {
        self.inner.authoritative_transfer_targets()
    }
    fn delegation_depth(&self) -> u32 {
        self.inner.delegation_depth()
    }
    fn max_delegation_depth(&self) -> Option<u32> {
        self.inner.max_delegation_depth()
    }
    fn orchestration_root_invocation_id(&self) -> &str {
        self.inner.orchestration_root_invocation_id()
    }
    fn orchestration_edge_id(&self) -> Option<&str> {
        self.inner.orchestration_edge_id()
    }
    fn requires_tool_confirmation(&self, tool: &str) -> bool {
        self.inner.requires_tool_confirmation(tool)
    }
    async fn get_secret(&self, name: &str) -> adk_rust::Result<Option<String>> {
        self.inner.get_secret(name).await
    }
    async fn get_secret_for(&self, request: &SecretRequest) -> adk_rust::Result<Option<String>> {
        self.inner.get_secret_for(request).await
    }
}
