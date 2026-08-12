//! Deterministic offline ADK-Rust test doubles and exact tool registry fixtures.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use adk_rust::{
    async_trait, AdkError, ErrorCategory, ErrorComponent, Llm, LlmRequest, LlmResponse,
    LlmResponseStream, Tool, ToolContext,
};
use serde_json::Value;
use workflow_compiler::{RegistryCategory, RegistryEntry, RegistryNotFound, ToolRegistry};

type RequestPredicate = dyn Fn(&LlmRequest) -> Result<(), String> + Send + Sync;

fn model_error(code: &'static str, message: impl Into<String>) -> AdkError {
    AdkError::new(
        ErrorComponent::Model,
        ErrorCategory::Internal,
        code,
        message,
    )
}

fn tool_error(code: &'static str, message: impl Into<String>) -> AdkError {
    AdkError::new(ErrorComponent::Tool, ErrorCategory::Internal, code, message)
}

/// One expected model request and its deterministic response.
pub struct ScriptStep {
    predicate: Box<RequestPredicate>,
    response: LlmResponse,
}

impl ScriptStep {
    /// Creates a step from an explicit request predicate and response.
    pub fn new<F>(predicate: F, response: LlmResponse) -> Self
    where
        F: Fn(&LlmRequest) -> Result<(), String> + Send + Sync + 'static,
    {
        Self {
            predicate: Box::new(predicate),
            response,
        }
    }
}

struct ScriptState {
    steps: VecDeque<ScriptStep>,
    requests: Vec<LlmRequest>,
}

/// A finite, ordered ADK model script that fails closed on unexpected requests.
pub struct ScriptedLlm {
    state: Mutex<ScriptState>,
}

impl ScriptedLlm {
    /// Creates a scripted model with the supplied ordered steps.
    pub fn new(steps: Vec<ScriptStep>) -> Self {
        Self {
            state: Mutex::new(ScriptState {
                steps: steps.into(),
                requests: Vec::new(),
            }),
        }
    }

    /// Returns stable copies of all observed requests.
    pub fn requests(&self) -> adk_rust::Result<Vec<LlmRequest>> {
        self.state
            .lock()
            .map(|state| state.requests.clone())
            .map_err(|_| {
                model_error(
                    "model.scripted.state_poisoned",
                    "scripted model state is poisoned",
                )
            })
    }

    /// Returns the number of unconsumed script steps.
    pub fn remaining_steps(&self) -> adk_rust::Result<usize> {
        self.state
            .lock()
            .map(|state| state.steps.len())
            .map_err(|_| {
                model_error(
                    "model.scripted.state_poisoned",
                    "scripted model state is poisoned",
                )
            })
    }
}

#[async_trait]
impl Llm for ScriptedLlm {
    fn name(&self) -> &str {
        "scripted-llm"
    }

    async fn generate_content(
        &self,
        request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<LlmResponseStream> {
        let mut state = self.state.lock().map_err(|_| {
            model_error(
                "model.scripted.state_poisoned",
                "scripted model state is poisoned",
            )
        })?;
        state.requests.push(request.clone());

        let response = {
            let step = state.steps.front().ok_or_else(|| {
                model_error(
                    "model.scripted.exhausted",
                    "scripted model has no remaining response",
                )
            })?;
            (step.predicate)(&request)
                .map_err(|message| model_error("model.scripted.request_mismatch", message))?;
            step.response.clone()
        };
        let _ = state.steps.pop_front();

        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(response)])))
    }
}

/// One exact function call observed by a [`FakeTool`].
#[derive(Clone, Debug, PartialEq)]
pub struct FakeToolCall {
    function_call_id: String,
    arguments: Value,
}

impl FakeToolCall {
    /// Returns the exact ADK function-call ID.
    pub fn function_call_id(&self) -> &str {
        &self.function_call_id
    }

    /// Returns the exact JSON arguments supplied by ADK.
    pub fn arguments(&self) -> &Value {
        &self.arguments
    }
}

/// An ADK tool with deterministic JSON output and an in-memory call ledger.
pub struct FakeTool {
    name: String,
    description: String,
    response: Value,
    calls: Mutex<Vec<FakeToolCall>>,
}

impl FakeTool {
    /// Creates a deterministic fake tool.
    pub fn new(name: impl Into<String>, description: impl Into<String>, response: Value) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            response,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Returns stable copies of all observed calls.
    pub fn calls(&self) -> adk_rust::Result<Vec<FakeToolCall>> {
        self.calls.lock().map(|calls| calls.clone()).map_err(|_| {
            tool_error(
                "tool.fake.state_poisoned",
                "fake tool call state is poisoned",
            )
        })
    }
}

#[async_trait]
impl Tool for FakeTool {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    async fn execute(
        &self,
        context: Arc<dyn ToolContext>,
        arguments: Value,
    ) -> adk_rust::Result<Value> {
        self.calls
            .lock()
            .map_err(|_| {
                tool_error(
                    "tool.fake.state_poisoned",
                    "fake tool call state is poisoned",
                )
            })?
            .push(FakeToolCall {
                function_call_id: context.function_call_id().to_owned(),
                arguments,
            });
        Ok(self.response.clone())
    }
}

/// A compiler tool registry containing one exact opaque ID and version pair.
pub struct FakeToolRegistry<T> {
    id: String,
    version: String,
    implementation: T,
}

impl<T> FakeToolRegistry<T> {
    /// Creates a single-entry exact-version registry.
    pub fn new(id: impl Into<String>, version: impl Into<String>, implementation: T) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            implementation,
        }
    }
}

impl<T> ToolRegistry for FakeToolRegistry<T> {
    type Implementation = T;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        if (id, version) == (self.id.as_str(), self.version.as_str()) {
            Ok(RegistryEntry::new(
                &self.implementation,
                &self.id,
                &self.version,
            ))
        } else {
            Err(RegistryNotFound::new(RegistryCategory::Tool, id, version))
        }
    }
}
