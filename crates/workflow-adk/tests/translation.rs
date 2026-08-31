use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use adk_rust::graph::prelude::{ExecutionConfig, State};
use adk_rust::graph::{Checkpointer, MemoryCheckpointer};
use adk_rust::{
    Agent, AgentCapabilities, Content, Event, EventStream, InvocationContext, async_trait,
};
use serde_json::json;
use workflow_adk::events::AdkEventMapper;
use workflow_adk::{AdkGraphError, AdkGraphTranslator, TerminalOutcome, TranslationError};
use workflow_compiler::{
    BindingCategory, BindingRef, CapabilitySet, PredicateRegistry, RegistryEntry, RegistryNotFound,
    RegistryResolutionError, ResolvedBinding, ResolvedRuntimePlan, RuntimePlanRegistry,
    RuntimePlanRequest, compile_str, compile_str_with_predicates,
};
use workflow_runtime::{InMemoryArtifactStore, WorkflowRuntimeEventKindV1};

const SEQUENTIAL: &str = r#"
schema_version = 1
[workflow]
id = "sequential"
version = "1"
entry = "agent"
[[nodes]]
id = "agent"
kind = "agent"
model = { role = "worker", id = "fake-model", version = "1" }
[[nodes]]
id = "action"
kind = "action"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "agent"
to = "action"
[[edges]]
from = "action"
to = "done"
"#;

const BOUNDED_CYCLE: &str = r#"
schema_version = 1
[workflow]
id = "bounded-cycle"
version = "1"
entry = "loop"
[[nodes]]
id = "loop"
kind = "action"
max_visits = 2
idempotent = true
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "loop"
to = "loop"
[[edges]]
from = "loop"
to = "done"
"#;

const UNBOUNDED_CYCLE: &str = r#"
schema_version = 1
[workflow]
id = "unbounded-cycle"
version = "1"
entry = "loop"
[[nodes]]
id = "loop"
kind = "action"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "loop"
to = "loop"
[[edges]]
from = "loop"
to = "done"
"#;

const BOUNDED_INVOKE: &str = r#"
schema_version = 1
[workflow]
id = "bounded-invoke"
version = "1"
entry = "loop"
[[nodes]]
id = "loop"
kind = "action"
max_visits = 2
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "loop"
to = "done"
"#;

const OTHER_WORKFLOW: &str = r#"
schema_version = 1
edges = []
[workflow]
id = "other"
version = "1"
entry = "only"
[[nodes]]
id = "only"
kind = "terminal"
"#;

const CONDITIONAL: &str = r#"
schema_version = 1
edges = []
[workflow]
id = "conditional"
version = "1"
entry = "decide"
[[nodes]]
id = "decide"
kind = "agent"
[[nodes]]
id = "left"
kind = "terminal"
[[nodes]]
id = "fallback"
kind = "terminal"
[[routes]]
from = "decide"
predicate = { id = "route-pred", version = "1" }
cases = { left = "left" }
default = "fallback"
"#;

const AGENT_SELECTED_ROUTE: &str = r#"
schema_version = 1
edges = []
[workflow]
id = "agent-selected-route"
version = "1"
entry = "decide"
[[nodes]]
id = "decide"
kind = "agent"
[[nodes]]
id = "left"
kind = "terminal"
[[routes]]
from = "decide"
predicate = { id = "route-pred", version = "1" }
cases = { ok = "left" }
"#;

const UNKNOWN_ROUTE: &str = r#"
schema_version = 1
edges = []
[workflow]
id = "unknown-route"
version = "1"
entry = "decide"
[[nodes]]
id = "decide"
kind = "agent"
[[nodes]]
id = "left"
kind = "terminal"
[[routes]]
from = "decide"
predicate = { id = "route-pred", version = "1" }
cases = { left = "left" }
"#;

const FAN_IN_WITHOUT_SHARED_STATE: &str = r#"
schema_version = 1
[workflow]
id = "fan-in-without-shared-state"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "action"
[[nodes]]
id = "left"
kind = "agent"
[[nodes]]
id = "right"
kind = "agent"
[[nodes]]
id = "join"
kind = "terminal"
[[edges]]
from = "start"
to = "left"
[[edges]]
from = "start"
to = "right"
[[edges]]
from = "left"
to = "join"
[[edges]]
from = "right"
to = "join"
"#;

const FAN_IN_DECLARED_STATE_WITH_ZERO_WRITES: &str = r#"
schema_version = 1
[workflow]
id = "fan-in-declared-state-with-zero-writes"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "action"
[[nodes]]
id = "left"
kind = "agent"
[[nodes]]
id = "right"
kind = "agent"
[[nodes]]
id = "join"
kind = "terminal"
[[edges]]
from = "start"
to = "left"
[[edges]]
from = "start"
to = "right"
[[edges]]
from = "left"
to = "join"
[[edges]]
from = "right"
to = "join"
[state]
schema_id = "shared-state"
schema_version = "1"
required_keys = ["shared"]
[state.keys.shared]
schema_id = "shared"
schema_version = "1"
"#;

const FAN_IN_DECLARED_STATE_WITH_DISJOINT_KEYS: &str = r#"
schema_version = 1
[workflow]
id = "fan-in-declared-state-with-disjoint-keys"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "action"
[[nodes]]
id = "left"
kind = "agent"
[[nodes]]
id = "right"
kind = "agent"
[[nodes]]
id = "join"
kind = "terminal"
[[edges]]
from = "start"
to = "left"
[[edges]]
from = "start"
to = "right"
[[edges]]
from = "left"
to = "join"
[[edges]]
from = "right"
to = "join"
[state]
schema_id = "disjoint-state"
schema_version = "1"
required_keys = ["left", "right"]
[state.keys.left]
schema_id = "left"
schema_version = "1"
[state.keys.right]
schema_id = "right"
schema_version = "1"
"#;

const MULTI_HOP_FAN_IN: &str = r#"
schema_version = 1
[workflow]
id = "multi-hop-fan-in"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "action"
[[nodes]]
id = "left_writer"
kind = "agent"
[[nodes]]
id = "right_writer"
kind = "agent"
[[nodes]]
id = "left_relay"
kind = "action"
[[nodes]]
id = "right_relay"
kind = "action"
[[nodes]]
id = "join"
kind = "terminal"
[[edges]]
from = "start"
to = "left_writer"
[[edges]]
from = "start"
to = "right_writer"
[[edges]]
from = "left_writer"
to = "left_relay"
[[edges]]
from = "right_writer"
to = "right_relay"
[[edges]]
from = "left_relay"
to = "join"
[[edges]]
from = "right_relay"
to = "join"
"#;

const ROUTE_FAN_IN: &str = r#"
schema_version = 1
[workflow]
id = "route-fan-in"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "action"
[[nodes]]
id = "left"
kind = "agent"
[[nodes]]
id = "right"
kind = "agent"
[[nodes]]
id = "join"
kind = "terminal"
[[edges]]
from = "start"
to = "left"
[[edges]]
from = "start"
to = "right"
[[routes]]
from = "left"
predicate = { id = "route-pred", version = "1" }
cases = { join = "join" }
default = "join"
[[routes]]
from = "right"
predicate = { id = "route-pred", version = "1" }
cases = { other = "join" }
default = "join"
"#;

const EXCLUSIVE_ROUTE_FAN_IN: &str = r#"
schema_version = 1
[workflow]
id = "exclusive-route-fan-in"
version = "1"
entry = "select"
[[nodes]]
id = "select"
kind = "agent"
[[nodes]]
id = "left"
kind = "agent"
[[nodes]]
id = "right"
kind = "agent"
[[nodes]]
id = "join"
kind = "terminal"
[[edges]]
from = "left"
to = "join"
[[edges]]
from = "right"
to = "join"
[[routes]]
from = "select"
predicate = { id = "route-pred", version = "1" }
cases = { left = "left", right = "right" }
"#;

const BOUNDED_CYCLIC_FAN_IN: &str = r#"
schema_version = 1
[workflow]
id = "bounded-cyclic-fan-in"
version = "1"
entry = "fork"
[[nodes]]
id = "fork"
kind = "action"
max_visits = 2
idempotent = true
[[nodes]]
id = "left"
kind = "agent"
max_visits = 2
[[nodes]]
id = "right"
kind = "agent"
max_visits = 2
[[nodes]]
id = "join"
kind = "action"
max_visits = 2
idempotent = true
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "fork"
to = "left"
[[edges]]
from = "fork"
to = "right"
[[edges]]
from = "left"
to = "join"
[[edges]]
from = "right"
to = "join"
[[edges]]
from = "join"
to = "fork"
[[edges]]
from = "join"
to = "done"
"#;

const BOUNDED_CYCLIC_EXCLUSIVE_FAN_IN: &str = r#"
schema_version = 1
[workflow]
id = "bounded-cyclic-exclusive-fan-in"
version = "1"
entry = "fork"
[[nodes]]
id = "fork"
kind = "agent"
max_visits = 4
[[nodes]]
id = "left"
kind = "agent"
max_visits = 4
[[nodes]]
id = "right"
kind = "agent"
max_visits = 4
[[nodes]]
id = "join"
kind = "agent"
max_visits = 4
[[nodes]]
id = "done"
kind = "terminal"
[[routes]]
from = "fork"
predicate = { id = "route-pred", version = "1" }
cases = { left = "left", right = "right" }
[[edges]]
from = "left"
to = "join"
[[edges]]
from = "right"
to = "join"
[[routes]]
from = "join"
predicate = { id = "route-pred", version = "1" }
cases = { again = "fork", done = "done" }
"#;

const FAILURE_TERMINALS: &str = r#"
schema_version = 1
edges = []
[workflow]
id = "failure-terminals"
version = "1"
entry = "authorization_denied"
[[nodes]]
id = "authorization_denied"
kind = "terminal"
"#;

const INVALID_TERMINAL_OUTPUT: &str = r#"
schema_version = 1
[workflow]
id = "invalid-terminal-output"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "agent"
[[nodes]]
id = "failed"
kind = "terminal"
[[edges]]
from = "start"
to = "failed"
"#;

fn emit_fixture_receipt(selector: &str, probe: &str, assertion: &str) {
    if std::env::var("M1_15_FIXTURE_RECEIPT_SELECTOR").as_deref() == Ok(selector) {
        println!(
            "M1_15_FIXTURE_RECEIPT={}",
            serde_json::to_string(&json!({
                "selector": selector,
                "class": "graph",
                "probe": probe,
                "assertion": assertion,
                "test_count": 1,
                "exit_code": 0,
                "result": "PASS",
            }))
            .expect("fixture receipt serializes")
        );
    }
}

struct AnyPredicate;

impl PredicateRegistry for AnyPredicate {
    type Implementation = ();

    fn resolve(&self, id: &str, version: &str) -> Result<RegistryEntry<'_, ()>, RegistryNotFound> {
        let _ = (id, version);
        const IMPLEMENTATION: () = ();
        Ok(RegistryEntry::new(&IMPLEMENTATION, "route-pred", "1"))
    }
}

struct AnyRuntimeBinding;

impl RuntimePlanRegistry for AnyRuntimeBinding {
    fn resolve(
        &self,
        category: BindingCategory,
        binding: &BindingRef,
    ) -> Result<ResolvedBinding, RegistryResolutionError> {
        let _ = category;
        Ok(ResolvedBinding::new(binding.id(), binding.version()))
    }
}

struct StateAgent {
    name: String,
    response: String,
}

#[async_trait]
impl Agent for StateAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "test state writer"
    }

    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            shared_state: true,
            ..AgentCapabilities::default()
        }
    }

    async fn run(&self, _ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        let mut event = Event::new(&self.name);
        event.set_content(Content::new("assistant").with_text(&self.response));
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])))
    }
}

fn state_agent(name: &str, state: serde_json::Value) -> Arc<dyn Agent> {
    Arc::new(StateAgent {
        name: name.to_owned(),
        response: json!({"state": state}).to_string(),
    })
}

struct InvalidOutputAgent;

#[async_trait]
impl Agent for InvalidOutputAgent {
    fn name(&self) -> &str {
        "start"
    }

    fn description(&self) -> &str {
        "invalid output fixture"
    }

    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            shared_state: true,
            ..AgentCapabilities::default()
        }
    }

    async fn run(&self, _ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(Event::new(
            "invalid-output",
        ))])))
    }
}

struct SequenceAgent {
    name: String,
    responses: Vec<String>,
    next: AtomicUsize,
}

#[async_trait]
impl Agent for SequenceAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "test route sequence"
    }

    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            shared_state: true,
            ..AgentCapabilities::default()
        }
    }

    async fn run(&self, _ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let response = self
            .responses
            .get(index)
            .or_else(|| self.responses.last())
            .expect("route sequence has a response");
        let mut event = Event::new(&self.name);
        event.set_content(Content::new("assistant").with_text(response));
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])))
    }
}

fn sequence_agent(name: &str, responses: &[&str]) -> Arc<dyn Agent> {
    Arc::new(SequenceAgent {
        name: name.to_owned(),
        responses: responses
            .iter()
            .map(|response| (*response).to_owned())
            .collect(),
        next: AtomicUsize::new(0),
    })
}

fn resolved_plan(ir: &workflow_ir::WorkflowIr, capabilities: CapabilitySet) -> ResolvedRuntimePlan {
    let mut request = RuntimePlanRequest::from_ir(ir);
    request.set_capabilities(capabilities.clone());
    request.set_effective_capabilities(capabilities);
    ResolvedRuntimePlan::resolve(request, &AnyRuntimeBinding).expect("runtime plan resolves")
}

#[tokio::test]
async fn translates_and_executes_sequential_plan_through_adk() {
    let plan = compile_str("sequential.workflow.toml", SEQUENTIAL).expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");
    assert_eq!(graph.node_order(), vec!["action", "agent", "done"]);
    let state = graph
        .invoke(State::new(), ExecutionConfig::new("test-run"))
        .await
        .expect("fake ADK graph executes");
    assert_eq!(state.get("terminal"), Some(&json!("done")));
    assert_eq!(
        graph.terminal_outcome("done"),
        None,
        "arbitrary terminal node IDs are not stable terminal outcomes"
    );
}

#[tokio::test]
async fn production_graph_maps_real_adk_event_into_project_record() {
    let plan = compile_str("observed.workflow.toml", SEQUENTIAL).expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");
    let mut mapper = AdkEventMapper::new("run-observed", "sequential").unwrap();
    let mut artifacts = InMemoryArtifactStore::new(
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
    );

    let state = graph
        .invoke_observed(
            State::new(),
            ExecutionConfig::new("observed-run"),
            &mut mapper,
            &mut artifacts,
        )
        .await
        .expect("production ADK stream is observed");

    assert_eq!(state.get("terminal"), Some(&json!("done")));
    assert_eq!(mapper.events().len(), 8);
    assert_eq!(
        mapper
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        vec![
            WorkflowRuntimeEventKindV1::NodeStarted,
            WorkflowRuntimeEventKindV1::NodeCompleted,
            WorkflowRuntimeEventKindV1::ModelRequestCompleted,
            WorkflowRuntimeEventKindV1::NodeStarted,
            WorkflowRuntimeEventKindV1::NodeCompleted,
            WorkflowRuntimeEventKindV1::NodeStarted,
            WorkflowRuntimeEventKindV1::NodeCompleted,
            WorkflowRuntimeEventKindV1::WorkflowCompleted,
        ]
    );
    let model = &mapper.events()[2];
    assert_eq!(model.node_id(), Some("agent"));
    assert_eq!(model.payload()["structured_output"]["role"], "assistant");
    let persisted = serde_json::to_string(model).unwrap();
    assert!(persisted.contains("ok"));
    assert!(!persisted.contains("adk_rust"));
}

#[test]
fn translation_surface_contains_no_adk_types_in_persisted_summary() {
    let plan = compile_str("summary.workflow.toml", SEQUENTIAL).expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");
    let summary = serde_json::to_string(&graph.summary()).expect("summary serializes");
    assert!(!summary.contains("adk_rust"));
    assert_eq!(graph.summary().node_order, vec!["action", "agent", "done"]);
}

#[tokio::test]
async fn bounded_cycle_honors_max_visits_not_adk_default() {
    let plan = compile_str("bounded-cycle.workflow.toml", BOUNDED_CYCLE).expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");
    let err = graph
        .invoke(State::new(), ExecutionConfig::new("cycle"))
        .await
        .expect_err("bounded cycle must stop at IR max_visits");
    let rendered = err.to_string();
    assert_eq!(
        rendered, "visit bound exceeded: max_visits=2",
        "project diagnostic must retain IR max_visits=2, got {rendered}"
    );
    assert!(
        !rendered.contains("50"),
        "must not rely on ADK default recursion_limit, got {rendered}"
    );
}

#[test]
fn unbounded_cycle_is_rejected_before_adk_translation() {
    let error = compile_str("unbounded-cycle.workflow.toml", UNBOUNDED_CYCLE)
        .expect_err("an unbounded cycle must be rejected before ADK translation");
    assert!(
        error.to_string().contains("cycle"),
        "unbounded-cycle diagnostic must name the rejected cycle: {error}"
    );
}

#[test]
fn fan_in_without_shared_state_translates() {
    let plan = compile_str(
        "fan-in-without-shared-state.workflow.toml",
        FAN_IN_WITHOUT_SHARED_STATE,
    )
    .expect("state-free fan-in fixture compiles");
    AdkGraphTranslator::new()
        .translate(&plan)
        .expect("a join without shared state must translate");
}

#[tokio::test]
async fn fan_in_same_key_writes_fail_closed_before_merge() {
    let plan = compile_str(
        "fan-in-same-key-writes.workflow.toml",
        FAN_IN_DECLARED_STATE_WITH_ZERO_WRITES,
    )
    .expect("fixture compiles");
    let agents = BTreeMap::from([
        (
            "left".to_owned(),
            state_agent("left", json!({"shared": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"shared": "right"})),
        ),
    ]);
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .expect("translation defers dynamic write-set validation until invocation");

    let error = graph
        .invoke(State::new(), ExecutionConfig::new("fan-in-overlap"))
        .await
        .expect_err("same-key branch writes require an explicit merge policy");
    assert_eq!(
        error.to_string(),
        "fan-in state conflict at \"join\" for key \"shared\""
    );
}

#[tokio::test]
async fn fan_in_disjoint_key_writes_execute() {
    let plan = compile_str(
        "fan-in-disjoint-key-writes.workflow.toml",
        FAN_IN_DECLARED_STATE_WITH_DISJOINT_KEYS,
    )
    .expect("fixture compiles");
    let agents = BTreeMap::from([
        (
            "left".to_owned(),
            state_agent("left", json!({"left": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"right": "right"})),
        ),
    ]);
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .expect("disjoint write fixture translates");

    let state = graph
        .invoke(State::new(), ExecutionConfig::new("fan-in-disjoint"))
        .await
        .expect("disjoint writes are merged by the kit-owned join guard");
    assert_eq!(state.get("left"), Some(&json!("left")));
    assert_eq!(state.get("right"), Some(&json!("right")));
}

#[tokio::test]
async fn multi_hop_fan_in_same_key_writes_fail_closed_before_merge() {
    let plan =
        compile_str("multi-hop-fan-in.workflow.toml", MULTI_HOP_FAN_IN).expect("fixture compiles");
    let agents = BTreeMap::from([
        (
            "left_writer".to_owned(),
            state_agent("left_writer", json!({"shared": "left"})),
        ),
        (
            "right_writer".to_owned(),
            state_agent("right_writer", json!({"shared": "right"})),
        ),
    ]);
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .expect("multi-hop fan-in translates");

    let error = graph
        .invoke(
            State::new(),
            ExecutionConfig::new("multi-hop-fan-in-overlap"),
        )
        .await
        .expect_err("same-key writer provenance must reach the downstream join guard");
    assert_eq!(
        error.to_string(),
        "fan-in state conflict at \"join\" for key \"shared\""
    );
}

#[tokio::test]
async fn multi_hop_fan_in_disjoint_key_writes_execute() {
    let plan =
        compile_str("multi-hop-fan-in.workflow.toml", MULTI_HOP_FAN_IN).expect("fixture compiles");
    let agents = BTreeMap::from([
        (
            "left_writer".to_owned(),
            state_agent("left_writer", json!({"left": "left"})),
        ),
        (
            "right_writer".to_owned(),
            state_agent("right_writer", json!({"right": "right"})),
        ),
    ]);
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .expect("multi-hop fan-in translates");

    let state = graph
        .invoke(
            State::new(),
            ExecutionConfig::new("multi-hop-fan-in-disjoint"),
        )
        .await
        .expect("disjoint writer provenance must reach the downstream join guard");
    assert_eq!(state.get("left"), Some(&json!("left")));
    assert_eq!(state.get("right"), Some(&json!("right")));
}

#[tokio::test]
async fn route_fan_in_same_key_writes_fail_closed_before_merge() {
    let plan =
        compile_str_with_predicates("route-fan-in.workflow.toml", ROUTE_FAN_IN, &AnyPredicate)
            .expect("fixture compiles");
    let agents = BTreeMap::from([
        (
            "left".to_owned(),
            state_agent("left", json!({"shared": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"shared": "right"})),
        ),
    ]);
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .expect("route fan-in translates");
    let mut state = State::new();
    state.insert("route:left".to_owned(), json!("join"));

    let error = graph
        .invoke(state, ExecutionConfig::new("route-fan-in-overlap"))
        .await
        .expect_err("same-key route fan-in writes require an explicit merge policy");
    assert_eq!(
        error.to_string(),
        "fan-in state conflict at \"join\" for key \"shared\""
    );
}

#[tokio::test]
async fn route_fan_in_disjoint_key_writes_execute() {
    let plan =
        compile_str_with_predicates("route-fan-in.workflow.toml", ROUTE_FAN_IN, &AnyPredicate)
            .expect("fixture compiles");
    let agents = BTreeMap::from([
        (
            "left".to_owned(),
            state_agent("left", json!({"left": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"right": "right"})),
        ),
    ]);
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .expect("route fan-in translates");
    let mut state = State::new();
    state.insert("route:left".to_owned(), json!("join"));

    let state = graph
        .invoke(state, ExecutionConfig::new("route-fan-in-disjoint"))
        .await
        .expect("disjoint route fan-in writes are merged by the kit-owned join guard");
    assert_eq!(state.get("left"), Some(&json!("left")));
    assert_eq!(state.get("right"), Some(&json!("right")));
}

#[tokio::test]
async fn exclusive_fan_in_activations_traverse_the_guard_without_cross_activation_conflict() {
    let plan = compile_str_with_predicates(
        "exclusive-route-fan-in.workflow.toml",
        EXCLUSIVE_ROUTE_FAN_IN,
        &AnyPredicate,
    )
    .expect("exclusive fixture compiles");
    let agents = BTreeMap::from([
        ("select".to_owned(), sequence_agent("select", &["unused"])),
        (
            "left".to_owned(),
            state_agent("left", json!({"shared": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"shared": "right"})),
        ),
    ]);
    let checkpointer = Arc::new(MemoryCheckpointer::default());
    let graph = AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &plan,
            &agents,
            None,
            &json!({}),
            Some(checkpointer.clone()),
        )
        .expect("exclusive fan-in translates");
    let mut artifacts = InMemoryArtifactStore::new(
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
    );

    for (activation, branch, expected) in [("left", "left", "left"), ("right", "right", "right")] {
        let mut state = State::new();
        state.insert("route:select".to_owned(), json!(branch));
        let mut mapper =
            AdkEventMapper::new(format!("exclusive-{activation}"), "exclusive-route-fan-in")
                .expect("event mapper starts");
        let state = graph
            .invoke_observed(
                state,
                ExecutionConfig::new(&format!("exclusive-{activation}")),
                &mut mapper,
                &mut artifacts,
            )
            .await
            .expect("each exclusive activation reaches the join guard");
        assert_eq!(state.get("shared"), Some(&json!(expected)));
        let checkpoint = checkpointer
            .load(&format!("exclusive-{activation}"))
            .await
            .expect("test Checkpointer loads")
            .expect("each activation saves a checkpoint");
        assert!(
            checkpoint
                .state
                .keys()
                .all(|key| !key.starts_with("__workflow_fanin:")),
            "completed join provenance must not cross into the next activation"
        );
    }
}

#[tokio::test]
async fn exclusive_fan_in_checkpoint_state_resumes_without_stale_same_key_provenance() {
    let plan = compile_str_with_predicates(
        "exclusive-route-fan-in.workflow.toml",
        EXCLUSIVE_ROUTE_FAN_IN,
        &AnyPredicate,
    )
    .expect("exclusive checkpoint fixture compiles");
    let agents = BTreeMap::from([
        ("select".to_owned(), sequence_agent("select", &["unused"])),
        (
            "left".to_owned(),
            state_agent("left", json!({"shared": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"shared": "right"})),
        ),
    ]);
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .expect("exclusive checkpoint fan-in translates");

    let mut checkpoint_state = State::new();
    checkpoint_state.insert("route:select".to_owned(), json!("left"));
    let checkpoint_state = graph
        .invoke(checkpoint_state, ExecutionConfig::new("checkpoint-left"))
        .await
        .expect("left checkpoint visit succeeds");
    assert!(
        checkpoint_state
            .keys()
            .all(|key| !key.starts_with("__workflow_fanin:")),
        "checkpoint state must not retain internal fan-in provenance"
    );

    let mut resumed_state = checkpoint_state;
    resumed_state.insert("route:select".to_owned(), json!("right"));
    let resumed_state = graph
        .invoke(resumed_state, ExecutionConfig::new("resume-right"))
        .await
        .expect("resumed right visit succeeds without stale left provenance");
    assert_eq!(resumed_state.get("shared"), Some(&json!("right")));
}

#[tokio::test]
async fn exclusive_fan_in_checkpoints_consume_provenance_before_real_resume() {
    let plan = compile_str_with_predicates(
        "exclusive-route-fan-in.workflow.toml",
        EXCLUSIVE_ROUTE_FAN_IN,
        &AnyPredicate,
    )
    .expect("exclusive checkpoint fixture compiles");
    let agents = BTreeMap::from([
        ("select".to_owned(), sequence_agent("select", &["left"])),
        (
            "left".to_owned(),
            state_agent("left", json!({"shared": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"shared": "right"})),
        ),
    ]);
    let checkpointer = Arc::new(MemoryCheckpointer::default());
    let graph = AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &plan,
            &agents,
            None,
            &json!({}),
            Some(checkpointer.clone()),
        )
        .expect("exclusive checkpoint fan-in translates");
    let mut mapper = AdkEventMapper::new("checkpoint-left", "exclusive-route-fan-in").unwrap();
    let mut artifacts = InMemoryArtifactStore::new(
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
    );

    let state = graph
        .invoke_observed(
            State::new(),
            ExecutionConfig::new("checkpoint-left"),
            &mut mapper,
            &mut artifacts,
        )
        .await
        .expect("exclusive left activation succeeds");
    assert_eq!(state.get("shared"), Some(&json!("left")));
    let checkpoint = checkpointer
        .load("checkpoint-left")
        .await
        .expect("test Checkpointer loads")
        .expect("graph saves a checkpoint through the real Checkpointer");
    assert!(
        checkpoint
            .state
            .keys()
            .all(|key| !key.starts_with("__workflow_fanin:")),
        "completed join provenance must not enter durable checkpoint state"
    );

    let mut resumed_mapper = AdkEventMapper::resume(
        "checkpoint-left",
        "exclusive-route-fan-in",
        mapper.events().to_vec(),
    )
    .expect("event mapper resumes");
    let resumed = graph
        .invoke_observed(
            State::new(),
            ExecutionConfig::new("checkpoint-left").with_resume_from(&checkpoint.checkpoint_id),
            &mut resumed_mapper,
            &mut artifacts,
        )
        .await
        .expect("durable checkpoint resumes without fan-in provenance");
    assert_eq!(resumed.get("shared"), Some(&json!("left")));
}

#[tokio::test]
async fn mid_fan_in_checkpoints_preserve_disjoint_writes_and_conflicts_until_guard() {
    let disjoint_plan = compile_str(
        "fan-in-disjoint-checkpoint.workflow.toml",
        &FAN_IN_DECLARED_STATE_WITH_DISJOINT_KEYS.replace("kind = \"action\"", "kind = \"agent\""),
    )
    .expect("disjoint checkpoint fixture compiles");
    let disjoint_agents = BTreeMap::from([
        ("start".to_owned(), state_agent("start", json!({}))),
        (
            "left".to_owned(),
            state_agent("left", json!({"left": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"right": "right"})),
        ),
    ]);
    let disjoint_checkpointer = Arc::new(MemoryCheckpointer::default());
    let disjoint_graph = AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &disjoint_plan,
            &disjoint_agents,
            None,
            &json!({}),
            Some(disjoint_checkpointer.clone()),
        )
        .expect("disjoint checkpoint graph translates");
    let state = disjoint_graph
        .invoke(
            State::new(),
            ExecutionConfig::new("fan-in-disjoint-checkpoint"),
        )
        .await
        .expect("disjoint fan-in executes before resume");
    assert_eq!(state.get("left"), Some(&json!("left")));
    assert_eq!(state.get("right"), Some(&json!("right")));
    let checkpoint = disjoint_checkpointer
        .list("fan-in-disjoint-checkpoint")
        .await
        .expect("test Checkpointer lists mid-fan-in checkpoints")
        .into_iter()
        .find(|checkpoint| {
            checkpoint
                .state
                .keys()
                .any(|key| key.starts_with("__workflow_fanin:join:"))
        })
        .expect("checkpoint after branch writes retains pending fan-in provenance");
    let resumed = disjoint_graph
        .invoke(
            State::new(),
            ExecutionConfig::new("fan-in-disjoint-checkpoint")
                .with_resume_from(&checkpoint.checkpoint_id),
        )
        .await
        .expect("mid-fan-in checkpoint resumes through the join guard");
    assert_eq!(resumed.get("left"), Some(&json!("left")));
    assert_eq!(resumed.get("right"), Some(&json!("right")));
    assert!(
        resumed
            .keys()
            .all(|key| !key.starts_with("__workflow_fanin:")),
        "join consumption removes completed provenance from returned state"
    );

    let conflict_plan = compile_str(
        "fan-in-conflict-checkpoint.workflow.toml",
        &FAN_IN_DECLARED_STATE_WITH_ZERO_WRITES.replace("kind = \"action\"", "kind = \"agent\""),
    )
    .expect("conflict checkpoint fixture compiles");
    let conflict_agents = BTreeMap::from([
        ("start".to_owned(), state_agent("start", json!({}))),
        (
            "left".to_owned(),
            state_agent("left", json!({"shared": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"shared": "right"})),
        ),
    ]);
    let conflict_checkpointer = Arc::new(MemoryCheckpointer::default());
    let conflict_graph = AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &conflict_plan,
            &conflict_agents,
            None,
            &json!({}),
            Some(conflict_checkpointer.clone()),
        )
        .expect("conflict checkpoint graph translates");
    let _ = conflict_graph
        .invoke(
            State::new(),
            ExecutionConfig::new("fan-in-conflict-checkpoint"),
        )
        .await
        .expect_err("same-key writes fail after the live guard receives both branches");
    let checkpoint = conflict_checkpointer
        .list("fan-in-conflict-checkpoint")
        .await
        .expect("test Checkpointer lists conflict checkpoints")
        .into_iter()
        .find(|checkpoint| {
            checkpoint
                .state
                .keys()
                .any(|key| key.starts_with("__workflow_fanin:join:"))
        })
        .expect("checkpoint before the guard retains conflicting branch provenance");
    let error = conflict_graph
        .invoke(
            State::new(),
            ExecutionConfig::new("fan-in-conflict-checkpoint")
                .with_resume_from(&checkpoint.checkpoint_id),
        )
        .await
        .expect_err("resumed guard must retain same-key conflict evidence");
    assert_eq!(
        error.to_string(),
        "fan-in state conflict at \"join\" for key \"shared\""
    );
}

#[tokio::test]
async fn bounded_cyclic_fork_fan_in_same_key_writes_fail_closed() {
    let plan = compile_str("bounded-cyclic-fan-in.workflow.toml", BOUNDED_CYCLIC_FAN_IN)
        .expect("bounded cyclic fixture compiles");
    let agents = BTreeMap::from([
        (
            "left".to_owned(),
            state_agent("left", json!({"shared": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"shared": "right"})),
        ),
    ]);
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .expect("bounded cyclic fan-in translates");

    let error = graph
        .invoke(State::new(), ExecutionConfig::new("bounded-cyclic-fan-in"))
        .await
        .expect_err("cyclic fork writes must reach the join guard");
    assert_eq!(
        error.to_string(),
        "fan-in state conflict at \"join\" for key \"shared\""
    );
}

#[tokio::test]
async fn bounded_cyclic_exclusive_fan_in_keeps_activation_provenance_isolated() {
    let plan = compile_str_with_predicates(
        "bounded-cyclic-exclusive-fan-in.workflow.toml",
        BOUNDED_CYCLIC_EXCLUSIVE_FAN_IN,
        &AnyPredicate,
    )
    .expect("bounded cyclic exclusive fixture compiles");
    let agents = BTreeMap::from([
        (
            "fork".to_owned(),
            sequence_agent("fork", &["left", "right"]),
        ),
        (
            "left".to_owned(),
            state_agent("left", json!({"shared": "left"})),
        ),
        (
            "right".to_owned(),
            state_agent("right", json!({"shared": "right"})),
        ),
        (
            "join".to_owned(),
            sequence_agent("join", &["again", "done"]),
        ),
    ]);
    let checkpointer = Arc::new(MemoryCheckpointer::default());
    let graph = AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &plan,
            &agents,
            None,
            &json!({}),
            Some(checkpointer.clone()),
        )
        .expect("bounded cyclic exclusive fan-in translates");

    let state = graph
        .invoke(
            State::new(),
            ExecutionConfig::new("bounded-cyclic-exclusive-fan-in"),
        )
        .await
        .expect("alternating exclusive branches do not cross-reject");
    assert_eq!(state.get("terminal"), Some(&json!("done")));
    assert_eq!(state.get("shared"), Some(&json!("right")));
    assert!(
        checkpointer
            .list("bounded-cyclic-exclusive-fan-in")
            .await
            .expect("test Checkpointer lists cyclic activation checkpoints")
            .iter()
            .any(|checkpoint| {
                checkpoint
                    .state
                    .keys()
                    .any(|key| key.starts_with("__workflow_fanin:join:"))
            }),
        "each cyclic activation retains its provenance until its join guard consumes it"
    );
}

#[test]
fn fan_in_declared_state_with_zero_writes_translates() {
    let plan = compile_str(
        "fan-in-declared-state-with-zero-writes.workflow.toml",
        FAN_IN_DECLARED_STATE_WITH_ZERO_WRITES,
    )
    .expect("declared-state fixture compiles");
    AdkGraphTranslator::new()
        .translate(&plan)
        .expect("a state declaration is not fan-in write-conflict evidence");
}

#[test]
fn fan_in_declared_state_with_disjoint_keys_translates() {
    let plan = compile_str(
        "fan-in-declared-state-with-disjoint-keys.workflow.toml",
        FAN_IN_DECLARED_STATE_WITH_DISJOINT_KEYS,
    )
    .expect("declared-state fixture compiles");
    AdkGraphTranslator::new()
        .translate(&plan)
        .expect("disjoint declared keys are not fan-in write-conflict evidence");
}

#[test]
fn terminal_outcome_maps_failure_terminals_without_success_fallback() {
    let plan = compile_str("failure-terminals.workflow.toml", FAILURE_TERMINALS)
        .expect("failure terminal fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("failure terminal fixture translates");
    for expected in TerminalOutcome::ALL {
        let id = expected.as_str();
        let fixture = FAILURE_TERMINALS.replace("authorization_denied", id);
        let plan = compile_str("failure-terminals.workflow.toml", &fixture)
            .expect("failure terminal fixture compiles");
        let graph = AdkGraphTranslator::new()
            .translate(&plan)
            .expect("failure terminal fixture translates");
        assert_eq!(graph.terminal_outcome(id), Some(expected), "{id}");
    }
    assert_eq!(graph.terminal_outcome("unknown_terminal"), None);
}

#[tokio::test]
async fn terminal_invalid_output_fixture_reaches_failed_terminal_without_publication() {
    let plan = compile_str(
        "invalid-terminal-output.workflow.toml",
        INVALID_TERMINAL_OUTPUT,
    )
    .expect("failure terminal fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(
            &plan,
            &BTreeMap::from([(
                "start".to_owned(),
                Arc::new(InvalidOutputAgent) as Arc<dyn Agent>,
            )]),
        )
        .expect("failure terminal fixture translates");
    let mut mapper = AdkEventMapper::new("invalid-terminal-output", "invalid-terminal-output")
        .expect("event mapper starts");
    let mut artifacts = InMemoryArtifactStore::new(
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
    );
    assert_eq!(
        graph.terminal_outcome("failed"),
        Some(TerminalOutcome::Failed)
    );
    assert_eq!(
        graph
            .invoke_observed(
                State::new(),
                ExecutionConfig::new("invalid-terminal-output"),
                &mut mapper,
                &mut artifacts,
            )
            .await
            .expect_err("invalid terminal output must fail before publication"),
        AdkGraphError::InvalidOutput {
            node: "start".to_owned()
        }
    );
    assert!(
        mapper.events().iter().all(|event| {
            !matches!(
                event.kind(),
                WorkflowRuntimeEventKindV1::WorkflowCompleted
                    | WorkflowRuntimeEventKindV1::ArtifactCommitted
            )
        }),
        "invalid output must not publish a terminal or artifact"
    );
    emit_fixture_receipt(
        "workflow-adk --test translation terminal_invalid_output_fixture_reaches_failed_terminal_without_publication",
        "terminal node reached with invalid output",
        "invalid terminal output reaches the failed terminal without publication",
    );
}

#[tokio::test]
async fn unknown_route_fails_closed_with_project_diagnostic() {
    let plan =
        compile_str_with_predicates("unknown-route.workflow.toml", UNKNOWN_ROUTE, &AnyPredicate)
            .expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");
    let missing = graph
        .invoke(State::new(), ExecutionConfig::new("missing-route"))
        .await
        .expect_err("missing selector must fail closed");
    let missing_rendered = missing.to_string();
    assert!(
        !missing_rendered.contains("__unknown__"),
        "must not use silent __unknown__ selector, got {missing_rendered}"
    );
    assert!(
        !missing_rendered.contains("Router returned") && !missing_rendered.contains("Declared:"),
        "must use a project diagnostic, not raw GraphError, got {missing_rendered}"
    );

    let mut unmatched = State::new();
    unmatched.insert("route:decide".to_owned(), json!("nope"));
    let unmatched_err = graph
        .invoke(unmatched, ExecutionConfig::new("unknown"))
        .await
        .expect_err("unknown route must fail closed");
    let rendered = unmatched_err.to_string();
    assert!(
        !rendered.contains("__unknown__")
            && !rendered.contains("Router returned")
            && !rendered.contains("Declared:")
            && !rendered.contains("adk_rust"),
        "stable project diagnostic for unmatched selector, got {rendered}"
    );
    assert!(
        rendered.contains("nope") || rendered.contains("unknown"),
        "project diagnostic must name the unmatched route, got {rendered}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_unknown_route_invokes_keep_diagnostics_isolated() {
    let plan =
        compile_str_with_predicates("unknown-route.workflow.toml", UNKNOWN_ROUTE, &AnyPredicate)
            .expect("fixture compiles");
    let graph = std::sync::Arc::new(
        AdkGraphTranslator::new()
            .translate(&plan)
            .expect("translation succeeds"),
    );

    for _ in 0..100 {
        let mut first_state = State::new();
        first_state.insert("route:decide".to_owned(), json!("first-missing"));
        let mut second_state = State::new();
        second_state.insert("route:decide".to_owned(), json!("second-missing"));
        let first_graph = std::sync::Arc::clone(&graph);
        let second_graph = std::sync::Arc::clone(&graph);
        let (first, second) = tokio::join!(
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                first_graph
                    .invoke(first_state, ExecutionConfig::new("first-unknown"))
                    .await
            }),
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                second_graph
                    .invoke(second_state, ExecutionConfig::new("second-unknown"))
                    .await
            }),
        );

        let first = first
            .expect("first invoke task completes")
            .expect_err("first unknown route must fail closed");
        let second = second
            .expect("second invoke task completes")
            .expect_err("second unknown route must fail closed");
        assert_eq!(
            first.to_string(),
            "unknown route from \"decide\" selector \"first-missing\""
        );
        assert_eq!(
            second.to_string(),
            "unknown route from \"decide\" selector \"second-missing\""
        );
    }
}

#[tokio::test]
async fn conditional_plan_executes_cases_and_ir_default_fallback() {
    let plan = compile_str_with_predicates("conditional.workflow.toml", CONDITIONAL, &AnyPredicate)
        .expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");
    assert_eq!(graph.node_order(), vec!["decide", "fallback", "left"]);

    let mut matched = State::new();
    matched.insert("route:decide".to_owned(), json!("left"));
    let matched_state = graph
        .invoke(matched, ExecutionConfig::new("matched"))
        .await
        .expect("matched case executes");
    assert_eq!(matched_state.get("terminal"), Some(&json!("left")));

    let mut unmatched = State::new();
    unmatched.insert("route:decide".to_owned(), json!("nope"));
    let fallback_state = graph
        .invoke(unmatched, ExecutionConfig::new("fallback"))
        .await
        .expect("IR default is fallback, not a literal default case key");
    assert_eq!(fallback_state.get("terminal"), Some(&json!("fallback")));
}

#[tokio::test]
async fn translated_agent_output_selects_conditional_edge() {
    let plan = compile_str_with_predicates(
        "agent-selected-route.workflow.toml",
        AGENT_SELECTED_ROUTE,
        &AnyPredicate,
    )
    .expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");

    let state = graph
        .invoke(State::new(), ExecutionConfig::new("agent-selected-route"))
        .await
        .expect("the agent's text output selects a declared route");
    assert_eq!(state.get("node:decide"), Some(&json!("ok")));
    assert_eq!(state.get("terminal"), Some(&json!("left")));
}

#[tokio::test]
async fn bounded_cycle_visit_budget_resets_for_each_invoke() {
    let plan =
        compile_str("bounded-invoke.workflow.toml", BOUNDED_INVOKE).expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");

    for run in ["first", "second"] {
        let state = graph
            .invoke(State::new(), ExecutionConfig::new(run))
            .await
            .expect("each invoke must receive a fresh visit counter");
        assert_eq!(state.get("visits:loop"), Some(&json!(1)));
    }
}

#[test]
fn resolved_plan_identity_and_capabilities_are_bound_to_graph() {
    let compiled = compile_str("resolved.workflow.toml", SEQUENTIAL).expect("fixture compiles");
    let first_plan = resolved_plan(compiled.ir(), CapabilitySet::from(["read"]));
    let second_plan = resolved_plan(compiled.ir(), CapabilitySet::from(["read", "network"]));
    let translator = AdkGraphTranslator::new();
    let first = translator
        .translate_resolved(&first_plan, compiled.ir())
        .expect("first translation succeeds");
    let second = translator
        .translate_resolved(&second_plan, compiled.ir())
        .expect("second translation succeeds");

    assert_eq!(first.plan_hash(), Some(first_plan.plan_hash()));
    assert_eq!(first.effective_capabilities(), vec!["read"]);
    assert_ne!(first.plan_hash(), second.plan_hash());
    assert_eq!(second.effective_capabilities(), vec!["network", "read"]);
}

#[test]
fn resolved_plan_rejects_ir_hash_mismatch() {
    let compiled = compile_str("resolved.workflow.toml", SEQUENTIAL).expect("fixture compiles");
    let other = compile_str("other.workflow.toml", OTHER_WORKFLOW).expect("fixture compiles");
    let plan = resolved_plan(compiled.ir(), CapabilitySet::from(["read"]));

    let error = match AdkGraphTranslator::new().translate_resolved(&plan, other.ir()) {
        Ok(_) => panic!("a plan resolved for another IR must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        TranslationError::ResolvedPlanMismatch { .. }
    ));
}
