use adk_rust::graph::prelude::{ExecutionConfig, State};
use serde_json::json;
use workflow_adk::events::AdkEventMapper;
use workflow_adk::{AdkGraphTranslator, TerminalOutcome, TranslationError};
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

const FAN_IN_SHARED_STATE: &str = r#"
schema_version = 1
[workflow]
id = "fan-in-shared-state"
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

fn resolved_plan(ir: &workflow_ir::WorkflowIr, capabilities: CapabilitySet) -> ResolvedRuntimePlan {
    let mut request = RuntimePlanRequest::from_ir(ir).with_model("fake-model", "1");
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

#[test]
fn fan_in_shared_state_without_merge_policy_is_rejected() {
    let plan = compile_str("fan-in-shared-state.workflow.toml", FAN_IN_SHARED_STATE)
        .expect("shared-state fan-in fixture compiles");
    assert!(
        matches!(
            AdkGraphTranslator::new().translate(&plan),
            Err(TranslationError::FanInStateConflict { .. })
        ),
        "a shared-state fan-in without a merge policy must be rejected"
    );
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
