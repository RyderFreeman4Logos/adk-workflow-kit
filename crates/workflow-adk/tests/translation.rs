use adk_rust::graph::prelude::{ExecutionConfig, State};
use serde_json::json;
use workflow_adk::{AdkGraphTranslator, TerminalOutcome};
use workflow_compiler::{
    PredicateRegistry, RegistryEntry, RegistryNotFound, compile_str, compile_str_with_predicates,
};

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

struct AnyPredicate;

impl PredicateRegistry for AnyPredicate {
    type Implementation = ();

    fn resolve(&self, id: &str, version: &str) -> Result<RegistryEntry<'_, ()>, RegistryNotFound> {
        let _ = (id, version);
        const IMPLEMENTATION: () = ();
        Ok(RegistryEntry::new(&IMPLEMENTATION, "route-pred", "1"))
    }
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
        Some(TerminalOutcome::Succeeded)
    );
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
    assert!(
        rendered.contains('2'),
        "cycle-count evidence must be the IR bound, got {rendered}"
    );
    assert!(
        !rendered.contains("50"),
        "must not rely on ADK default recursion_limit, got {rendered}"
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
