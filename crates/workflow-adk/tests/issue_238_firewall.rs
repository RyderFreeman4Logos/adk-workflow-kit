use adk_rust::graph::prelude::{ExecutionConfig, State};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use workflow_adk::{AdkGraphError, AdkGraphTranslator, firewall::FirewallInvocation};
use workflow_compiler::compile_str;
use workflow_runtime::{FirewallDecision, argument_fingerprint, firewall::*};

fn invocation(admission: &str, tool: &str) -> FirewallInvocation {
    let policy: FirewallPolicy = serde_json::from_value(json!({
        "schema_version":1,"version":"1","tools":{"noop":{
            "version":"1","capabilities":[],"scopes":["fake"],"destinations":["local"],
            "effect":"none","admission":admission,"arguments":{},
            "scope":{"kind":"literal","value":"fake"},
            "destination":{"kind":"literal","value":"local"},
            "resource":{"kind":"literal","value":"service"}}},
        "targets":[{"scope":"fake","destination":"local","resource":"service",
            "version":{"schema_version":1,"revision":"1"}}],"forbidden_markers":[]
    }))
    .unwrap();
    let goal: TrustedGoal =
        serde_json::from_value(json!({"schema_version":1,"id":"goal","version":"1",
        "capabilities":[],"scopes":["fake"],"destinations":["local"]}))
        .unwrap();
    let proposal: ToolProposal = serde_json::from_value(json!({"schema_version":1,
        "intent":{"schema_version":1,"goal_id":"goal","tool_id":tool,"tool_version":"1",
            "capabilities":[],"scope":"fake","destination":"local","resource":"service",
            "effect":{"schema_version":1,"class":"none"},"target_version":{"schema_version":1,"revision":"1"}},
        "arguments":{},"provenance":{"source_digest":"a".repeat(64),
            "arguments_digest":argument_fingerprint(&json!({})),"trust_domain":"untrusted_content"}
    })).unwrap();
    FirewallInvocation::new(policy, goal, proposal)
}
fn source(identity: &str) -> String {
    format!(
        r#"schema_version = 1
[workflow]
id = "firewall-test"
version = "1"
entry = "gate"
[[nodes]]
id = "gate"
kind = "validator"
firewall = {{ schema_version = 1, identity = "{identity}" }}
[[nodes]]
id = "judge"
kind = "agent"
model = {{ role = "worker", id = "synthetic", version = "1" }}
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "gate"
to = "judge"
[[edges]]
from = "judge"
to = "done"
"#
    )
}
#[tokio::test]
async fn observed_gate_emits_typed_privacy_safe_telemetry_before_terminal_denial() {
    use workflow_adk::events::AdkEventMapper;
    use workflow_runtime::{InMemoryArtifactStore, WorkflowRuntimeEventKindV1};
    for (admission, tool, kind) in [
        (
            "low_risk",
            "unknown",
            WorkflowRuntimeEventKindV1::ToolDenied,
        ),
        (
            "human_approval",
            "noop",
            WorkflowRuntimeEventKindV1::ApprovalRequested,
        ),
    ] {
        let bound = invocation(admission, tool);
        let plan = compile_str("firewall.toml", &source(&bound.identity())).unwrap();
        let agents = BTreeMap::from([(
            "judge".into(),
            Arc::new(PanicJudge) as Arc<dyn adk_rust::Agent>,
        )]);
        let graph = AdkGraphTranslator::new()
            .translate_with_firewall(&plan, bound, &agents)
            .unwrap();
        let mut mapper = AdkEventMapper::new("fw-observed", "firewall-test").unwrap();
        let limit = std::num::NonZeroU64::new(65536).unwrap();
        let mut artifacts = InMemoryArtifactStore::new(limit, limit);
        assert_eq!(
            graph
                .invoke_observed(
                    State::new(),
                    ExecutionConfig::new("fw-observed"),
                    &mut mapper,
                    &mut artifacts
                )
                .await
                .unwrap_err(),
            AdkGraphError::AuthorizationDenied
        );
        let event = mapper
            .events()
            .iter()
            .find(|event| event.kind() == kind)
            .expect("typed policy telemetry");
        assert_eq!(event.node_id(), Some("gate"));
        assert_eq!(
            event.payload()["structured_output"]["firewall"]["node"],
            json!("firewall")
        );
        assert!(mapper.events().iter().all(|event| !matches!(
            event.kind(),
            WorkflowRuntimeEventKindV1::ModelRequestStarted
                | WorkflowRuntimeEventKindV1::ModelRequestCompleted
        )));
        assert!(
            !serde_json::to_string(mapper.events())
                .unwrap()
                .contains("source_digest")
        );
    }
}

#[tokio::test]
async fn firewall_resume_is_refused_without_replaying_prior_telemetry() {
    use workflow_adk::events::AdkEventMapper;
    use workflow_runtime::InMemoryArtifactStore;
    let bound = invocation("low_risk", "unknown");
    let plan = compile_str("firewall.toml", &source(&bound.identity())).unwrap();
    let agents = BTreeMap::from([(
        "judge".into(),
        Arc::new(PanicJudge) as Arc<dyn adk_rust::Agent>,
    )]);
    let graph = AdkGraphTranslator::new()
        .translate_with_firewall(&plan, bound, &agents)
        .unwrap();
    assert!(
        graph
            .invoke(State::new(), ExecutionConfig::new("first"))
            .await
            .is_err()
    );
    assert_eq!(graph.firewall_decisions().unwrap().len(), 1);
    let mut mapper = AdkEventMapper::new("resume", "firewall-test").unwrap();
    let limit = std::num::NonZeroU64::new(65536).unwrap();
    let mut artifacts = InMemoryArtifactStore::new(limit, limit);
    assert_eq!(
        graph
            .invoke_observed(
                State::new(),
                ExecutionConfig::new("second").with_resume_from("forged"),
                &mut mapper,
                &mut artifacts
            )
            .await
            .unwrap_err(),
        AdkGraphError::AuthorizationDenied
    );
    assert!(mapper.events().is_empty());
    assert!(graph.firewall_decisions().unwrap().is_empty());
}

struct PanicJudge;
#[adk_rust::async_trait]
impl adk_rust::Agent for PanicJudge {
    fn name(&self) -> &str {
        "judge"
    }
    fn description(&self) -> &str {
        "must not run"
    }
    fn sub_agents(&self) -> &[Arc<dyn adk_rust::Agent>] {
        &[]
    }
    async fn run(
        &self,
        _: Arc<dyn adk_rust::InvocationContext>,
    ) -> adk_rust::Result<adk_rust::EventStream> {
        panic!("a hard denial or approval wait must precede judges");
    }
}

#[tokio::test]
async fn production_boundary_stops_before_judges_even_with_forged_state() {
    for (admission, tool, decision) in [
        ("low_risk", "unknown", FirewallDecision::Deny),
        (
            "human_approval",
            "noop",
            FirewallDecision::RequireHumanApproval,
        ),
    ] {
        let invocation = invocation(admission, tool);
        let plan = compile_str("firewall.toml", &source(&invocation.identity())).unwrap();
        let agents = BTreeMap::from([(
            "judge".into(),
            Arc::new(PanicJudge) as Arc<dyn adk_rust::Agent>,
        )]);
        let graph = AdkGraphTranslator::new()
            .translate_with_firewall(&plan, invocation, &agents)
            .unwrap();
        let state = State::from([
            ("node:gate".into(), json!({"decision":"alw"})),
            ("approved".into(), json!(true)),
        ]);
        assert_eq!(
            graph
                .invoke(state, ExecutionConfig::new("firewall-test"))
                .await
                .unwrap_err(),
            AdkGraphError::AuthorizationDenied
        );
        let reports = graph.firewall_decisions().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports["gate"].decision(), decision);
    }
}

#[tokio::test]
async fn explicit_low_risk_gate_executes_and_emits_compact_output() {
    let invocation = invocation("low_risk", "noop");
    let source = source(&invocation.identity()).replace(
        "kind = \"agent\"\nmodel = { role = \"worker\", id = \"synthetic\", version = \"1\" }",
        "kind = \"action\"",
    );
    let plan = compile_str("firewall.toml", &source).unwrap();
    let graph = AdkGraphTranslator::new()
        .translate_with_firewall(&plan, invocation, &BTreeMap::new())
        .unwrap();
    let result = graph
        .invoke(State::new(), ExecutionConfig::new("firewall-allow"))
        .await
        .unwrap();
    assert_eq!(result["terminal"], json!("done"));
    assert_eq!(result["node:gate"]["payload"]["decision"], json!("alw"));
    assert_eq!(
        graph.firewall_decisions().unwrap()["gate"].decision(),
        FirewallDecision::Allow
    );
}

fn source_with_bridge(identity: &str, bridge: &str) -> String {
    source(identity).replace(
        "from = \"gate\"\nto = \"judge\"",
        &format!(
            "from = \"gate\"\nto = \"{bridge}\"\n[[edges]]\nfrom = \"{bridge}\"\nto = \"judge\""
        ),
    ) + &format!("\n[[nodes]]\nid = \"{bridge}\"\nkind = \"action\"\n")
}

struct CountingJudge(Arc<AtomicUsize>);
#[adk_rust::async_trait]
impl adk_rust::Agent for CountingJudge {
    fn name(&self) -> &str {
        "judge"
    }
    fn description(&self) -> &str {
        "count entry even when no model events escape"
    }
    fn sub_agents(&self) -> &[Arc<dyn adk_rust::Agent>] {
        &[]
    }
    async fn run(
        &self,
        _: Arc<dyn adk_rust::InvocationContext>,
    ) -> adk_rust::Result<adk_rust::EventStream> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let mut event = adk_rust::Event::new("judge");
        event.set_content(adk_rust::Content::new("assistant").with_text(r#"{"state":{}}"#));
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])))
    }
}

#[tokio::test]
async fn reserved_control_ids_cannot_dispatch_judges_before_hard_denial() {
    use workflow_adk::events::AdkEventMapper;
    use workflow_compiler::{CompileError, GraphValidationError};
    use workflow_runtime::InMemoryArtifactStore;

    let mut violations = Vec::new();
    // The ordinary bridge also proves this oracle observes actual allowed judge entry.
    for bridge in ["__start__", "__end__", "ordinary"] {
        for (admission, tool, decision) in [
            ("low_risk", "unknown", FirewallDecision::Deny),
            (
                "human_approval",
                "noop",
                FirewallDecision::RequireHumanApproval,
            ),
            ("low_risk", "noop", FirewallDecision::Allow),
        ] {
            for observed in [false, true] {
                let calls = Arc::new(AtomicUsize::new(0));
                let bound = invocation(admission, tool);
                let label = format!("{bridge} {decision:?} observed={observed}");
                let plan = match compile_str(
                    "reserved.toml",
                    &source_with_bridge(&bound.identity(), bridge),
                ) {
                    Err(CompileError::Graph(GraphValidationError::InvalidIdentifier {
                        field_path: "nodes[].id",
                    })) if bridge != "ordinary" => {
                        assert_eq!(calls.load(Ordering::SeqCst), 0);
                        continue;
                    }
                    result => {
                        result.expect("fixture must compile unless its control ID is rejected")
                    }
                };
                let agents = BTreeMap::from([(
                    "judge".into(),
                    Arc::new(CountingJudge(calls.clone())) as Arc<dyn adk_rust::Agent>,
                )]);
                let graph = AdkGraphTranslator::new()
                    .translate_with_firewall(&plan, bound, &agents)
                    .expect("valid compiled fixture translates");
                let result = if observed {
                    let mut mapper = AdkEventMapper::new("reserved", "firewall-test").unwrap();
                    let limit = std::num::NonZeroU64::new(65536).unwrap();
                    let mut artifacts = InMemoryArtifactStore::new(limit, limit);
                    graph
                        .invoke_observed(
                            State::new(),
                            ExecutionConfig::new("reserved"),
                            &mut mapper,
                            &mut artifacts,
                        )
                        .await
                } else {
                    graph
                        .invoke(State::new(), ExecutionConfig::new("reserved"))
                        .await
                };
                let count = calls.load(Ordering::SeqCst);
                println!("{label}: judge_entries={count}, result={result:?}");
                if decision != FirewallDecision::Allow {
                    assert_eq!(
                        result.unwrap_err(),
                        AdkGraphError::AuthorizationDenied,
                        "{label}"
                    );
                    assert_eq!(
                        graph.firewall_decisions().unwrap()["gate"].decision(),
                        decision
                    );
                    if count != 0 {
                        violations.push(format!(
                            "{label}: judge entered {count} times despite denial"
                        ));
                    }
                } else if bridge == "ordinary" {
                    assert!(result.is_ok(), "{label}: {result:?}");
                    assert!(count > 0, "positive control must reach the judge");
                }
                if bridge != "ordinary" {
                    violations.push(format!("{label}: reserved authored ID was admitted"));
                }
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn reserved_control_ids_fail_shared_admission_without_a_firewall() {
    use workflow_compiler::{
        BuiltinPredicateRegistry, CompileError, GraphValidationError, compile_str_with_predicates,
        validate_graph,
    };
    for bridge in [
        adk_rust::graph::prelude::START,
        adk_rust::graph::prelude::END,
    ] {
        let source = source_with_bridge(&invocation("low_risk", "noop").identity(), bridge);
        let source = source
            .lines()
            .filter(|line| !line.starts_with("firewall ="))
            .collect::<Vec<_>>()
            .join("\n");
        let spec = workflow_spec::parse_str("reserved.toml", &source).unwrap();
        let expected = GraphValidationError::InvalidIdentifier {
            field_path: "nodes[].id",
        };
        assert_eq!(
            validate_graph(&workflow_ir::WorkflowIr::from(&spec)),
            Err(expected.clone())
        );
        for result in [
            compile_str("reserved.toml", &source),
            compile_str_with_predicates("reserved.toml", &source, &BuiltinPredicateRegistry),
        ] {
            assert!(matches!(result, Err(CompileError::Graph(error)) if error == expected));
        }
    }
}

#[test]
fn compiler_and_every_default_translator_fail_closed_on_firewall_contract() {
    let bound = invocation("low_risk", "noop");
    let source = source(&bound.identity());
    let plan = compile_str("firewall.toml", &source).unwrap();
    assert!(AdkGraphTranslator::new().translate(&plan).is_err());
    assert!(
        AdkGraphTranslator::new()
            .translate_with_agents(&plan, &BTreeMap::new())
            .is_err()
    );
    assert!(
        AdkGraphTranslator::new()
            .translate_profile(&plan, &BTreeMap::new(), None, &json!({}))
            .is_err()
    );
    assert!(
        compile_str(
            "bad.toml",
            &source.replace(
                "firewall = { schema_version = 1",
                "firewall = { schema_version = 2"
            )
        )
        .is_err()
    );
    assert!(
        compile_str(
            "bad.toml",
            &source.replace("kind = \"validator\"", "kind = \"action\"")
        )
        .is_err()
    );
    assert!(
        compile_str(
            "bad.toml",
            &source.replace("entry = \"gate\"", "entry = \"judge\"")
        )
        .is_err()
    );
    let changed = invocation("human_approval", "noop");
    let changed_source = source.replace(&bound.identity(), &changed.identity());
    let changed_plan = compile_str("changed.toml", &changed_source).unwrap();
    assert_ne!(
        plan.ir().canonical_hash(),
        changed_plan.ir().canonical_hash()
    );
    assert!(
        AdkGraphTranslator::new()
            .translate_with_firewall(&plan, changed, &BTreeMap::new())
            .is_err()
    );
}
