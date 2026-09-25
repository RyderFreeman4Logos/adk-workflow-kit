//! Authored preparation must be observed at its own terminal, not synthetic nodes.
use super::{
    AdkEventMapper, AdkGraphTranslator, ArtifactId, ArtifactStore, BEHAVIORAL, ControlledStore,
    ExecutionConfig, NoBindings, PageRequest, RAW, ResolvedRuntimePlan, RuntimePlanRequest,
    WORKFLOW, WorkflowIr, approval, compile_spec_with_sentinel_script, compile_str, deadline,
    input_state, store, uncancelled,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_runtime::behavioral::ProbeStop;

const NAMES: &[&str] = &[
    "revise",
    "prepare",
    "__workflow_revise_admit",
    "__workflow_revise_admit_0",
    "__workflow_unknown_route_0",
    "__workflow_fanin_guard_revise",
];

fn source(node: &str) -> String {
    WORKFLOW.replace("\"prepare\"", &format!("\"{node}\""))
}

fn position(events: &[Value], kind: &str, node: Option<&str>) -> usize {
    let matches: Vec<_> = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event["kind"] == kind && event["node_id"].as_str() == node)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(matches.len(), 1, "{kind} {node:?}: {events:?}");
    matches[0]
}

async fn behavioral_order(resolved: bool) {
    for node in NAMES {
        let text = format!("{}{BEHAVIORAL}", source(node));
        let spec = workflow_spec::parse_str("sentinel.toml", &text).unwrap();
        let ir = WorkflowIr::from(&spec);
        let script = approval(
            &spec,
            RAW,
            "node-order",
            json!([{"kind":"call","tool":"complete","arguments":{}}]),
        );
        let compiled = compile_spec_with_sentinel_script(&spec, &script).unwrap();
        let translator = AdkGraphTranslator::new()
            .with_sentinel_trusted_script(&compiled, script)
            .unwrap();
        let graph = if resolved {
            let plan = ResolvedRuntimePlan::resolve(RuntimePlanRequest::from_ir(&ir), &NoBindings)
                .unwrap();
            translator.translate_resolved(&plan, &ir)
        } else {
            translator.translate(&compiled)
        }
        .unwrap();
        let mut artifacts = ControlledStore {
            inner: store(),
            cancel: None,
            fail_report: false,
            fail_trajectory: false,
            expire: false,
            report_attempts: 0,
        };
        let mut mapper = AdkEventMapper::new("node-order", "sentinel-preparation").unwrap();
        let result = graph
            .invoke_observed_with_sentinel_script(
                input_state(),
                ExecutionConfig::new("node-order"),
                &mut mapper,
                &mut artifacts,
                uncancelled(),
                deadline(),
            )
            .await;
        let events: Vec<Value> = serde_json::from_value(json!(mapper.events())).unwrap();
        assert!(
            result.is_ok(),
            "node={node}, resolved={resolved}, events={events:?}"
        );
        let (state, report) = result.unwrap();
        assert_eq!(state[&format!("visits:{node}")], 1);
        assert_eq!(report.stop(), ProbeStop::NoCompromiseObserved);
        assert_eq!(report.events().len(), 1);
        assert_eq!(artifacts.report_attempts, 1);
        let bytes = report.to_json().unwrap();
        let id = ArtifactId::parse(format!("{:x}", Sha256::digest(bytes.as_bytes()))).unwrap();
        assert_eq!(
            artifacts
                .read_page(&id, PageRequest::new(0, 100_000.try_into().unwrap()))
                .unwrap()
                .bytes(),
            bytes.as_bytes()
        );
        let retained: Vec<_> = events
            .iter()
            .enumerate()
            .filter(|(_, event)| event["event_id"] == "sentinel-behavioral")
            .collect();
        assert_eq!(retained.len(), 1);
        let (retained_at, retained) = retained[0];
        assert_eq!(retained["node_id"], *node);
        assert_eq!(
            retained["payload"]["artifact_reference"]["artifact_id"],
            id.as_str()
        );
        let start = position(&events, "node_started", Some(node));
        let end = position(&events, "node_completed", Some(node));
        let done = position(&events, "workflow_completed", None);
        assert!(start < retained_at && retained_at < end && end < done);
        assert_eq!(
            events[end]["payload"]["structured_output"]["preparation"]["behavioral"]["identity"],
            report.identity()
        );
        if *node == "revise" {
            let helper = position(&events, "node_completed", Some("__workflow_revise_admit"));
            assert!(helper < start);
            assert!(
                events[helper]["payload"]["structured_output"]
                    .get("preparation")
                    .is_none()
            );
        }
        eprintln!("node={node}, resolved={resolved}, probe_steps=1, report_writes=1, ordered=true");
    }
}

#[tokio::test]
async fn authored_synthetic_names_retain_report_only_at_real_terminal() {
    behavioral_order(false).await;
}

#[tokio::test]
async fn resolved_synthetic_names_retain_report_only_at_real_terminal() {
    behavioral_order(true).await;
}

#[tokio::test]
async fn ordinary_revise_preparation_remains_available_on_both_paths() {
    let text = source("revise");
    let compiled = compile_str("sentinel.toml", &text).unwrap();
    let (resolved, ir) = super::resolved(&text);
    for graph in [
        AdkGraphTranslator::new().translate(&compiled),
        AdkGraphTranslator::new().translate_resolved(&resolved, &ir),
    ] {
        let mut mapper = AdkEventMapper::new("ordinary-order", "sentinel-preparation").unwrap();
        let state = graph
            .unwrap()
            .invoke_observed(
                input_state(),
                ExecutionConfig::new("ordinary-order"),
                &mut mapper,
                &mut store(),
            )
            .await
            .unwrap();
        assert_eq!(state["visits:revise"], 1);
        assert_eq!(state["terminal"]["state"], "pending_classification");
        let events: Vec<Value> = serde_json::from_value(json!(mapper.events())).unwrap();
        let helper = position(&events, "node_completed", Some("__workflow_revise_admit"));
        let end = position(&events, "node_completed", Some("revise"));
        assert!(helper < end && end < position(&events, "workflow_completed", None));
        assert!(
            events[helper]["payload"]["structured_output"]
                .get("preparation")
                .is_none()
        );
        assert_eq!(
            events[end]["payload"]["structured_output"]["preparation"]["state"],
            "pending_classification"
        );
        assert!(
            !events
                .iter()
                .any(|event| event["event_id"] == "sentinel-behavioral")
        );
    }
}

#[test]
fn reserved_control_names_remain_rejected_before_execution() {
    for node in ["", "__start__", "__end__"] {
        let text = format!("{}{BEHAVIORAL}", source(node));
        let spec = workflow_spec::parse_str("sentinel.toml", &text).unwrap();
        let script = approval(&spec, RAW, "reserved-name", json!([]));
        assert!(
            compile_spec_with_sentinel_script(&spec, &script).is_err(),
            "{node}"
        );
        let (plan, ir) = super::resolved(&source(node));
        assert!(
            AdkGraphTranslator::new()
                .translate_resolved(&plan, &ir)
                .is_err(),
            "{node}"
        );
    }
}
