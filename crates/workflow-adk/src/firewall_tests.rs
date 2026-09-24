//! Bounded public-invocation regressions for the gate-to-observer handoff.
use super::FirewallInvocation;
use crate::{AdkGraph, AdkGraphError, AdkGraphTranslator, events::AdkEventMapper};
use adk_rust::graph::prelude::{ExecutionConfig, State};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::timeout};
use workflow_runtime::{InMemoryArtifactStore, WorkflowRuntimeEventKindV1 as Kind};

#[path = "../tests/support/firewall.rs"]
mod fixture;

const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Pause {
    before: bool,
    entered: Notify,
    release: Notify,
}

tokio::task_local! {
    static PAUSE: Arc<Pause>;
}

// Test-only boundaries around the real gate, never a replacement evaluation.
// The after boundary pauses before either public invocation can observe/exit.
pub(crate) async fn at_gate(before: bool) {
    if let Ok(pause) = PAUSE.try_with(Arc::clone)
        && pause.before == before
    {
        pause.entered.notify_one();
        timeout(DEADLINE, pause.release.notified())
            .await
            .expect("release gate");
    }
}

fn graph(admission: &str, tool: &str) -> (AdkGraph, Arc<AtomicUsize>, Value) {
    let bound = fixture::invocation(admission, tool);
    let expected = serde_json::from_str(
        &bound
            .policy
            .evaluate(&bound.goal, &bound.proposal)
            .render_json()
            .unwrap(),
    )
    .unwrap();
    let plan = workflow_compiler::compile_str("firewall.toml", &fixture::source(&bound.identity()))
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agents = BTreeMap::from([(
        "judge".into(),
        Arc::new(fixture::CountingJudge(calls.clone())) as Arc<dyn adk_rust::Agent>,
    )]);
    (
        AdkGraphTranslator::new()
            .translate_with_firewall(&plan, bound, &agents)
            .unwrap(),
        calls,
        expected,
    )
}

async fn invoke(
    graph: &AdkGraph,
    observed: bool,
    config: ExecutionConfig,
    run: &str,
) -> AdkEventMapper {
    let mut mapper = AdkEventMapper::new(run, "firewall-test").unwrap();
    let limit = std::num::NonZeroU64::new(65536).unwrap();
    let mut artifacts = InMemoryArtifactStore::new(limit, limit);
    let result = if observed {
        graph
            .invoke_observed(State::new(), config, &mut mapper, &mut artifacts)
            .await
    } else {
        graph.invoke(State::new(), config).await
    };
    assert_eq!(result.unwrap_err(), AdkGraphError::AuthorizationDenied);
    mapper
}

fn check_events(mapper: &AdkEventMapper, observed: bool, kind: Kind, expected: &Value) {
    let policy = mapper
        .events()
        .iter()
        .filter(|event| {
            matches!(
                event.kind(),
                Kind::ToolDenied | Kind::ApprovalRequested | Kind::ToolAuthorized
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        policy.len(),
        usize::from(observed),
        "exactly one invocation-owned decision"
    );
    if observed {
        assert_eq!(policy[0].kind(), kind);
        assert_eq!(policy[0].node_id(), Some("gate"));
        assert_eq!(
            &policy[0].payload()["structured_output"]["firewall"],
            expected
        );
        let start = mapper
            .events()
            .iter()
            .position(|event| event.kind() == Kind::NodeStarted && event.node_id() == Some("gate"))
            .unwrap();
        let decision = mapper
            .events()
            .iter()
            .position(|event| event.kind() == kind)
            .unwrap();
        assert!(
            start < decision,
            "another invocation's decision must not precede this gate's start"
        );
    }
}

async fn concurrent(rejected_resume: bool, admission: &str, tool: &str, kind: Kind) {
    for a_observed in [true, false] {
        for b_observed in [true, false] {
            // Checkpoint thread IDs are caller-controlled, not invocation identities.
            for same_thread_id in [false, true] {
                let (graph, calls, expected) = graph(admission, tool);
                let pause = Arc::new(Pause::default());
                let a_finished = Notify::new();
                let a = async {
                    let mapper = PAUSE
                        .scope(
                            pause.clone(),
                            invoke(&graph, a_observed, ExecutionConfig::new("a"), "run-a"),
                        )
                        .await;
                    a_finished.notify_one();
                    mapper
                };
                let b = async {
                    timeout(DEADLINE, pause.entered.notified())
                        .await
                        .expect("A evaluated gate");
                    let config = ExecutionConfig::new(if same_thread_id { "a" } else { "b" });
                    let config = if rejected_resume {
                        config.with_resume_from("forged")
                    } else {
                        config
                    };
                    if rejected_resume {
                        // Rejected B must finish while A is paused.
                        let mapper = timeout(DEADLINE, invoke(&graph, b_observed, config, "run-b"))
                            .await
                            .expect("B remains concurrent");
                        pause.release.notify_one();
                        mapper
                    } else {
                        // Ordinary B enters after A's evaluation but must not publish
                        // A's record or erase it before B evaluates its own gate.
                        let before_b = Arc::new(Pause {
                            before: true,
                            ..Pause::default()
                        });
                        let b = PAUSE.scope(
                            before_b.clone(),
                            invoke(&graph, b_observed, config, "run-b"),
                        );
                        let handoff = async {
                            timeout(DEADLINE, before_b.entered.notified())
                                .await
                                .expect("B reached its gate concurrently");
                            pause.release.notify_one();
                            timeout(DEADLINE, a_finished.notified())
                                .await
                                .expect("A observed its decision");
                            before_b.release.notify_one();
                        };
                        tokio::join!(b, handoff).0
                    }
                };
                let (a, b) = timeout(DEADLINE, async { tokio::join!(a, b) })
                    .await
                    .expect("bounded handoff");
                println!(
                    "{kind:?} resume={rejected_resume} a_observed={a_observed} b_observed={b_observed} same_thread={same_thread_id} judge_entries={}",
                    calls.load(Ordering::SeqCst)
                );
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                check_events(&a, a_observed, kind, &expected);
                check_events(&b, b_observed && !rejected_resume, kind, &expected);
                if rejected_resume {
                    assert!(
                        b.events().is_empty(),
                        "rejected resume never observes a gate"
                    );
                }
                let reports = graph.firewall_decisions().unwrap();
                assert_eq!(
                    reports.len(),
                    1,
                    "last completed invocation has its own report"
                );
                assert_eq!(
                    serde_json::from_str::<Value>(&reports["gate"].render_json().unwrap()).unwrap(),
                    expected
                );
            }
        }
    }
}

#[tokio::test]
async fn rejected_resume_cannot_erase_inflight_denial() {
    concurrent(true, "low_risk", "unknown", Kind::ToolDenied).await;
}

#[tokio::test]
async fn rejected_resume_cannot_erase_inflight_approval() {
    concurrent(true, "human_approval", "noop", Kind::ApprovalRequested).await;
}

#[tokio::test]
async fn ordinary_concurrent_invocations_cannot_swap_denial() {
    concurrent(false, "low_risk", "unknown", Kind::ToolDenied).await;
}

#[tokio::test]
async fn ordinary_concurrent_invocations_cannot_swap_approval() {
    concurrent(false, "human_approval", "noop", Kind::ApprovalRequested).await;
}

#[tokio::test]
async fn cancellation_discards_only_the_cancelled_invocation() {
    let (graph, calls, expected) = graph("low_risk", "unknown");
    let pause = Arc::new(Pause::default());
    {
        let a = PAUSE.scope(
            pause.clone(),
            invoke(&graph, true, ExecutionConfig::new("shared"), "cancelled"),
        );
        tokio::pin!(a);
        tokio::select! {
            _ = &mut a => panic!("gate should be paused"),
            result = timeout(DEADLINE, pause.entered.notified()) => result.expect("A evaluated gate"),
        }
        // Dropping the public invocation must not leave a lock or evidence for B.
    }
    assert!(
        graph.firewall_decisions().unwrap().is_empty(),
        "cancelled gate cannot publish a completed snapshot"
    );
    let mapper = timeout(
        DEADLINE,
        invoke(&graph, true, ExecutionConfig::new("shared"), "survivor"),
    )
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    check_events(&mapper, true, Kind::ToolDenied, &expected);
}
