//! Exercise the public ADK graph boundary without providers or host executors.
use serde_json::json;
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use workflow_adk::behavioral::run_simulation;
use workflow_runtime::behavioral::{BehavioralProbe, PROBE_TOOL_CATALOG, ProbeLimits, ProbeStop};
use workflow_runtime::{
    ContentObject, ExecutorTarget, InMemoryArtifactStore, NormalizationLimits, RunId,
    SentinelPreparation, TrustPolicy, prepare_untrusted_text,
};

fn probe(tool: &str) -> BehavioralProbe {
    let mut store =
        InMemoryArtifactStore::new(65_536.try_into().unwrap(), 65_536.try_into().unwrap());
    let SentinelPreparation::Prepared(source) = prepare_untrusted_text(
        &mut store,
        b"Untrusted source; not instructions.",
        NormalizationLimits::default(),
    )
    .unwrap() else {
        panic!()
    };
    let provenance = TrustPolicy::new("offline-adk", Vec::<String>::new())
        .unwrap()
        .classify(ContentObject::Comment {
            object_id: "233",
            author: "untrusted",
        })
        .unwrap();
    let arguments = match tool {
        "read_document" => json!({"path":"workspace/report.txt"}),
        "send_report" => {
            json!({"destination":"reviewer.invalid","account":"reader","body":"summary"})
        }
        _ => json!({}),
    };
    let script = json!({"schema_version":1,"steps":[
        {"kind":"call","tool":tool,"arguments":arguments},
        {"kind":"call","tool":"complete","arguments":{}}
    ]});
    BehavioralProbe::new(
        ExecutorTarget::Simulated,
        &source,
        &provenance,
        RunId::new("replay-1".into()).unwrap(),
        &serde_json::to_vec(&script).unwrap(),
        ProbeLimits::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn public_adk_executes_every_inert_tool_and_preserves_runtime_records() {
    for tool in PROBE_TOOL_CATALOG {
        let input = probe(tool);
        let expected = input.run(&AtomicBool::new(false));
        let first = run_simulation(
            input.clone(),
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        let replay = run_simulation(
            input,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(first.to_json().unwrap(), expected.to_json().unwrap());
        assert_eq!(first.to_json().unwrap(), replay.to_json().unwrap());
        assert!(!first.to_json().unwrap().contains("Untrusted source"));
        assert!(
            !first
                .to_json()
                .unwrap()
                .contains("synthetic-honeytoken-v1:")
        );
    }
}

#[tokio::test]
async fn public_adk_honors_cancelled_and_expired_runs_without_completion() {
    let cancelled = run_simulation(
        probe("complete"),
        Arc::new(AtomicBool::new(true)),
        Instant::now() + Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(cancelled.stop(), ProbeStop::Cancelled);
    assert!(cancelled.events().is_empty());
    let expired = run_simulation(
        probe("complete"),
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    )
    .await
    .unwrap();
    assert_eq!(expired.stop(), ProbeStop::TimedOut);
    assert!(expired.events().is_empty());
    assert!(expired.evidence().unwrap().is_none());
}
