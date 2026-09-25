//! Falsifying controls and typed assertions for authored execution.
use super::{
    AdkEventMapper, ArtifactId, ArtifactStore, BEHAVIORAL, PageRequest, RAW, WORKFLOW, approval,
    store,
};
use sha2::{Digest, Sha256};
use workflow_adk::events::{AdkRuntimeObservationKindV1 as Observation, AdkRuntimeObservationV1};
use workflow_runtime::{WorkflowRuntimeEventKindV1 as Kind, behavioral::ProbeReport};

pub(super) fn no_model(mapper: &AdkEventMapper) {
    assert!(
        mapper.events().iter().all(|event| !matches!(
            event.kind(),
            Kind::ModelRequestStarted | Kind::ModelRequestCompleted
        )),
        "simulation must not publish model lifecycle events"
    );
}

pub(super) fn no_report(mapper: &AdkEventMapper) {
    no_model(mapper);
    for event in mapper.events() {
        assert_ne!(event.kind(), Kind::WorkflowCompleted);
        assert!(!(event.kind() == Kind::NodeCompleted && event.node_id() == Some("prepare")));
        if event.kind() == Kind::ArtifactCommitted {
            // Report failure may follow successful source/envelope retention, nothing else.
            assert_eq!(event.node_id(), Some("prepare"));
            assert!(matches!(
                event.event_id(),
                "sentinel-original" | "sentinel-envelope"
            ));
        }
    }
    assert!(
        !serde_json::to_string(mapper.events())
            .unwrap()
            .contains("forged")
    );
}

pub(super) fn expected_report(steps: serde_json::Value, run: &str) -> ProbeReport {
    let spec =
        workflow_spec::parse_str("sentinel.toml", &format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    let script = approval(&spec, RAW, "revision-1", steps);
    let source = workflow_runtime::prepare_untrusted_text(
        &mut store(),
        RAW,
        workflow_runtime::NormalizationLimits::default(),
    )
    .unwrap();
    let workflow_runtime::SentinelPreparation::Prepared(source) = source else {
        panic!("prepared source");
    };
    script
        .bind(&source, workflow_runtime::RunId::new(run.into()).unwrap())
        .unwrap()
        .run(&std::sync::atomic::AtomicBool::new(false))
}

pub(super) fn owned_report(
    expected: &ProbeReport,
    report: &ProbeReport,
    mapper: &AdkEventMapper,
    artifacts: &impl ArtifactStore,
) {
    assert_eq!(
        report.identity(),
        expected.identity(),
        "report belongs to the host run"
    );
    let bytes = expected.to_json().unwrap();
    assert_eq!(report.to_json().unwrap(), bytes);
    let id = ArtifactId::parse(format!("{:x}", Sha256::digest(bytes.as_bytes()))).unwrap();
    assert_eq!(
        artifacts
            .read_page(&id, PageRequest::new(0, 100_000.try_into().unwrap()))
            .unwrap()
            .bytes(),
        bytes.as_bytes()
    );
    let retained: Vec<_> = mapper
        .events()
        .iter()
        .filter(|event| {
            event.kind() == Kind::ArtifactCommitted && event.event_id() == "sentinel-behavioral"
        })
        .collect();
    assert_eq!(retained.len(), 1);
    assert_eq!(
        retained[0].payload()["artifact_reference"]["artifact_id"],
        id.as_str()
    );
    let completed: Vec<_> = mapper
        .events()
        .iter()
        .filter(|event| event.kind() == Kind::NodeCompleted && event.node_id() == Some("prepare"))
        .collect();
    assert_eq!(completed.len(), 1);
    let telemetry = &completed[0].payload()["structured_output"]["preparation"]["behavioral"];
    assert_eq!(telemetry["identity"], expected.identity());
    assert_eq!(telemetry["artifact_id"], id.as_str());
}

#[test]
fn negative_oracles_reject_forbidden_events() {
    let mut accepted = Vec::new();
    for kind in [
        Observation::WorkflowCompleted,
        Observation::ModelRequestStarted,
        Observation::ModelRequestCompleted,
        Observation::NodeCompleted,
        Observation::ArtifactCommitted,
    ] {
        let mut mapper = AdkEventMapper::new("oracle", "sentinel-preparation").unwrap();
        let observation = AdkRuntimeObservationV1::new("adk-stream-1", "adk-stream", kind)
            .with_node_id("prepare");
        mapper.map(observation).unwrap();
        if std::panic::catch_unwind(|| no_report(&mapper)).is_ok() {
            accepted.push(kind);
        }
    }
    assert!(
        accepted.is_empty(),
        "forbidden events accepted: {accepted:?}"
    );
}

#[test]
fn report_failure_oracle_allows_only_earlier_preparation_artifacts() {
    let mut mapper = AdkEventMapper::new("oracle", "sentinel-preparation").unwrap();
    for role in ["original", "envelope"] {
        mapper
            .map(
                AdkRuntimeObservationV1::new(
                    format!("sentinel-{role}"),
                    "sentinel-preparation",
                    Observation::ArtifactCommitted,
                )
                .with_node_id("prepare"),
            )
            .unwrap();
    }
    no_report(&mapper);
    mapper
        .map(
            AdkRuntimeObservationV1::new(
                "sentinel-behavioral",
                "sentinel-preparation",
                Observation::ArtifactCommitted,
            )
            .with_node_id("prepare"),
        )
        .unwrap();
    assert!(std::panic::catch_unwind(|| no_report(&mapper)).is_err());
}
