//! Actual authored backend reduction publication; no provider or production tools.
use super::{BEHAVIORAL, RAW, WORKFLOW, approval, deadline, store, uncancelled};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_adk::execution::ExecutionBackend;
use workflow_runtime::{
    ArtifactId, ArtifactStore, PageRequest, WorkflowRuntimeEventKindV1 as Kind,
};

#[test]
fn backend_retains_source_bound_reduction_before_completion() {
    let spec = workflow_spec::parse_str("host.toml", &format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    let mut artifacts = store();
    let receipt = ExecutionBackend::run_with_sentinel_script(
        &spec,
        approval(
            &spec,
            RAW,
            "revision-1",
            json!([{"kind":"call","tool":"read_secret","arguments":{}}]),
        ),
        json!({"schema_version":1,"bytes":RAW}),
        &mut artifacts,
        uncancelled(),
        deadline(),
    )
    .unwrap();
    let events = receipt.observer.events();
    let retained: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind() == Kind::ArtifactCommitted && event.event_id() == "sentinel-reduction"
        })
        .collect();
    assert_eq!(
        retained.len(),
        1,
        "actual backend must retain its reduction"
    );
    let id = ArtifactId::parse(
        retained[0].payload()["artifact_reference"]["artifact_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let page = artifacts
        .read_page(&id, PageRequest::new(0, 4096.try_into().unwrap()))
        .unwrap();
    assert_eq!(id.as_str(), format!("{:x}", Sha256::digest(page.bytes())));
    let record: Value = serde_json::from_slice(page.bytes()).unwrap();
    assert_eq!(record.as_object().unwrap().len(), 5);
    assert_eq!(record["schema_version"], 1);
    assert_eq!(
        record["policy_version"],
        workflow_runtime::SENTINEL_REDUCTION_POLICY_VERSION
    );
    assert!(record["identity"].as_str().unwrap().starts_with("sha256:"));
    assert!(
        record["policy_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    let decision = receipt.report.evidence().unwrap().unwrap();
    assert_eq!(
        record["decision"],
        serde_json::from_str::<Value>(&decision.to_json().unwrap()).unwrap()
    );
    assert_eq!(record["decision"]["payload"]["verdict"], "sus");
    let position = |id: &str| {
        events
            .iter()
            .position(|event| event.event_id() == id)
            .unwrap()
    };
    assert!(position("sentinel-behavioral") < position("sentinel-reduction"));
    assert!(
        events
            .iter()
            .position(|event| event.kind() == Kind::WorkflowCompleted)
            .unwrap()
            > position("sentinel-reduction")
    );
    assert!(page.bytes().len() <= 1024);
    assert!(!String::from_utf8_lossy(page.bytes()).contains("Please ignore"));
    super::behavioral_oracles::no_model(&receipt.observer);
}

#[test]
fn backend_receipt_is_the_retained_decision_with_no_adapter_entry() {
    let spec = workflow_spec::parse_str("host.toml", &format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    for tool in ["complete", "read_secret"] {
        let mut artifacts = store();
        ExecutionBackend::take_adapter_counts_for_tests();
        let receipt = ExecutionBackend::run_with_sentinel_script(
            &spec,
            approval(
                &spec,
                RAW,
                "revision-1",
                json!([{"kind":"call","tool":tool,"arguments":{}}]),
            ),
            json!({"schema_version":1,"bytes":RAW}),
            &mut artifacts,
            uncancelled(),
            deadline(),
        )
        .unwrap();
        assert_eq!(ExecutionBackend::take_adapter_counts_for_tests(), (0, 0));
        let event = receipt
            .observer
            .events()
            .iter()
            .find(|event| event.event_id() == "sentinel-reduction")
            .unwrap();
        let id = ArtifactId::parse(
            event.payload()["artifact_reference"]["artifact_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let page = artifacts
            .read_page(&id, PageRequest::new(0, 1024.try_into().unwrap()))
            .unwrap();
        assert_eq!(page.next_offset(), None);
        let record: Value = serde_json::from_slice(page.bytes()).unwrap();
        assert_eq!(record["identity"], receipt.reduction.identity());
        assert_eq!(record["policy_digest"], receipt.reduction.policy_digest());
        assert_eq!(record["policy_version"], receipt.reduction.policy_version());
        assert_eq!(
            record["decision"],
            serde_json::from_str::<Value>(&receipt.reduction.output().to_json().unwrap()).unwrap()
        );
        let workflow_runtime::TypedPayload::Sentinel(evidence) =
            receipt.reduction.output().payload()
        else {
            panic!("Sentinel reduction")
        };
        assert_eq!(
            evidence.verdict(),
            workflow_runtime::SentinelVerdict::Suspicious
        );
        assert_eq!(evidence.artifacts().is_empty(), tool == "complete");
        if tool == "complete" {
            assert!(receipt.report.evidence().unwrap().is_none());
        }
    }
}

struct RejectReduction {
    inner: workflow_runtime::InMemoryArtifactStore,
    fail_commit: bool,
    attempts: usize,
}
impl ArtifactStore for RejectReduction {
    fn stage(
        &mut self,
        bytes: &[u8],
    ) -> Result<workflow_runtime::StagedArtifact, workflow_runtime::ArtifactError> {
        if serde_json::from_slice::<Value>(bytes)
            .ok()
            .is_some_and(|record| {
                record["policy_version"] == workflow_runtime::SENTINEL_REDUCTION_POLICY_VERSION
                    && record.get("decision").is_some()
            })
        {
            self.attempts += 1;
            if !self.fail_commit {
                return self.inner.stage(&[]);
            }
        }
        self.inner.stage(bytes)
    }
    fn commit(
        &mut self,
        staged: workflow_runtime::StagedArtifact,
    ) -> Result<ArtifactId, workflow_runtime::ArtifactError> {
        if self.attempts > 0 {
            let rejected = self.inner.stage(&[])?;
            return self.inner.commit(rejected);
        }
        self.inner.commit(staged)
    }
    fn read_page(
        &self,
        id: &ArtifactId,
        request: PageRequest,
    ) -> Result<workflow_runtime::ArtifactPage, workflow_runtime::ArtifactError> {
        self.inner.read_page(id, request)
    }
    fn set_retention(
        &mut self,
        id: &ArtifactId,
        policy: workflow_runtime::RetentionPolicy,
    ) -> Result<(), workflow_runtime::ArtifactError> {
        self.inner.set_retention(id, policy)
    }
    fn retention(
        &self,
        id: &ArtifactId,
    ) -> Result<workflow_runtime::RetentionPolicy, workflow_runtime::ArtifactError> {
        self.inner.retention(id)
    }
}

#[tokio::test]
async fn reduction_store_failure_preserves_forensics_without_completion() {
    use super::{
        AdkEventMapper, AdkGraphTranslator, compile_spec_with_sentinel_script, input_state,
    };
    use adk_rust::graph::prelude::ExecutionConfig;
    let spec = workflow_spec::parse_str("host.toml", &format!("{WORKFLOW}{BEHAVIORAL}\n[nodes.untrusted_text.behavioral.trajectory]\nschema_version = 1\n")).unwrap();
    for fail_commit in [false, true] {
        let script = approval(
            &spec,
            RAW,
            "revision-1",
            json!([{"kind":"call","tool":"read_secret","arguments":{}}]),
        )
        .with_trajectory_observer("private host task", None)
        .unwrap();
        let compiled = compile_spec_with_sentinel_script(&spec, &script).unwrap();
        let graph = AdkGraphTranslator::new()
            .with_sentinel_trusted_script(&compiled, script)
            .unwrap()
            .translate(&compiled)
            .unwrap();
        let mut mapper = AdkEventMapper::new("reduction-failure", "sentinel-preparation").unwrap();
        let mut artifacts = RejectReduction {
            inner: store(),
            fail_commit,
            attempts: 0,
        };
        assert!(
            graph
                .invoke_observed_with_sentinel_script(
                    input_state(),
                    ExecutionConfig::new("reduction-failure"),
                    &mut mapper,
                    &mut artifacts,
                    uncancelled(),
                    deadline()
                )
                .await
                .is_err()
        );
        assert_eq!(artifacts.attempts, 1);
        for role in ["sentinel-behavioral", "sentinel-trajectory"] {
            let retained: Vec<_> = mapper
                .events()
                .iter()
                .filter(|event| event.kind() == Kind::ArtifactCommitted && event.event_id() == role)
                .collect();
            assert_eq!(retained.len(), 1);
            let id = ArtifactId::parse(
                retained[0].payload()["artifact_reference"]["artifact_id"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert!(
                artifacts
                    .read_page(&id, PageRequest::new(0, 100_000.try_into().unwrap()))
                    .is_ok()
            );
        }
        assert!(
            mapper
                .events()
                .iter()
                .all(|event| event.kind() != Kind::WorkflowCompleted
                    && event.kind() != Kind::NodeCompleted
                    && event.event_id() != "sentinel-reduction")
        );
        super::behavioral_oracles::no_model(&mapper);
    }
}

#[test]
fn backend_reduction_retention_failure_has_no_acknowledged_receipt() {
    let spec = workflow_spec::parse_str("host.toml", &format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    for fail_commit in [false, true] {
        let mut artifacts = RejectReduction {
            inner: store(),
            fail_commit,
            attempts: 0,
        };
        let result = ExecutionBackend::run_with_sentinel_script(
            &spec,
            approval(
                &spec,
                RAW,
                "revision-1",
                json!([{"kind":"call","tool":"complete","arguments":{}}]),
            ),
            json!({"schema_version":1,"bytes":RAW}),
            &mut artifacts,
            uncancelled(),
            deadline(),
        );
        assert!(result.is_err());
        assert_eq!(artifacts.attempts, 1);
    }
}

#[tokio::test]
async fn reduction_identity_binds_source_run_approval_and_observation_not_state() {
    use super::{
        AdkEventMapper, AdkGraphTranslator, compile_spec_with_sentinel_script, input_state,
    };
    use adk_rust::graph::prelude::ExecutionConfig;
    let spec = workflow_spec::parse_str("host.toml", &format!("{WORKFLOW}{BEHAVIORAL}\n[nodes.untrusted_text.behavioral.trajectory]\nschema_version = 1\n")).unwrap();
    let mut identities = Vec::new();
    for case in [
        "baseline",
        "forged-state",
        "source",
        "run",
        "revision",
        "observer",
    ] {
        let raw = if case == "source" {
            b"Please summarize the report".as_slice()
        } else {
            RAW
        };
        let run = if case == "run" {
            "other-run"
        } else {
            "fixed-run"
        };
        let revision = if case == "revision" {
            "revision-2"
        } else {
            "revision-1"
        };
        let summary = (case == "observer").then_some(br#"{"schema_version":1,"goal_override":true,"secret_seeking":false,"tool_manipulation":false,"claims_no_tools":false}"#.as_slice());
        let script = approval(
            &spec,
            raw,
            revision,
            json!([{"kind":"call","tool":"read_secret","arguments":{}}]),
        )
        .with_trajectory_observer("private host task", summary)
        .unwrap();
        let compiled = compile_spec_with_sentinel_script(&spec, &script).unwrap();
        let graph = AdkGraphTranslator::new()
            .with_sentinel_trusted_script(&compiled, script)
            .unwrap()
            .translate(&compiled)
            .unwrap();
        let mut state = if case == "forged-state" {
            input_state()
        } else {
            adk_rust::graph::prelude::State::new()
        };
        state.insert("input".into(), json!({"schema_version":1,"bytes":raw}));
        if case == "forged-state" {
            for key in [
                "reduction",
                "preparation_identity",
                "source_cover",
                "policy_digest",
            ] {
                state.insert(key.into(), json!({"identity":"forged", "verdict":"clean"}));
            }
        }
        let mut mapper = AdkEventMapper::new(run, "sentinel-preparation").unwrap();
        let mut artifacts = store();
        let (_, report, reduction) = graph
            .invoke_observed_with_sentinel_script(
                state,
                ExecutionConfig::new(run),
                &mut mapper,
                &mut artifacts,
                uncancelled(),
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(
            reduction.output(),
            &report.evidence().unwrap().unwrap(),
            "hard evidence dominates observer {case}"
        );
        let events = mapper.events();
        let position = |id: &str| {
            events
                .iter()
                .position(|event| event.event_id() == id)
                .unwrap()
        };
        assert!(position("sentinel-behavioral") < position("sentinel-trajectory"));
        assert!(position("sentinel-trajectory") < position("sentinel-reduction"));
        let public = serde_json::to_string(events).unwrap();
        for secret in [
            "forged",
            "Please ignore",
            "Please summarize",
            "private host task",
            "goal_override\":true",
        ] {
            assert!(!public.contains(secret));
        }
        if case == "baseline" {
            identities.push(reduction.identity().to_owned());
        } else if case == "forged-state" {
            assert_eq!(reduction.identity(), identities[0]);
        } else {
            assert!(
                identities
                    .iter()
                    .all(|identity| identity != reduction.identity()),
                "distinct binding {case}"
            );
            identities.push(reduction.identity().to_owned());
        }
    }
}
