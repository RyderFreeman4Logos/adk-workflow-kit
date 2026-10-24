use super::{ExecutionConfig, Mode, RAW, setup, state};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use workflow_runtime::{
    ArtifactError, ArtifactId, ArtifactPage, ArtifactStore, InMemoryArtifactStore, PageRequest,
    RetentionPolicy, StagedArtifact,
};

struct SlowStage {
    inner: InMemoryArtifactStore,
    at: usize,
    stages: usize,
    delayed_id: Option<String>,
    committed: Vec<String>,
}
impl ArtifactStore for SlowStage {
    fn stage(&mut self, bytes: &[u8]) -> Result<StagedArtifact, ArtifactError> {
        let staged = self.inner.stage(bytes)?;
        self.stages += 1;
        if self.stages == self.at {
            self.delayed_id = Some(format!("{:x}", Sha256::digest(bytes)));
            std::thread::sleep(Duration::from_millis(1_025));
        }
        Ok(staged)
    }
    fn commit(&mut self, staged: StagedArtifact) -> Result<ArtifactId, ArtifactError> {
        let id = self.inner.commit(staged)?;
        self.committed.push(id.as_str().to_owned());
        Ok(id)
    }
    fn read_page(
        &self,
        id: &ArtifactId,
        request: PageRequest,
    ) -> Result<ArtifactPage, ArtifactError> {
        self.inner.read_page(id, request)
    }
    fn set_retention(
        &mut self,
        id: &ArtifactId,
        policy: RetentionPolicy,
    ) -> Result<(), ArtifactError> {
        self.inner.set_retention(id, policy)
    }
    fn retention(&self, id: &ArtifactId) -> Result<RetentionPolicy, ArtifactError> {
        self.inner.retention(id)
    }
}

#[tokio::test]
async fn public_preparation_expiry_precedes_publication_and_provider_entry() {
    for at in [1, 3, 4] {
        let (graph, probe, inner, mut mapper) = setup(Mode::Agree, 2);
        let mut store = SlowStage {
            inner,
            at,
            stages: 0,
            delayed_id: None,
            committed: vec![],
        };
        graph
            .invoke_observed(
                state(RAW),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await
            .unwrap();
        let events = serde_json::to_value(mapper.events()).unwrap();
        let report = events
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "node_completed")
            .unwrap()["payload"]["structured_output"]["preparation"]
            .clone();
        assert_eq!(report["state"], "invalid_input", "stage {at}: {report}");
        assert_eq!(report["reason"], "deadline_exceeded");
        assert_eq!(report["semantics"], Value::Null);
        assert!(probe.requests.lock().unwrap().is_empty());
        assert_eq!(probe.active.load(std::sync::atomic::Ordering::SeqCst), 0);
        let original = format!("{:x}", Sha256::digest(RAW));
        assert_eq!(report["original_artifact_id"], original);
        assert!(store.committed.contains(&original));
        if at != 1 {
            assert!(
                !store.committed.contains(store.delayed_id.as_ref().unwrap()),
                "expired staged view was published"
            );
        }
    }
}

#[tokio::test]
async fn semantic_response_time_uses_its_own_existing_budget() {
    let (graph, probe, mut store, mut mapper) = setup(Mode::DelayedAgree, 2);
    let started = std::time::Instant::now();
    graph
        .invoke_observed(
            state(RAW),
            ExecutionConfig::new("probe-run"),
            &mut mapper,
            &mut store,
        )
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(1_100));
    assert_eq!(probe.requests.lock().unwrap().len(), 2);
    let semantic = super::report(&store, &mapper);
    assert_eq!(semantic["reason"], "agreement");
    assert_eq!(semantic["findings"].as_array().unwrap().len(), 2);
}
