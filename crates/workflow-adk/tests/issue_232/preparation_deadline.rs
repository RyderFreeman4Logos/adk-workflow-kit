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
    raw_puts: usize,
    raw_stages: usize,
    delay_repeated_raw: bool,
    wrong_first_raw_id: bool,
}
impl SlowStage {
    fn new(inner: InMemoryArtifactStore, at: usize) -> Self {
        Self {
            inner,
            at,
            stages: 0,
            delayed_id: None,
            committed: vec![],
            raw_puts: 0,
            raw_stages: 0,
            delay_repeated_raw: false,
            wrong_first_raw_id: false,
        }
    }
}
impl ArtifactStore for SlowStage {
    fn stage(&mut self, bytes: &[u8]) -> Result<StagedArtifact, ArtifactError> {
        let staged = self.inner.stage(bytes)?;
        self.stages += 1;
        if bytes == RAW {
            self.raw_stages += 1;
        }
        if self.stages == self.at
            || (self.delay_repeated_raw && bytes == RAW && self.raw_stages == 2)
        {
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
    fn put(&mut self, bytes: &[u8]) -> Result<ArtifactId, ArtifactError> {
        if bytes == RAW {
            self.raw_puts += 1;
        }
        let staged = self.stage(bytes)?;
        let id = self.commit(staged)?;
        if self.wrong_first_raw_id && bytes == RAW && self.raw_puts == 1 {
            return Ok(ArtifactId::parse("f".repeat(64)).unwrap());
        }
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
    for at in [1, 2, 3] {
        let (graph, probe, inner, mut mapper) = setup(Mode::Agree, 2);
        let mut store = SlowStage::new(inner, at);
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

async fn assert_positive_retained_once(delay_repeated_raw: bool) {
    let (graph, probe, inner, mut mapper) = setup(Mode::Agree, 2);
    let mut store = SlowStage::new(inner, usize::MAX);
    store.delay_repeated_raw = delay_repeated_raw;
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
    let events = events.as_array().unwrap();
    let preparation = &events
        .iter()
        .find(|event| event["kind"] == "node_completed")
        .unwrap()["payload"]["structured_output"]["preparation"];
    assert_eq!(
        preparation["state"], "pending_classification",
        "{preparation}"
    );
    assert_eq!(preparation["policy_digest"].as_str().unwrap().len(), 71);
    assert_eq!(preparation["normalization"]["preparation_budget_ms"], 1_000);
    assert_eq!(probe.requests.lock().unwrap().len(), 2);
    assert_eq!(probe.active.load(std::sync::atomic::Ordering::SeqCst), 0);
    let semantic = super::report(&store.inner, &mapper);
    assert_eq!(semantic["reason"], "agreement");
    assert_eq!(semantic["findings"].as_array().unwrap().len(), 2);
    let id = ArtifactId::parse(format!("{:x}", Sha256::digest(RAW))).unwrap();
    assert_eq!(preparation["original_artifact_id"], id.as_str());
    assert_eq!(
        store
            .read_page(
                &id,
                PageRequest::new(0, std::num::NonZeroU64::new(100).unwrap())
            )
            .unwrap()
            .bytes(),
        RAW
    );
    let original_events = events
        .iter()
        .filter(|event| {
            event["kind"] == "artifact_committed"
                && event["payload"]["artifact_reference"]["artifact_id"] == id.as_str()
        })
        .collect::<Vec<_>>();
    assert_eq!(original_events.len(), 1);
    assert_eq!(
        events[0]["payload"]["artifact_reference"]["artifact_id"],
        id.as_str()
    );
    assert_eq!(store.raw_puts, 1, "original put must have one owner");
    assert_eq!(
        store.raw_stages, 1,
        "original must not be durably staged twice"
    );
    assert_eq!(
        store
            .committed
            .iter()
            .filter(|value| *value == id.as_str())
            .count(),
        1
    );
    assert!(
        store.delayed_id.is_none(),
        "repeated original IO was reached"
    );
}

#[tokio::test]
async fn retain_once_public_graph_counts_original_persistence() {
    assert_positive_retained_once(false).await;
}

#[tokio::test]
async fn retain_once_public_graph_avoids_repeated_original_io_deadline() {
    assert_positive_retained_once(true).await;
}

#[tokio::test]
async fn retain_once_wrong_original_id_fails_without_retry() {
    let (graph, probe, inner, mut mapper) = setup(Mode::Agree, 2);
    let mut store = SlowStage::new(inner, usize::MAX);
    store.wrong_first_raw_id = true;
    assert_eq!(
        graph
            .invoke_observed(
                state(RAW),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await,
        Err(workflow_adk::AdkGraphError::Failed)
    );
    assert_eq!(store.raw_puts, 1);
    assert_eq!(store.raw_stages, 1);
    assert_eq!(store.committed.len(), 1);
    assert!(mapper.events().is_empty());
    assert!(probe.requests.lock().unwrap().is_empty());
    assert_eq!(probe.active.load(std::sync::atomic::Ordering::SeqCst), 0);
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

#[test]
fn legacy_runtime_wrong_original_id_is_invalid_without_retry() {
    let limit = std::num::NonZeroU64::new(100_000).unwrap();
    let mut store = SlowStage::new(InMemoryArtifactStore::new(limit, limit), usize::MAX);
    store.wrong_first_raw_id = true;
    assert!(matches!(
        workflow_runtime::prepare_untrusted_text(
            &mut store,
            RAW,
            workflow_runtime::NormalizationLimits::default(),
            std::time::Instant::now(),
        )
        .unwrap(),
        workflow_runtime::SentinelPreparation::Invalid {
            reason: workflow_runtime::NormalizationReason::InvalidPolicy,
            original_id: None,
        }
    ));
    assert_eq!(store.raw_puts, 1);
    assert_eq!(store.raw_stages, 1);
    assert_eq!(store.committed.len(), 1);
}

#[tokio::test]
async fn original_storage_error_is_hard_failure_before_evidence_or_provider() {
    let (graph, probe, _, mut mapper) = setup(Mode::Agree, 2);
    let limit = std::num::NonZeroU64::new(1).unwrap();
    let mut store = SlowStage::new(InMemoryArtifactStore::new(limit, limit), usize::MAX);
    assert_eq!(
        graph
            .invoke_observed(
                state(RAW),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await,
        Err(workflow_adk::AdkGraphError::Failed)
    );
    assert_eq!(store.raw_puts, 1);
    assert!(store.committed.is_empty());
    assert!(mapper.events().is_empty());
    assert!(probe.requests.lock().unwrap().is_empty());
    assert_eq!(probe.active.load(std::sync::atomic::Ordering::SeqCst), 0);
}
