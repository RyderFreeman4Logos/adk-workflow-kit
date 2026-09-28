use std::{cell::Cell, collections::BTreeMap, num::NonZeroU64};

use sha2::{Digest, Sha256};
use workflow_ir::compact_state::{CompactState, SourceRecord, SourceRef};
use workflow_runtime::{
    ArtifactError, ArtifactErrorKind, ArtifactId, ArtifactPage, ArtifactRef, ArtifactStore,
    CompactStateDelta, CompactStateExchangeError, Completeness, InMemoryArtifactStore, PageRequest,
    RetentionPolicy, StagedArtifact, TypedOutput, TypedPayload, WorkflowExchange,
    consume_compact_state_delta, publish_compact_state_delta, read_source_ref_page,
};

use super::{FaultInjectingStore, delta};

#[derive(Clone, Copy)]
enum SwitchMode {
    AfterFirst,
    FirstOnly,
}

struct ReadSwitchingStore {
    inner: InMemoryArtifactStore,
    target: ArtifactId,
    alternate: ArtifactId,
    mode: SwitchMode,
    target_reads: Cell<usize>,
}

impl ReadSwitchingStore {
    fn new(
        inner: InMemoryArtifactStore,
        target: ArtifactId,
        alternate: ArtifactId,
        mode: SwitchMode,
    ) -> Self {
        Self {
            inner,
            target,
            alternate,
            mode,
            target_reads: Cell::new(0),
        }
    }
}

impl ArtifactStore for ReadSwitchingStore {
    fn stage(&mut self, bytes: &[u8]) -> Result<StagedArtifact, ArtifactError> {
        self.inner.stage(bytes)
    }

    fn commit(&mut self, staged: StagedArtifact) -> Result<ArtifactId, ArtifactError> {
        self.inner.commit(staged)
    }

    fn read_page(
        &self,
        id: &ArtifactId,
        request: PageRequest,
    ) -> Result<ArtifactPage, ArtifactError> {
        let selected = if id == &self.target {
            let reads = self.target_reads.get();
            self.target_reads.set(reads + 1);
            match self.mode {
                SwitchMode::AfterFirst if reads > 0 => &self.alternate,
                SwitchMode::FirstOnly if reads == 0 => &self.alternate,
                _ => id,
            }
        } else {
            id
        };
        self.inner.read_page(selected, request)
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

#[test]
fn source_page_binds_returned_bytes_to_the_verified_read() {
    let mut inner = InMemoryArtifactStore::new(
        NonZeroU64::new(1 << 20).unwrap(),
        NonZeroU64::new(1 << 20).unwrap(),
    );
    let canonical = inner.put(b"abc").unwrap();
    let alternate = inner.put(b"XYZ").unwrap();
    let store =
        ReadSwitchingStore::new(inner, canonical.clone(), alternate, SwitchMode::AfterFirst);
    let sources = BTreeMap::from([(
        "source".to_owned(),
        SourceRecord {
            artifact_id: canonical.as_str().to_owned(),
            byte_len: 3,
        },
    )]);
    let source_ref = SourceRef {
        source: "source".to_owned(),
        artifact_id: canonical.as_str().to_owned(),
        start: 0,
        end: 3,
    };

    let page = read_source_ref_page(
        &store,
        &sources,
        &source_ref,
        0,
        NonZeroU64::new(3).unwrap(),
    )
    .unwrap();

    assert_eq!(page.bytes(), b"abc");
    assert_eq!(page.next_offset(), None);
}

#[test]
fn envelope_consumer_binds_admission_to_one_authenticated_buffer() {
    let mut inner = InMemoryArtifactStore::new(
        NonZeroU64::new(1 << 20).unwrap(),
        NonZeroU64::new(1 << 20).unwrap(),
    );
    let delta_bytes = serde_json::to_vec(&delta()).unwrap();
    let delta_artifact = inner.put(&delta_bytes).unwrap();
    let artifact_ref = ArtifactRef::new(
        delta_artifact.as_str(),
        format!("sha256:{}", delta_artifact.as_str()),
    )
    .unwrap();
    let valid_output = TypedOutput::new(
        TypedPayload::CompactState(CompactStateDelta::new(
            "compact_state",
            "add",
            vec![artifact_ref.clone()],
        )),
        Completeness::Complete,
    )
    .unwrap();
    let valid_envelope = WorkflowExchange::CodeInvestigation
        .publish(WorkflowExchange::GroundedAnswer, &mut inner, &valid_output)
        .unwrap();
    let invalid_bytes = serde_json::to_vec(&serde_json::json!({
        "from": "code.investigation",
        "to": "grounded.answer",
        "output": {
            "schema_version": 2,
            "node": "compact_state",
            "completeness": "complete",
            "payload": {
                "kind": "compact_state",
                "key": "compact_state",
                "op": "add",
                "artifacts": [{
                    "artifact_id": delta_artifact.as_str(),
                    "sha256": format!("sha256:{}", delta_artifact.as_str()),
                }],
            },
        },
    }))
    .unwrap();
    let valid_len = inner
        .read_page(
            &valid_envelope,
            PageRequest::new(0, NonZeroU64::new(1 << 20).unwrap()),
        )
        .unwrap()
        .bytes()
        .len();
    assert_eq!(invalid_bytes.len(), valid_len);
    let invalid_envelope = inner.put(&invalid_bytes).unwrap();
    let store = ReadSwitchingStore::new(
        inner,
        invalid_envelope.clone(),
        valid_envelope,
        SwitchMode::FirstOnly,
    );
    let mut state = CompactState::default();

    let error = consume_compact_state_delta(
        &store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &invalid_envelope,
        "compact_state",
        "add",
        &mut state,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        CompactStateExchangeError::DigestMismatch | CompactStateExchangeError::InvalidEnvelope
    ));
    assert!(state.sources().is_empty());
    assert!(state.entries().is_empty());
}

#[test]
fn invalid_delta_has_no_publication_side_effects() {
    let mut invalid = delta();
    invalid.entries[0].provenance.clear();
    let invalid_bytes = serde_json::to_vec(&invalid).unwrap();
    let invalid_artifact =
        ArtifactId::parse(format!("{:x}", Sha256::digest(&invalid_bytes))).unwrap();
    let mut store = FaultInjectingStore::new(None, None);

    let error = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &invalid,
    )
    .unwrap_err();

    assert_eq!(error, CompactStateExchangeError::InvalidStateDelta);
    assert_eq!(store.stage_calls, 0);
    assert_eq!(store.commit_calls, 0);
    assert!(store.events.is_empty());
    assert!(matches!(
        store.read_page(
            &invalid_artifact,
            PageRequest::new(0, NonZeroU64::new(1).unwrap()),
        ),
        Err(error) if error.kind() == ArtifactErrorKind::NotFound
    ));
}
