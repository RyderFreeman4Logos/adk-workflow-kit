use std::{collections::BTreeMap, num::NonZeroU64};

use sha2::{Digest, Sha256};
use workflow_ir::compact_state::{
    CompactState, EntryKind, SourceRecord, SourceRef, StateDelta, StateEntry, StateVersion,
};
use workflow_runtime::{
    ArtifactError, ArtifactErrorKind, ArtifactId, ArtifactPage, ArtifactRef, ArtifactStore,
    CompactStateDelta, CompactStateExchangeError, CompactStatePublicationPhase, Completeness,
    InMemoryArtifactStore, PageRequest, RetentionPolicy, StagedArtifact, TypedOutput, TypedPayload,
    WorkflowExchange, consume_compact_state_delta, publish_compact_state_delta,
    read_source_ref_page,
};

fn source_bytes() -> &'static [u8] {
    b"compact state source bytes"
}

fn source_id() -> String {
    format!("{:x}", Sha256::digest(source_bytes()))
}

fn delta() -> StateDelta {
    let source = source_id();
    StateDelta {
        schema_version: StateVersion,
        sources: BTreeMap::from([(
            "source-a".to_owned(),
            SourceRecord {
                artifact_id: source.clone(),
                byte_len: source_bytes().len() as u64,
            },
        )]),
        entries: vec![StateEntry {
            kind: EntryKind::Fact,
            scope: "scope".to_owned(),
            key: "key".to_owned(),
            text: "text".to_owned(),
            provenance: [SourceRef {
                source: "source-a".to_owned(),
                artifact_id: source,
                start: 0,
                end: 6,
            }]
            .into_iter()
            .collect(),
            supersedes: Default::default(),
            contradicts: Default::default(),
        }],
    }
}

#[test]
fn publishes_and_consumes_artifact_backed_delta_and_pages_source() {
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(1 << 20).unwrap(),
        NonZeroU64::new(7).unwrap(),
    );
    let source_artifact = store.put(source_bytes()).unwrap();
    assert_eq!(source_artifact.as_str(), source_id());
    let receipt = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &delta(),
    )
    .unwrap();

    let mut state = CompactState::default();
    consume_compact_state_delta(
        &store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        receipt.envelope_artifact(),
        "compact_state",
        "add",
        &mut state,
    )
    .unwrap();

    let source_ref = state
        .entries()
        .values()
        .next()
        .unwrap()
        .provenance
        .iter()
        .next()
        .unwrap()
        .clone();
    let page = read_source_ref_page(
        &store,
        state.sources(),
        &source_ref,
        0,
        NonZeroU64::new(3).unwrap(),
    )
    .unwrap();
    assert_eq!(page.bytes(), b"com");
    assert_eq!(page.next_offset(), Some(3));
    let page_debug = format!("{page:?}");
    assert!(!page_debug.contains("[99, 111, 109]"));
    let tail = read_source_ref_page(
        &store,
        state.sources(),
        &source_ref,
        page.next_offset().unwrap(),
        NonZeroU64::new(3).unwrap(),
    )
    .unwrap();
    assert_eq!(tail.bytes(), b"pac");
    assert_eq!(tail.next_offset(), None);
    assert_eq!(
        read_source_ref_page(
            &store,
            state.sources(),
            &SourceRef {
                source: "missing".to_owned(),
                artifact_id: source_id(),
                start: 0,
                end: 1,
            },
            0,
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap_err(),
        workflow_runtime::CompactStateExchangeError::MissingSource
    );
    let rebound = SourceRef {
        artifact_id: "0".repeat(64),
        ..source_ref.clone()
    };
    assert_eq!(
        read_source_ref_page(
            &store,
            state.sources(),
            &rebound,
            0,
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap_err(),
        workflow_runtime::CompactStateExchangeError::SourceBinding
    );
    assert_eq!(
        read_source_ref_page(
            &store,
            state.sources(),
            &source_ref,
            7,
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap_err(),
        workflow_runtime::CompactStateExchangeError::InvalidSpan
    );
    assert!(!format!("{receipt:?}").contains("compact state source bytes"));
}

#[test]
fn rejects_wrong_compact_state_key_operation_and_payload_kind() {
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(1 << 20).unwrap(),
        NonZeroU64::new(7).unwrap(),
    );
    let delta_artifact = store.put(&serde_json::to_vec(&delta()).unwrap()).unwrap();
    let artifact_ref = ArtifactRef::new(
        delta_artifact.as_str(),
        format!("sha256:{}", delta_artifact.as_str()),
    )
    .unwrap();
    let wrong_key = TypedOutput::new(
        TypedPayload::CompactState(CompactStateDelta::new(
            "wrong_key",
            "add",
            vec![artifact_ref.clone()],
        )),
        Completeness::Complete,
    )
    .unwrap();
    let wrong_key_artifact = WorkflowExchange::CodeInvestigation
        .publish(WorkflowExchange::GroundedAnswer, &mut store, &wrong_key)
        .unwrap();
    let mut state = CompactState::default();
    assert!(
        consume_compact_state_delta(
            &store,
            WorkflowExchange::CodeInvestigation,
            WorkflowExchange::GroundedAnswer,
            &wrong_key_artifact,
            "compact_state",
            "add",
            &mut state,
        )
        .is_err()
    );

    let wrong_op = TypedOutput::new(
        TypedPayload::CompactState(CompactStateDelta::new(
            "compact_state",
            "set",
            vec![artifact_ref.clone()],
        )),
        Completeness::Complete,
    )
    .unwrap();
    let wrong_op_artifact = WorkflowExchange::CodeInvestigation
        .publish(WorkflowExchange::GroundedAnswer, &mut store, &wrong_op)
        .unwrap();
    assert!(
        consume_compact_state_delta(
            &store,
            WorkflowExchange::CodeInvestigation,
            WorkflowExchange::GroundedAnswer,
            &wrong_op_artifact,
            "compact_state",
            "add",
            &mut state,
        )
        .is_err()
    );

    let wrong_kind = TypedOutput::new(
        TypedPayload::IssueCard(workflow_runtime::IssueCard::new("id", "open", vec![])),
        Completeness::Complete,
    )
    .unwrap();
    let wrong_kind_artifact = WorkflowExchange::CodeInvestigation
        .publish(WorkflowExchange::GroundedAnswer, &mut store, &wrong_kind)
        .unwrap();
    assert!(
        consume_compact_state_delta(
            &store,
            WorkflowExchange::CodeInvestigation,
            WorkflowExchange::GroundedAnswer,
            &wrong_kind_artifact,
            "compact_state",
            "add",
            &mut state,
        )
        .is_err()
    );
}

#[test]
fn rejected_delta_does_not_mutate_state() {
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(1 << 20).unwrap(),
        NonZeroU64::new(7).unwrap(),
    );
    let bad_artifact = store.put(br#"{}"#).unwrap();
    let artifact_ref = ArtifactRef::new(
        bad_artifact.as_str(),
        format!("sha256:{}", bad_artifact.as_str()),
    )
    .unwrap();
    let output = TypedOutput::new(
        TypedPayload::CompactState(CompactStateDelta::new(
            "compact_state",
            "add",
            vec![artifact_ref],
        )),
        Completeness::Complete,
    )
    .unwrap();
    let envelope = WorkflowExchange::CodeInvestigation
        .publish(WorkflowExchange::GroundedAnswer, &mut store, &output)
        .unwrap();
    let mut state = CompactState::default();
    assert!(
        consume_compact_state_delta(
            &store,
            WorkflowExchange::CodeInvestigation,
            WorkflowExchange::GroundedAnswer,
            &envelope,
            "compact_state",
            "add",
            &mut state,
        )
        .is_err()
    );
    assert!(state.sources().is_empty());
    assert!(state.entries().is_empty());
}

#[test]
fn returned_delta_artifact_is_content_addressed() {
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(1 << 20).unwrap(),
        NonZeroU64::new(7).unwrap(),
    );
    let receipt = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &delta(),
    )
    .unwrap();
    let bytes = serde_json::to_vec(&delta()).unwrap();
    let expected = ArtifactId::parse(format!("{:x}", Sha256::digest(&bytes))).unwrap();
    assert_eq!(receipt.delta_artifact(), &expected);
    assert_eq!(receipt.byte_len(), bytes.len() as u64);
}

struct FaultInjectingStore {
    inner: InMemoryArtifactStore,
    fail_stage_on: Option<usize>,
    fail_commit_on: Option<usize>,
    wrong_id_on: Option<usize>,
    stage_calls: usize,
    commit_calls: usize,
    events: Vec<&'static str>,
}

impl FaultInjectingStore {
    fn new(fail_stage_on: Option<usize>, fail_commit_on: Option<usize>) -> Self {
        Self {
            inner: InMemoryArtifactStore::new(
                NonZeroU64::new(1 << 20).unwrap(),
                NonZeroU64::new(7).unwrap(),
            ),
            fail_stage_on,
            fail_commit_on,
            wrong_id_on: None,
            stage_calls: 0,
            commit_calls: 0,
            events: Vec::new(),
        }
    }
}

fn injected_artifact_error() -> ArtifactError {
    match InMemoryArtifactStore::new(NonZeroU64::new(1).unwrap(), NonZeroU64::new(1).unwrap())
        .stage(&[])
    {
        Ok(_) => unreachable!("empty artifact staging must fail"),
        Err(error) => error,
    }
}

impl ArtifactStore for FaultInjectingStore {
    fn stage(&mut self, bytes: &[u8]) -> Result<StagedArtifact, ArtifactError> {
        self.stage_calls += 1;
        self.events.push("stage");
        if self.fail_stage_on == Some(self.stage_calls) {
            self.fail_stage_on = None;
            return Err(injected_artifact_error());
        }
        self.inner.stage(bytes)
    }

    fn commit(&mut self, staged: StagedArtifact) -> Result<ArtifactId, ArtifactError> {
        self.commit_calls += 1;
        self.events.push("commit");
        if self.fail_commit_on == Some(self.commit_calls) {
            self.fail_commit_on = None;
            return Err(injected_artifact_error());
        }
        let committed = self.inner.commit(staged)?;
        if self.wrong_id_on == Some(self.commit_calls) {
            self.wrong_id_on = None;
            return Ok(wrong_artifact_id());
        }
        Ok(committed)
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

fn canonical_delta_artifact() -> ArtifactId {
    let bytes = serde_json::to_vec(&delta()).unwrap();
    ArtifactId::parse(format!("{:x}", Sha256::digest(bytes))).unwrap()
}

fn wrong_artifact_id() -> ArtifactId {
    ArtifactId::parse("f".repeat(64)).unwrap()
}

#[test]
fn post_visibility_wrong_delta_id_exposes_canonical_recovery_handle() {
    let mut store = FaultInjectingStore::new(None, None);
    store.wrong_id_on = Some(1);
    let error = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &delta(),
    )
    .unwrap_err();
    let recovery_id = error
        .partial_publication()
        .expect("post-visibility wrong ID must expose a recovery handle")
        .delta_artifact()
        .clone();

    assert_eq!(recovery_id, canonical_delta_artifact());
    assert_ne!(recovery_id, wrong_artifact_id());
    assert_eq!(store.events, ["stage", "stage", "commit"]);
    assert!(
        store
            .read_page(
                &recovery_id,
                PageRequest::new(0, NonZeroU64::new(1).unwrap())
            )
            .is_ok()
    );
    assert!(matches!(
        store.read_page(
            &wrong_artifact_id(),
            PageRequest::new(0, NonZeroU64::new(1).unwrap()),
        ),
        Err(error) if error.kind() == ArtifactErrorKind::NotFound
    ));
    assert!(!format!("{error:?}").contains(recovery_id.as_str()));
    assert!(!error.to_string().contains(recovery_id.as_str()));
}

#[test]
fn post_visibility_wrong_envelope_id_preserves_delta_recovery_handle() {
    let mut store = FaultInjectingStore::new(None, None);
    store.wrong_id_on = Some(2);
    let error = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &delta(),
    )
    .unwrap_err();
    let recovery_id = error
        .partial_publication()
        .expect("post-visibility wrong ID must expose a recovery handle")
        .delta_artifact()
        .clone();

    assert_eq!(recovery_id, canonical_delta_artifact());
    assert_eq!(store.events, ["stage", "stage", "commit", "commit"]);
    assert!(
        store
            .read_page(
                &recovery_id,
                PageRequest::new(0, NonZeroU64::new(1).unwrap())
            )
            .is_ok()
    );
    assert!(!format!("{error:?}").contains(recovery_id.as_str()));
    assert!(!error.to_string().contains(recovery_id.as_str()));
}

#[test]
fn precommit_delta_error_remains_without_partial_recovery_handle() {
    let mut store = FaultInjectingStore::new(None, Some(1));
    let error = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &delta(),
    )
    .unwrap_err();

    assert_eq!(error, CompactStateExchangeError::Artifact);
    assert!(error.partial_publication().is_none());
    assert_eq!(store.events, ["stage", "stage", "commit"]);
    assert!(matches!(
        store.read_page(
            &canonical_delta_artifact(),
            PageRequest::new(0, NonZeroU64::new(1).unwrap()),
        ),
        Err(error) if error.kind() == ArtifactErrorKind::NotFound
    ));
}

#[test]
fn prepares_both_artifacts_before_visibility_on_stage_failure() {
    let mut store = FaultInjectingStore::new(Some(2), None);
    let error = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &delta(),
    )
    .unwrap_err();
    assert_eq!(error, CompactStateExchangeError::Artifact);
    assert!(error.partial_publication().is_none());
    assert_eq!(store.events, ["stage", "stage"]);
    assert!(matches!(
        store.read_page(
            &canonical_delta_artifact(),
            PageRequest::new(0, NonZeroU64::new(1).unwrap()),
        ),
        Err(error) if error.kind() == ArtifactErrorKind::NotFound
    ));
}

#[test]
fn retains_committed_delta_for_idempotent_retry_after_envelope_commit_failure() {
    let mut store = FaultInjectingStore::new(None, Some(2));
    let error = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &delta(),
    )
    .unwrap_err();
    let partial = error
        .partial_publication()
        .expect("post-delta failure must expose a recovery handle");
    assert_eq!(
        partial.phase(),
        CompactStatePublicationPhase::PostDeltaCommit
    );
    let recovery_id = partial.delta_artifact().clone();
    assert!(!format!("{error:?}").contains(recovery_id.as_str()));
    assert!(!error.to_string().contains(recovery_id.as_str()));
    assert_eq!(store.events, ["stage", "stage", "commit", "commit"]);
    assert!(
        store
            .read_page(
                &recovery_id,
                PageRequest::new(0, NonZeroU64::new(1).unwrap())
            )
            .is_ok()
    );
    assert_eq!(
        store.retention(&recovery_id).unwrap(),
        RetentionPolicy::Retain
    );

    let receipt = publish_compact_state_delta(
        &mut store,
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        &delta(),
    )
    .unwrap();
    assert_eq!(receipt.delta_artifact(), &recovery_id);
    assert_eq!(
        store.events,
        [
            "stage", "stage", "commit", "commit", "stage", "stage", "commit", "commit"
        ]
    );
}
