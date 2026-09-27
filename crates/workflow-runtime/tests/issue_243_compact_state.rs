use std::{collections::BTreeMap, num::NonZeroU64};

use sha2::{Digest, Sha256};
use workflow_ir::compact_state::{
    CompactState, EntryKind, SourceRecord, SourceRef, StateDelta, StateEntry, StateVersion,
};
use workflow_runtime::{
    ArtifactId, ArtifactRef, ArtifactStore, CompactStateDelta, Completeness, InMemoryArtifactStore,
    TypedOutput, TypedPayload, WorkflowExchange, consume_compact_state_delta,
    publish_compact_state_delta, read_source_ref_page,
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
