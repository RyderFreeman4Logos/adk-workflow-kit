use std::collections::{BTreeMap, BTreeSet};

use workflow_ir::compact_state::{
    CompactState, EntryKind, RelationKind, SourceIndex, SourceRecord, SourceRef, StateDelta,
    StateEntry, StateError, StateVersion, entry_id,
};

const ARTIFACT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn sources() -> SourceIndex {
    BTreeMap::from([(
        "notes".to_owned(),
        SourceRecord {
            artifact_id: ARTIFACT.to_owned(),
            byte_len: 128,
        },
    )])
}

fn entry(kind: EntryKind, scope: &str, key: &str, text: &str) -> StateEntry {
    StateEntry {
        kind,
        scope: scope.to_owned(),
        key: key.to_owned(),
        text: text.to_owned(),
        provenance: BTreeSet::from([SourceRef {
            source: "notes".to_owned(),
            start: 0,
            end: 16,
        }]),
        supersedes: BTreeSet::new(),
        contradicts: BTreeSet::new(),
    }
}

fn delta(entries: Vec<StateEntry>) -> StateDelta {
    StateDelta {
        schema_version: StateVersion,
        sources: sources(),
        entries,
    }
}

#[test]
fn relation_union_roundtrip_retains_history_and_missing_targets() {
    let old = entry(EntryKind::Fact, "task", "plan", "ship now");
    let prior = entry(EntryKind::Proposal, "task", "plan", "ship later");
    let old_id = entry_id(&old).expect("old identity");
    let prior_id = entry_id(&prior).expect("prior identity");
    let missing_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let mut current = entry(EntryKind::Decision, "task", "plan", "do not ship");
    current.contradicts.insert(old_id.clone());
    current.supersedes.insert(prior_id.clone());
    current.supersedes.insert(missing_id.to_owned());

    let left = CompactState::default()
        .apply(&delta(vec![old.clone()]))
        .expect("old state");
    let right = CompactState::default()
        .apply(&delta(vec![prior.clone(), current.clone()]))
        .expect("new state");
    let union = left.union(&right).expect("additive union");

    assert_eq!(union.entries().len(), 3, "history is never deleted");
    let relations = union.relations();
    assert_eq!(relations.len(), 3);
    assert!(relations.iter().any(|relation| {
        relation.source == entry_id(&current).expect("current identity")
            && relation.target == old_id
            && relation.target_present
            && relation.kind == RelationKind::Contradicts
    }));
    assert!(relations.iter().any(|relation| {
        relation.target == prior_id
            && relation.target_present
            && relation.kind == RelationKind::Supersedes
    }));
    assert!(
        relations
            .iter()
            .any(|relation| { relation.target == missing_id && !relation.target_present })
    );

    let encoded = union.to_json().expect("serialize state");
    let decoded: CompactState = serde_json::from_str(&encoded).expect("deserialize state");
    assert_eq!(decoded, union, "serialization preserves the reducer state");
    assert_eq!(decoded.to_json().expect("serialize decoded state"), encoded);

    let reversed = CompactState::default()
        .apply(&delta(vec![current, old, prior]))
        .expect("reversed insertion order");
    assert_eq!(reversed.to_json().expect("stable serialization"), encoded);
}

#[test]
fn scoped_and_kind_differences_do_not_infer_relations() {
    let scoped = entry(EntryKind::Fact, "other", "plan", "ship now");
    let proposal = entry(EntryKind::Proposal, "task", "plan", "ship now");
    let decision = entry(EntryKind::Decision, "task", "plan", "ship now");
    let state = CompactState::default()
        .apply(&delta(vec![scoped, proposal, decision]))
        .expect("unlinked entries");

    assert_eq!(state.entries().len(), 3);
    assert!(state.relations().is_empty(), "relations must be explicit");
}

#[test]
fn malformed_and_self_links_fail_closed() {
    let mut malformed = entry(EntryKind::Fact, "task", "plan", "ship now");
    malformed.supersedes.insert("not-a-digest".to_owned());
    assert_eq!(
        CompactState::default().apply(&delta(vec![malformed])),
        Err(StateError::Entry)
    );

    let mut self_link = entry(EntryKind::Fact, "task", "plan", "ship now");
    self_link
        .contradicts
        .insert(entry_id(&self_link).expect("self identity"));
    assert_eq!(
        CompactState::default().apply(&delta(vec![self_link])),
        Err(StateError::Entry)
    );
}
