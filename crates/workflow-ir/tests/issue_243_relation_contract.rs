use std::collections::{BTreeMap, BTreeSet};

use workflow_ir::compact_state::{
    CompactState, EntryKind, RelationKind, SourceIndex, SourceRecord, SourceRef, StateDelta,
    StateEntry, StateError, StateRelation, StateVersion, entry_id,
};

const ARTIFACT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LINK_ONE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LINK_TWO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const LINK_THREE: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const LINK_FOUR: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const LINK_FIVE: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const LINK_SIX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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
            artifact_id: ARTIFACT.to_owned(),
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

fn serialized_delta(entry: StateEntry) -> serde_json::Value {
    serde_json::to_value(delta(vec![entry])).expect("serialize fixture")
}

fn history_entry(start: u64, supersedes: &str, contradicts: &str) -> StateEntry {
    let mut entry = entry(EntryKind::Fact, "task", "plan", "same text");
    entry.provenance = BTreeSet::from([SourceRef {
        source: "notes".to_owned(),
        artifact_id: ARTIFACT.to_owned(),
        start,
        end: start + 16,
    }]);
    entry.supersedes.insert(supersedes.to_owned());
    entry.contradicts.insert(contradicts.to_owned());
    entry
}

#[test]
fn self_contained_delta_roundtrips_and_applies_to_existing_source() {
    let base = CompactState::default()
        .apply(&delta(vec![entry(
            EntryKind::Fact,
            "task",
            "plan",
            "ship now",
        )]))
        .expect("base state");
    let addition = entry(EntryKind::Fact, "task", "plan", "ship later");
    let encoded = serde_json::to_string(&delta(vec![addition])).expect("serialize delta");
    let decoded: StateDelta = serde_json::from_str(&encoded).expect("deserialize delta");

    let updated = base
        .apply(&decoded)
        .expect("self-contained delta applies with an existing source");
    assert_eq!(updated.entries().len(), 2);
    assert_eq!(updated.sources(), &sources());
}

#[test]
fn apply_rejects_delta_with_omitted_preexisting_source() {
    let base = CompactState::default()
        .apply(&delta(vec![entry(
            EntryKind::Fact,
            "task",
            "plan",
            "ship now",
        )]))
        .expect("base state");
    let addition = entry(EntryKind::Fact, "task", "plan", "ship later");
    let mut omitted_source = delta(vec![addition]);
    omitted_source.sources.clear();

    assert_eq!(base.apply(&omitted_source), Err(StateError::Source));

    let encoded = serde_json::to_string(&omitted_source).expect("serialize invalid delta");
    let direct_error =
        serde_json::from_str::<StateDelta>(&encoded).expect_err("missing source must not decode");
    assert!(
        direct_error
            .to_string()
            .contains(&StateError::Source.to_string())
    );
}

#[test]
fn same_identity_union_retains_exact_history_in_any_order() {
    let first = history_entry(0, LINK_ONE, LINK_TWO);
    let second = history_entry(16, LINK_THREE, LINK_FOUR);
    let third = history_entry(32, LINK_FIVE, LINK_SIX);
    let first_id = entry_id(&first).expect("identity");

    let first_state = CompactState::default()
        .apply(&delta(vec![first.clone()]))
        .expect("first state");
    let second_state = CompactState::default()
        .apply(&delta(vec![second.clone()]))
        .expect("second state");
    let third_state = CompactState::default()
        .apply(&delta(vec![third.clone()]))
        .expect("third state");

    let assert_exact_history = |state: &CompactState, expected: &[&StateEntry]| {
        let retained = state.entries().get(&first_id).expect("same identity");
        let expected_provenance = expected
            .iter()
            .flat_map(|entry| entry.provenance.iter().cloned())
            .collect::<BTreeSet<_>>();
        let expected_supersedes = expected
            .iter()
            .flat_map(|entry| entry.supersedes.iter().cloned())
            .collect::<BTreeSet<_>>();
        let expected_contradicts = expected
            .iter()
            .flat_map(|entry| entry.contradicts.iter().cloned())
            .collect::<BTreeSet<_>>();

        assert_eq!(state.entries().len(), 1);
        assert_eq!(retained.provenance, expected_provenance);
        assert_eq!(retained.supersedes, expected_supersedes);
        assert_eq!(retained.contradicts, expected_contradicts);
    };

    let forward = first_state.union(&second_state).expect("forward union");
    let reverse = second_state.union(&first_state).expect("reverse union");
    assert_exact_history(&forward, &[&first, &second]);
    assert_exact_history(&reverse, &[&first, &second]);
    assert_eq!(forward, reverse);
    assert_eq!(
        forward.to_json().expect("forward JSON"),
        reverse.to_json().expect("reverse JSON")
    );

    let idempotent = forward.union(&forward).expect("idempotent union");
    assert_eq!(idempotent, forward);
    assert_eq!(
        idempotent.to_json().expect("idempotent JSON"),
        forward.to_json().expect("forward JSON")
    );

    let left_associated = forward.union(&third_state).expect("left association");
    let right_associated = first_state
        .union(&second_state.union(&third_state).expect("inner union"))
        .expect("right association");
    assert_exact_history(&left_associated, &[&first, &second, &third]);
    assert_exact_history(&right_associated, &[&first, &second, &third]);
    assert_eq!(left_associated, right_associated);
    assert_eq!(
        left_associated.to_json().expect("left JSON"),
        right_associated.to_json().expect("right JSON")
    );
}

#[test]
fn scope_and_key_each_contribute_to_identity() {
    let base = entry(EntryKind::Fact, "task", "plan", "ship now");
    let different_scope = entry(EntryKind::Fact, "other", "plan", "ship now");
    let different_key = entry(EntryKind::Fact, "task", "other", "ship now");
    let base_id = entry_id(&base).expect("base identity");
    let scope_id = entry_id(&different_scope).expect("scope identity");
    let key_id = entry_id(&different_key).expect("key identity");

    let state = CompactState::default()
        .apply(&delta(vec![base, different_scope, different_key]))
        .expect("independent identity dimensions");

    assert_eq!(state.entries().len(), 3);
    assert_ne!(base_id, scope_id);
    assert_ne!(base_id, key_id);
    assert_ne!(scope_id, key_id);
    assert!(state.relations().is_empty(), "relations must be explicit");
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
    let current_id = entry_id(&current).expect("current identity");
    assert_eq!(
        union.relations(),
        vec![
            StateRelation {
                source: current_id.clone(),
                kind: RelationKind::Contradicts,
                target: old_id.clone(),
                target_present: true,
            },
            StateRelation {
                source: current_id.clone(),
                kind: RelationKind::Supersedes,
                target: missing_id.to_owned(),
                target_present: false,
            },
            StateRelation {
                source: current_id,
                kind: RelationKind::Supersedes,
                target: prior_id.clone(),
                target_present: true,
            },
        ]
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
fn exact_whitespace_history_is_retained() {
    for [first, second] in [["ship now", "ship  now"], ["ship now", "ship\nnow"]] {
        let state = CompactState::default()
            .apply(&delta(vec![
                entry(EntryKind::Fact, "task", "plan", first),
                entry(EntryKind::Fact, "task", "plan", second),
            ]))
            .expect("distinct source text");

        assert_eq!(state.entries().len(), 2);
        assert!(
            state
                .entries()
                .values()
                .any(|retained| retained.text == first)
        );
        assert!(
            state
                .entries()
                .values()
                .any(|retained| retained.text == second)
        );
    }
}

#[test]
fn direct_delta_decode_rejects_invalid_documents() {
    let base = entry(EntryKind::Fact, "task", "plan", "ship now");
    let mut documents: Vec<(serde_json::Value, StateError)> = Vec::new();

    let mut unsupported_version = serialized_delta(base.clone());
    unsupported_version["schema_version"] = serde_json::json!(2);
    documents.push((unsupported_version, StateError::Document));

    let mut blank_source_id = serialized_delta(base.clone());
    blank_source_id["sources"] = serde_json::json!({
        " ": {"artifact_id": ARTIFACT, "byte_len": 128}
    });
    documents.push((blank_source_id, StateError::Source));

    let mut invalid_source_digest = serialized_delta(base.clone());
    invalid_source_digest["sources"]["notes"]["artifact_id"] = serde_json::json!("A");
    documents.push((invalid_source_digest, StateError::Source));

    let mut empty_source = serialized_delta(base.clone());
    empty_source["sources"]["notes"]["byte_len"] = serde_json::json!(0);
    documents.push((empty_source, StateError::Source));

    let mut empty_provenance = serialized_delta(base.clone());
    empty_provenance["entries"][0]["provenance"] = serde_json::json!([]);
    documents.push((empty_provenance, StateError::Entry));

    let mut missing_source = serialized_delta(base.clone());
    missing_source["entries"][0]["provenance"][0]["source"] = serde_json::json!("missing");
    documents.push((missing_source, StateError::Source));

    let mut inverted_range = serialized_delta(base.clone());
    inverted_range["entries"][0]["provenance"][0]["start"] = serde_json::json!(16);
    inverted_range["entries"][0]["provenance"][0]["end"] = serde_json::json!(16);
    documents.push((inverted_range, StateError::Source));

    let mut out_of_bounds_range = serialized_delta(base.clone());
    out_of_bounds_range["entries"][0]["provenance"][0]["end"] = serde_json::json!(129);
    documents.push((out_of_bounds_range, StateError::Source));

    let self_link_entry = entry(EntryKind::Fact, "task", "plan", "ship  now");
    let mut self_link = serialized_delta(self_link_entry.clone());
    self_link["entries"][0]["contradicts"] =
        serde_json::json!([entry_id(&self_link_entry).unwrap()]);
    documents.push((self_link, StateError::Entry));

    let mut uppercase_link = serialized_delta(base);
    uppercase_link["entries"][0]["supersedes"] =
        serde_json::json!(["BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"]);
    documents.push((uppercase_link, StateError::Entry));

    for (document, expected) in documents {
        let encoded = serde_json::to_string(&document).expect("encode invalid fixture");
        assert_eq!(CompactState::from_json(&encoded), Err(expected));
        let direct_error = serde_json::from_str::<StateDelta>(&encoded)
            .expect_err("direct StateDelta decode accepted invalid input")
            .to_string();
        assert!(
            direct_error.contains(&expected.to_string()),
            "unexpected direct error: {direct_error}"
        );
    }
}

#[test]
fn direct_delta_decode_reports_swapped_artifact_binding_as_source_error() {
    let mut document = serialized_delta(entry(EntryKind::Fact, "task", "plan", "ship now"));
    document["entries"][0]["provenance"][0]["artifact_id"] =
        serde_json::json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let encoded = serde_json::to_string(&document).expect("encode fixture");
    assert_eq!(CompactState::from_json(&encoded), Err(StateError::Source));
    let error = serde_json::from_str::<StateDelta>(&encoded)
        .expect_err("swapped artifact must be rejected")
        .to_string();
    assert!(
        error.contains("invalid compact state source"),
        "unexpected error: {error}"
    );
}

#[test]
fn source_binding_is_immutable() {
    let state = CompactState::default()
        .apply(&delta(vec![entry(
            EntryKind::Fact,
            "task",
            "plan",
            "ship now",
        )]))
        .expect("initial source binding");

    let mut rebound = delta(Vec::new());
    rebound.sources.get_mut("notes").unwrap().artifact_id =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    assert_eq!(state.apply(&rebound), Err(StateError::Source));

    let mut resized = delta(Vec::new());
    resized.sources.get_mut("notes").unwrap().byte_len = 129;
    assert_eq!(state.apply(&resized), Err(StateError::Source));
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
