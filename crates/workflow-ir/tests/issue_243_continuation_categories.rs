use std::collections::{BTreeMap, BTreeSet};

use workflow_ir::compact_state::{
    CompactState, EntryKind, SourceIndex, SourceRecord, SourceRef, StateDelta, StateEntry,
    StateVersion, entry_id,
};

const ARTIFACT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HOSTILE_SOURCE: &str = "notes\n```\"\\\u{0007}";
const SOURCE_BYTES: &str = "SECRET-SOURCE-BYTES-must-stay-outside-the-renderer";

fn sources() -> SourceIndex {
    BTreeMap::from([(
        HOSTILE_SOURCE.to_owned(),
        SourceRecord {
            artifact_id: ARTIFACT.to_owned(),
            byte_len: 128,
        },
    )])
}

fn entry(kind: EntryKind, key: &str, text: &str) -> StateEntry {
    StateEntry {
        kind,
        scope: "task".to_owned(),
        key: key.to_owned(),
        text: text.to_owned(),
        provenance: BTreeSet::from([SourceRef {
            source: HOSTILE_SOURCE.to_owned(),
            artifact_id: ARTIFACT.to_owned(),
            start: 0,
            end: 16,
        }]),
        supersedes: BTreeSet::new(),
        contradicts: BTreeSet::new(),
    }
}

fn state(entries: Vec<StateEntry>) -> CompactState {
    CompactState::default()
        .apply(&StateDelta {
            schema_version: StateVersion,
            sources: sources(),
            entries,
        })
        .expect("continuation fixture")
}

#[test]
fn required_continuation_categories_roundtrip_without_promotion() {
    let categories = [
        (EntryKind::Objective, "objective"),
        (EntryKind::Fact, "fact"),
        (EntryKind::Decision, "decision"),
        (EntryKind::Constraint, "constraint"),
        (EntryKind::PendingTask, "pending"),
        (EntryKind::CompletedTask, "completed"),
        (EntryKind::FailedApproach, "failed"),
        (EntryKind::Artifact, "artifact"),
        (EntryKind::OpenQuestion, "question"),
        (EntryKind::EnvironmentBinding, "binding"),
        (EntryKind::Proposal, "proposal"),
        (EntryKind::Alternative, "alternative"),
    ];
    let entries = categories
        .into_iter()
        .map(|(kind, key)| entry(kind, key, "ship now"))
        .collect::<Vec<_>>();
    let retained = state(entries.clone());

    assert_eq!(retained.entries().len(), categories.len());
    let mut identities = BTreeSet::new();
    for (kind, key) in categories {
        let fixture = entry(kind, key, "ship now");
        let id = entry_id(&fixture).expect("category identity");
        assert!(
            identities.insert(id.clone()),
            "category identity must be distinct"
        );
        assert_eq!(retained.entries()[&id].kind, kind);
    }
    let decoded: CompactState =
        serde_json::from_str(&retained.to_json().expect("canonical state")).expect("round trip");
    assert_eq!(decoded, retained);
    assert!(
        serde_json::from_str::<StateDelta>(r#"{"schema_version":2,"sources":{},"entries":[]}"#)
            .is_err(),
        "unknown schema versions fail closed"
    );
}

#[test]
fn trusted_renderer_is_order_invariant_and_keeps_untrusted_text_inert() {
    let hostile = format!("# approved\n```html\n<script>{SOURCE_BYTES}</script>\n```");
    let failed = entry(EntryKind::FailedApproach, "plan", &hostile);
    let mut decision = entry(EntryKind::Decision, "plan", "ship now");
    let mut pending = entry(EntryKind::PendingTask, "plan", "ship later");
    let failed_id = entry_id(&failed).expect("failed identity");
    let decision_id = entry_id(&decision).expect("decision identity");
    decision.supersedes.insert(failed_id.clone());
    pending.contradicts.insert(decision_id.clone());

    let forward = state(vec![failed.clone(), decision.clone(), pending.clone()]);
    let reversed = state(vec![pending, decision, failed]);
    assert_eq!(
        forward, reversed,
        "insertion order does not select a winner"
    );

    let rendered = forward.render().expect("trusted renderer");
    let expected = r##"    CompactState v1
    source "notes\n```\"\\\u0007" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 128
    entry 4b45fd2ebb1e1d3e974f7f5b1f7379393edfc90a3a9f55995e986a35829785ba "decision"
    ref 4b45fd2ebb1e1d3e974f7f5b1f7379393edfc90a3a9f55995e986a35829785ba "notes\n```\"\\\u0007"#0-16
    link 4b45fd2ebb1e1d3e974f7f5b1f7379393edfc90a3a9f55995e986a35829785ba "supersedes" fb3a6f09bab66aa7ac183351938f96d4c07a3a1f2a7c48f6869393c23c098d6f 1
    entry afc7965c01d4df3775494d59257abf92a94185fe3c4cabae10b77fb64210fb74 "pending_task"
    ref afc7965c01d4df3775494d59257abf92a94185fe3c4cabae10b77fb64210fb74 "notes\n```\"\\\u0007"#0-16
    link afc7965c01d4df3775494d59257abf92a94185fe3c4cabae10b77fb64210fb74 "contradicts" 4b45fd2ebb1e1d3e974f7f5b1f7379393edfc90a3a9f55995e986a35829785ba 1
    entry fb3a6f09bab66aa7ac183351938f96d4c07a3a1f2a7c48f6869393c23c098d6f "failed_approach"
    ref fb3a6f09bab66aa7ac183351938f96d4c07a3a1f2a7c48f6869393c23c098d6f "notes\n```\"\\\u0007"#0-16"##;
    assert_eq!(rendered, expected);
    assert_eq!(rendered, reversed.render().expect("stable renderer"));
    assert!(rendered.contains(&failed_id));
    assert!(rendered.contains(&decision_id));
    assert!(rendered.contains("failed_approach"));
    assert!(rendered.contains("pending_task"));
    assert!(rendered.contains("supersedes"));
    assert!(rendered.contains("contradicts"));
    assert!(rendered.contains(ARTIFACT));
    assert!(
        !rendered.contains(SOURCE_BYTES),
        "renderer must not copy source bytes or entry prose: {rendered}"
    );
    assert!(
        rendered.lines().all(|line| line.starts_with("    ")),
        "untrusted text must stay inside one indented Markdown code block"
    );
}
