use std::{collections::BTreeMap, num::NonZeroU64};

use sha2::{Digest, Sha256};
use workflow_compiler::compile_str;
use workflow_ir::compact_state::{
    CompactState, EntryKind, SourceRecord, SourceRef, StateDelta, StateEntry, StateVersion,
};
use workflow_runtime::{
    ArtifactStore, CompactStateExchangeError, InMemoryArtifactStore, consume_compact_state_delta,
    publish_compact_state_delta, read_source_ref_page,
};

const WORKFLOW: &str = r#"
schema_version = 1
edges = []

[workflow]
id = "compact-state-runtime"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[compact_state_exchange]
from = "review"
to = "multi.hop"
"#;

fn delta(source_id: &str, byte_len: u64) -> StateDelta {
    StateDelta {
        schema_version: StateVersion,
        sources: BTreeMap::from([(
            "compiled-source".to_owned(),
            SourceRecord {
                artifact_id: source_id.to_owned(),
                byte_len,
            },
        )]),
        entries: vec![StateEntry {
            kind: EntryKind::Fact,
            scope: "compiled".to_owned(),
            key: "source".to_owned(),
            text: "compiled IR source".to_owned(),
            provenance: [SourceRef {
                source: "compiled-source".to_owned(),
                artifact_id: source_id.to_owned(),
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
fn compiled_ir_exchange_drives_artifact_publish_consume_and_progressive_source_pages() {
    let plan = compile_str("compact-state-runtime.workflow.toml", WORKFLOW)
        .expect("authored compact-state exchange should compile");
    let exchange = plan
        .ir()
        .compact_state_exchange()
        .expect("compiled IR should retain the exchange");
    let source_bytes = b"compiled IR source bytes";
    let source_id = format!("{:x}", Sha256::digest(source_bytes));
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(1 << 20).unwrap(),
        NonZeroU64::new(7).unwrap(),
    );
    assert_eq!(store.put(source_bytes).unwrap().as_str(), source_id);
    let delta = delta(&source_id, source_bytes.len() as u64);

    let receipt = publish_compact_state_delta(&mut store, exchange.from(), exchange.to(), &delta)
        .expect("runtime publication should succeed");
    let mut state = CompactState::default();
    consume_compact_state_delta(
        &store,
        exchange.from(),
        exchange.to(),
        receipt.envelope_artifact(),
        "compact_state",
        "add",
        &mut state,
    )
    .expect("compiled IR exchange should drive runtime consumption");

    let source_ref = state
        .entries()
        .values()
        .next()
        .expect("consumed delta should contain an entry")
        .provenance
        .iter()
        .next()
        .expect("consumed entry should retain provenance");
    let first = read_source_ref_page(
        &store,
        state.sources(),
        source_ref,
        0,
        NonZeroU64::new(3).unwrap(),
    )
    .unwrap();
    assert_eq!(first.bytes(), b"com");
    assert_eq!(first.next_offset(), Some(3));
    let second = read_source_ref_page(
        &store,
        state.sources(),
        source_ref,
        first.next_offset().unwrap(),
        NonZeroU64::new(3).unwrap(),
    )
    .unwrap();
    assert_eq!(second.bytes(), b"pil");
    assert_eq!(second.next_offset(), None);
    assert_eq!(
        read_source_ref_page(
            &store,
            state.sources(),
            &SourceRef {
                source: "missing-source".to_owned(),
                artifact_id: source_id,
                start: 0,
                end: 1,
            },
            0,
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap_err(),
        CompactStateExchangeError::MissingSource
    );
}
