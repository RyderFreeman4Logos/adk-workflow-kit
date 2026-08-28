use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::json;
use workflow_runtime::{EffectCommit, EffectJournal, EffectKey};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "workflow-runtime-m1-12-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("test root must be unique");
    root
}

#[test]
fn effect_journal_commits_one_result_for_one_stable_key() {
    let root = root();
    let journal = EffectJournal::open(root.join("effects.sqlite")).expect("journal");
    let key = EffectKey::new("run-1", "node-1", "send", &json!({"to":"a","body":"b"}));
    let result = json!({"accepted":true});

    assert_eq!(
        journal.commit(&key, &result).expect("first commit"),
        EffectCommit::Committed
    );
    assert_eq!(
        journal
            .commit(&key, &json!({"accepted":false}))
            .expect("duplicate commit"),
        EffectCommit::AlreadyCommitted(result),
    );
    assert_eq!(journal.committed_count().expect("count"), 1);
    assert_eq!(
        EffectKey::new("run-1", "node-1", "send", &json!({"body":"b","to":"a"})),
        key
    );

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn effect_journal_rejects_corrupt_database() {
    let root = root();
    fs::write(root.join("effects.sqlite"), b"not sqlite").expect("corrupt journal");
    assert!(EffectJournal::open(root.join("effects.sqlite")).is_err());
    fs::remove_dir_all(root).expect("cleanup");
}
