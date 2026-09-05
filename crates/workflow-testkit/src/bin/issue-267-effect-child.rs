use std::{env, fs, thread, time::Duration};

use serde_json::json;
use workflow_runtime::{EffectCommit, EffectJournal, EffectKey};

fn main() {
    let mode = env::var("ISSUE_267_MODE").expect("synthetic mode is set");
    let journal_path = env::var("ISSUE_267_JOURNAL").expect("synthetic journal path is set");
    let marker_path = env::var("ISSUE_267_MARKER").expect("synthetic marker path is set");
    let journal = EffectJournal::open(journal_path).expect("journal opens");
    let key = EffectKey::new(
        "run-issue-267",
        "write_effect",
        "publish-investigation",
        &json!({"artifact": "investigation.json"}),
    );
    let result = match journal
        .commit(&key, &json!({"accepted": true}))
        .expect("effect commits")
    {
        EffectCommit::Committed => "committed",
        EffectCommit::AlreadyCommitted(_) => "already",
    };
    fs::write(marker_path, result).expect("marker writes");
    if mode == "commit-and-wait" {
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }
}
