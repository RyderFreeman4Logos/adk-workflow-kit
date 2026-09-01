use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

const MULTI_TOOL_WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "multi-tools"
version = "1"
entry = "first"
[[nodes]]
id = "first"
kind = "agent"
model = { role = "worker", id = "worker-model", version = "1" }
tools = [{ id = "alpha", version = "1" }, { id = "beta", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "first"
to = "done"
"#;

fn test_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "workflow-adk-m3-03-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("unique test root");
    root
}

fn cleanup_test_root(path: &Path) {
    let metadata = fs::symlink_metadata(path).expect("test root metadata");
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        for entry in fs::read_dir(path).expect("test root entries") {
            cleanup_test_root(&entry.expect("test root entry").path());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("test root directory unlock");
    }
}

fn profile() -> ExecutionProfileV1 {
    ExecutionProfileV1::parse(
        &serde_json::to_vec(&json!({
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "worker-model",
                "version": "1",
                "model": "worker",
                "responses": [
                    {"calls": [
                        {"id": "call-alpha", "name": "alpha", "args": {}},
                        {"id": "call-beta", "name": "beta", "args": {}}
                    ]},
                    "{\"status\":\"finished\",\"output\":\"worker-response\"}"
                ]
            },
            "tools": [
                {"name": "alpha", "result": {"tool": "alpha"}, "input_schema": {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"additionalProperties":false}},
                {"name": "beta", "result": {"tool": "beta"}, "input_schema": {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"additionalProperties":false}},
                {"name": "gamma", "result": {"tool": "gamma"}, "input_schema": {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"additionalProperties":false}}
            ],
            "sandbox": {"capabilities": []}
        }))
        .expect("profile serializes"),
    )
    .expect("profile parses")
}

fn tool_events(root: &Path) -> BTreeMap<String, BTreeSet<String>> {
    fs::read_to_string(root.join("events.jsonl"))
        .expect("events exist")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .filter(|event| event["kind"] == "tool_completed")
        .fold(BTreeMap::new(), |mut tools, event| {
            let node = event["node_id"].as_str().expect("tool node").to_owned();
            let output = serde_json::to_string(&event).expect("tool event serializes");
            tools.entry(node).or_default().insert(output);
            tools
        })
}

#[test]
fn exposes_only_the_selected_node_toolset() {
    let root = test_root();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, MULTI_TOOL_WORKFLOW).expect("workflow fixture");
    let receipt = ExecutionBackend::run(&workflow, profile(), json!({"request": "public"}), &root)
        .expect("per-node selected tools execute");
    let events = tool_events(receipt.run_root());
    assert_eq!(events.len(), 1);
    assert!(
        events["first"]
            .iter()
            .any(|event| event.contains("\"tool\":\"alpha\""))
    );
    assert!(
        events["first"]
            .iter()
            .any(|event| event.contains("\"tool\":\"beta\""))
    );
    assert!(
        !events["first"]
            .iter()
            .any(|event| event.contains("\"tool\":\"gamma\""))
    );

    let protected = ["events.jsonl", "effects.sqlite", "checkpoint.sqlite"]
        .map(|name| receipt.run_root().join(name));
    let before = protected
        .each_ref()
        .map(|path| fs::read(path).expect("run state"));
    let profile_path = receipt.run_root().join("execution-profile.json");
    let mut changed: Value =
        serde_json::from_slice(&fs::read(&profile_path).expect("profile state"))
            .expect("profile JSON");
    changed["tools"][1]["result"] = json!({"tool": "beta-drift"});
    fs::write(
        &profile_path,
        serde_json::to_vec(&changed).expect("profile JSON"),
    )
    .expect("drift fixture");

    let error = ExecutionBackend::resume(&root, receipt.run_id())
        .expect_err("metadata drift rejects resume before effects");
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(
        protected
            .each_ref()
            .map(|path| fs::read(path).expect("run state")),
        before
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}
