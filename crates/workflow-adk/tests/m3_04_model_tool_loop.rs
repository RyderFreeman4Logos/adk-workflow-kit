use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::Connection;
use serde_json::{Value, json};
use workflow_adk::execution::{
    ExecutionBackend, ExecutionError, ExecutionErrorKind, ExecutionProfileV1, ExecutionReceipt,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "tool-loop"
version = "1"
entry = "work"
[[nodes]]
id = "work"
kind = "agent"
model = { role = "worker", id = "worker", version = "1" }
tools = [{ id = "search_code", version = "1" }, { id = "read_source_range", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "work"
to = "done"
"#;

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "m3-04-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    root
}

fn loop_policy() -> Value {
    json!({
        "schema_version": 1,
        "max_model_iterations": 100,
        "max_total_tool_calls": 100,
        "max_tool_calls_per_tool": 100,
        "wall_time_ms": 60000,
        "idle_time_ms": 60000,
        "tool_time_ms": 60000,
        "max_tool_output_bytes": 65536
    })
}

fn profile_with(responses: Vec<Value>, policy: Option<Value>) -> ExecutionProfileV1 {
    let mut profile = json!({
        "schema_version": 1,
        "model": { "provider": "fake", "name": "worker", "version": "1", "model": "worker", "responses": responses },
        "tools": [
            {"name":"search_code","result":{"found":true}},
            {"name":"read_source_range","result":{"source":"ok"}}
        ],
        "sandbox": {"capabilities": []}
    });
    if let Some(policy) = policy {
        profile["loop_policy"] = policy;
    }
    ExecutionProfileV1::parse(&serde_json::to_vec(&profile).unwrap()).unwrap()
}

fn profile() -> ExecutionProfileV1 {
    profile_with(
        vec![
            json!({"calls": [{"id":"call-search","name":"search_code","args":{"query":"needle"}}]}),
            json!({"calls": [{"id":"call-read","name":"read_source_range","args":{"path":"src/lib.rs","start":1}}]}),
            json!("done"),
        ],
        None,
    )
}

fn run(profile: ExecutionProfileV1) -> (PathBuf, Result<ExecutionReceipt, ExecutionError>) {
    let root = root();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let result = ExecutionBackend::run(
        &workflow,
        profile,
        json!({"request":"must not become args"}),
        &root,
    );
    (root, result)
}

fn events(error: &ExecutionError) -> String {
    fs::read_to_string(error.receipt().unwrap().run_root().join("events.jsonl")).unwrap()
}

#[test]
fn model_authors_two_selected_calls_then_typed_finish() {
    let (root, receipt) = run(profile());
    let receipt = receipt.unwrap();
    let events = fs::read_to_string(receipt.run_root().join("events.jsonl")).unwrap();
    assert!(events.contains("call-search"));
    assert!(events.contains("call-read"));
    assert!(events.find("call-search") < events.find("call-read"));
    assert!(!events.contains("must not become args"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn undeclared_or_unknown_call_fails_before_effect() {
    let responses = vec![
        json!({"calls": [{"id":"call-unknown","name":"unknown","args":{}}]}),
        json!("done"),
    ];
    let (root, error) = run(profile_with(responses, None));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Adk);
    assert!(!events(&error).contains("tool_completed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_or_schema_invalid_arguments_fail_before_effect() {
    let responses = vec![
        json!({"calls": [{"id":"call-bad","name":"search_code","args":[]}]}),
        json!("done"),
    ];
    let (root, error) = run(profile_with(responses, None));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Adk);
    assert!(!events(&error).contains("tool_completed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn empty_response_missing_finish_and_repeated_call_fail_closed() {
    for responses in [
        vec![json!(" ")],
        vec![
            json!({"calls": [{"id":"call-repeat","name":"search_code","args":{"query":"same"}}]}),
            json!({"calls": [{"id":"call-repeat","name":"search_code","args":{"query":"same"}}]}),
            json!("done"),
        ],
    ] {
        let (root, error) = run(profile_with(responses, None));
        let error = error.unwrap_err();
        assert_eq!(error.kind(), ExecutionErrorKind::Adk);
        assert_eq!(error.receipt().unwrap().status(), "failed");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn each_limit_is_specific_and_exhaustion_is_blocked() {
    let mut responses = (0..101)
        .map(|index| json!({"calls": [{"id":format!("call-{index}"),"name":"search_code","args":{"index":index}}]}))
        .collect::<Vec<_>>();
    responses.push(json!("done"));
    let (root, error) = run(profile_with(responses, None));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Adk);
    assert_eq!(error.receipt().unwrap().status(), "failed");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resume_rejects_loop_identity_drift_before_effects() {
    let (root, receipt) = run(profile_with(
        vec![
            json!({"calls": [{"id":"call-search","name":"search_code","args":{"query":"needle"}}]}),
            json!("done"),
        ],
        Some(loop_policy()),
    ));
    let receipt = receipt.unwrap();
    let protected = ["events.jsonl", "effects.sqlite", "checkpoint.sqlite"]
        .map(|name| receipt.run_root().join(name));
    let before = protected.each_ref().map(|path| fs::read(path).unwrap());
    let profile_path = receipt.run_root().join("execution-profile.json");
    let mut changed: Value = serde_json::from_slice(&fs::read(&profile_path).unwrap()).unwrap();
    changed["loop_policy"]["max_model_iterations"] = json!(99);
    fs::write(&profile_path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let error = ExecutionBackend::resume(&root, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(
        protected.each_ref().map(|path| fs::read(path).unwrap()),
        before
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn call_id_and_argument_fingerprint_survive_event_and_resume() {
    let args = json!({"query":"needle"});
    let expected = workflow_runtime::argument_fingerprint(&args);
    let (root, receipt) = run(profile_with(
        vec![
            json!({"calls": [{"id":"call-stable","name":"search_code","args":args}]}),
            json!("done"),
        ],
        Some(loop_policy()),
    ));
    let receipt = receipt.unwrap();
    let event_path = receipt.run_root().join("events.jsonl");
    let before = fs::read_to_string(&event_path).unwrap();
    assert!(before.contains("call-stable"));
    assert!(before.contains(&expected));
    let effects = Connection::open(receipt.run_root().join("effects.sqlite"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM kit_effects", [], |row| {
            row.get::<_, u64>(0)
        })
        .unwrap();
    assert_eq!(effects, 1);
    let _ = ExecutionBackend::resume(&root, receipt.run_id());
    assert_eq!(
        fs::read_to_string(event_path)
            .unwrap()
            .matches("call-stable")
            .count(),
        1
    );
    fs::remove_dir_all(root).unwrap();
}
