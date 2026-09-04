use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "workflow-adk-issue-264-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("unique test root");
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).expect("fixture write");
        path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn workflow(instruction_digest: &str) -> String {
    format!(
        r#"
schema_version = 1
[workflow]
id = "issue-264-runtime"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
model = {{ role = "worker", id = "worker", version = "1" }}
instruction = {{ path = "prompt.md", sha256 = "{instruction_digest}" }}
input = {{ state_keys = ["request"] }}
output = {{ state_key = "review", schema = "review.schema.json" }}
session = "isolated"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "worker"
to = "done"
[state]
schema_id = "review-state"
schema_version = "1"
required_keys = ["request", "review"]
[state.keys.request]
schema_id = "text"
schema_version = "1"
[state.keys.review]
schema_id = "review"
schema_version = "1"
"#,
    )
}

fn profile(output: Value) -> ExecutionProfileV1 {
    let profile = json!({
        "schema_version": 1,
        "model": {
            "provider": "fake",
            "name": "worker",
            "version": "1",
            "model": "worker",
            "responses": [serde_json::to_string(&json!({"status":"finished","output":output})).expect("response")]
        },
        "tool": {
            "name": "echo",
            "result": {"echo": "runtime smoke"},
            "input_schema": {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"additionalProperties":false},
            "required_capabilities": [],
            "required_scopes": []
        },
        "sandbox": {"capabilities": []}
    });
    ExecutionProfileV1::parse(&serde_json::to_vec(&profile).expect("profile JSON"))
        .expect("profile parses")
}

fn checkpoint_state(run_root: &Path) -> Value {
    let connection = Connection::open(run_root.join("checkpoint.sqlite")).expect("checkpoint");
    let state: Vec<u8> = connection
        .query_row("SELECT state FROM kit_checkpoints", [], |row| row.get(0))
        .expect("checkpoint state");
    serde_json::from_slice(&state).expect("state JSON")
}

fn uncontracted_workflow() -> &'static str {
    r#"
 schema_version = 1
 [workflow]
 id = "issue-264-uncontracted"
 version = "1"
 entry = "worker"
 [[nodes]]
 id = "worker"
 kind = "agent"
 model = { role = "worker", id = "worker", version = "1" }
 tools = [{ id = "echo", version = "1" }]
 [[nodes]]
 id = "done"
 kind = "terminal"
 [[edges]]
 from = "worker"
 to = "done"
 "#
}

#[test]
fn uncontracted_agent_preserves_prior_unstructured_output_behavior() {
    let root = TestRoot::new();
    let workflow_path = root.write("workflow.toml", uncontracted_workflow().as_bytes());

    let receipt = ExecutionBackend::run(
        &workflow_path,
        profile(json!("runtime smoke complete")),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("uncontracted agent executes");

    let state = checkpoint_state(receipt.run_root());
    assert_eq!(state["node:worker"], json!("runtime smoke complete"));
}

#[test]
fn authored_contract_controls_runtime_state_output_and_drift() {
    let root = TestRoot::new();
    let instruction = b"Review only the declared request.\n";
    root.write("prompt.md", instruction);
    root.write(
        "review.schema.json",
        br#"{"type":"object","properties":{"approved":{"type":"boolean"}},"required":["approved"],"additionalProperties":false}"#,
    );
    let workflow_path = root.write("workflow.toml", workflow(&digest(instruction)).as_bytes());

    let receipt = ExecutionBackend::run(
        &workflow_path,
        profile(json!({"approved": true})),
        json!({"request": "public", "undeclared": "private"}),
        &root.0,
    )
    .expect("declared contract executes");
    let state = checkpoint_state(receipt.run_root());
    assert_eq!(state["review"], json!({"approved": true}));
    assert!(state.get("node:worker").is_none());

    fs::write(
        receipt.run_root().join("prompt.md"),
        b"Drifted instruction.\n",
    )
    .expect("persisted instruction drift fixture");
    let error = ExecutionBackend::resume(&root.0, receipt.run_id())
        .expect_err("instruction drift must fail before another model or tool effect");
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);

    let malformed_root = TestRoot::new();
    malformed_root.write("prompt.md", instruction);
    malformed_root.write(
        "review.schema.json",
        br#"{"type":"object","properties":{"approved":{"type":"boolean"}},"required":["approved"],"additionalProperties":false}"#,
    );
    let malformed_workflow =
        malformed_root.write("workflow.toml", workflow(&digest(instruction)).as_bytes());
    let error = ExecutionBackend::run(
        malformed_workflow,
        profile(json!({"approved": "not-a-boolean"})),
        json!({"request": "public"}),
        &malformed_root.0,
    )
    .expect_err("malformed node output must fail closed before routing");
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidOutput);
    assert!(
        checkpoint_state(error.receipt().expect("failed run receipt").run_root())
            .get("terminal")
            .is_none(),
        "malformed output must not publish a terminal route"
    );
}
