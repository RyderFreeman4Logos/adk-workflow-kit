use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use adk_rust::futures::StreamExt;
use adk_rust::{Content, LlmRequest};
use serde_json::{Value, json};
use workflow_adk::execution::{
    ExecutionBackend, ExecutionError, ExecutionErrorKind, ExecutionProfileV1,
};
use workflow_adk::model_profiles::{
    CredentialBroker, FakeModelProfile, ModelBinding, ModelProfileRegistry, ModelRole,
    ModelRuntimeConfig,
};
use workflow_review::{REVIEW_SCHEMA_VERSION_V1, ReviewResult, ReviewVerdict};
use workflow_testkit::compatibility::{
    CompatibilityDimension, CompatibilityOutcome, documented_compatibility_matrix,
};
use workflow_testkit::{NoProgressReason, NonProgressDetector};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

#[path = "support/issue_268_binding.rs"]
mod binding_oracles;

struct TestRoot(PathBuf);

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "issue-268"
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

fn root() -> TestRoot {
    let root = std::env::temp_dir().join(format!(
        "issue-268-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    TestRoot(root)
}

fn fake_profile(responses: Vec<Value>) -> FakeModelProfile {
    let mut profile = serde_json::to_value(FakeModelProfile::new(
        "worker",
        "1",
        "fake-model",
        ["unused"],
    ))
    .unwrap();
    profile["responses"] = Value::Array(responses);
    serde_json::from_value(profile).unwrap()
}

fn finish(output: Value) -> Value {
    json!(serde_json::to_string(&json!({"status":"finished", "output":output})).unwrap())
}

fn assert_fake_profile_response(binding: &ModelBinding, expected: &str) {
    let observed = adk_rust::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let request = LlmRequest::new("fake", vec![Content::new("user").with_text("ping")]);
            let mut stream = binding.generate_content(request, false).await.unwrap();
            let response = stream.next().await.unwrap().unwrap();
            assert!(stream.next().await.is_none());
            response.content.unwrap().parts[0]
                .text()
                .unwrap()
                .to_owned()
        });
    assert_eq!(observed, expected);
}

fn execution_profile(
    responses: Vec<Value>,
    response_delay_ms: u64,
    wall_time_ms: u64,
    max_model_iterations: u64,
) -> ExecutionProfileV1 {
    let value = json!({
        "schema_version": 1,
        "model": {
            "provider": "fake",
            "name": "worker",
            "version": "1",
            "model": "fake-model",
            "responses": responses,
            "response_delay_ms": response_delay_ms
        },
        "tools": [
            {
                "name": "search_code",
                "result": {"found": true},
                "input_schema": {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": false
                }
            },
            {
                "name": "read_source_range",
                "result": {"source": "ok"},
                "input_schema": {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start": {"type": "integer"}
                    },
                    "required": ["path", "start"],
                    "additionalProperties": false
                }
            }
        ],
        "sandbox": {"capabilities": []},
        "loop_policy": {
            "schema_version": 1,
            "max_model_iterations": max_model_iterations,
            "max_total_tool_calls": 16,
            "max_tool_calls_per_tool": 16,
            "wall_time_ms": wall_time_ms,
            "idle_time_ms": wall_time_ms,
            "tool_time_ms": wall_time_ms,
            "max_tool_output_bytes": 65536
        }
    });
    ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn run(
    responses: Vec<Value>,
    response_delay_ms: u64,
    wall_time_ms: u64,
    max_model_iterations: u64,
) -> (
    TestRoot,
    Result<workflow_adk::execution::ExecutionReceipt, ExecutionError>,
) {
    let root = root();
    let workflow = root.0.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let profile = execution_profile(
        responses,
        response_delay_ms,
        wall_time_ms,
        max_model_iterations,
    );
    let result = ExecutionBackend::run(&workflow, profile, json!({}), &root.0);
    (root, result)
}

fn read_json(run_root: &Path, name: &str) -> Value {
    serde_json::from_slice(&fs::read(run_root.join(name)).unwrap()).unwrap()
}

fn node_state(run_root: &Path) -> Value {
    read_json(run_root, "loop-ledger.json")["nodes"]["work"].clone()
}

fn events(run_root: &Path) -> Vec<Value> {
    fs::read_to_string(run_root.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn assert_tool_calls(run_root: &Path, expected: &[Value]) {
    let state = node_state(run_root);
    let mut completed = state["completed_calls"].as_array().unwrap().clone();
    let mut expected_calls = expected.to_vec();
    completed.sort_by_key(|entry| entry["call"]["id"].as_str().unwrap().to_owned());
    expected_calls.sort_by_key(|entry| entry["call"]["id"].as_str().unwrap().to_owned());
    assert_eq!(completed, expected_calls, "exact completed effect ledger");
    let events = events(run_root);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["kind"] == "tool_completed")
            .count(),
        expected.len(),
        "no extra or missing completion events"
    );
    let requested: Vec<_> = events
        .iter()
        .filter(|event| event["kind"] == "tool_requested")
        .flat_map(|event| event["payload"]["structured_output"].as_array().unwrap())
        .cloned()
        .collect();
    let expected_requests: Vec<_> = expected
        .iter()
        .map(|entry| {
            json!({
                "tool_call_id": entry["call"]["id"],
                "tool_name": entry["call"]["name"],
                "argument_fingerprint": entry["call"]["fingerprint"],
            })
        })
        .collect();
    assert_eq!(requested, expected_requests, "exact dispatch attribution");
}

// Fake profiles retain synthetic fixture arguments; events must still use fingerprints.
// Never supply sensitive arguments to this offline fixture.
fn completed_call(id: &str, name: &str, args: Value, response: Value, ordinal: u64) -> Value {
    let fingerprint = workflow_runtime::argument_fingerprint(&args);
    json!({"kind":"ordinary", "call": {
        "id":id, "name":name, "args":args,
        "fingerprint":fingerprint, "response":{
            "status":"success", "payload":response,
            "provenance":{"tool_id":name,"tool_version":"1"}
        },
        "model_iteration":1, "admission_ordinal":ordinal
    }})
}

fn assert_finished(run_root: &Path, expected: Value) {
    let state = node_state(run_root);
    assert_eq!(state["finish_admitted"], true);
    assert_eq!(
        state["finished_output"], expected,
        "retained terminal output"
    );
    assert_eq!(
        state["finish_successor"], expected,
        "resumed finish successor"
    );
    let manifest = read_json(run_root, "run-manifest.json");
    let artifact = read_json(
        &run_root.join("artifacts"),
        manifest["artifact_id"].as_str().unwrap(),
    );
    assert_eq!(artifact["status"], "succeeded");
    assert_eq!(artifact["terminal"], "done");
    let checkpoint_manifest =
        serde_json::from_value(read_json(run_root, "checkpoint-manifest.json")).unwrap();
    let store = workflow_runtime::SqliteCheckpointStore::open(
        run_root.join("checkpoint.sqlite"),
        checkpoint_manifest,
    )
    .unwrap();
    let run_id =
        workflow_runtime::RunId::new(manifest["run_id"].as_str().unwrap().to_owned()).unwrap();
    let checkpoint = store.load_latest(&run_id).unwrap().unwrap();
    let restored: Value = serde_json::from_slice(checkpoint.state()).unwrap();
    assert_eq!(
        restored["node:work"], expected,
        "checkpoint retains actual agent output"
    );
    assert_eq!(restored["terminal"], "done");
}

fn review(summary: &str) -> ReviewResult {
    ReviewResult::new(
        REVIEW_SCHEMA_VERSION_V1,
        ReviewVerdict::Revise,
        summary.to_owned(),
        Vec::new(),
        0.9,
    )
    .unwrap()
}

#[test]
fn fake_profile_compatibility_matrix_executes_every_done_when_row() {
    let matrix = documented_compatibility_matrix();
    assert_eq!(matrix.len(), 12);
    assert!(
        matrix
            .iter()
            .all(|case| case.outcome == CompatibilityOutcome::Pass)
    );
    assert!(matrix.iter().all(|case| case.stack == "fake-profile"));

    for case in matrix {
        match case.dimension {
            CompatibilityDimension::ModelIdentityRevision => {
                let profile = fake_profile(vec![json!("ok")])
                    .with_resolved_model("fake-model-resolved")
                    .with_tokenizer("fake-tokenizer");
                let binding = ModelProfileRegistry::new()
                    .with_worker(profile)
                    .unwrap()
                    .bind(ModelRole::Worker, &CredentialBroker::new())
                    .unwrap();
                assert_eq!(binding.profile_identity().version(), "1", "{}", case.name);
                assert_eq!(
                    binding.requested_model_identity(),
                    "fake-model",
                    "{}",
                    case.name
                );
                assert_eq!(
                    binding.resolved_model_identity(),
                    "fake-model-resolved",
                    "{}",
                    case.name
                );
                assert_eq!(
                    binding.resume_identity(),
                    "model-profile-v1:worker:1",
                    "{}",
                    case.name
                );
                assert_fake_profile_response(&binding, "ok");
            }
            CompatibilityDimension::InferenceEngineVersion => {
                let package = include_str!("../../../Cargo.lock")
                    .split("[[package]]")
                    .find(|block| block.contains("\nname = \"adk-rust\"\n"))
                    .expect("ADK-Rust must be locked");
                assert!(package.contains("\nversion = \"2.1.0\"\n"), "{}", case.name);
                let binding = ModelProfileRegistry::new()
                    .with_worker(fake_profile(vec![json!("engine-ok")]))
                    .unwrap()
                    .bind_worker(&CredentialBroker::new())
                    .unwrap();
                assert_fake_profile_response(&binding, "engine-ok");
            }
            CompatibilityDimension::ToolParserChatTemplate => {
                let runtime = ModelRuntimeConfig::default()
                    .with_tool_parser("fake-parser")
                    .with_tool_template("fake-chat-template");
                assert_eq!(runtime.tool_parser(), Some("fake-parser"), "{}", case.name);
                assert_eq!(
                    runtime.tool_template(),
                    Some("fake-chat-template"),
                    "{}",
                    case.name
                );
                let binding = ModelProfileRegistry::new()
                    .with_worker(fake_profile(vec![json!("configured-ok")]).with_runtime(runtime))
                    .unwrap()
                    .bind_worker(&CredentialBroker::new())
                    .unwrap();
                assert_fake_profile_response(&binding, "configured-ok");
            }
            CompatibilityDimension::Streaming => {
                binding_oracles::assert_streaming();
            }
            CompatibilityDimension::SingleToolCall => {
                let (_root, result) = run(
                    vec![
                        json!({"calls": [{"id":"single","name":"search_code","args":{"query":"one"}}]}),
                        finish(json!({"ok":true})),
                    ],
                    0,
                    1000,
                    4,
                );
                let receipt = result.unwrap();
                assert_eq!(receipt.status(), "succeeded", "{}", case.name);
                assert_tool_calls(
                    receipt.run_root(),
                    &[completed_call(
                        "single",
                        "search_code",
                        json!({"query":"one"}),
                        json!({"found":true}),
                        1,
                    )],
                );
            }
            CompatibilityDimension::ParallelToolCalls => {
                let (_root, result) = run(
                    vec![
                        json!({"calls": [
                            {"id":"parallel-a","name":"search_code","args":{"query":"one"}},
                            {"id":"parallel-b","name":"read_source_range","args":{"path":"src/lib.rs","start":1}}
                        ]}),
                        finish(json!({"ok":true})),
                    ],
                    0,
                    1000,
                    4,
                );
                let receipt = result.unwrap();
                assert_eq!(receipt.status(), "succeeded", "{}", case.name);
                assert_tool_calls(
                    receipt.run_root(),
                    &[
                        completed_call(
                            "parallel-a",
                            "search_code",
                            json!({"query":"one"}),
                            json!({"found":true}),
                            1,
                        ),
                        completed_call(
                            "parallel-b",
                            "read_source_range",
                            json!({"path":"src/lib.rs","start":1}),
                            json!({"source":"ok"}),
                            2,
                        ),
                    ],
                );
            }
            CompatibilityDimension::MalformedArguments => {
                // Shape rejection and schema rejection are different existing owners.
                for (args, kind) in [
                    (json!([]), ExecutionErrorKind::MalformedTool),
                    (json!({"query":1}), ExecutionErrorKind::AuthorizationDenied),
                ] {
                    let (_root, result) = run(
                        vec![
                            json!({"calls": [{"id":"malformed","name":"search_code","args":args}]}),
                            finish(json!({"must_not":"succeed"})),
                        ],
                        0,
                        1000,
                        4,
                    );
                    let error = result.unwrap_err();
                    assert_eq!(error.kind(), kind, "{}", case.name);
                    let run_root = error.receipt().unwrap().run_root();
                    assert_eq!(node_state(run_root)["completed_calls"], json!([]));
                    assert!(
                        !events(run_root)
                            .iter()
                            .any(|event| event["kind"] == "tool_completed")
                    );
                }
            }
            CompatibilityDimension::StructuredFinish => {
                let (_root, result) = run(vec![finish(json!({"answer":"structured"}))], 0, 1000, 2);
                let receipt = result.unwrap();
                assert_eq!(receipt.status(), "succeeded", "{}", case.name);
                assert_finished(receipt.run_root(), json!({"answer":"structured"}));
            }
            CompatibilityDimension::TimeoutRetry => {
                let (_root, result) = run(vec![finish(json!({"late":true}))], 50, 5, 2);
                assert_eq!(
                    result.unwrap_err().kind(),
                    ExecutionErrorKind::WallTimeLimit,
                    "{}",
                    case.name
                );
                binding_oracles::assert_retry_policy();
            }
            CompatibilityDimension::BoundedNonProgress => {
                let (_root, result) = run(
                    vec![
                        json!({"calls": [{"id":"repeat-a","name":"search_code","args":{"query":"same"}}]}),
                        json!({"calls": [{"id":"repeat-a","name":"search_code","args":{"query":"same"}}]}),
                    ],
                    0,
                    1000,
                    4,
                );
                let error = result.unwrap_err();
                assert_eq!(
                    error.kind(),
                    ExecutionErrorKind::NonProgress,
                    "{}",
                    case.name
                );
                let run_root = error.receipt().unwrap().run_root();
                assert_tool_calls(
                    run_root,
                    &[completed_call(
                        "repeat-a",
                        "search_code",
                        json!({"query":"same"}),
                        json!({"found":true}),
                        1,
                    )],
                );
                let state = node_state(run_root);
                assert_eq!(
                    state["total_tool_calls"], 1,
                    "reject before admitting duplicate effect"
                );
                assert_eq!(
                    state["model_iterations"], 1,
                    "only first response was admitted"
                );
            }
            CompatibilityDimension::Abstention => {
                let mut detector = NonProgressDetector::new(2);
                let observation = review("no progress");
                assert_eq!(
                    detector.observe(&observation).unwrap(),
                    None,
                    "{}",
                    case.name
                );
                assert_eq!(
                    detector.observe(&observation).unwrap(),
                    Some(NoProgressReason::RepeatedOutputHash),
                    "{}",
                    case.name
                );
            }
            CompatibilityDimension::RunResumeSessionRetention => {
                let (root, result) = run(
                    vec![
                        json!({"calls": [{"id":"retained-tool","name":"search_code","args":{"query":"retained-query"}}]}),
                        finish(json!({"answer":"retained"})),
                    ],
                    0,
                    1000,
                    4,
                );
                let receipt = result.unwrap();
                assert_eq!(receipt.status(), "succeeded");
                let expected_calls = [completed_call(
                    "retained-tool",
                    "search_code",
                    json!({"query":"retained-query"}),
                    json!({"found":true}),
                    1,
                )];
                assert_finished(receipt.run_root(), json!({"answer":"retained"}));
                assert_tool_calls(receipt.run_root(), &expected_calls);
                let before = node_state(receipt.run_root());
                assert_eq!(before["model_iterations"], 2);
                let before_manifest = read_json(receipt.run_root(), "run-manifest.json");
                let resumed = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap();
                assert_eq!(resumed.run_id(), receipt.run_id(), "{}", case.name);
                assert_eq!(resumed.status(), "succeeded", "{}", case.name);
                assert_eq!(resumed.run_root(), receipt.run_root());
                assert_eq!(resumed.resume_identity(), receipt.resume_identity());
                assert_eq!(resumed.plan_hash(), receipt.plan_hash());
                // Completed finish is restored, although the graph itself resumes.
                assert_finished(resumed.run_root(), json!({"answer":"retained"}));
                assert_tool_calls(resumed.run_root(), &expected_calls);
                assert_eq!(
                    node_state(resumed.run_root()),
                    before,
                    "no new model admission, tool effect, or conversation loss"
                );
                let manifest = read_json(resumed.run_root(), "run-manifest.json");
                for key in [
                    "workflow_id",
                    "workdir_id",
                    "profile_identity",
                    "checkpoint_manifest",
                ] {
                    assert!(
                        !before_manifest[key].is_null(),
                        "identity field {key} must exist"
                    );
                    assert_eq!(
                        manifest[key], before_manifest[key],
                        "retained identity {key}"
                    );
                }
                assert_eq!(manifest["resume_count"], 1, "{}", case.name);
            }
        }
    }
}
