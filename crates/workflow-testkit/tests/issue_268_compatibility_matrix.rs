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
    CredentialBroker, FakeModelProfile, ModelProfileRegistry, ModelRole, ModelRuntimeConfig,
};
use workflow_adk::{InferenceBudget, InferenceBudgetError, ReasoningEffort};
use workflow_review::{REVIEW_SCHEMA_VERSION_V1, ReviewResult, ReviewVerdict};
use workflow_testkit::compatibility::{
    CompatibilityDimension, CompatibilityOutcome, documented_compatibility_matrix,
};
use workflow_testkit::{NoProgressReason, NonProgressDetector};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

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

fn completed_tools(run_root: &Path) -> usize {
    fs::read_to_string(run_root.join("events.jsonl"))
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["kind"] == "tool_completed")
        .count()
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
            }
            CompatibilityDimension::InferenceEngineVersion => {
                let package = include_str!("../../../Cargo.lock")
                    .split("[[package]]")
                    .find(|block| block.contains("\nname = \"adk-rust\"\n"))
                    .expect("ADK-Rust must be locked");
                assert!(package.contains("\nversion = \"2.1.0\"\n"), "{}", case.name);
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
            }
            CompatibilityDimension::Streaming => {
                let binding = ModelProfileRegistry::new()
                    .with_worker(fake_profile(vec![json!("chunk-one"), json!("chunk-two")]))
                    .unwrap()
                    .bind_worker(&CredentialBroker::new())
                    .unwrap();
                let observed = adk_rust::tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let request =
                            LlmRequest::new("fake", vec![Content::new("user").with_text("ping")]);
                        let mut stream = binding.generate_content(request, true).await.unwrap();
                        let first = stream.next().await.unwrap().unwrap().content.unwrap().parts[0]
                            .text()
                            .map(str::to_owned);
                        (first, stream.next().await.is_none())
                    });
                assert_eq!(
                    observed,
                    (Some("chunk-one".to_owned()), true),
                    "{}",
                    case.name
                );
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
                assert_eq!(result.unwrap().status(), "succeeded", "{}", case.name);
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
                assert_eq!(completed_tools(receipt.run_root()), 2, "{}", case.name);
            }
            CompatibilityDimension::MalformedArguments => {
                let (_root, result) = run(
                    vec![
                        json!({"calls": [{"id":"malformed","name":"search_code","args":{"query":1}}]}),
                        finish(json!({"must_not":"succeed"})),
                    ],
                    0,
                    1000,
                    4,
                );
                let error = result.unwrap_err();
                assert_eq!(
                    completed_tools(error.receipt().unwrap().run_root()),
                    0,
                    "{}",
                    case.name
                );
            }
            CompatibilityDimension::StructuredFinish => {
                let (_root, result) = run(vec![finish(json!({"answer":"structured"}))], 0, 1000, 2);
                assert_eq!(result.unwrap().status(), "succeeded", "{}", case.name);
            }
            CompatibilityDimension::TimeoutRetry => {
                let (_root, result) = run(vec![finish(json!({"late":true}))], 50, 5, 2);
                assert_eq!(
                    result.unwrap_err().kind(),
                    ExecutionErrorKind::WallTimeLimit,
                    "{}",
                    case.name
                );
                let budget = InferenceBudget::new(ReasoningEffort::Low, 128, 2).unwrap();
                assert_eq!(budget.max_retries(), 2, "{}", case.name);
                assert_eq!(
                    InferenceBudget::new(ReasoningEffort::Low, 128, 4),
                    Err(InferenceBudgetError::RetryLimitExceeded),
                    "{}",
                    case.name
                );
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
                assert_eq!(
                    result.unwrap_err().kind(),
                    ExecutionErrorKind::NonProgress,
                    "{}",
                    case.name
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
                let (root, result) = run(vec![finish(json!({"answer":"retained"}))], 0, 1000, 2);
                let receipt = result.unwrap();
                let resumed = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap();
                assert_eq!(resumed.run_id(), receipt.run_id(), "{}", case.name);
                assert_eq!(resumed.status(), "succeeded", "{}", case.name);
                let manifest: Value = serde_json::from_slice(
                    &fs::read(resumed.run_root().join("run-manifest.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(manifest["resume_count"], 1, "{}", case.name);
            }
        }
    }
}
