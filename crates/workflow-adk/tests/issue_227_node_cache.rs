use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use adk_rust::{Content, FileDataPart, FunctionResponseData, InlineDataPart, LlmRequest, Part};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_adk::execution::{
    ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1, request_input_digest,
};
use workflow_runtime::{NodeCacheKey, NodeCacheKeyMaterial, NodeCacheRetention, NodeResultCache};

fn request_key(request: &LlmRequest) -> String {
    NodeCacheKey::bind(NodeCacheKeyMaterial {
        workflow_id: "wf-cache",
        workflow_version: "1",
        node_id: "work",
        node_version: "work:1",
        invocation_identity: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        input_artifact_hashes: &[],
        request_input_digest: &request_input_digest(request),
        policy_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    })
    .expect("valid cache key")
    .digest()
    .to_owned()
}

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "workflow-adk-issue-227-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("unique test root");
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(cache_dir(&self.0));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn profile() -> ExecutionProfileV1 {
    ExecutionProfileV1::parse(
        br#"{
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": ["{\"status\":\"finished\",\"output\":\"cached-answer\"}"]
            },
            "sandbox": {"capabilities": []}
        }"#,
    )
    .expect("profile fixture should parse")
}

fn workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/minimal.workflow.toml")
}

fn events(run_root: &std::path::Path) -> Vec<Value> {
    fs::read_to_string(run_root.join("events.jsonl"))
        .expect("events exist")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event json"))
        .collect()
}

fn model_completed(run_root: &std::path::Path) -> usize {
    events(run_root)
        .iter()
        .filter(|event| event["kind"] == "model_request_completed")
        .count()
}

fn node_completed(run_root: &std::path::Path, node_id: &str) -> Value {
    events(run_root)
        .into_iter()
        .rev()
        .find(|event| event["kind"] == "node_completed" && event["node_id"] == node_id)
        .expect("node completed")
}

fn node_completed_count(run_root: &std::path::Path, node_id: &str) -> usize {
    events(run_root)
        .iter()
        .filter(|event| event["kind"] == "node_completed" && event["node_id"] == node_id)
        .count()
}

fn recorded_node_count(run_root: &std::path::Path, node_id: &str) -> usize {
    events(run_root)
        .iter()
        .filter(|event| {
            event["kind"] == "node_completed"
                && event["node_id"] == node_id
                && event["payload"]["cache_disposition"] == "recorded"
        })
        .count()
}

fn terminal_output(run_root: &std::path::Path) -> Value {
    let manifest: Value = serde_json::from_slice(
        &fs::read(run_root.join("run-manifest.json")).expect("run manifest"),
    )
    .expect("manifest json");
    let artifact_id = manifest["artifact_id"].as_str().expect("artifact id");
    serde_json::from_slice(
        &fs::read(run_root.join("artifacts").join(artifact_id)).expect("artifact"),
    )
    .expect("artifact json")
}

#[test]
fn production_cache_hit_skips_fenced_model_with_zero_calls() {
    let root = TestRoot::new();
    let input = json!({"request": "public"});
    let first = ExecutionBackend::run(workflow(), profile(), input.clone(), &root.0)
        .expect("first production run records a node result");
    assert_eq!(first.status(), "succeeded");
    assert_eq!(model_completed(first.run_root()), 1);
    assert_eq!(
        node_completed(first.run_root(), "start")["payload"]["cache_disposition"],
        "recorded"
    );
    let recorded = terminal_output(first.run_root());

    let second = ExecutionBackend::run(workflow(), profile(), input, &root.0)
        .expect("identical production run must reuse the durable node result");
    assert_eq!(second.status(), "succeeded");
    assert_eq!(
        model_completed(second.run_root()),
        0,
        "valid cache hit must issue zero inner model calls"
    );
    assert_eq!(
        node_completed(second.run_root(), "start")["payload"]["cache_disposition"],
        "reused"
    );
    assert_eq!(
        terminal_output(second.run_root())["terminal"],
        recorded["terminal"]
    );
}

#[test]
fn request_input_identity_misses_role_order_boundary_and_tool_collisions() {
    let text = |role: &str, parts: Vec<&str>| Content {
        role: role.to_owned(),
        parts: parts
            .into_iter()
            .map(|text| Part::Text {
                text: text.to_owned(),
            })
            .collect(),
    };
    let baseline = LlmRequest::new(
        "fake",
        vec![text("user", vec!["ab"]), text("assistant", vec!["c"])],
    );
    let role_swap = LlmRequest::new(
        "fake",
        vec![text("assistant", vec!["ab"]), text("user", vec!["c"])],
    );
    let reordered = LlmRequest::new(
        "fake",
        vec![text("assistant", vec!["c"]), text("user", vec!["ab"])],
    );
    let boundary = LlmRequest::new(
        "fake",
        vec![text("user", vec!["a", "b"]), text("assistant", vec!["c"])],
    );
    let with_tool = LlmRequest::new(
        "fake",
        vec![
            text("user", vec!["ab"]),
            Content {
                role: "assistant".to_owned(),
                parts: vec![
                    Part::Text {
                        text: "c".to_owned(),
                    },
                    Part::FunctionCall {
                        name: "lookup".to_owned(),
                        args: json!({"q": "ab"}),
                        id: None,
                        thought_signature: None,
                    },
                ],
            },
        ],
    );
    let with_tool_response = LlmRequest::new(
        "fake",
        vec![
            text("user", vec!["ab"]),
            text("assistant", vec!["c"]),
            Content {
                role: "function".to_owned(),
                parts: vec![Part::FunctionResponse {
                    function_response: FunctionResponseData::new("lookup", json!({"q": "ab"})),
                    id: None,
                    annotations: None,
                }],
            },
        ],
    );
    let same_again = LlmRequest::new(
        "fake",
        vec![text("user", vec!["ab"]), text("assistant", vec!["c"])],
    );
    let baseline_key = request_key(&baseline);
    assert_eq!(baseline_key, request_key(&same_again));
    assert_ne!(baseline_key, request_key(&role_swap));
    assert_ne!(baseline_key, request_key(&reordered));
    assert_ne!(baseline_key, request_key(&boundary));
    assert_ne!(baseline_key, request_key(&with_tool));
    assert_ne!(baseline_key, request_key(&with_tool_response));
}

fn function_response_request(function_response: FunctionResponseData) -> LlmRequest {
    LlmRequest::new(
        "fake",
        vec![Content {
            role: "function".to_owned(),
            parts: vec![Part::FunctionResponse {
                function_response,
                id: None,
                annotations: None,
            }],
        }],
    )
}

#[test]
fn request_input_identity_misses_nested_function_response_inline_annotations() {
    let mut absent = FunctionResponseData::new("lookup", json!({"q": "ab"}));
    absent.inline_data = vec![InlineDataPart {
        mime_type: "image/png".to_owned(),
        data: vec![0x89, 0x50, 0x4E, 0x47],
        uri: None,
        annotations: None,
    }];
    let mut present = absent.clone();
    present.inline_data[0].annotations = Some(json!({"caption": "chart"}));
    assert_ne!(
        request_key(&function_response_request(absent)),
        request_key(&function_response_request(present)),
        "nested FunctionResponse inline_data annotations must enter request identity"
    );
}

#[test]
fn request_input_identity_misses_nested_function_response_file_annotations() {
    let mut absent = FunctionResponseData::new("lookup", json!({"q": "ab"}));
    absent.file_data = vec![FileDataPart {
        mime_type: "application/pdf".to_owned(),
        file_uri: "gs://bucket/report.pdf".to_owned(),
        annotations: None,
    }];
    let mut present = absent.clone();
    present.file_data[0].annotations = Some(json!({"source": "tool"}));
    assert_ne!(
        request_key(&function_response_request(absent)),
        request_key(&function_response_request(present)),
        "nested FunctionResponse file_data annotations must enter request identity"
    );
}

#[test]
fn identity_mutation_invalidates_production_cache() {
    let root = TestRoot::new();
    ExecutionBackend::run(workflow(), profile(), json!({"request": "public"}), &root.0)
        .expect("seed cache");
    let mutated =
        ExecutionBackend::run(workflow(), profile(), json!({"request": "other"}), &root.0)
            .expect("mutated input must miss");
    assert_eq!(model_completed(mutated.run_root()), 1);
    assert_eq!(
        node_completed(mutated.run_root(), "start")["payload"]["cache_disposition"],
        "recorded"
    );
}

#[test]
fn sandbox_capability_enlargement_misses_production_cache() {
    let root = TestRoot::new();
    let input = json!({"request": "public"});
    let first = ExecutionBackend::run(workflow(), profile(), input.clone(), &root.0)
        .expect("read-only sandbox records a node result");
    assert_eq!(first.status(), "succeeded");
    assert_eq!(
        node_completed(first.run_root(), "start")["payload"]["cache_disposition"],
        "recorded"
    );

    let mut widened = serde_json::to_value(profile()).expect("profile json");
    widened["sandbox"]["capabilities"] = json!(["filesystem.write", "process.spawn"]);
    let widened = ExecutionProfileV1::parse(&serde_json::to_vec(&widened).expect("encode"))
        .expect("capability-enlarged profile must parse");
    let missed = ExecutionBackend::run(workflow(), widened, input, &root.0)
        .expect("capability-enlarged sibling must miss and re-execute");
    assert_eq!(missed.status(), "succeeded");
    assert_eq!(
        model_completed(missed.run_root()),
        1,
        "sandbox/policy/capability difference must not reuse a read-only cache hit"
    );
    assert_eq!(
        node_completed(missed.run_root(), "start")["payload"]["cache_disposition"],
        "recorded"
    );
}

#[test]
fn resume_of_succeeded_run_does_not_reexecute_cached_node() {
    let root = TestRoot::new();
    let first = ExecutionBackend::run(workflow(), profile(), json!({"request": "public"}), &root.0)
        .expect("first production run records a node result");
    assert_eq!(first.status(), "succeeded");
    assert_eq!(model_completed(first.run_root()), 1);
    assert_eq!(node_completed_count(first.run_root(), "start"), 1);
    assert_eq!(recorded_node_count(first.run_root(), "start"), 1);

    let resumed = ExecutionBackend::resume(&root.0, first.run_id())
        .expect("resume of a succeeded cached run must finish without repeating the node");
    assert_eq!(resumed.status(), "succeeded");
    assert_eq!(resumed.run_id(), first.run_id());
    assert_eq!(
        model_completed(resumed.run_root()),
        1,
        "succeeded resume must not issue another fake-model call"
    );
    assert_eq!(
        node_completed_count(resumed.run_root(), "start"),
        1,
        "completed cached node must not be executed a second time"
    );
    assert_eq!(
        recorded_node_count(resumed.run_root(), "start"),
        1,
        "resume must not append a second recorded execution"
    );
}

fn cache_dir(base: &std::path::Path) -> std::path::PathBuf {
    base.join(".node-result-cache")
}

fn tamper_success_payloads(base: &std::path::Path) {
    let entries = cache_dir(base).join("entries");
    for entry in fs::read_dir(&entries).expect("cache entries") {
        let path = entry.expect("entry").path();
        if !path.is_file() {
            continue;
        }
        let mut raw = serde_json::from_slice::<Value>(&fs::read(&path).expect("read cache"))
            .expect("cache json");
        raw["payload"] = json!({"tampered": true});
        fs::write(&path, serde_json::to_vec(&raw).expect("encode")).expect("tamper cache");
    }
}

#[test]
fn production_invalidation_reexecutes_fenced_model() {
    let root = TestRoot::new();
    let input = json!({"request": "public"});
    ExecutionBackend::run(workflow(), profile(), input.clone(), &root.0).expect("seed cache");
    tamper_success_payloads(&root.0);
    let reexecuted = ExecutionBackend::run(workflow(), profile(), input, &root.0)
        .expect("invalid durable entry must re-run the production node");
    assert_eq!(reexecuted.status(), "succeeded");
    assert_eq!(model_completed(reexecuted.run_root()), 1);
    assert_eq!(
        node_completed(reexecuted.run_root(), "start")["payload"]["cache_disposition"],
        "reexecuted"
    );
    let restored =
        ExecutionBackend::run(workflow(), profile(), json!({"request": "public"}), &root.0)
            .expect("successful recompute must restore a reusable hit");
    assert_eq!(restored.status(), "succeeded");
    assert_eq!(
        model_completed(restored.run_root()),
        0,
        "following run after invalidation recompute must be a durable hit"
    );
    assert_eq!(
        node_completed(restored.run_root(), "start")["payload"]["cache_disposition"],
        "reused"
    );
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn contracted_workflow(instruction_digest: &str) -> String {
    format!(
        r#"
schema_version = 1
[workflow]
id = "issue-227-instruction"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
model = {{ role = "worker", id = "fake-model", version = "1" }}
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
"#
    )
}

fn sequential_workflow() -> &'static str {
    r#"
schema_version = 1
[workflow]
id = "issue-227-sequential"
version = "1"
entry = "first"
[[nodes]]
id = "first"
kind = "agent"
model = { role = "worker", id = "fake-model", version = "1" }
[[nodes]]
id = "second"
kind = "agent"
model = { role = "worker", id = "fake-model", version = "1" }
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "first"
to = "second"
[[edges]]
from = "second"
to = "done"
"#
}

fn profile_with(responses: &[&str]) -> ExecutionProfileV1 {
    let profile = json!({
        "schema_version": 1,
        "model": {
            "provider": "fake",
            "name": "fake-model",
            "version": "1",
            "model": "fake",
            "responses": responses
        },
        "sandbox": {"capabilities": []}
    });
    ExecutionProfileV1::parse(&serde_json::to_vec(&profile).expect("profile json"))
        .expect("profile fixture should parse")
}

fn rewrite_valid_payload(base: &std::path::Path, from: &Value, to: Value) {
    let entries = cache_dir(base).join("entries");
    for entry in fs::read_dir(&entries).expect("cache entries") {
        let path = entry.expect("entry").path();
        if !path.is_file() {
            continue;
        }
        let mut raw = serde_json::from_slice::<Value>(&fs::read(&path).expect("read cache"))
            .expect("cache json");
        if raw["payload"] != *from {
            continue;
        }
        raw["payload"] = to.clone();
        raw["payload_sha256"] = json!(digest(&serde_json::to_vec(&to).expect("payload bytes")));
        fs::write(&path, serde_json::to_vec(&raw).expect("encode")).expect("rewrite cache");
        return;
    }
    panic!("expected a cache entry with payload {from}");
}

#[test]
fn instruction_bytes_are_bound_into_production_cache_key() {
    let root = TestRoot::new();
    let first_instruction = b"Review only the declared request.\n";
    fs::write(root.0.join("prompt.md"), first_instruction).expect("instruction");
    fs::write(
        root.0.join("review.schema.json"),
        br#"{"type":"object","properties":{"approved":{"type":"boolean"}},"required":["approved"],"additionalProperties":false}"#,
    )
    .expect("schema");
    let workflow_path = root.0.join("workflow.toml");
    fs::write(
        &workflow_path,
        contracted_workflow(&digest(first_instruction)),
    )
    .expect("workflow");
    let finish = "{\"status\":\"finished\",\"output\":{\"approved\":true}}";
    let first = ExecutionBackend::run(
        &workflow_path,
        profile_with(&[finish]),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("seed instruction cache");
    assert_eq!(first.status(), "succeeded");
    assert_eq!(model_completed(first.run_root()), 1);

    let mutated = b"Review a different declared request.\n";
    fs::write(root.0.join("prompt.md"), mutated).expect("mutated instruction");
    fs::write(&workflow_path, contracted_workflow(&digest(mutated))).expect("mutated workflow");
    let missed = ExecutionBackend::run(
        &workflow_path,
        profile_with(&[finish]),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("path-stable instruction-byte change must miss");
    assert_eq!(missed.status(), "succeeded");
    assert_eq!(
        model_completed(missed.run_root()),
        1,
        "instruction bytes must be part of cache identity"
    );
    assert_eq!(
        node_completed(missed.run_root(), "worker")["payload"]["cache_disposition"],
        "recorded"
    );
}

#[test]
fn downstream_node_misses_when_upstream_result_changes() {
    let root = TestRoot::new();
    let workflow_path = root.0.join("workflow.toml");
    fs::write(&workflow_path, sequential_workflow()).expect("workflow");
    let first = ExecutionBackend::run(
        &workflow_path,
        profile_with(&[
            "{\"status\":\"finished\",\"output\":\"upstream-a\"}",
            "{\"status\":\"finished\",\"output\":\"downstream-from-a\"}",
        ]),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("seed sequential cache");
    assert_eq!(first.status(), "succeeded");
    assert_eq!(model_completed(first.run_root()), 2);
    rewrite_valid_payload(&root.0, &json!("upstream-a"), json!("upstream-a2"));

    let missed = ExecutionBackend::run(
        &workflow_path,
        profile_with(&[
            "{\"status\":\"finished\",\"output\":\"upstream-a2\"}",
            "{\"status\":\"finished\",\"output\":\"downstream-from-a2\"}",
        ]),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("changed upstream result must miss downstream");
    assert_eq!(missed.status(), "succeeded");
    assert_eq!(
        model_completed(missed.run_root()),
        1,
        "downstream must not reuse a result computed from different upstream data"
    );
    assert_ne!(
        node_completed(missed.run_root(), "second")["payload"]["cache_disposition"],
        "reused"
    );
}

#[test]
fn non_fake_run_omits_recorded_disposition() {
    let root = TestRoot::new();
    let profile = ExecutionProfileV1::parse(
        br#"{
            "schema_version": 1,
            "model": {
                "provider": "openai-compatible",
                "name": "fake-model",
                "version": "1",
                "model": "worker-model",
                "base_url": "http://127.0.0.1:1/v1",
                "credential_env": "ADK_WORKFLOW_KIT_ISSUE_227_NON_FAKE"
            },
            "sandbox": {"capabilities": []}
        }"#,
    )
    .expect("non-fake profile must parse");
    unsafe {
        std::env::set_var("ADK_WORKFLOW_KIT_ISSUE_227_NON_FAKE", "test-key");
    }
    let result = ExecutionBackend::run(workflow(), profile, json!({"request": "public"}), &root.0);
    let events = result
        .as_ref()
        .map(|receipt| events(receipt.run_root()))
        .unwrap_or_else(|error| {
            error
                .receipt()
                .map(|receipt| events(receipt.run_root()))
                .unwrap_or_default()
        });
    assert!(
        events
            .iter()
            .all(|event| { event["payload"].get("cache_disposition") != Some(&json!("recorded")) }),
        "non-fake runs must not claim a confirmed cache store"
    );
}

#[test]
fn production_surfaces_expose_cache_provenance() {
    let root = TestRoot::new();
    let input = json!({"request": "public"});
    let first =
        ExecutionBackend::run(workflow(), profile(), input.clone(), &root.0).expect("record");
    let first_manifest: Value = serde_json::from_slice(
        &fs::read(first.run_root().join("run-manifest.json")).expect("manifest"),
    )
    .expect("manifest json");
    assert_eq!(first_manifest["cache_dispositions"]["start"], "recorded");
    assert_eq!(first_manifest["event_counts"]["model_turns"], 1);
    assert_eq!(first_manifest["event_counts"]["cache_hits"], 0);
    assert_eq!(first_manifest["event_counts"]["reexecuted"], 0);

    let inspected =
        serde_json::to_value(ExecutionBackend::inspect(&root.0, first.run_id()).expect("inspect"))
            .expect("inspect json");
    assert_eq!(inspected["cache_dispositions"]["start"], "recorded");
    assert_eq!(inspected["event_counts"]["model_turns"], 1);
    assert_eq!(inspected["event_counts"]["cache_hits"], 0);

    let second = ExecutionBackend::run(workflow(), profile(), input, &root.0).expect("reuse");
    let second_manifest: Value = serde_json::from_slice(
        &fs::read(second.run_root().join("run-manifest.json")).expect("manifest"),
    )
    .expect("manifest json");
    assert_eq!(second_manifest["cache_dispositions"]["start"], "reused");
    assert_eq!(second_manifest["event_counts"]["model_turns"], 0);
    assert_eq!(second_manifest["event_counts"]["cache_hits"], 1);

    tamper_success_payloads(&root.0);
    let third = ExecutionBackend::run(workflow(), profile(), json!({"request": "public"}), &root.0)
        .expect("reexecute after invalidation");
    let third_manifest: Value = serde_json::from_slice(
        &fs::read(third.run_root().join("run-manifest.json")).expect("manifest"),
    )
    .expect("manifest json");
    assert_eq!(third_manifest["cache_dispositions"]["start"], "reexecuted");
    assert_eq!(third_manifest["event_counts"]["reexecuted"], 1);
}

#[test]
fn inspect_gc_export_import_and_negative_cache_are_visible() {
    let root = TestRoot::new();
    let first = ExecutionBackend::run(workflow(), profile(), json!({"request": "public"}), &root.0)
        .expect("seed");
    let inspected =
        serde_json::to_value(ExecutionBackend::inspect(&root.0, first.run_id()).expect("inspect"))
            .expect("inspect json");
    assert!(
        inspected["node_cache"]["entry_count"].as_u64().unwrap() >= 1,
        "inspect must surface durable cache inventory"
    );
    assert_eq!(
        inspected["node_cache"]["negative_entries"]
            .as_u64()
            .unwrap(),
        0
    );

    let exported = NodeResultCache::open(cache_dir(&root.0))
        .expect("open cache")
        .export()
        .expect("export");
    let imported_root = TestRoot::new();
    let imported = NodeResultCache::open(cache_dir(&imported_root.0)).expect("open imported");
    assert_eq!(imported.import(&exported).expect("import"), 1);
    assert_eq!(
        imported.inspect().expect("inspect imported").entry_count(),
        1
    );
    assert_eq!(
        NodeResultCache::open(cache_dir(&root.0))
            .expect("open for gc")
            .gc(NodeCacheRetention {
                max_entries: Some(0)
            })
            .expect("gc"),
        1
    );
    assert_eq!(
        NodeResultCache::open(cache_dir(&root.0))
            .expect("open after gc")
            .inspect()
            .expect("inspect after gc")
            .entry_count(),
        0
    );
}

#[test]
fn schema_invalid_finish_is_not_a_durable_success_hit() {
    let root = TestRoot::new();
    let instruction = b"Review only the declared request.\n";
    fs::write(root.0.join("prompt.md"), instruction).expect("instruction");
    fs::write(
        root.0.join("review.schema.json"),
        br#"{"type":"object","properties":{"approved":{"type":"boolean"}},"required":["approved"],"additionalProperties":false}"#,
    )
    .expect("schema");
    let workflow_path = root.0.join("workflow.toml");
    fs::write(&workflow_path, contracted_workflow(&digest(instruction))).expect("workflow");
    let invalid = r#"{"status":"finished","output":"not-an-object"}"#;
    let valid = r#"{"status":"finished","output":{"approved":true}}"#;
    let first = ExecutionBackend::run(
        &workflow_path,
        profile_with(&[invalid]),
        json!({"request": "public"}),
        &root.0,
    )
    .expect_err("schema-invalid finish must fail closed");
    assert_eq!(first.kind(), ExecutionErrorKind::InvalidOutput);
    assert_eq!(
        NodeResultCache::open(cache_dir(&root.0))
            .expect("open after invalid finish")
            .inspect()
            .expect("inspect after invalid finish")
            .entry_count(),
        0,
        "semantic-invalid finish must not become a Success hit"
    );

    let healed = ExecutionBackend::run(
        &workflow_path,
        profile_with(&[valid]),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("following run must still reach the inner model");
    assert_eq!(healed.status(), "succeeded");
    assert_eq!(
        model_completed(healed.run_root()),
        1,
        "schema-invalid poison must not be reused with zero inner calls"
    );
    assert_eq!(
        node_completed(healed.run_root(), "worker")["payload"]["cache_disposition"],
        "recorded"
    );
}
