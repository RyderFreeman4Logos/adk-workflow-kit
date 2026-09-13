use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1};
use workflow_runtime::{NodeCacheRetention, NodeResultCache};

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
        "valid cache hit must skip FencedModel generate_content"
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
    base.join("node-result-cache")
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
