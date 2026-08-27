use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "m1-10-adk"
version = "1"
entry = "agent"
[[nodes]]
id = "agent"
kind = "agent"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "agent"
to = "done"
"#;

const HETEROGENEOUS_WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "m1-10-heterogeneous"
version = "1"
entry = "agent"
[[nodes]]
id = "agent"
kind = "agent"
[[nodes]]
id = "action"
kind = "action"
[[nodes]]
id = "validator"
kind = "validator"
[[nodes]]
id = "registered"
kind = "registered"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "agent"
to = "action"
[[edges]]
from = "action"
to = "validator"
[[edges]]
from = "validator"
to = "registered"
[[edges]]
from = "registered"
to = "done"
"#;

const IDENTITY_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/transform_identity.wasm"
);

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "workflowctl-m1-10-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("test root must be unique");
    root
}

fn write_fixture(root: &Path, profile: Value) -> (PathBuf, PathBuf, PathBuf) {
    let workflow = root.join("workflow.toml");
    let profile_path = root.join("profile.json");
    let runs = root.join("runs");
    fs::write(&workflow, WORKFLOW).expect("workflow fixture must write");
    fs::write(
        &profile_path,
        serde_json::to_vec(&profile).expect("profile fixture must serialize"),
    )
    .expect("profile fixture must write");
    fs::create_dir(&runs).expect("run base must exist");
    (workflow, profile_path, runs)
}

fn fake_profile() -> Value {
    json!({
        "schema_version": 1,
        "model": {
            "provider": "fake",
            "name": "worker",
            "version": "1",
            "model": "fixture-model",
            "responses": ["model-ok"]
        },
        "tool": {
            "name": "echo",
            "result": {"echo": "tool-ok"},
            "required_capabilities": []
        },
        "sandbox": {"capabilities": []}
    })
}

fn run_adk(workflow: &Path, profile: &Path, runs: &Path) -> Output {
    run_adk_with_input(workflow, profile, runs, r#"{"value":7}"#)
}

fn run_adk_with_input(workflow: &Path, profile: &Path, runs: &Path, input: &str) -> Output {
    binary()
        .args([
            "--json",
            "run",
            workflow.to_str().expect("UTF-8 workflow path"),
            "--profile",
            profile.to_str().expect("UTF-8 profile path"),
            "--input",
            input,
            "--workdir",
            runs.to_str().expect("UTF-8 run base"),
        ])
        .output()
        .expect("workflowctl run must start")
}

fn non_agent_workflow(node_count: usize) -> String {
    let mut workflow = String::from(
        "schema_version = 1\n[workflow]\nid = \"m1-10-large-outputs\"\nversion = \"1\"\nentry = \"node-0\"\n",
    );
    for index in 0..node_count {
        workflow.push_str(&format!(
            "[[nodes]]\nid = \"node-{index}\"\nkind = \"action\"\n"
        ));
    }
    workflow.push_str("[[nodes]]\nid = \"done\"\nkind = \"terminal\"\n");
    for index in 0..node_count {
        let target = if index + 1 == node_count {
            "done".to_owned()
        } else {
            format!("node-{}", index + 1)
        };
        workflow.push_str(&format!(
            "[[edges]]\nfrom = \"node-{index}\"\nto = \"{target}\"\n"
        ));
    }
    workflow
}

fn large_input() -> (Value, String) {
    let value = json!({"payload": "x".repeat(40 * 1024)});
    let encoded = serde_json::to_string(&value).expect("large input must serialize");
    assert!(
        encoded.len() < 64 * 1024,
        "canonical input must remain bounded"
    );
    (value, encoded)
}

fn terminal_artifact(run_root: &Path) -> (Vec<u8>, Value) {
    let manifest: Value = serde_json::from_slice(
        &fs::read(run_root.join("run-manifest.json")).expect("manifest must be readable"),
    )
    .expect("manifest must be JSON");
    let artifact_id = manifest["artifact_id"]
        .as_str()
        .expect("manifest must reference the terminal artifact");
    let bytes = fs::read(run_root.join("artifacts").join(artifact_id))
        .expect("terminal artifact must be readable");
    let value = serde_json::from_slice(&bytes).expect("terminal artifact must be JSON");
    (bytes, value)
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must be JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn run_root(runs: &Path) -> PathBuf {
    let roots = fs::read_dir(runs)
        .expect("run base must be readable")
        .map(|entry| entry.expect("run entry must be readable").path())
        .collect::<Vec<_>>();
    assert_eq!(roots.len(), 1, "one invocation must allocate one run root");
    roots[0].clone()
}

fn command_json(args: &[&str]) -> Output {
    let output = binary()
        .args(args)
        .output()
        .expect("workflowctl must start");
    assert!(
        output.status.success(),
        "command must succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn subprocess_adk_run_needs_no_transform_module_and_persists_state() {
    let root = temp_root("run");
    let (workflow, profile, runs) = write_fixture(&root, fake_profile());

    let output = run_adk(&workflow, &profile, &runs);
    assert!(
        output.status.success(),
        "ADK run must succeed without --module, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt = json_stdout(&output);
    assert_eq!(receipt["status"], "succeeded");
    assert!(receipt["run_id"].as_str().is_some_and(|id| !id.is_empty()));

    let run_root = run_root(&runs);
    assert!(run_root.join("run-manifest.json").is_file());
    assert!(run_root.join("events.jsonl").is_file());
    let artifacts = fs::read_dir(run_root.join("artifacts"))
        .expect("artifact directory must exist")
        .collect::<Result<Vec<_>, _>>()
        .expect("artifact entries must be readable");
    assert!(
        !artifacts.is_empty(),
        "successful run must persist an artifact"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn fake_model_and_tool_execute_end_to_end_through_adk_events() {
    let root = temp_root("fake-graph");
    let (workflow, profile, runs) = write_fixture(&root, fake_profile());

    let output = run_adk(&workflow, &profile, &runs);
    assert!(output.status.success());
    let events =
        fs::read_to_string(run_root(&runs).join("events.jsonl")).expect("events must be persisted");
    assert!(events.contains("\"kind\":\"model_request_completed\""));
    assert!(events.contains("model-ok"));
    assert!(events.contains("\"kind\":\"tool_completed\""));
    assert!(events.contains("tool-ok"));

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn profile_graph_runs_non_agent_nodes_through_the_wasm_backend() {
    let root = temp_root("heterogeneous");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] = json!({"module": IDENTITY_WASM});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, HETEROGENEOUS_WORKFLOW).expect("workflow fixture must write");

    let output = run_adk(&workflow, &profile, &runs);
    assert!(
        output.status.success(),
        "heterogeneous ADK run must succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run_root = run_root(&runs);
    let (_, terminal) = terminal_artifact(&run_root);
    let node_outputs = terminal["node_output_refs"]
        .as_object()
        .expect("terminal artifact must reference non-Agent node outputs");
    for node in ["action", "validator", "registered"] {
        let artifact_id = node_outputs[node]["artifact_id"]
            .as_str()
            .expect("node output must have an artifact reference");
        let output: Value = serde_json::from_slice(
            &fs::read(run_root.join("artifacts").join(artifact_id))
                .expect("referenced node output must be readable"),
        )
        .expect("node output artifact must be JSON");
        assert_eq!(
            output,
            json!({"value": 7}),
            "{node} must preserve the WASM transform output instead of a true placeholder"
        );
    }

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn large_non_agent_outputs_are_individually_persisted_and_inspectable() {
    let root = temp_root("large-node-outputs");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] = json!({"module": IDENTITY_WASM});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, non_agent_workflow(2)).expect("workflow fixture must write");
    let (input_value, input) = large_input();

    let output = run_adk_with_input(&workflow, &profile, &runs, &input);
    assert!(
        output.status.success(),
        "large multi-node run must succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt = json_stdout(&output);
    let run_id = receipt["run_id"].as_str().expect("run ID must be text");
    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().expect("UTF-8 run base"),
    ]);
    assert_eq!(json_stdout(&inspect), receipt);

    let run_root = run_root(&runs);
    let (terminal_bytes, terminal) = terminal_artifact(&run_root);
    assert!(terminal_bytes.len() <= 64 * 1024);
    assert!(terminal.get("node_outputs").is_none());
    let refs = terminal["node_output_refs"]
        .as_object()
        .expect("terminal artifact must contain node output references");
    assert_eq!(refs.len(), 2);
    let mut combined_bytes = 0_u64;
    for node in ["node-0", "node-1"] {
        let reference = &refs[node];
        let artifact_id = reference["artifact_id"]
            .as_str()
            .expect("reference must contain an artifact ID");
        assert_eq!(reference["sha256"], format!("sha256:{artifact_id}"));
        combined_bytes += reference["byte_len"]
            .as_u64()
            .expect("reference must contain a byte length");
        let persisted: Value = serde_json::from_slice(
            &fs::read(run_root.join("artifacts").join(artifact_id))
                .expect("node artifact must be readable"),
        )
        .expect("node artifact must be JSON");
        assert_eq!(persisted, input_value);
    }
    assert!(combined_bytes > 64 * 1024);

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn post_execution_artifact_failure_still_persists_the_returned_receipt() {
    let root = temp_root("node-output-persistence-failure");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] = json!({"module": IDENTITY_WASM});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, non_agent_workflow(16)).expect("workflow fixture must write");
    let (input_value, input) = large_input();
    let output_digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&input_value).expect("node output must serialize"))
    );

    let mut child = binary()
        .args([
            "--json",
            "run",
            workflow.to_str().expect("UTF-8 workflow path"),
            "--profile",
            profile.to_str().expect("UTF-8 profile path"),
            "--input",
            &input,
            "--workdir",
            runs.to_str().expect("UTF-8 run base"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("workflowctl run must start");
    let deadline = Instant::now() + Duration::from_secs(5);
    let artifact_root = loop {
        let candidate = fs::read_dir(&runs)
            .expect("run base must be readable")
            .next()
            .transpose()
            .expect("run entry must be readable")
            .map(|entry| entry.path().join("artifacts"));
        if let Some(path) = candidate
            && path.is_dir()
        {
            break path;
        }
        if Instant::now() >= deadline {
            child.kill().expect("timed-out child must stop");
            let _ = child.wait();
            panic!("artifact store was not allocated before the deadline");
        }
        thread::yield_now();
    };
    fs::create_dir(artifact_root.join(output_digest))
        .expect("collision fixture must make node artifact persistence fail");

    let failed = child
        .wait_with_output()
        .expect("workflowctl run must finish after persistence failure");
    assert_eq!(failed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("workflow.run.failed"));
    let failed_receipt = json_stdout(&failed);
    assert_eq!(
        failed_receipt["status"], "succeeded",
        "artifact persistence failure must occur after graph execution"
    );
    let run_id = failed_receipt["run_id"]
        .as_str()
        .expect("persistence failure must return the allocated run ID");
    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().expect("UTF-8 run base"),
    ]);
    assert_eq!(json_stdout(&inspect), failed_receipt);

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn invalid_profile_fails_closed_with_stable_exit_code() {
    let root = temp_root("invalid-profile");
    let invalid = json!({
        "schema_version": 1,
        "model": {"provider": "unknown"},
        "sandbox": {"capabilities": []}
    });
    let (workflow, profile, runs) = write_fixture(&root, invalid);

    let output = run_adk(&workflow, &profile, &runs);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("workflow.run.unsupported_input"));
    assert!(
        fs::read_dir(&runs)
            .expect("run base must be readable")
            .next()
            .is_none(),
        "invalid profile must fail before allocating run state"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn sandbox_denial_fails_before_backend_spawn() {
    let root = temp_root("sandbox-denial");
    let mut profile_value = fake_profile();
    profile_value["tool"]["required_capabilities"] = json!(["process.spawn"]);
    let (workflow, profile, runs) = write_fixture(&root, profile_value);

    let output = run_adk(&workflow, &profile, &runs);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("workflow.run.failed"));
    assert!(
        fs::read_dir(&runs)
            .expect("run base must be readable")
            .next()
            .is_none(),
        "sandbox denial must happen before workdir allocation or backend spawn"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn failed_profile_run_persists_and_remains_inspectable() {
    let root = temp_root("failed-run");
    let invalid_module = root.join("invalid.wasm");
    fs::write(&invalid_module, b"not wasm").expect("invalid module fixture must write");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] =
        json!({"module": invalid_module.to_str().expect("UTF-8 module path")});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, HETEROGENEOUS_WORKFLOW).expect("workflow fixture must write");

    let failed = run_adk(&workflow, &profile, &runs);
    assert_eq!(failed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("workflow.run.failed"));
    let failed_receipt = json_stdout(&failed);
    let run_id = failed_receipt["run_id"]
        .as_str()
        .expect("failed receipt must carry the allocated run ID");
    assert_eq!(failed_receipt["status"], "failed");

    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().expect("UTF-8 run base"),
    ]);
    let inspected = json_stdout(&inspect);
    assert_eq!(inspected["run_id"], run_id);
    assert_eq!(inspected["status"], "failed");
    let events = fs::read_to_string(run_root(&runs).join("events.jsonl"))
        .expect("failed events must be persisted");
    assert!(events.contains("\"kind\":\"workflow_failed\""));
    assert!(
        fs::read_dir(run_root(&runs).join("artifacts"))
            .expect("failed artifact directory must exist")
            .next()
            .is_some(),
        "failed run must persist a terminal artifact"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn oversized_agent_only_profile_input_fails_before_run_allocation() {
    let root = temp_root("oversized-input");
    let (workflow, profile, runs) = write_fixture(&root, fake_profile());
    let input = serde_json::to_string(&json!({"payload": "x".repeat(64 * 1024)}))
        .expect("oversized input must serialize");

    let output = run_adk_with_input(&workflow, &profile, &runs, &input);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("workflow.run.unsupported_input"));
    assert!(
        fs::read_dir(&runs)
            .expect("run base must be readable")
            .next()
            .is_none(),
        "oversized input must fail before allocating run state"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn resume_and_inspect_reuse_the_original_run_identity() {
    let root = temp_root("resume-inspect");
    let (workflow, profile, runs) = write_fixture(&root, fake_profile());
    let run = run_adk(&workflow, &profile, &runs);
    assert!(run.status.success());
    let run_receipt = json_stdout(&run);
    let run_id = run_receipt["run_id"].as_str().expect("run ID must be text");
    let runs_text = runs.to_str().expect("UTF-8 run base");

    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs_text,
    ]);
    let inspected = json_stdout(&inspect);
    assert_eq!(inspected["run_id"], run_id);
    assert_eq!(inspected["status"], "succeeded");

    let resume = command_json(&[
        "--json",
        "resume",
        "--run-id",
        run_id,
        "--workdir",
        runs_text,
    ]);
    let resumed = json_stdout(&resume);
    assert_eq!(resumed["run_id"], run_id);
    assert_eq!(resumed["status"], "succeeded");

    let events = fs::read_to_string(run_root(&runs).join("events.jsonl"))
        .expect("resumed events must be readable");
    assert!(events.contains("\"kind\":\"workflow_resumed\""));

    fs::remove_dir_all(root).expect("test root must be removed");
}
