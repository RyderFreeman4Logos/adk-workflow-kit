use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

use serde_json::{Value, json};

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
    binary()
        .args([
            "--json",
            "run",
            workflow.to_str().expect("UTF-8 workflow path"),
            "--profile",
            profile.to_str().expect("UTF-8 profile path"),
            "--input",
            r#"{"value":7}"#,
            "--workdir",
            runs.to_str().expect("UTF-8 run base"),
        ])
        .output()
        .expect("workflowctl run must start")
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
