use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CANARY_CLI_TEST_54: &str = "CANARY_CLI_TEST_54";
const CANARY_CLI_EVAL_54: &str = "CANARY_CLI_EVAL_54";
const CANARY_CLI_REPLAY_54: &str = "CANARY_CLI_REPLAY_54";
const CANARY_CLI_BOUNDARY_54: &str = "CANARY_CLI_BOUNDARY_54";
const LOCK_DIGEST: &str = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
        .args(args)
        .output()
        .expect("run workflowctl")
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "workflowctl-cli004-{}-{}-{}.json",
        name,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

fn write_json(name: &str, value: &Value) -> PathBuf {
    let path = temp_path(name);
    fs::write(&path, serde_json::to_vec(value).expect("serialize fixture")).expect("write fixture");
    path
}

fn assert_no_canary(output: &std::process::Output, canary: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(canary), "stdout leaked canary: {stdout}");
    assert!(!stderr.contains(canary), "stderr leaked canary: {stderr}");
}

fn assert_not_all_three(output: &std::process::Output) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !(text.contains("test_run") && text.contains("eval_run") && text.contains("replay_run")),
        "boundary must not report that test, eval, and replay all ran: {text}"
    );
}

fn replay_bundle(canary: &str) -> Value {
    let digest = format!("sha256:{:x}", Sha256::digest(canary.as_bytes()));
    json!({
        "schema_version": 1,
        "workflow_lock": { "toml": "test", "sha256": LOCK_DIGEST },
        "input_sha256": LOCK_DIGEST,
        "events": [
            { "type": "node_started", "node_id": "node-a" },
            { "type": "terminal", "status": "completed", "outcome_sha256": LOCK_DIGEST }
        ],
        "fixtures": [
            { "sha256": LOCK_DIGEST },
            { "sha256": digest, "bytes": canary.as_bytes() }
        ],
        "artifacts": []
    })
}

#[test]
fn canary_cli_test_54_runs_as_typed_test_not_eval_or_replay() {
    let path = write_json(
        "test",
        &json!({"name": "canary-cli-test-54", "payload": CANARY_CLI_TEST_54}),
    );
    let output = run(&["--json", "test", path.to_str().expect("utf8 path")]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("typed JSON stdout");
    assert_eq!(value["disposition"], "test_run");
    assert_ne!(value["disposition"], "eval_run");
    assert_ne!(value["disposition"], "replay_run");
    assert_no_canary(&output, CANARY_CLI_TEST_54);
    fs::remove_file(path).expect("remove test fixture");
}

#[test]
fn canary_cli_eval_54_runs_as_typed_eval_not_test_or_replay() {
    let path = write_json(
        "eval",
        &json!({"name": "canary-cli-eval-54", "payload": CANARY_CLI_EVAL_54}),
    );
    let output = run(&["--json", "eval", path.to_str().expect("utf8 path")]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("typed JSON stdout");
    assert_eq!(value["disposition"], "eval_run");
    assert_ne!(value["disposition"], "test_run");
    assert_ne!(value["disposition"], "replay_run");
    assert_no_canary(&output, CANARY_CLI_EVAL_54);
    fs::remove_file(path).expect("remove eval fixture");
}

#[test]
fn canary_cli_replay_54_runs_as_typed_replay_not_test_or_eval() {
    let path = write_json("replay", &replay_bundle(CANARY_CLI_REPLAY_54));
    let output = run(&["--json", "replay", path.to_str().expect("utf8 path")]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("typed JSON stdout");
    assert_eq!(value["disposition"], "replay_run");
    assert_ne!(value["disposition"], "test_run");
    assert_ne!(value["disposition"], "eval_run");
    assert_no_canary(&output, CANARY_CLI_REPLAY_54);
    fs::remove_file(path).expect("remove replay fixture");
}

#[test]
fn canary_cli_boundary_54_takes_typed_path_and_cannot_report_all_three_ran() {
    let path = write_json(
        "boundary",
        &json!({"name": "", "payload": CANARY_CLI_BOUNDARY_54}),
    );
    let utf8 = path.to_str().expect("utf8 path");

    let test_out = run(&["--json", "test", utf8]);
    assert_eq!(test_out.status.code(), Some(2));
    assert!(test_out.stdout.is_empty());
    let test_stderr = String::from_utf8_lossy(&test_out.stderr);
    assert!(
        test_stderr.contains("workflow.cli.boundary_miss"),
        "unexpected test stderr: {test_stderr}"
    );
    assert!(!test_stderr.contains("workflow.cli.invalid_arguments"));
    assert_not_all_three(&test_out);
    assert_no_canary(&test_out, CANARY_CLI_BOUNDARY_54);

    let eval_out = run(&["--json", "eval", utf8]);
    assert_eq!(eval_out.status.code(), Some(2));
    assert!(eval_out.stdout.is_empty());
    let eval_stderr = String::from_utf8_lossy(&eval_out.stderr);
    assert!(
        eval_stderr.contains("eval.boundary_miss"),
        "unexpected eval stderr: {eval_stderr}"
    );
    assert!(!eval_stderr.contains("workflow.cli.invalid_arguments"));
    assert_not_all_three(&eval_out);
    assert_no_canary(&eval_out, CANARY_CLI_BOUNDARY_54);

    let replay_path = write_json(
        "replay-boundary",
        &json!({"payload": CANARY_CLI_BOUNDARY_54}),
    );
    let replay_out = run(&["--json", "replay", replay_path.to_str().expect("utf8 path")]);
    assert_eq!(replay_out.status.code(), Some(2));
    assert!(replay_out.stdout.is_empty());
    let replay_stderr = String::from_utf8_lossy(&replay_out.stderr);
    assert!(
        replay_stderr.contains("workflow.cli.replay_invalid"),
        "unexpected replay stderr: {replay_stderr}"
    );
    assert!(!replay_stderr.contains("workflow.cli.invalid_arguments"));
    assert_not_all_three(&replay_out);
    assert_no_canary(&replay_out, CANARY_CLI_BOUNDARY_54);

    fs::remove_file(path).expect("remove boundary fixture");
    fs::remove_file(replay_path).expect("remove replay boundary fixture");
}

#[test]
fn local_ci_recipe_invokes_test_eval_and_replay() {
    let justfile = include_str!("../../../justfile");
    assert!(
        justfile.contains("workflowctl test "),
        "local CI must invoke test"
    );
    assert!(
        justfile.contains("workflowctl eval "),
        "local CI must invoke eval"
    );
    assert!(
        justfile.contains("workflowctl replay "),
        "local CI must invoke replay"
    );
}
