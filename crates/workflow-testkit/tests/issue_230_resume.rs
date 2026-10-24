//! Real public-process resume contracts; scripted inference is not live telemetry.
use std::{fs, path::PathBuf, process::Command};

use serde_json::Value;

fn scratch() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("resume230-{}-{stamp}", std::process::id()))
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bench-230"));
    command.current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    command
}

fn read(path: impl AsRef<std::path::Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn snapshot(root: &std::path::Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(snapshot(&path));
        } else {
            files.insert(path.clone(), fs::read(path).unwrap());
        }
    }
    files
}

#[test]
fn killed_case_requires_explicit_abandon_without_replaying_effects() {
    use std::os::unix::process::ExitStatusExt;
    let root = scratch();
    let killed = command()
        .args(["scripted", "--output"])
        .arg(&root)
        .env(
            "WORKFLOW_KIT_TEST_CRASH_BARRIER",
            "after-model-ledger-persist#12",
        )
        .output()
        .unwrap();
    assert_eq!(
        killed.status.signal(),
        Some(9),
        "real child must reach the ADK barrier: {}",
        String::from_utf8_lossy(&killed.stderr)
    );
    let first = read(root.join("case-0.json"));
    assert_eq!(first["status"], "succeeded");
    assert!(!root.join("case-1.json").exists());
    let admission = read(root.join("admission-1.json"));
    assert_eq!(admission["case_id"], "downstream-consumer");
    let run_id = admission["run_id"].as_str().unwrap();
    let receipt =
        workflow_adk::execution::ExecutionBackend::inspect(root.join("runs"), run_id).unwrap();
    let ledger = read(receipt.run_root().join("loop-ledger.json"));
    assert!(
        ledger["nodes"]["agent"]["completed_calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|call| call["kind"] == "ordinary" && call["call"]["name"] == "echo"),
        "the killed case completed its scripted echo tool through the real runtime"
    );
    let before = snapshot(&root.join("runs"));
    assert!(
        before
            .iter()
            .any(|(path, bytes)| path.ends_with("loop-ledger.json") && {
                let ledger: Value = serde_json::from_slice(bytes).unwrap();
                ledger["nodes"]
                    .as_object()
                    .unwrap()
                    .values()
                    .any(|node| node["total_tool_calls"].as_u64().unwrap_or(0) > 0)
            }),
        "the killed runtime has real tool-call ledger evidence"
    );
    let resumed = command().arg("resume").arg(&root).output().unwrap();
    assert_eq!(resumed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&resumed.stderr).contains("in-flight"));
    assert_eq!(
        snapshot(&root.join("runs")),
        before,
        "fail-closed must not replay runtime effects"
    );
    let wrong = command()
        .arg("abandon")
        .arg(&root)
        .args(["downstream-consumer", "wrong-run"])
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("identity mismatch"));
    let mut foreign = admission.clone();
    foreign["manifest"]["model_digest"] = serde_json::json!("foreign");
    fs::write(
        root.join("admission-1.json"),
        serde_json::to_vec(&foreign).unwrap(),
    )
    .unwrap();
    let wrong = command()
        .arg("abandon")
        .arg(&root)
        .args(["downstream-consumer", run_id])
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("identity mismatch"));
    assert!(!root.join("case-1.json").exists());
    fs::write(
        root.join("admission-1.json"),
        serde_json::to_vec(&admission).unwrap(),
    )
    .unwrap();
    // An interrupted pending write is never promoted to a completion.
    fs::write(root.join("orphan.pending"), b"partial JSON").unwrap();
    let abandoned = command()
        .arg("abandon")
        .arg(&root)
        .args(["downstream-consumer", run_id])
        .output()
        .unwrap();
    assert!(
        abandoned.status.success(),
        "{}",
        String::from_utf8_lossy(&abandoned.stderr)
    );
    assert_eq!(
        snapshot(&root.join("runs")),
        before,
        "abandon is a journal operation, not runtime resume"
    );
    let failed = read(root.join("case-1.json"));
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["admitted_run_id"], run_id);
    for key in ["receipt", "elapsed_ns", "events_digest"] {
        assert!(failed[key].is_null());
    }
    assert!(
        failed["hard_invariant_failures"][0]
            .as_str()
            .unwrap()
            .contains("effects unknown")
    );
    let resumed = command().arg("resume").arg(&root).output().unwrap();
    assert_eq!(resumed.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&resumed.stdout).unwrap();
    assert_eq!(report["cases"].as_array().unwrap().len(), 5);
    assert_eq!(report["cases"][0], first);
    assert_eq!(report["cases"][1], failed);
    assert_eq!(report["cases"][3]["status"], "succeeded");
    for (path, bytes) in before {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    let again = command()
        .arg("abandon")
        .arg(&root)
        .args(["downstream-consumer", run_id])
        .output()
        .unwrap();
    assert_eq!(
        again.status.code(),
        Some(1),
        "must not overwrite an existing completion"
    );
}

#[test]
fn resume_rejects_forged_success_and_unknown_case_records() {
    let root = scratch();
    let initial = command()
        .args(["scripted", "--output"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(initial.status.code(), Some(0));
    let path = root.join("case-2.json");
    let original = fs::read(&path).unwrap();
    let mut forged: Value = serde_json::from_slice(&original).unwrap();
    for field in ["receipt", "elapsed_ns", "events_digest", "admitted_run_id"] {
        forged[field] = Value::Null;
    }
    forged["unsupported_reason"] = serde_json::json!("fixture: unavailable adapter");
    forged["status"] = Value::String("succeeded".to_owned());
    fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    let rejected = command().arg("resume").arg(&root).output().unwrap();
    assert!(
        rejected.stdout.is_empty(),
        "unsupported cannot become success by changing a status label"
    );
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("completion evidence"));
    fs::write(&path, &original).unwrap();
    fs::write(root.join("case-99.json"), &original).unwrap();
    let rejected = command().arg("resume").arg(&root).output().unwrap();
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unexpected journal record"));
    fs::remove_file(root.join("case-99.json")).unwrap();
    let path = root.join("case-0.json");
    let original = fs::read(&path).unwrap();
    let mut forged: Value = serde_json::from_slice(&original).unwrap();
    forged["receipt"]["event_counts"]["model_turns"] = serde_json::json!(999);
    fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    let rejected = command().arg("resume").arg(&root).output().unwrap();
    assert!(
        rejected.stdout.is_empty(),
        "receipt counters must still match the actual runtime"
    );
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("execution evidence mismatch"));
    fs::write(&path, &original).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("suite.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let rejected = command().arg("resume").arg(&root).output().unwrap();
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("already locked"));
    assert!(rejected.stdout.is_empty());
}

#[test]
fn admission_failure_prevents_compilation_and_runtime_artifacts() {
    use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};
    let root = scratch();
    fs::create_dir(&root).unwrap();
    let profile = ExecutionProfileV1::parse(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/00-runtime-smoke/profiles/fake.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut admitted = false;
    let failure = ExecutionBackend::run_admitted(
        root.join("nonexistent-workflow.toml"),
        profile,
        serde_json::json!({}),
        &root,
        |run_id| {
            assert!(run_id.starts_with("run-"));
            assert!(fs::read_dir(&root).unwrap().next().is_none());
            admitted = true;
            Err(std::io::Error::other("journal fsync failed"))
        },
    )
    .unwrap_err();
    assert!(admitted);
    assert_eq!(failure.kind(), ExecutionErrorKind::Persistence);
    assert!(failure.receipt().is_none());
    assert!(fs::read_dir(&root).unwrap().next().is_none());
}

#[test]
fn completed_suite_resume_is_identical_and_identity_mismatch_fails_closed() {
    let root = scratch();
    let initial = command()
        .args(["scripted", "--output"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(
        initial.status.code(),
        Some(0),
        "all legitimate bindings must execute: {}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let original: Value = serde_json::from_slice(&initial.stdout).unwrap();
    let resumed = command().arg("resume").arg(&root).output().unwrap();
    assert_eq!(resumed.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<Value>(&resumed.stdout).unwrap(),
        original
    );
    let suite_path = root.join("suite.json");
    let suite = read(&suite_path);
    for key in [
        "source_revision",
        "source_tree",
        "source_files_digest",
        "executable_digest",
        "workflow_digest",
        "config_digest",
        "dataset_digest",
        "model_digest",
    ] {
        let mut changed = suite.clone();
        changed["cases"][0]["manifest"][key] = Value::String("foreign".to_owned());
        fs::write(&suite_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let rejected = command().arg("resume").arg(&root).output().unwrap();
        assert_eq!(rejected.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("identity mismatch"),
            "{key}: {}",
            String::from_utf8_lossy(&rejected.stderr)
        );
        assert!(rejected.stdout.is_empty());
    }
    fs::write(&suite_path, serde_json::to_vec(&suite).unwrap()).unwrap();
    for (index, case) in original["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(read(root.join(format!("case-{index}.json"))), *case);
        if let Some(run_id) = case["receipt"]["run_id"].as_str() {
            assert_eq!(
                read(root.join(format!("admission-{index}.json")))["run_id"],
                run_id
            );
            assert_eq!(case["admitted_run_id"], run_id);
        }
    }
}
