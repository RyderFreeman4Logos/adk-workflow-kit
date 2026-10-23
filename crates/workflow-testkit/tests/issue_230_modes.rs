//! Public offline policy boundaries. Runtime receipts, never fixture scores.
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn scratch() -> PathBuf {
    std::env::temp_dir().join(format!(
        "modes230-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bench-230"))
        .args(args)
        .output()
        .unwrap()
}
fn value(output: Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("structured policy result")
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn initialize() -> PathBuf {
    let root = scratch();
    let policy = root.with_extension("json");
    fs::write(&policy, serde_json::to_vec(&json!({"schema_version":1,"tuning":["runtime-smoke","downstream-consumer"],"holdout":["minimal-template","code-investigation"]})).unwrap()).unwrap();
    value(
        cli(&["init", policy.to_str().unwrap(), root.to_str().unwrap()]),
        0,
    );
    root
}
fn run(mode: &str, root: &Path, extra: &[&str], code: i32) -> Value {
    let mut args = vec![mode, root.to_str().unwrap()];
    args.extend(extra);
    value(cli(&args), code)
}
fn cases(report: &Value) -> &Vec<Value> {
    report["execution"]["cases"].as_array().unwrap()
}

fn relative_campaign(mode: &str) {
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let path = scratch();
    fs::create_dir(&path).unwrap();
    let root = Scratch(path);
    fs::write(root.0.join("split.json"), serde_json::to_vec(&json!({"schema_version":1,"tuning":["runtime-smoke","downstream-consumer"],"holdout":["minimal-template","code-investigation"]})).unwrap()).unwrap();
    fs::write(root.0.join("config.json"), serde_json::to_vec(&json!({"schema_version":1,"loop_policy":{"schema_version":1,"max_model_iterations":20,"max_total_tool_calls":20,"max_tool_calls_per_tool":20,"wall_time_ms":60000,"idle_time_ms":30000,"tool_time_ms":10000,"max_tool_output_bytes":65536}})).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_bench-230"));
    command.current_dir(&root.0).args([mode, "split.json"]);
    if mode == "init-config" {
        command.arg("config.json");
    }
    let result = value(command.arg("campaign").output().unwrap(), 0);
    assert!(result["campaign_digest"].is_string());
    assert_eq!(result["live_executed"], false);
    let campaign = read(root.0.join("campaign/campaign.json"));
    assert_eq!(
        campaign["split"]["tuning"],
        json!(["downstream-consumer", "runtime-smoke"])
    );
    assert_eq!(campaign["config"].is_object(), mode == "init-config");
}

#[test]
fn init_accepts_single_component_relative_campaign() {
    relative_campaign("init");
}

#[test]
fn init_config_accepts_single_component_relative_campaign() {
    relative_campaign("init-config");
}

#[test]
fn regression_runs_only_frozen_tuning_and_resumes_original_receipts() {
    let root = initialize();
    let report = run("regression", &root, &[], 0);
    assert_eq!(report["mode"], "regression");
    assert_eq!(
        report["selected_case_ids"],
        json!(["downstream-consumer", "runtime-smoke"])
    );
    assert_eq!(cases(&report).len(), 2);
    for case in cases(&report) {
        assert_eq!(case["status"], "succeeded");
        assert!(case["elapsed_ns"].as_u64().unwrap() > 0);
        assert!(
            Path::new(case["receipt"]["run_root"].as_str().unwrap())
                .join("events.jsonl")
                .is_file()
        );
    }
    let resumed = value(
        cli(&[
            "resume",
            report["execution"]["output_directory"].as_str().unwrap(),
        ]),
        0,
    );
    assert_eq!(resumed, report["execution"]);
    assert!(report["revision_comparison"].is_null());
}

#[test]
fn adaptive_selects_measured_slowest_and_rejects_missing_or_unknown_metrics() {
    let root = initialize();
    assert_eq!(
        run("adaptive", &root, &["elapsed_ns", "1"], 1)["error"]["kind"],
        "missing_measurement"
    );
    let baseline = run("regression", &root, &[], 0);
    let expected = cases(&baseline)
        .iter()
        .max_by(|a, b| {
            a["elapsed_ns"]
                .as_u64()
                .cmp(&b["elapsed_ns"].as_u64())
                .then_with(|| b["case_id"].as_str().cmp(&a["case_id"].as_str()))
        })
        .unwrap();
    assert_eq!(
        run("adaptive", &root, &["tokens", "1"], 1)["error"]["kind"],
        "unsupported_metric"
    );
    let report = run("adaptive", &root, &["elapsed_ns", "1"], 0);
    assert_eq!(report["selected_case_ids"], json!([expected["case_id"]]));
    assert_ne!(
        cases(&report)[0]["admitted_run_id"],
        expected["admitted_run_id"]
    );
    // Durable receipt tampering must not become an adaptive selection observation.
    let directory = Path::new(baseline["execution"]["output_directory"].as_str().unwrap());
    let mut case = read(directory.join("case-0.json"));
    case["receipt"]["model_turns"] = json!(999999);
    fs::write(
        directory.join("case-0.json"),
        serde_json::to_vec(&case).unwrap(),
    )
    .unwrap();
    assert_eq!(
        run("adaptive", &root, &["elapsed_ns", "1"], 1)["error"]["kind"],
        "invalid_evidence"
    );
}

#[test]
fn soak_reexecutes_each_tuning_case_without_claiming_warm_cache() {
    let root = initialize();
    assert_eq!(
        run("soak", &root, &["0"], 1)["error"]["kind"],
        "invalid_policy"
    );
    let report = run("soak", &root, &["2"], 0);
    let rows = cases(&report);
    assert_eq!(rows.len(), 4);
    let ids = rows
        .iter()
        .map(|c| c["admitted_run_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 4);
    assert!(rows.iter().all(|c| c["status"] == "succeeded"
        && c["prefix_hit"].is_null()
        && c["cache_class"].is_null()));
    assert_eq!(report["repeats"], 2);
}

#[test]
fn sealed_final_is_one_shot_blocks_tuning_and_exposes_fourth_binding() {
    let root = initialize();
    let report = run("sealed-final", &root, &[], 0);
    assert_eq!(
        report["selected_case_ids"],
        json!(["code-investigation", "minimal-template"])
    );
    assert_eq!(cases(&report)[0]["status"], "succeeded");
    assert_eq!(cases(&report)[1]["status"], "succeeded");
    assert!(cases(&report)[1]["receipt"].is_object());
    for (mode, args) in [
        ("regression", vec![]),
        ("adaptive", vec!["elapsed_ns", "1"]),
        ("soak", vec!["2"]),
        ("sealed-final", vec![]),
    ] {
        assert_eq!(run(mode, &root, &args, 1)["error"]["kind"], "sealed");
    }
    let directory = report["execution"]["output_directory"].as_str().unwrap();
    assert_eq!(value(cli(&["resume", directory]), 0), report["execution"]);
}

#[test]
fn interrupted_final_remains_sealed_and_cannot_replay_admitted_effects() {
    use std::os::unix::process::ExitStatusExt;
    let root = initialize();
    let killed = Command::new(env!("CARGO_BIN_EXE_bench-230"))
        .arg("sealed-final")
        .arg(&root)
        .env(
            "WORKFLOW_KIT_TEST_CRASH_BARRIER",
            "after-model-ledger-persist#1",
        )
        .output()
        .unwrap();
    assert_eq!(killed.status.signal(), Some(9));
    assert_eq!(read(root.join("operation-0.json"))["mode"], "sealed_final");
    let output = root.join("operation-0");
    let admission = fs::read(output.join("admission-0.json")).unwrap();
    assert!(!output.join("case-0.json").exists());
    assert_eq!(run("regression", &root, &[], 1)["error"]["kind"], "sealed");
    assert_eq!(
        run("sealed-final", &root, &[], 1)["error"]["kind"],
        "sealed"
    );
    let resumed = cli(&["resume", output.to_str().unwrap()]);
    assert_eq!(resumed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&resumed.stderr).contains("in-flight"));
    assert_eq!(
        fs::read(output.join("admission-0.json")).unwrap(),
        admission
    );
    assert!(!output.join("case-0.json").exists());
}

#[test]
fn foreign_campaign_receipts_cannot_be_imported_as_selection_history() {
    let foreign = initialize();
    run("regression", &foreign, &[], 0);
    let root = initialize();
    fs::copy(
        foreign.join("operation-0.json"),
        root.join("operation-0.json"),
    )
    .unwrap();
    assert_eq!(
        run("adaptive", &root, &["elapsed_ns", "1"], 1)["error"]["kind"],
        "identity_mismatch"
    );
    assert!(!root.join("operation-1.json").exists());
}

#[test]
fn partitions_fail_closed_on_overlap_missing_unknown_and_identity_drift() {
    for (tuning, holdout) in [
        (
            json!(["runtime-smoke"]),
            json!([
                "runtime-smoke",
                "minimal-template",
                "code-investigation",
                "downstream-consumer"
            ]),
        ),
        (json!(["runtime-smoke"]), json!(["minimal-template"])),
        (
            json!(["runtime-smoke", "unknown"]),
            json!([
                "minimal-template",
                "code-investigation",
                "downstream-consumer"
            ]),
        ),
    ] {
        let root = scratch();
        let policy = root.with_extension("json");
        fs::write(
            &policy,
            serde_json::to_vec(&json!({"schema_version":1,"tuning":tuning,"holdout":holdout}))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            value(
                cli(&["init", policy.to_str().unwrap(), root.to_str().unwrap()]),
                1
            )["error"]["kind"],
            "invalid_policy"
        );
        assert!(!root.exists(), "reject before campaign creation");
    }
    let root = initialize();
    let mut campaign = read(root.join("campaign.json"));
    campaign["registry"][0]["manifest"]["dataset_digest"] = json!("foreign");
    fs::write(
        root.join("campaign.json"),
        serde_json::to_vec(&campaign).unwrap(),
    )
    .unwrap();
    assert_eq!(
        run("regression", &root, &[], 1)["error"]["kind"],
        "identity_mismatch"
    );
    assert!(!root.join("operation-0").exists());
}
