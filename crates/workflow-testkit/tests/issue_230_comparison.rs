//! Public comparison admission, using real scripted runtime artifacts.
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

fn cli(args: &[&str], code: i32) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_bench-230"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("structured comparison response")
}
fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn explicit_config_campaigns_bind_real_execution_and_reject_unsafe_controls() {
    let root = std::env::temp_dir().join(format!("config-comparison230-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let split = root.join("split.json");
    write(
        &split,
        &json!({"schema_version":1,"tuning":["runtime-smoke","downstream-consumer"],"holdout":["code-investigation","minimal-template"]}),
    );
    let config = root.join("config.json");
    let valid = json!({"schema_version":1,"loop_policy":{"schema_version":1,"max_model_iterations":20,"max_total_tool_calls":20,"max_tool_calls_per_tool":20,"wall_time_ms":60000,"idle_time_ms":30000,"tool_time_ms":10000,"max_tool_output_bytes":65536}});
    write(&config, &valid);
    let a = root.join("a");
    cli(
        &[
            "init-config",
            split.to_str().unwrap(),
            config.to_str().unwrap(),
            a.to_str().unwrap(),
        ],
        0,
    );
    let mut changed = valid.clone();
    changed["loop_policy"]["max_model_iterations"] = json!(30);
    write(&config, &changed);
    let b = root.join("b");
    cli(
        &[
            "init-config",
            split.to_str().unwrap(),
            config.to_str().unwrap(),
            b.to_str().unwrap(),
        ],
        0,
    );
    let before = cli(&["regression", a.to_str().unwrap()], 0);
    let after = cli(&["regression", b.to_str().unwrap()], 0);
    for (a, b) in before["execution"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(after["execution"]["cases"].as_array().unwrap())
    {
        assert_ne!(a["admitted_run_id"], b["admitted_run_id"]);
        assert!(a["elapsed_ns"].as_u64().unwrap() > 0);
        assert!(b["elapsed_ns"].as_u64().unwrap() > 0);
        assert_ne!(
            a["manifest"]["config_digest"],
            b["manifest"]["config_digest"]
        );
        for field in [
            "source_revision",
            "source_tree",
            "executable_digest",
            "workflow_digest",
            "model_digest",
            "dataset_digest",
        ] {
            assert_eq!(a["manifest"][field], b["manifest"][field], "{field}");
        }
    }
    // Explicit config-only plan uses the structured one-shot admission boundary.
    let rejected = cli(
        &[
            "compare-plan",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "100",
            "config-only",
        ],
        1,
    );
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("predeclare threshold")
    );
    // Resume preserves observations; it is not an independent sample.
    let resumed = cli(&["resume", a.join("operation-0").to_str().unwrap()], 0);
    assert_eq!(resumed["cases"], before["execution"]["cases"]);
    for field in ["model", "sandbox", "trust_domain", "independent_samples"] {
        let mut bad = valid.clone();
        bad[field] = json!({});
        write(&config, &bad);
        let output = root.join(format!("bad-{field}"));
        assert_eq!(
            cli(
                &[
                    "init-config",
                    split.to_str().unwrap(),
                    config.to_str().unwrap(),
                    output.to_str().unwrap()
                ],
                1
            )["error"]["kind"],
            "invalid_policy"
        );
        assert!(!output.exists());
    }
    let mut bad = valid;
    bad["loop_policy"]["wall_time_ms"] = json!(0);
    write(&config, &bad);
    let output = root.join("bad-budget");
    assert_eq!(
        cli(
            &[
                "init-config",
                split.to_str().unwrap(),
                config.to_str().unwrap(),
                output.to_str().unwrap()
            ],
            1
        )["error"]["kind"],
        "invalid_policy"
    );
    assert!(!output.exists());
}

#[test]
fn comparison_admission_fails_closed_on_ineligible_real_reports() {
    let root = std::env::temp_dir().join(format!("comparison230-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let split = root.join("split.json");
    write(
        &split,
        &json!({"schema_version":1,"tuning":["runtime-smoke","downstream-consumer"],"holdout":["code-investigation","minimal-template"]}),
    );
    let baseline = root.join("baseline");
    let candidate = root.join("candidate");
    for campaign in [&baseline, &candidate] {
        cli(
            &["init", split.to_str().unwrap(), campaign.to_str().unwrap()],
            0,
        );
    }
    let args = [
        "compare-plan",
        baseline.to_str().unwrap(),
        candidate.to_str().unwrap(),
        "100",
    ];
    let missing = cli(&args, 1);
    assert_eq!(missing["error"]["kind"], "invalid_comparison");
    cli(&["regression", baseline.to_str().unwrap()], 0);
    let same = cli(&args, 1);
    assert!(
        same["error"]["message"]
            .as_str()
            .unwrap()
            .contains("distinct committed revisions")
    );
    let path = baseline.join("operation-0/case-0.json");
    let original = read(&path);
    let mut tampered = original.clone();
    tampered["receipt"]["event_counts"]["model_turns"] = json!(999999);
    write(&path, &tampered);
    let rejected = cli(&args, 1);
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("evidence mismatch")
    );
    write(&path, &original);
    let mut unsupported = original.clone();
    unsupported["status"] = json!("unsupported");
    unsupported["receipt"] = Value::Null;
    unsupported["elapsed_ns"] = Value::Null;
    unsupported["events_digest"] = Value::Null;
    unsupported["admitted_run_id"] = Value::Null;
    unsupported["unsupported_reason"] = json!("fixture: unavailable adapter");
    write(&path, &unsupported);
    assert_eq!(cli(&args, 1)["error"]["kind"], "invalid_comparison");
    write(&path, &original);
    let mut mismatch = original.clone();
    mismatch["manifest"]["dataset_digest"] = json!("sha256:foreign");
    write(&path, &mismatch);
    assert!(
        cli(&args, 1)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("identity mismatch")
    );
    assert!(!candidate.join("comparison.json").exists());
    write(&path, &original);
    let mut missing_receipt = original.clone();
    missing_receipt["receipt"] = Value::Null;
    write(&path, &missing_receipt);
    assert!(cli(&args, 1)["hard_invariant_failed"] == true);
    write(&path, &original);
    let mut unavailable = original.clone();
    unavailable["elapsed_ns"] = Value::Null;
    write(&path, &unavailable);
    let rejected = cli(&args, 1);
    assert_eq!(rejected["error"]["kind"], "invalid_comparison");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("completion evidence")
    );
    assert!(!candidate.join("comparison.json").exists());
    write(&path, &original);
    // Preserve read-only runtime artifacts as evidence; the executor owns their modes.
}
