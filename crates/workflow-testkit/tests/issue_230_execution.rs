//! Public CLI contracts: runtime evidence must not be three synthetic envelopes.
use std::{collections::BTreeSet, fs, path::PathBuf, process::Command};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[test]
fn scripted_cli_executes_registered_sources_and_measures_receipts() {
    let output = Command::new(env!("CARGO_BIN_EXE_bench-230"))
        .current_dir(repo())
        .arg("scripted")
        .output()
        .expect("public binary");
    assert_eq!(
        output.status.code(),
        Some(0),
        "all registered packages must execute: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
    assert_eq!(
        report["evidence_kind"], "scripted_execution",
        "static fixtures are not execution"
    );
    assert_eq!(report["live_executed"], false);
    assert_eq!(report["hard_invariant_failed"], false);
    let cases = report["cases"].as_array().unwrap();
    let ids: BTreeSet<_> = cases
        .iter()
        .map(|case| case["case_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        BTreeSet::from([
            "code-investigation",
            "downstream-consumer",
            "minimal-template",
            "runtime-smoke",
            "sentinel-preparation"
        ])
    );
    assert_eq!(ids.len(), cases.len());
    let output_directory = PathBuf::from(
        report["output_directory"]
            .as_str()
            .expect("durable per-case directory"),
    );
    for (index, case) in cases.iter().enumerate() {
        let persisted: Value = serde_json::from_slice(
            &fs::read(output_directory.join(format!("case-{index}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(&persisted, case);
        assert!(
            !output_directory
                .join(format!("case-{index}.pending"))
                .exists()
        );
    }
    for case in cases {
        let binding = &case["manifest"];
        let source = repo().join(binding["workflow_source"].as_str().unwrap());
        assert_eq!(
            binding["workflow_digest"],
            digest(&fs::read(source).unwrap())
        );
        assert!(binding["source_revision"].as_str().unwrap().len() == 40);
        for key in [
            "source_files_digest",
            "executable_digest",
            "config_digest",
            "dataset_digest",
            "model_digest",
        ] {
            assert!(
                binding[key].as_str().unwrap().starts_with("sha256:"),
                "{key}"
            );
        }
        assert_eq!(case["status"], "succeeded", "{case}");
        let receipt = &case["receipt"];
        assert_eq!(receipt["status"], "succeeded");
        assert!(!receipt["run_id"].as_str().unwrap().is_empty());
        assert!(case["elapsed_ns"].as_u64().unwrap() > 0);
        for metric in [
            "tokens",
            "prefill_ns",
            "decode_ns",
            "provider_cost_micros",
            "prefix_hit",
            "retries",
            "escalation",
            "hitl",
        ] {
            assert!(
                case[metric].is_null(),
                "unavailable {metric} must not be invented"
            );
        }
        let root = PathBuf::from(receipt["run_root"].as_str().unwrap());
        assert_eq!(
            digest(&fs::read(root.join("events.jsonl")).unwrap()),
            case["events_digest"]
        );
        let durable: Value =
            serde_json::from_slice(&fs::read(root.join("run-manifest.json")).unwrap()).unwrap();
        assert_eq!(durable["cache_dispositions"], receipt["cache_dispositions"]);
        assert_eq!(durable["event_counts"], receipt["event_counts"]);
        assert!(
            fs::read_to_string(root.join("events.jsonl"))
                .unwrap()
                .contains("workflow_completed")
        );
        if case["case_id"] == "minimal-template" {
            let expected = "Run the explicitly bound minimal workflow.";
            let input: Value =
                serde_json::from_slice(&fs::read(root.join("execution-input.json")).unwrap())
                    .unwrap();
            assert_eq!(input["request"], expected);
            let ledger: Value =
                serde_json::from_slice(&fs::read(root.join("loop-ledger.json")).unwrap()).unwrap();
            let contents: Vec<adk_rust::Content> =
                serde_json::from_value(ledger["nodes"]["start"]["conversation"].clone()).unwrap();
            assert!(
                contents
                    .iter()
                    .filter(|c| c.role == "user")
                    .flat_map(|c| &c.parts)
                    .filter_map(adk_rust::Part::text)
                    .filter_map(|text| serde_json::from_str::<Value>(text).ok())
                    .any(|value| value
                        .pointer("/input/request")
                        .or_else(|| value.get("request"))
                        .and_then(Value::as_str)
                        == Some(expected)),
                "the distinct request must reach the actual model input"
            );
        }
        assert_eq!(case["hard_invariant_failures"], serde_json::json!([]));
    }
}

#[test]
fn minimal_template_has_legitimate_executor_binding() {
    use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1};
    let mut profile: Value = serde_json::from_slice(
        &fs::read(repo().join("examples/00-runtime-smoke/profiles/fake.json")).unwrap(),
    )
    .unwrap();
    profile["model"]["name"] = serde_json::json!("minimal-worker");
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&profile).unwrap()).unwrap();
    let receipt = ExecutionBackend::run(
        repo().join("templates/minimal/workflow.toml"),
        profile,
        serde_json::json!({"request": "runtime smoke"}),
        std::env::temp_dir(),
    )
    .expect("every registered template requires a real executor binding");
    assert_eq!(receipt.status(), "succeeded");
}

#[test]
fn mismatched_model_binding_is_rejected_before_run_admission() {
    use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};
    let profile = ExecutionProfileV1::parse(
        &fs::read(repo().join("examples/00-runtime-smoke/profiles/fake.json")).unwrap(),
    )
    .unwrap();
    let failure = ExecutionBackend::run(
        repo().join("templates/minimal/workflow.toml"),
        profile,
        serde_json::json!({"request": "runtime smoke"}),
        std::env::temp_dir(),
    )
    .unwrap_err();
    assert_eq!(failure.kind(), ExecutionErrorKind::MissingBinding);
    assert!(failure.receipt().is_none());
}

#[test]
fn registry_discovers_unknown_packages_and_rejects_missing_or_linked_packages() {
    use workflow_testkit::execution230::scripted_workflows;
    let root = std::env::temp_dir().join(format!("registry230-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let shipped = scripted_workflows(&repo()).unwrap();
    // Minimal file-discovery fixture only, not another Rust checkout.
    for workflow in &shipped {
        let file = root.join(&workflow.source);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, "discovery-only").unwrap();
    }
    let unknown = root.join("examples/new/workflow.toml");
    fs::create_dir(unknown.parent().unwrap()).unwrap();
    fs::write(&unknown, "discovery-only").unwrap();
    let found = scripted_workflows(&root).unwrap();
    assert_eq!(found.len(), shipped.len() + 1);
    assert!(
        found
            .iter()
            .any(|case| case.source == "examples/new/workflow.toml")
    );
    std::os::unix::fs::symlink(root.join("examples/new"), root.join("examples/linked")).unwrap();
    assert!(scripted_workflows(&root).unwrap_err().contains("symlinked"));
    fs::remove_file(root.join("examples/linked")).unwrap();
    fs::remove_file(root.join(&shipped[0].source)).unwrap();
    assert!(
        scripted_workflows(&root)
            .unwrap_err()
            .contains("registered workflow missing")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scripted_cli_rejects_unknown_arguments_instead_of_ignoring_them() {
    let output = Command::new(env!("CARGO_BIN_EXE_bench-230"))
        .args(["scripted", "silently-ignored"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}
