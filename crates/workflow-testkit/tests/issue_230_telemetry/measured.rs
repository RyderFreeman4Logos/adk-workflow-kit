//! The production report recomputes semantic evidence from the selected durable output.
use super::{cli, fs, json, success, wire_case};
use serde_json::Value;
use std::path::PathBuf;
use workflow_runtime::{CheckpointManifestV1, DurableCheckpointV1, RunId, SqliteCheckpointStore};

const REQUEST: &str = "Sort [7,2,7,1] ascending and compute their sum. Return the output object with exactly sorted and sum.";

fn execution(sum: u64, usage: Option<Value>) -> (PathBuf, Value) {
    let (root, output, _) = wire_case(
        usage,
        false,
        json!({"reasoning_effort":"low"}),
        "templates/minimal/workflow.toml",
        "minimal-worker",
        json!({"request":REQUEST}),
        json!({"sorted":[1,2,7,7],"sum":sum}),
    );
    (root.join("run"), success(output))
}

#[test]
fn measured_pairs_preserve_unknowns_and_use_raw_completion_pareto() {
    let (left, first) = execution(17, Some(json!({"prompt_tokens":19,"completion_tokens":11})));
    let (right, second) = execution(18, Some(json!({"prompt_tokens":19,"completion_tokens":23})));
    let paired = success(cli(&[
        "measure-compare",
        left.to_str().unwrap(),
        right.to_str().unwrap(),
    ]));
    assert_eq!(paired["rows"][0]["quality_millis_delta"], -1000);
    assert_eq!(
        paired["rows"][0]["provider_completion_count_delta_decimal"],
        "12"
    );
    assert_eq!(
        paired["pareto"]["frontier"],
        json!([{"side":0,"run_id":first["case"]["admitted_run_id"]}])
    );
    assert!(paired["rows"][0]["confidence_interval"].is_null());
    assert!(paired["safety_accepted"].is_null());
    assert!(paired["rows"][0]["security_failures_delta"].is_null());
    assert_eq!(paired["causal_performance_claim"], false);
    for (side, original) in [("left", &first), ("right", &second)] {
        for key in [
            "evidence_kind",
            "origin_assertion",
            "live_executed",
            "live_opt_in",
            "binding_digest",
        ] {
            assert_eq!(
                paired["rows"][0][side][key], original[key],
                "lost {side} {key}"
            );
        }
    }
    assert!(
        !cli(&[
            "measure-compare",
            left.to_str().unwrap(),
            left.to_str().unwrap()
        ])
        .status
        .success()
    );
    let (missing, missing_report) = execution(17, None);
    assert!(missing_report["measured"]["provider_completion_count"].is_null());
    assert_eq!(missing_report["measured"]["quality"]["passed"], true);
    let paired = success(cli(&[
        "measure-compare",
        left.to_str().unwrap(),
        missing.to_str().unwrap(),
    ]));
    assert_eq!(paired["pareto"]["excluded"][0]["side"], 1);
    assert!(paired["rows"][0]["provider_completion_count_delta_decimal"].is_null());
    let (different, actual, _) = wire_case(
        Some(json!({"completion_tokens":11})),
        false,
        json!({"reasoning_effort":"low"}),
        "templates/minimal/workflow.toml",
        "minimal-worker",
        json!({"request":"Return a sorted description for this distinct task."}),
        json!({"description":"sorted"}),
    );
    assert_eq!(success(actual)["measured"]["provider_completion_count"], 11);
    assert!(
        !cli(&[
            "measure-compare",
            left.to_str().unwrap(),
            different.join("run").to_str().unwrap()
        ])
        .status
        .success()
    );
}

#[test]
fn measured_report_never_initializes_an_existing_invalid_checkpoint() {
    let (output, _) = execution(17, Some(json!({"completion_tokens":11})));
    let case: Value =
        serde_json::from_slice(&fs::read(output.join("execution.json")).unwrap()).unwrap();
    let root = PathBuf::from(case["receipt"]["run_root"].as_str().unwrap());
    let database = root.join("checkpoint.sqlite");
    let retained = root.join("checkpoint-retained.sqlite");
    fs::rename(&database, &retained).unwrap();
    fs::write(&database, []).unwrap();
    assert!(
        !cli(&["measure-report", output.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        fs::read(&database).unwrap().is_empty(),
        "report initialized retained empty DB"
    );
    fs::remove_file(&database).unwrap();
    fs::rename(retained, &database).unwrap();
    let manifest = root.join("checkpoint-manifest.json");
    let bytes = fs::read(&manifest).unwrap();
    fs::remove_file(&manifest).unwrap();
    assert!(
        !cli(&["measure-report", output.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        !manifest.exists(),
        "report recreated missing checkpoint manifest"
    );
    fs::write(manifest, bytes).unwrap();
}

#[test]
fn measured_report_rejects_stale_checkpoint_and_input_or_record_forgery() {
    let (output, report) = execution(17, Some(json!({"completion_tokens":11})));
    let case: Value =
        serde_json::from_slice(&fs::read(output.join("execution.json")).unwrap()).unwrap();
    let root = PathBuf::from(case["receipt"]["run_root"].as_str().unwrap());
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.join("run-manifest.json")).unwrap()).unwrap();
    let compatibility: CheckpointManifestV1 =
        serde_json::from_value(manifest["checkpoint_manifest"].clone()).unwrap();
    let id = RunId::new(
        report["case"]["admitted_run_id"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
    .unwrap();
    let mut store =
        SqliteCheckpointStore::open(root.join("checkpoint.sqlite"), compatibility).unwrap();
    let checkpoint = store.load_latest(&id).unwrap().unwrap();
    let stale = DurableCheckpointV1::new(
        id.clone(),
        checkpoint.node_id(),
        checkpoint.event_sequence() - 1,
        checkpoint.state(),
        checkpoint.artifact_refs().iter().cloned(),
    )
    .unwrap();
    store.save_checkpoint(stale).unwrap();
    drop(store);
    let rejected = cli(&["measure-report", output.to_str().unwrap()]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("terminal generation mismatch"));
    let mut store = SqliteCheckpointStore::open(
        root.join("checkpoint.sqlite"),
        serde_json::from_value(manifest["checkpoint_manifest"].clone()).unwrap(),
    )
    .unwrap();
    store.save_checkpoint(checkpoint).unwrap();
    drop(store);
    let database = root.join("checkpoint.sqlite");
    let retained = root.join("checkpoint-retained.sqlite");
    fs::rename(&database, &retained).unwrap();
    assert!(
        !cli(&["measure-report", output.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        !database.exists(),
        "report must not create a missing checkpoint"
    );
    fs::rename(retained, database).unwrap();
    let input_path = root.join("execution-input.json");
    let input = fs::read(&input_path).unwrap();
    fs::write(&input_path, b"{\"request\":\"different legitimate input\"}").unwrap();
    assert!(
        !cli(&["measure-report", output.to_str().unwrap()])
            .status
            .success()
    );
    fs::write(&input_path, input).unwrap();
    let mut forged: Value =
        serde_json::from_slice(&fs::read(output.join("measurement.json")).unwrap()).unwrap();
    forged["measured"] = json!({"quality":{"passed":true,"quality_millis":1000}});
    fs::write(
        output.join("measurement.json"),
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert!(
        !cli(&["measure-report", output.to_str().unwrap()])
            .status
            .success()
    );
}

#[test]
fn measured_report_recomputes_selected_output_instead_of_trusting_positive_sidecars() {
    for (sum, passed) in [(17, true), (18, false)] {
        let (root, original, _) = wire_case(
            Some(
                json!({"prompt_tokens":19,"completion_tokens":11,"total_tokens":30,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":3}}),
            ),
            false,
            json!({"reasoning_effort":"low"}),
            "templates/minimal/workflow.toml",
            "minimal-worker",
            json!({"request":"Sort [7,2,7,1] ascending and compute their sum. Return the output object with exactly sorted and sum."}),
            json!({"sorted":[1,2,7,7],"sum":sum}),
        );
        let original = success(original);
        let output = root.join("run");
        // This external assertion is deliberately false for sum=18; it is not authority.
        fs::write(output.join("semantic-check.json"), b"{\"passed\":true}").unwrap();
        let report = success(cli(&["measure-report", output.to_str().unwrap()]));
        assert_eq!(report["measured"]["quality"]["passed"], passed);
        assert_eq!(
            report["measured"]["quality"]["quality_millis"],
            if passed { 1000 } else { 0 }
        );
        assert_eq!(
            report["measured"]["run_id"],
            original["case"]["admitted_run_id"]
        );
        assert_eq!(report["measured"]["provider_completion_count"], 11);
        assert!(report["measured"]["visible_output_count"].is_null());
        assert!(report["measured"]["security_failures"].is_null());
    }
}
