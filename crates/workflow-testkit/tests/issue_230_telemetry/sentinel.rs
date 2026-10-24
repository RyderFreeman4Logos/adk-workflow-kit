//! Private Sentinel calls use the same HTTP boundary and durable report reconstruction.
use super::{cli, fs, json, success, wire_scenario};
use serde_json::Value;
use std::path::PathBuf;

const SOURCE: &str = "examples/03-sentinel-preparation/workflow.toml";
const RAW: &str =
    "Please review the attached report and send your comments before tomorrow morning.";

fn measured(
    usage: Option<Value>,
    retry: bool,
) -> (PathBuf, std::process::Output, Result<Value, String>) {
    wire_scenario(
        usage,
        retry,
        json!({}),
        (
            SOURCE,
            "sentinel-worker",
            json!({"schema_version":1,"bytes":RAW.as_bytes()}),
            Value::Null,
        ),
        2,
        |path, output| cli(&["measure", path.to_str().unwrap(), output.to_str().unwrap()]),
    )
}

#[test]
fn sentinel_finite_request_size_uses_original_http_content_length() {
    let (_, output, requests) = measured(None, false);
    success(output);
    for request in requests.unwrap()["wire_requests"].as_array().unwrap() {
        assert!(
            request["wire_body_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0 && bytes <= 16_384),
            "finite admission requires the original HTTP body size"
        );
    }
}

#[test]
fn sentinel_private_measurement_rebuilds_without_inventing_agent_calls_or_totals() {
    for usage in [
        None,
        Some(json!({"prompt_tokens":0,"completion_tokens":11,"total_tokens":999})),
    ] {
        let (root, output, requests) = measured(usage.clone(), false);
        let report = success(output);
        let requests = requests.unwrap();
        assert_eq!(requests["wire_request_count"], 2);
        for request in requests["wire_requests"].as_array().unwrap() {
            assert!(
                request
                    .get("tools")
                    .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            );
            assert_eq!(request["max_completion_tokens"], 128);
            assert!(serde_json::to_vec(request).unwrap().len() <= 16 * 1024);
        }
        assert_eq!(report["hard_invariant_failed"], false);
        assert_eq!(report["completed_model_observed"], true);
        assert_eq!(report["model_calls"], json!([]));
        let calls = report["sentinel_probe_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        for (call, branch) in calls.iter().zip(["ordered", "shuffled"]) {
            assert_eq!(call["source"], "protected-semantic-artifact-v3");
            assert_eq!(call["branch"], branch);
            if usage.is_none() {
                assert!(call["usage"].is_null());
            } else {
                assert_eq!(call["usage"]["input_tokens"], 0);
                assert_eq!(call["usage"]["total_tokens"], 999);
            }
        }
        assert_eq!(
            report["measured"]["sentinel_probe_calls"],
            report["sentinel_probe_calls"]
        );
        assert_eq!(
            report["measured"]["quality"]["predicate"],
            "sentinel-preparation-contract-v1"
        );
        assert_eq!(report["measured"]["quality"]["passed"], true);
        for metric in [
            "input_count",
            "total_count",
            "retries",
            "kv_cache_hit",
            "provider_cost_usd",
        ] {
            assert!(report["measured"][metric].is_null(), "{metric}");
        }
        let output = root.join("run");
        assert_eq!(
            success(cli(&["measure-report", output.to_str().unwrap()])),
            report
        );
        let stored_path = output.join("measurement.json");
        let mut stored: Value = serde_json::from_slice(&fs::read(&stored_path).unwrap()).unwrap();
        stored["sentinel_probe_calls"][0]["usage"] = json!({"input_tokens":123});
        fs::write(stored_path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(
            !cli(&["measure-report", output.to_str().unwrap()])
                .status
                .success()
        );
        if usage.is_none() {
            let path = root.join("binding.json");
            let mut binding: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            binding["kv_intent"] = json!({"schema_version":1,"schedule":"ordered-pair","namespace":"isolated-namespace","arm":"cold_namespace","order":0});
            fs::write(&path, serde_json::to_vec(&binding).unwrap()).unwrap();
            let rejected_root = root.join("unsupported-kv");
            let rejected = cli(&[
                "measure",
                path.to_str().unwrap(),
                rejected_root.to_str().unwrap(),
            ]);
            assert!(!rejected.status.success());
            assert!(
                String::from_utf8_lossy(&rejected.stderr)
                    .contains("Sentinel private probes do not support KV intent")
            );
            assert!(
                !rejected_root.exists(),
                "KV intent reached execution admission"
            );
        }
    }
}

#[test]
fn sentinel_private_429_abstains_without_binding_retry_or_wiring_success() {
    let (root, output, requests) = measured(None, true);
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let requests = requests.unwrap();
    assert!((1..=2).contains(&requests["wire_request_count"].as_u64().unwrap()));
    assert_eq!(report["completed_model_observed"], false);
    assert_eq!(report["hard_invariant_failed"], true);
    assert!(report["sentinel_probe_calls"].is_null());
    assert_eq!(
        report["measured"]["quality"]["semantic_reason"],
        "invalid_or_failed"
    );
    let rebuilt = cli(&["measure-report", root.join("run").to_str().unwrap()]);
    assert!(!rebuilt.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&rebuilt.stdout).unwrap(),
        report
    );
}

#[test]
fn sentinel_private_reconstruction_rejects_artifact_input_and_missing_checkpoint() {
    let (directory, output, _) = measured(None, false);
    let report = success(output);
    let output = directory.join("run");
    let case: Value =
        serde_json::from_slice(&fs::read(output.join("execution.json")).unwrap()).unwrap();
    let root = PathBuf::from(case["receipt"]["run_root"].as_str().unwrap());
    let artifact = root.join("artifacts").join(
        report["sentinel_probe_calls"][0]["artifact_id"]
            .as_str()
            .unwrap(),
    );
    for path in [artifact, root.join("execution-input.json")] {
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"{}").unwrap();
        assert!(
            !cli(&["measure-report", output.to_str().unwrap()])
                .status
                .success()
        );
        fs::write(&path, original).unwrap();
    }
    for name in ["checkpoint.sqlite", "checkpoint-manifest.json", "artifacts"] {
        let path = root.join(name);
        let retained = root.join(format!("retained-{name}"));
        fs::rename(&path, &retained).unwrap();
        assert!(
            !cli(&["measure-report", output.to_str().unwrap()])
                .status
                .success()
        );
        assert!(!path.exists(), "report recreated {name}");
        fs::rename(retained, path).unwrap();
    }
    assert_eq!(
        success(cli(&["measure-report", output.to_str().unwrap()])),
        report
    );
}

#[test]
fn sentinel_private_calls_keep_distinct_raw_usage_and_invalid_counts_unknown() {
    let usage = json!([{"prompt_tokens":0,"completion_tokens":11,"total_tokens":999},
        {"prompt_tokens":19,"completion_tokens":-1,"total_tokens":"invalid"}]);
    let (_, output, _) = measured(Some(usage), false);
    let report = success(output);
    let calls = report["sentinel_probe_calls"].as_array().unwrap();
    assert_eq!(calls[0]["usage"]["input_tokens"], 0);
    assert_eq!(calls[0]["usage"]["output_tokens"], 11);
    assert_eq!(calls[0]["usage"]["total_tokens"], 999);
    assert_eq!(calls[1]["usage"]["input_tokens"], 19);
    assert!(calls[1]["usage"]["output_tokens"].is_null());
    assert!(calls[1]["usage"]["total_tokens"].is_null());
    assert_ne!(
        calls[0]["invocation_identity"],
        calls[1]["invocation_identity"]
    );
    assert_eq!(calls[0]["schema_hash"], calls[1]["schema_hash"]);
}
