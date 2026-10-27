//! Real host request observations remain distinct from admitted cache intent.
use super::{FixtureWindows, cli, json, success, wire_scenario, wire_scenario_with_windows};
use sha2::{Digest, Sha256};

#[test]
fn actual_request_prefix_and_field_sources_are_not_inferred_provider_metrics() {
    let (_, output, request) = wire_scenario(
        Some(
            json!({"prompt_tokens":19,"completion_tokens":11,"total_tokens":30,
            "prompt_tokens_details":{"cached_tokens":0,"cache_write_tokens":3},
            "completion_tokens_details":{"reasoning_tokens":5},
            "prefill_ns":9,"decode_ns":10,"cost":2,"kv_cache_hit":true}),
        ),
        false,
        json!({"reasoning_effort":"low"}),
        (
            "templates/minimal/workflow.toml",
            "minimal-worker",
            json!({"request":"Return a public status object."}),
            json!({"status":"ready"}),
        ),
        1,
        |binding, output| {
            cli(&[
                "measure",
                binding.to_str().unwrap(),
                output.to_str().unwrap(),
            ])
        },
    );
    let report = success(output);
    let measured = &report["measured"];
    assert_eq!(
        measured["field_sources"]["cached_input_count"]["observed"],
        true
    );
    assert_eq!(
        measured["field_sources"]["cached_input_count"]["source"],
        "provider_usage.prompt_tokens_details.cached_tokens"
    );
    assert_eq!(measured["cached_input_count"], 0);
    assert_eq!(measured["cache_write_count"], 3);
    assert!(
        measured["host_prefix_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    for field in [
        "visible_output_count",
        "prefill_ns",
        "decode_ns",
        "provider_cost_usd",
        "kv_cache_hit",
    ] {
        assert!(
            measured[field].is_null(),
            "unsupported raw field was trusted: {field}"
        );
        assert_eq!(measured["field_sources"][field]["observed"], false);
    }
    assert!(measured["sdk_estimated_cost_usd"].is_null());
    assert_eq!(measured["total_count"], 30);
    let request = request.unwrap();
    assert!(request.get("cache_salt").is_none());
    // This registered minimal agent has no authored instruction/system contents or tools.
    // Bind the observation to the actual wire model/schema, not a preset expected hash.
    assert!(
        request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["role"] != "system")
    );
    let actual = json!({"model":request["model"],"leading_system":[],"tools":{},
        "response_schema":request.pointer("/response_format/json_schema/schema").cloned().unwrap_or(serde_json::Value::Null)});
    assert_eq!(
        measured["host_prefix_hash"],
        format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&actual).unwrap())
        )
    );
}

#[test]
fn admitted_kv_schedule_drives_wire_salt_and_rejects_changed_or_ambiguous_predecessors() {
    let mut first = None;
    let (_, second, requests) = wire_scenario_with_windows(
        Some(
            json!({"prompt_tokens":9,"completion_tokens":4,"total_tokens":13,"prompt_tokens_details":{"cached_tokens":0}}),
        ),
        false,
        json!({"cache_salt":"public-trust-domain"}),
        (
            "templates/minimal/workflow.toml",
            "minimal-worker",
            json!({"request":"Return status ready."}),
            json!({"status":"ready"}),
        ),
        2,
        FixtureWindows::PerCli(std::time::Duration::from_secs(20)),
        |binding, output, admit_next_window| {
            let original: serde_json::Value =
                serde_json::from_slice(&std::fs::read(binding).unwrap()).unwrap();
            let mut cold = original;
            cold["kv_intent"] = json!({"schema_version":1,"schedule":"ordered-pair","namespace":"isolated-namespace","arm":"cold_namespace","order":0});
            std::fs::write(binding, serde_json::to_vec(&cold).unwrap()).unwrap();
            let cold_output = cli(&[
                "measure",
                binding.to_str().unwrap(),
                output.to_str().unwrap(),
            ]);
            if !cold_output.status.success() {
                return cold_output;
            }
            first = Some(success(cold_output));
            let mut warm = cold.clone();
            warm["kv_intent"]["arm"] = json!("warm_repeat");
            warm["kv_intent"]["order"] = json!(1);
            warm["kv_intent"]["predecessor"] = json!(output);
            std::fs::write(binding, serde_json::to_vec(&warm).unwrap()).unwrap();
            let warm_root = output.with_file_name("warm");
            admit_next_window();
            let second = cli(&[
                "measure",
                binding.to_str().unwrap(),
                warm_root.to_str().unwrap(),
            ]);
            if !second.status.success() {
                return second;
            }
            let repeated = success(cli(&["measure-report", warm_root.to_str().unwrap()]));
            assert_eq!(
                repeated["kv_intent"]["predecessor_run_id"],
                first.as_ref().unwrap()["case"]["admitted_run_id"]
            );
            let plan: serde_json::Value = serde_json::from_slice(
                &std::fs::read(output.join("measurement-plan.json")).unwrap(),
            )
            .unwrap();
            let admission: serde_json::Value = serde_json::from_slice(
                &std::fs::read(output.join("measurement-admission.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                admission["run_id"],
                first.as_ref().unwrap()["case"]["admitted_run_id"]
            );
            assert_eq!(plan["kv_intent"]["declaration"]["arm"], "cold_namespace");
            let plan_path = output.join("measurement-plan.json");
            let saved_plan = std::fs::read(&plan_path).unwrap();
            let mut changed_plan = plan.clone();
            changed_plan["kv_intent"]["declaration"]["namespace"] = json!("tampered");
            std::fs::write(&plan_path, serde_json::to_vec(&changed_plan).unwrap()).unwrap();
            assert!(
                !cli(&["measure-report", output.to_str().unwrap()])
                    .status
                    .success()
            );
            std::fs::write(&plan_path, saved_plan).unwrap();
            success(cli(&["measure-report", output.to_str().unwrap()]));
            // Every denied variant must stop before admission/provider or directory creation.
            for change in 0..6 {
                let mut bad = warm.clone();
                match change {
                    0 => bad["input"]["request"] = json!("different task"),
                    1 => bad["kv_intent"]["order"] = json!(3),
                    2 => bad["kv_intent"]["namespace"] = json!("other-namespace"),
                    3 => bad["profile"]["model"]["model"] = json!("different-model"),
                    4 => bad["kv_intent"]["predecessor"] = json!(output.join("missing")),
                    _ => bad["kv_intent"]["arm"] = json!("cold_namespace"),
                }
                std::fs::write(binding, serde_json::to_vec(&bad).unwrap()).unwrap();
                let denied = output.with_file_name(format!("denied-{change}"));
                assert!(
                    !cli(&[
                        "measure",
                        binding.to_str().unwrap(),
                        denied.to_str().unwrap()
                    ])
                    .status
                    .success()
                );
                assert!(!denied.exists());
            }
            let execution = output.join("execution.json");
            let saved = std::fs::read(&execution).unwrap();
            std::fs::remove_file(&execution).unwrap();
            std::fs::write(binding, serde_json::to_vec(&warm).unwrap()).unwrap();
            let ambiguous = output.with_file_name("ambiguous");
            assert!(
                !cli(&[
                    "measure",
                    binding.to_str().unwrap(),
                    ambiguous.to_str().unwrap()
                ])
                .status
                .success()
            );
            assert!(!ambiguous.exists());
            std::fs::write(&execution, saved).unwrap();
            second
        },
    );
    let second = success(second);
    let first = first.unwrap();
    let requests = requests.unwrap();
    assert_eq!(requests["wire_request_count"], 2);
    let salts = requests["wire_cache_salts"].as_array().unwrap();
    assert_eq!(salts.len(), 2);
    assert_eq!(salts[0], salts[1]);
    assert_ne!(salts[0], "public-trust-domain");
    assert_ne!(salts[0], "isolated-namespace");
    let salt_hash = format!(
        "sha256:{:x}",
        Sha256::digest(salts[0].as_str().unwrap().as_bytes())
    );
    assert_eq!(
        first["model_calls"][0]["telemetry"]["request_cache_salt_hash"],
        salt_hash
    );
    assert_eq!(
        first["measured"]["host_prefix_hash"],
        second["measured"]["host_prefix_hash"]
    );
    assert_ne!(first["measured"]["run_id"], second["measured"]["run_id"]);
    assert_eq!(first["kv_intent"]["declaration"]["arm"], "cold_namespace");
    assert_eq!(second["kv_intent"]["declaration"]["arm"], "warm_repeat");
    assert_eq!(
        second["kv_intent"]["predecessor_run_id"],
        first["measured"]["run_id"]
    );
    assert_eq!(second["measured"]["cached_input_count"], 0);
    assert!(second["measured"]["kv_cache_hit"].is_null());
}

#[test]
fn legacy_recorded_projection_is_readable_without_backfilled_observations() {
    let (_, output, _) = wire_scenario(
        None,
        false,
        json!({}),
        (
            "templates/minimal/workflow.toml",
            "minimal-worker",
            json!({"request":"Return ready."}),
            json!({"status":"ready"}),
        ),
        1,
        |binding, output| {
            success(cli(&[
                "measure",
                binding.to_str().unwrap(),
                output.to_str().unwrap(),
            ]));
            let path = output.join("measurement.json");
            let mut recorded: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            // The preceding production version emitted this base projection. Its
            // explanatory text is not a metric and must not invalidate its receipt.
            recorded["unavailable"]["provider_cost_usd"] = json!(
                "no provider billing receipt; reported_cost_usd is unavailable because normalized SDK estimates lack raw-response provenance"
            );
            let mut legacy = recorded["model_calls"][0]["telemetry"].clone();
            for field in [
                "host_prefix_hash",
                "request_cache_salt_hash",
                "sdk_estimated_cost_usd",
            ] {
                legacy.as_object_mut().unwrap().remove(field);
            }
            let parsed: workflow_adk::model_telemetry::ModelTelemetryV1 =
                serde_json::from_value(legacy.clone()).unwrap();
            assert!(parsed.host_prefix_hash.is_none());
            assert!(parsed.request_cache_salt_hash.is_none());
            assert!(parsed.sdk_estimated_cost_usd.is_none());
            assert_eq!(serde_json::to_value(parsed).unwrap(), legacy);
            std::fs::write(&path, serde_json::to_vec(&recorded).unwrap()).unwrap();
            let compatible = cli(&["measure-report", output.to_str().unwrap()]);
            if !compatible.status.success() {
                return compatible;
            }
            let mut tampered = recorded.clone();
            tampered["model_calls"][0]["telemetry"]["input_tokens"] = json!(99);
            std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
            assert!(
                !cli(&["measure-report", output.to_str().unwrap()])
                    .status
                    .success()
            );
            std::fs::write(&path, serde_json::to_vec(&recorded).unwrap()).unwrap();
            compatible
        },
    );
    let report = success(output);
    assert_eq!(report["case"]["status"], "succeeded");
    assert!(report["measured"]["input_count"].is_null());
    assert!(report["measured"]["sdk_estimated_cost_usd"].is_null());
}
