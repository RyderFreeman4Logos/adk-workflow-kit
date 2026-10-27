//! Typed provider options and one fixed semantic case; opt-in reuses the retained predicate.
use super::{PathBuf, Value, assert_cli_success, fs, json, repo, success, wire_case, wire_options};
use sha2::{Digest, Sha256};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};
fn input() -> Value {
    json!({"request":"Sort [7,2,7,1] ascending and compute their sum. Return the output object with exactly sorted and sum."})
}

fn expected() -> Value {
    json!({"sorted":[1,2,7,7],"sum":17})
}

#[test]
fn fixture_authorization_observation_preserves_exact_token_bytes() {
    for (authorization, expected) in [
        ("aUtHoRiZaTiOn: bEaReR CALLER_AUTH_NEVER_REPORT", true),
        ("AUTHORIZATION: Bearer caller_auth_never_report", false),
    ] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client = std::net::TcpStream::connect_timeout(
            &listener.local_addr().unwrap(),
            super::remaining(deadline).unwrap(),
        )
        .unwrap();
        let mut server = super::accept_request(&listener, deadline).unwrap();
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\n{authorization}\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        super::write_reply(&mut client, request.as_bytes(), deadline).unwrap();
        let observed = super::read_request(&mut server, deadline).unwrap();
        assert_eq!(observed["wire_caller_credential"], expected);
    }
}

// The actual CLI already recomputes this projection before returning. Reuse it without
// another child process or a second checkpoint algorithm inside the fixture's deadline.
fn check(output: &Path, report: &Value) -> Result<Value, &'static str> {
    let admission: Value = serde_json::from_slice(
        &fs::read(output.join("measurement-admission.json"))
            .map_err(|_| "admission unavailable")?,
    )
    .map_err(|_| "invalid admission")?;
    let quality = &report["measured"]["quality"];
    if admission["run_id"] != report["case"]["admitted_run_id"]
        || quality["run_id"] != admission["run_id"]
        || quality["execution_manifest"] != report["case"]["manifest"]
        || quality["input_digest"] != report["case"]["manifest"]["dataset_digest"]
        || quality["events_digest"] != report["case"]["events_digest"]
        || quality["schema_version"] != 1
        || quality["predicate"] != "sort-7-2-7-1-and-sum-exact-v1"
        || quality["selected_node"] != "start"
        || quality["state_key"] != "node:start"
        || quality["checkpoint_node"] != "done"
        || !quality["checkpoint_sequence"]
            .as_u64()
            .is_some_and(|n| n > 0)
    {
        return Err("semantic run identity rejected");
    }
    quality.as_object().ok_or("unsupported semantic input")?;
    Ok(quality.clone())
}

fn retain(output: &Path, evidence: &Value) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output.join("semantic-check.json"))
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(evidence).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    fs::File::open(output).unwrap().sync_all().unwrap();
    println!(
        "semantic evidence: {}",
        output.join("semantic-check.json").display()
    );
}

#[test]
fn minimal_semantic_predicate_rejects_a_real_finished_wrong_value() {
    for (value, accepted) in [
        (expected(), true),
        (json!({"sorted":[1,2,7,7],"sum":18}), false),
    ] {
        let (root, output, request) = wire_case(
            Some(
                json!({"prompt_tokens":19,"completion_tokens":11,"prompt_tokens_details":{"cached_tokens":0}}),
            ),
            false,
            json!({"reasoning_effort":"low"}),
            "templates/minimal/workflow.toml",
            "minimal-worker",
            input(),
            value,
        );
        let report = success(output);
        let request = request.unwrap();
        let messages = request["messages"].as_array().unwrap();
        assert!(messages.iter().any(|message| {
            message["role"] == "user"
                && message["content"]
                    .as_str()
                    .is_some_and(|text| text.contains(input()["request"].as_str().unwrap()))
        }));
        assert!(
            messages
                .iter()
                .filter(|message| message["role"] != "user")
                .all(|message| !message["content"].to_string().contains("[1,2,7,7]"))
        );
        let evidence = check(&root.join("run"), &report).unwrap();
        retain(&root.join("run"), &evidence);
        assert_eq!(evidence["passed"], accepted);
    }
}

#[test]
fn explicit_live_entry_is_exercised_with_only_a_loopback_fixture() {
    let (root, result, request) = super::wire_scenario(
        Some(
            json!({"prompt_tokens":19,"completion_tokens":11,"prompt_tokens_details":{"cached_tokens":0}}),
        ),
        false,
        json!({"reasoning_effort":"low","return_token_ids":true,"cache_salt":"public-bench230-minimal-v1"}),
        (
            "templates/minimal/workflow.toml",
            "minimal-worker",
            input(),
            expected(),
        ),
        2,
        |binding, output| {
            let mut value: Value = serde_json::from_slice(&fs::read(binding).unwrap()).unwrap();
            value["origin"] = json!("live_provider");
            value["profile"]["model"]["runtime"]["timeout_ms"] = json!(30000);
            value["profile"]["model"]["runtime"]["sampling"] = json!({"max_output_tokens":512});
            value["profile"]["loop_policy"] = json!({"schema_version":1,"max_model_iterations":1,"max_total_tool_calls":1,"max_tool_calls_per_tool":1,"wall_time_ms":60000,"idle_time_ms":60000,"tool_time_ms":1000,"max_tool_output_bytes":4096});
            fs::write(binding, serde_json::to_vec(&value).unwrap()).unwrap();
            // Both direct and proxy forms terminate at the same owned loopback fixture.
            let proxy = value["profile"]["model"]["base_url"]
                .as_str()
                .unwrap()
                .trim_end_matches("/v1");
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "semantic::minimal_semantic_live_pair_from_explicit_binding",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("WORKFLOW_KIT_BENCH230_LIVE_BINDING", binding)
                .env("WORKFLOW_KIT_BENCH230_LIVE_OUTPUT", output)
                .env("BENCH230_WIRE_TEST_KEY", "CALLER_AUTH_NEVER_REPORT")
                .env("HTTP_PROXY", proxy)
                .env_remove("http_proxy")
                .env("HTTPS_PROXY", "")
                .env_remove("https_proxy")
                .env("ALL_PROXY", "")
                .env_remove("all_proxy")
                .env("NO_PROXY", "")
                .env_remove("no_proxy")
                .output()
                .unwrap()
        },
    );
    fs::write(root.join("enabled-entry.stdout.txt"), &result.stdout).unwrap();
    fs::write(root.join("enabled-entry.stderr.txt"), &result.stderr).unwrap();
    println!("loopback-entry evidence: {}", root.display());
    assert_cli_success(&result);
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed; 0 failed"));
    let request = request.unwrap();
    assert_eq!(request["wire_request_count"], 2);
    assert_eq!(request["wire_caller_credential"], true);
    assert_eq!(request["wire_fixture_credential"], false);
    assert_eq!(request["wire_proxy_form"], true);
    for name in ["first", "second"] {
        let evidence: Value = serde_json::from_slice(
            &fs::read(root.join("run").join(name).join("semantic-check.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(evidence["passed"], true);
    }
}

#[test]
#[ignore = "requires a root-admitted explicit live binding/output; never runs by default"]
fn minimal_semantic_live_pair_from_explicit_binding() {
    let binding = PathBuf::from(
        std::env::var_os("WORKFLOW_KIT_BENCH230_LIVE_BINDING")
            .expect("explicit private binding path"),
    );
    let output = PathBuf::from(
        std::env::var_os("WORKFLOW_KIT_BENCH230_LIVE_OUTPUT").expect("explicit fresh output path"),
    );
    let binding_bytes = fs::read(&binding).unwrap();
    let binding_digest = format!("sha256:{:x}", Sha256::digest(&binding_bytes));
    let value: Value = serde_json::from_slice(&binding_bytes).unwrap();
    assert_eq!(value["origin"], "live_provider");
    assert_eq!(value["workflow_source"], "templates/minimal/workflow.toml");
    assert_eq!(value["input"], input());
    let profile = &value["profile"];
    assert_eq!(profile["model"]["name"], "minimal-worker");
    assert_eq!(profile["model"]["runtime"]["timeout_ms"], 30000);
    assert_eq!(
        profile["model"]["runtime"]["sampling"]["max_output_tokens"],
        512
    );
    assert_eq!(profile["loop_policy"]["max_model_iterations"], 1);
    assert_eq!(profile["loop_policy"]["wall_time_ms"], 60000);
    assert_eq!(profile["loop_policy"]["idle_time_ms"], 60000);
    assert!(
        profile["sandbox"]["capabilities"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fs::create_dir(&output).unwrap();
    let mut previous_run = None;
    for name in ["first", "second"] {
        assert_eq!(fs::read(&binding).unwrap(), binding_bytes);
        let run = output.join(name);
        // Caller-owned credentials and proxy policy belong to this explicit invocation.
        let report = success(
            std::process::Command::new(env!("CARGO_BIN_EXE_bench-230"))
                .current_dir(repo())
                .args([
                    "measure-live",
                    binding.to_str().unwrap(),
                    run.to_str().unwrap(),
                ])
                .output()
                .unwrap(),
        );
        assert_eq!(report["binding_digest"], binding_digest);
        let evidence = check(&run, &report).unwrap();
        retain(&run, &evidence);
        assert_eq!(
            evidence["passed"], true,
            "fixed semantic predicate rejected"
        );
        assert_ne!(previous_run.as_ref(), Some(&evidence["run_id"]));
        previous_run = Some(evidence["run_id"].clone());
        let calls = report["model_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        let telemetry = &calls[0]["telemetry"];
        assert!(telemetry["input_tokens"].as_u64().is_some());
        assert!(telemetry["output_tokens"].as_u64().is_some());
        assert!(telemetry["cached_input_count"].as_u64().is_some());
        assert!(telemetry["retries"].as_u64().is_some_and(|n| n <= 1));
    }
}

#[test]
fn benchmark_cache_options_reach_the_real_request_without_inventing_hits() {
    let (_, output, request) = wire_options(
        Some(
            json!({"prompt_tokens":19,"completion_tokens":11,"total_tokens":30,"prompt_tokens_details":{"cached_tokens":0}}),
        ),
        false,
        json!({"reasoning_effort":"low","cache_salt":"public-benchmark-domain","return_token_ids":true}),
    );
    let report = success(output);
    let request = request.unwrap();
    assert_eq!(request["return_token_ids"], true);
    let salt = request["cache_salt"].as_str().unwrap();
    assert!(salt.starts_with("sha256:") && salt.len() == 71);
    assert_ne!(salt, "public-benchmark-domain");
    assert_eq!(request["model"], "wire-fixture-model");
    assert_eq!(request["reasoning_effort"], "low");
    assert_eq!(request["wire_fixture_credential"], true);
    assert_eq!(request["wire_caller_credential"], false);
    let telemetry = &report["model_calls"][0]["telemetry"];
    assert_eq!(telemetry["cached_input_count"], 0);
    assert!(telemetry["kv_cache_hit"].is_null());
}

#[test]
fn metadata_flag_does_not_authorize_credential_fields_or_untyped_values() {
    let base: Value = serde_json::from_slice(
        &fs::read(repo().join("examples/00-runtime-smoke/profiles/fake.json")).unwrap(),
    )
    .unwrap();
    for (options, valid) in [
        (json!({"openai":{"return_token_ids":true}}), true),
        (json!({"openai":{"return_token_ids":false}}), true),
        (
            json!({"openai":{"return_token_ids":"private-token"}}),
            false,
        ),
        (
            json!({"openai":{"return_token_ids":true,"api_key":"private-value"}}),
            false,
        ),
        (json!({"other":{"return_token_ids":true}}), false),
    ] {
        let mut profile = base.clone();
        profile["model"] = json!({"provider":"openai-compatible","name":"m3-00-fake","version":"1","model":"wire-fixture-model","base_url":"http://127.0.0.1:9/v1","credential_env":"BENCH230_WIRE_TEST_KEY","runtime":{"provider_extensions":options}});
        assert_eq!(
            workflow_adk::execution::ExecutionProfileV1::parse(
                &serde_json::to_vec(&profile).unwrap()
            )
            .is_ok(),
            valid
        );
    }
}
