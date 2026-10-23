use std::fs;

use serde_json::{Value, json};
use workflow_testkit::live_conformance::ConformanceDisposition;

use super::{
    CANARY, HANDLE, example_root, finished, fixture_output, openai_profile, publish_script,
    run_opt_in, serve_script, temp_root, tool_call, write_profile,
};

#[test]
fn canonical_agent_contracts_reach_provider_requests() {
    let server = serve_script(publish_script(), false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(
        report.disposition(),
        ConformanceDisposition::Pass,
        "{report:?}"
    );
    let requests: Vec<Value> = server
        .request_bodies()
        .iter()
        .map(|request| {
            let (_, body) = request.split_once("\r\n\r\n").expect("HTTP request body");
            serde_json::from_str(body).expect("provider JSON request")
        })
        .collect();
    assert_eq!(requests.len(), 10, "original canonical request count");
    assert_eq!(
        requests[6]["response_format"]["json_schema"]["schema"]["properties"]["output"],
        json!({"type":"string","enum":["sufficient","insufficient","impossible"]}),
        "coverage must receive its authored routing schema"
    );
    server.finish();
}

fn request_input(request: &Value) -> Value {
    let user = request["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .rev()
        .find(|message| message["role"] == "user")
        .expect("mapped node input");
    serde_json::from_str(user["content"].as_str().expect("user text")).expect("mapped JSON")
}

#[test]
fn all_agent_contracts_wire_evidence_and_isolate_reentry() {
    const PRIVATE_PLAN: &str = "producer-only-plan-not-reviewer-history";
    let mut script = publish_script();
    script[1] = finished(PRIVATE_PLAN);
    script[6] = finished("insufficient");
    script.splice(
        7..7,
        [
            tool_call(
                "retry-search",
                "search_code",
                r#""{\"query\":\"pub\",\"path\":\"src\"}""#,
            ),
            finished(fixture_output(8)),
            tool_call(
                "retry-read",
                "read_source_range",
                r#""{\"path\":\"src/retry.rs\",\"start_line\":1,\"end_line\":8}""#,
            ),
            finished(fixture_output(10)),
            finished("sufficient"),
        ],
    );
    script[14] = finished("revise");
    script.extend([
        finished(fixture_output(12)),
        finished("valid"),
        finished("pass"),
    ]);
    let server = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(
        report.disposition(),
        ConformanceDisposition::Pass,
        "{report:?}"
    );
    let requests: Vec<Value> = server
        .request_bodies()
        .iter()
        .map(|request| {
            serde_json::from_str(request.split_once("\r\n\r\n").expect("HTTP body").1)
                .expect("JSON request")
        })
        .collect();
    assert_eq!(requests.len(), 18, "one retry branch and one revision");
    for (index, schema) in [
        (0, "summary"),
        (1, "summary"),
        (2, "search-hits"),
        (4, "source-range"),
        (6, "coverage"),
        (7, "search-hits"),
        (9, "source-range"),
        (11, "coverage"),
        (12, "investigation-output"),
        (13, "grounding"),
        (14, "review"),
        (15, "investigation-output"),
        (16, "grounding"),
        (17, "review"),
    ] {
        let expected: Value = serde_json::from_slice(
            &fs::read(example_root().join(format!("schemas/{schema}.json")))
                .expect("authored schema"),
        )
        .expect("schema JSON");
        assert_eq!(
            requests[index]["response_format"]["json_schema"]["schema"]["properties"]["output"],
            expected,
            "node request {index}"
        );
        assert!(
            requests[index]["messages"]
                .as_array()
                .expect("messages")
                .iter()
                .all(|message| message["role"] != "assistant" && message["role"] != "tool"),
            "fresh isolated node/reentry must not inherit another invocation's transcript: {index}; roles={:?}; inputs={:?}",
            requests
                .iter()
                .map(|r| r["messages"]
                    .as_array()
                    .expect("messages")
                    .iter()
                    .map(|m| m["role"].as_str().unwrap_or("?"))
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            requests
                .iter()
                .map(|r| request_input(r)
                    .as_object()
                    .map(|o| o.keys().cloned().collect::<Vec<_>>()))
                .collect::<Vec<_>>()
        );
    }
    let inputs: Vec<Value> = requests.iter().map(request_input).collect();
    assert_eq!(inputs[4]["node:search_code"], fixture_output(3));
    assert_eq!(inputs[6]["node:inspect_evidence"], fixture_output(5));
    assert_eq!(inputs[9]["node:retry_search_code"], fixture_output(8));
    assert_eq!(
        inputs[11]["node:retry_inspect_evidence"],
        fixture_output(10)
    );
    assert_eq!(inputs[12]["node:inspect_evidence"], fixture_output(5));
    assert_eq!(
        inputs[12]["node:retry_inspect_evidence"],
        fixture_output(10)
    );
    assert_eq!(inputs[14]["node:draft"], fixture_output(12));
    assert!(
        inputs[14].get("node:revise").is_none(),
        "future optional branch is absent"
    );
    assert_eq!(inputs[17]["node:revise"], fixture_output(12));
    for index in [14, 17] {
        assert_eq!(requests[index]["model"], "conformance-reviewer");
        assert!(!requests[index].to_string().contains(PRIVATE_PLAN));
        assert!(inputs[index].get("node:planner").is_none());
        assert!(inputs[index].get("node:prepare_workspace").is_none());
        assert!(inputs[index].get("node:search_code").is_none());
    }
    // Tool results and the following structured state carry the same real bytes.
    for (index, output) in [
        (3, fixture_output(3)),
        (5, fixture_output(5)),
        (8, fixture_output(8)),
        (10, fixture_output(10)),
    ] {
        let tool = requests[index]["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .find(|message| message["role"] == "tool")
            .expect("real tool response");
        let body = tool["content"].as_str().expect("tool content");
        let envelope: Value = serde_json::from_str(body).expect("tool JSON");
        assert_eq!(envelope["status"], "success");
        let actual = &envelope["payload"];
        if index == 3 || index == 8 {
            assert!(
                actual["matches"]
                    .as_array()
                    .expect("actual matches")
                    .iter()
                    .any(|hit| Some(hit)
                        == output["matches"].as_array().expect("selected hits").first())
            );
        } else {
            assert_eq!(
                actual, &output,
                "read evidence must retain actual tool bytes"
            );
        }
    }
    server.finish();
}

#[test]
fn checked_in_snapshot_facts_and_fake_answer_match_real_sources() {
    use workflow_testkit::code_investigation::{FixtureRepo, InvestigationAnswer, validate_answer};
    let files = ["Cargo.toml", "src/lib.rs", "src/retry.rs"];
    let snapshot = FixtureRepo::from_files(files.iter().map(|path| {
        (
            (*path).to_owned(),
            fs::read_to_string(example_root().join("repo").join(path)).expect("source"),
        )
    }))
    .snapshot();
    let input: Value = serde_json::from_slice(
        &fs::read(example_root().join("input.example.json")).expect("input"),
    )
    .expect("input JSON");
    assert_eq!(input["snapshot"]["id"], snapshot.id());
    for path in files {
        assert_eq!(
            input["snapshot"]["files"][path],
            snapshot.digest_for(path).expect("digest")
        );
    }
    let answer: InvestigationAnswer = serde_json::from_value(fixture_output(12)).expect("answer");
    validate_answer(&answer, &snapshot).expect("actual fake answer has exact citations");
}

#[test]
fn isolated_finish_crash_replays_once_then_reenters_with_current_state() {
    use std::process::Command;
    for (barrier, accepted_requests) in [
        ("after-model-ledger-persist#8", 10),
        ("after-model-ledger-persist#9", 11),
        ("after-model-ledger-persist#10", 12),
    ] {
        let mut script = publish_script();
        script[9] = finished("revise");
        let mut revision = fixture_output(12);
        revision["claims"][0]["text"] =
            json!("default_retry calls retry_with_limit(3) in src/retry.rs.");
        script.extend([
            finished(revision.clone()),
            finished("valid"),
            finished("pass"),
        ]);
        let server = serve_script(script, false);
        let root = temp_root();
        let workdir = root.0.join("runs");
        fs::create_dir(&workdir).expect("run workdir");
        let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
        let report = run_opt_in(
            &profile,
            &workdir,
            &[
                (HANDLE, CANARY),
                ("WORKFLOW_KIT_TEST_CRASH_BARRIER", barrier),
            ],
        );
        assert_eq!(
            report.disposition(),
            ConformanceDisposition::Fail,
            "crashed run: {barrier}"
        );
        assert_eq!(
            server.request_count(),
            accepted_requests,
            "accepted finish boundary: {barrier}"
        );
        let run_root = fs::read_dir(&workdir)
            .expect("runs")
            .map(|entry| entry.expect("run entry").path())
            .find(|path| path.join("run-manifest.json").is_file())
            .expect("retained crashed run");
        let manifest: Value = serde_json::from_slice(
            &fs::read(run_root.join("run-manifest.json")).expect("manifest"),
        )
        .expect("manifest JSON");
        assert_eq!(
            manifest["status"], "running",
            "intentional kill precedes final report: {barrier}"
        );
        let compatibility = serde_json::from_value::<workflow_runtime::CheckpointManifestV1>(
            manifest["checkpoint_manifest"].clone(),
        )
        .expect("compatibility manifest");
        let checkpoint = workflow_runtime::SqliteCheckpointStore::open(
            run_root.join("checkpoint.sqlite"),
            compatibility,
        )
        .expect("checkpoint store")
        .load_latest(
            &workflow_runtime::RunId::new(manifest["run_id"].as_str().expect("run ID").to_owned())
                .expect("valid run ID"),
        )
        .expect("checkpoint read")
        .expect("durable checkpoint");
        let checkpoint: Value =
            serde_json::from_slice(checkpoint.state()).expect("checkpoint JSON");
        let pending = match accepted_requests {
            10 => "review",
            11 => "revise",
            _ => "grounding_validation",
        };
        assert_eq!(
            checkpoint["kit_graph_continuation_v1"]["pending_nodes"],
            json!([pending]),
            "current accepted invocation: {barrier}"
        );
        let ledger: Value =
            serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).expect("ledger"))
                .expect("ledger JSON");
        assert_eq!(
            ledger["nodes"][pending]["finish_admitted"], true,
            "finish is durable before crash: {barrier}"
        );
        assert_eq!(
            ledger["nodes"][pending]["invocation"]["step"],
            checkpoint["kit_graph_continuation_v1"]["step"],
            "finish and frontier owner: {barrier}"
        );
        let output = Command::new(env!("CARGO_BIN_EXE_workflowctl"))
            .args([
                "--json",
                "resume",
                "--run-id",
                manifest["run_id"].as_str().expect("run ID"),
                "--workdir",
                workdir.to_str().expect("workdir"),
            ])
            .env(HANDLE, CANARY)
            .output()
            .expect("resume CLI");
        assert!(
            output.status.success(),
            "resume {barrier}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            server.request_count(),
            13,
            "accepted finishes/effects must not repeat: {barrier}"
        );
        let requests: Vec<Value> = server
            .request_bodies()
            .iter()
            .map(|raw| {
                serde_json::from_str(raw.split_once("\r\n\r\n").expect("HTTP body").1)
                    .expect("request JSON")
            })
            .collect();
        for request in &requests[11..] {
            assert_eq!(
                request_input(request)["node:revise"],
                revision,
                "current revision: {barrier}"
            );
            assert!(
                request["messages"]
                    .as_array()
                    .expect("messages")
                    .iter()
                    .all(|message| message["role"] != "assistant" && message["role"] != "tool"),
                "reentry after replay must have fresh history: {barrier}"
            );
        }
        let ledger: Value =
            serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).expect("ledger"))
                .expect("ledger JSON");
        for (node, iterations) in [
            ("prepare_workspace", 1),
            ("grounding_validation", 2),
            ("review", 2),
            ("revise", 1),
        ] {
            assert_eq!(
                ledger["nodes"][node]["model_iterations"], iterations,
                "accepted node count {barrier}: {node}"
            );
        }
        let completed: usize = ledger["nodes"]
            .as_object()
            .expect("nodes")
            .values()
            .map(|node| {
                node["completed_calls"]
                    .as_array()
                    .expect("completed calls")
                    .len()
            })
            .sum();
        assert_eq!(completed, 2, "exactly the original search/read completions");
        server.finish();
    }
}
