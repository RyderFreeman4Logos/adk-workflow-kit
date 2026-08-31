use std::{
    env, fs,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use rusqlite::Connection;
use serde_json::{Value, json};
use workflow_adk::execution::{
    ExecutionBackend, ExecutionError, ExecutionErrorKind, ExecutionProfileV1, ExecutionReceipt,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "tool-loop"
version = "1"
entry = "work"
[[nodes]]
id = "work"
kind = "agent"
model = { role = "worker", id = "worker", version = "1" }
tools = [{ id = "search_code", version = "1" }, { id = "read_source_range", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "work"
to = "done"
"#;

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "m3-04-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    root
}

fn loop_policy() -> Value {
    json!({
        "schema_version": 1,
        "max_model_iterations": 100,
        "max_total_tool_calls": 100,
        "max_tool_calls_per_tool": 100,
        "wall_time_ms": 60000,
        "idle_time_ms": 60000,
        "tool_time_ms": 60000,
        "max_tool_output_bytes": 65536
    })
}

fn policy_with(key: &str, value: u64) -> Value {
    let mut policy = loop_policy();
    policy[key] = json!(value);
    policy
}

fn finish(output: Value) -> Value {
    json!(serde_json::to_string(&json!({"status":"finished", "output":output})).unwrap())
}

fn profile_with(responses: Vec<Value>, policy: Option<Value>) -> ExecutionProfileV1 {
    profile_with_delays(responses, policy, 0, 0, json!({"found":true}))
}

fn profile_with_delays(
    responses: Vec<Value>,
    policy: Option<Value>,
    model_delay_ms: u64,
    tool_delay_ms: u64,
    search_result: Value,
) -> ExecutionProfileV1 {
    let handler_error = search_result.get("artifact_id").is_some();
    let mut profile = json!({
        "schema_version": 1,
        "model": { "provider": "fake", "name": "worker", "version": "1", "model": "worker", "responses": responses, "response_delay_ms": model_delay_ms },
        "tools": [
            {"name":"search_code","result":search_result,"delay_ms":tool_delay_ms,"handler_error":handler_error,
             "input_schema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}},
            {"name":"read_source_range","result":{"source":"ok"},
             "input_schema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"path":{"type":"string"},"start":{"type":"integer"}},"required":["path","start"],"additionalProperties":false}}
        ],
        "sandbox": {"capabilities": []}
    });
    if let Some(policy) = policy {
        profile["loop_policy"] = policy;
    }
    ExecutionProfileV1::parse(&serde_json::to_vec(&profile).unwrap()).unwrap()
}

fn profile() -> ExecutionProfileV1 {
    profile_with(
        vec![
            json!({"calls": [{"id":"call-search","name":"search_code","args":{"query":"needle"}}]}),
            json!({"calls": [{"id":"call-read","name":"read_source_range","args":{"path":"src/lib.rs","start":1}}]}),
            finish(json!({"answer":"done"})),
        ],
        None,
    )
}

fn run(profile: ExecutionProfileV1) -> (PathBuf, Result<ExecutionReceipt, ExecutionError>) {
    let root = root();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let result = ExecutionBackend::run(
        &workflow,
        profile,
        json!({"request":"must not become args"}),
        &root,
    );
    (root, result)
}

fn events(error: &ExecutionError) -> String {
    fs::read_to_string(error.receipt().unwrap().run_root().join("events.jsonl")).unwrap()
}

fn crash_run(root: &Path, test: &str, barrier: &str) -> PathBuf {
    let status = Command::new(env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("M3_04_CRASH_RUN_ROOT", root)
        .env("WORKFLOW_KIT_TEST_CRASH_BARRIER", barrier)
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("run-manifest.json").is_file())
        .unwrap()
}

fn run_id(run_root: &Path) -> String {
    let manifest: Value =
        serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
    manifest["run_id"].as_str().unwrap().to_owned()
}

fn function_response_bytes(run_root: &Path) -> Vec<u8> {
    let ledger: Value =
        serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).unwrap()).unwrap();
    let response = ledger["nodes"]["work"]["conversation"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|content| content["parts"].as_array().unwrap())
        .find_map(|part| part.get("functionResponse"))
        .map(|response| response["response"].clone())
        .unwrap();
    serde_json::to_vec(&response).unwrap()
}

fn finish_status_bytes(run_root: &Path) -> Vec<u8> {
    let ledger: Value =
        serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).unwrap()).unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
    serde_json::to_vec(&json!({
        "status": manifest["status"],
        "output": ledger["nodes"]["work"]["finished_output"],
    }))
    .unwrap()
}

fn effect_count(run_root: &Path) -> u64 {
    Connection::open(run_root.join("effects.sqlite"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM kit_effects", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn model_authors_two_selected_calls_then_typed_finish() {
    let (root, receipt) = run(profile());
    let receipt = receipt.unwrap();
    let events = fs::read_to_string(receipt.run_root().join("events.jsonl")).unwrap();
    assert!(events.contains("call-search"));
    assert!(events.contains("call-read"));
    assert!(events.find("call-search") < events.find("call-read"));
    assert!(!events.contains("must not become args"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn undeclared_or_unknown_call_fails_before_effect() {
    let responses = vec![
        json!({"calls": [{"id":"call-unknown","name":"unknown","args":{}}]}),
        json!("done"),
    ];
    let (root, error) = run(profile_with(responses, None));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Adk);
    assert!(!events(&error).contains("tool_completed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_or_schema_invalid_arguments_fail_before_effect() {
    for args in [
        json!([]),
        json!({}),
        json!({"query":1}),
        json!({"query":"x","extra":true}),
    ] {
        let responses = vec![
            json!({"calls": [{"id":"call-bad","name":"search_code","args":args}]}),
            finish(json!({"must_not":"succeed"})),
        ];
        let (root, error) = run(profile_with(responses, None));
        let error = error.unwrap_err();
        assert!(!events(&error).contains("tool_completed"));
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn real_tool_failure_is_terminal_before_later_finish() {
    let responses = vec![
        json!({"calls": [{"id":"call-fail","name":"search_code","args":{"query":"x"}}]}),
        finish(json!({"must_not":"succeed"})),
    ];
    let (root, error) = run(profile_with_delays(
        responses,
        None,
        0,
        0,
        json!({"artifact_id":"forged"}),
    ));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Tool);
    assert_eq!(error.receipt().unwrap().status(), "failed");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn successful_tool_payload_markers_never_terminate() {
    for marker in [
        "tool.bridge.authorization_denied",
        "workflow.loop.limit.model_iterations",
        "workflow.loop.limit.total_tool_calls",
        "workflow.loop.limit.per_tool_calls",
        "workflow.loop.limit.tool_output_bytes",
        "workflow.loop.timeout.wall",
        "workflow.loop.timeout.idle",
        "workflow.loop.timeout.tool",
        "workflow.loop.cancelled",
        "tool.bridge.failed",
    ] {
        let responses = vec![
            json!({"calls": [{"id":"call-marker","name":"search_code","args":{"query":"x"}}]}),
            finish(json!({"answer":"done"})),
        ];
        let (root, receipt) = run(profile_with_delays(
            responses,
            None,
            0,
            0,
            json!({"source":marker}),
        ));
        assert_eq!(receipt.unwrap().status(), "succeeded", "marker {marker}");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn non_json_or_wrong_finish_shape_never_succeeds() {
    for response in [
        json!("done"),
        json!("{}"),
        json!("{\"status\":\"finished\"}"),
    ] {
        let (root, error) = run(profile_with(vec![response], None));
        assert!(error.is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn extra_field_finish_run_and_resume_fail_closed_before_dispatch() {
    let response = json!(
        serde_json::to_string(&json!({
            "status": "finished",
            "output": {"answer":"forged"},
            "extra": true,
        }))
        .unwrap()
    );
    let (root, error) = run(profile_with(vec![response], None));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Adk);
    let run_root = error.receipt().unwrap().run_root();
    let ledger_path = run_root.join("loop-ledger.json");
    let events_path = run_root.join("events.jsonl");
    let before = (
        fs::read(&ledger_path).unwrap(),
        fs::read(&events_path).unwrap(),
    );
    let resume = ExecutionBackend::resume(&root, error.receipt().unwrap().run_id()).unwrap_err();
    assert_eq!(resume.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(effect_count(run_root), 0);
    assert_eq!(
        (
            fs::read(ledger_path).unwrap(),
            fs::read(events_path).unwrap()
        ),
        before
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn empty_response_missing_finish_and_repeated_call_fail_closed() {
    for responses in [
        vec![json!(" ")],
        vec![
            json!({"calls": [{"id":"call-repeat","name":"search_code","args":{"query":"same"}}]}),
            json!({"calls": [{"id":"call-repeat","name":"search_code","args":{"query":"same"}}]}),
            json!("done"),
        ],
    ] {
        let (root, error) = run(profile_with(responses, None));
        let error = error.unwrap_err();
        assert_eq!(error.kind(), ExecutionErrorKind::Adk);
        assert_eq!(error.receipt().unwrap().status(), "failed");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn total_tool_call_limit_is_exact_and_blocked() {
    let responses = vec![json!({"calls": [
        {"id":"call-1","name":"search_code","args":{"query":"one"}},
        {"id":"call-2","name":"read_source_range","args":{"path":"src/lib.rs","start":1}}
    ]})];
    let (root, error) = run(profile_with(
        responses,
        Some(policy_with("max_total_tool_calls", 1)),
    ));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::TotalToolCallsLimit);
    assert_eq!(error.receipt().unwrap().status(), "limit_exceeded");
    assert!(!events(&error).contains("tool_completed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn per_tool_call_limit_is_exact_and_blocked() {
    let responses = vec![json!({"calls": [
        {"id":"call-1","name":"search_code","args":{"query":"one"}},
        {"id":"call-2","name":"search_code","args":{"query":"two"}}
    ]})];
    let (root, error) = run(profile_with(
        responses,
        Some(policy_with("max_tool_calls_per_tool", 1)),
    ));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ToolCallsPerToolLimit);
    assert_eq!(error.receipt().unwrap().status(), "limit_exceeded");
    assert!(!events(&error).contains("tool_completed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn model_iteration_limit_is_exact_and_blocked() {
    let responses = vec![
        json!({"calls": [{"id":"call-1","name":"search_code","args":{"query":"one"}}]}),
        finish(json!({"answer":"too-late"})),
    ];
    let (root, error) = run(profile_with(
        responses,
        Some(policy_with("max_model_iterations", 1)),
    ));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ModelIterationsLimit);
    assert_eq!(error.receipt().unwrap().status(), "limit_exceeded");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tool_output_byte_limit_is_exact_and_blocked() {
    let root = root();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let error = ExecutionBackend::run(
        &workflow,
        profile_with_delays(
            vec![
                json!({"calls": [{"id":"call-large","name":"search_code","args":{"query":"one"}}]}),
            ],
            Some(policy_with("max_tool_output_bytes", 64)),
            0,
            0,
            json!({"text":"x".repeat(1024)}),
        ),
        json!({}),
        &root,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ToolOutputBytesLimit);
    assert_eq!(error.receipt().unwrap().status(), "limit_exceeded");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn wall_time_limit_is_exact_and_timed_out() {
    let (root, error) = run(profile_with_delays(
        vec![finish(json!({"answer":"late"}))],
        Some(policy_with("wall_time_ms", 5)),
        50,
        0,
        json!({"found":true}),
    ));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::WallTimeLimit);
    assert_eq!(error.receipt().unwrap().status(), "timed_out");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn idle_time_limit_is_exact_and_timed_out() {
    let (root, error) = run(profile_with_delays(
        vec![finish(json!({"answer":"late"}))],
        Some(policy_with("idle_time_ms", 5)),
        50,
        0,
        json!({"found":true}),
    ));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::IdleTimeLimit);
    assert_eq!(error.receipt().unwrap().status(), "timed_out");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tool_time_limit_is_exact_and_timed_out() {
    let (root, error) = run(profile_with_delays(
        vec![json!({"calls": [{"id":"call-slow","name":"search_code","args":{"query":"one"}}]})],
        Some(policy_with("tool_time_ms", 5)),
        0,
        50,
        json!({"found":true}),
    ));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ToolTimeLimit);
    assert_eq!(error.receipt().unwrap().status(), "timed_out");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tool_idle_limit_fences_effect_before_commit() {
    let mut policy = loop_policy();
    policy["idle_time_ms"] = json!(25);
    policy["tool_time_ms"] = json!(1000);
    let (root, error) = run(profile_with_delays(
        vec![
            json!({"calls": [{"id":"call-idle","name":"search_code","args":{"query":"one"}}]}),
            finish(json!({"answer":"must not run"})),
        ],
        Some(policy),
        0,
        100,
        json!({"found":true}),
    ));
    let error = error.unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::IdleTimeLimit);
    assert_eq!(error.receipt().unwrap().status(), "timed_out");
    assert_eq!(effect_count(error.receipt().unwrap().run_root()), 0);
    assert!(!events(&error).contains("tool_completed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancellation_is_exact_and_never_succeeds() {
    let root = root();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let error = ExecutionBackend::run_cancellable(
        &workflow,
        profile(),
        json!({}),
        &root,
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert_eq!(error.receipt().unwrap().status(), "cancelled");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancellation_after_dispatch_fences_effect_and_worker() {
    if let Ok(root) = env::var("M3_04_CANCEL_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let cancellation = Arc::new(AtomicBool::new(false));
        let error = ExecutionBackend::run_cancellable(
            &workflow,
            profile_with_delays(
                vec![
                    json!({"calls": [{"id":"call-cancel","name":"search_code","args":{"query":"needle"}}]}),
                    finish(json!({"answer":"must not run"})),
                ],
                Some(loop_policy()),
                0,
                250,
                json!({"found":true}),
            ),
            json!({}),
            &root,
            cancellation,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
        assert_eq!(error.receipt().unwrap().status(), "cancelled");
        assert_eq!(effect_count(error.receipt().unwrap().run_root()), 0);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(effect_count(error.receipt().unwrap().run_root()), 0);
        return;
    }

    let root = root();
    let barrier = root.join("effect-barrier");
    fs::create_dir(&barrier).unwrap();
    let mut child = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "cancellation_after_dispatch_fences_effect_and_worker",
            "--nocapture",
        ])
        .env("M3_04_CANCEL_RUN_ROOT", &root)
        .env("WORKFLOW_KIT_TEST_EFFECT_BARRIER", &barrier)
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !barrier.join("ready").is_file() && started.elapsed() < Duration::from_secs(2) {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(barrier.join("ready").is_file(), "tool dispatch barrier");
    fs::write(barrier.join("cancel"), b"cancel").unwrap();
    assert!(child.wait().unwrap().success());
    let run_root = fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("run-manifest.json").is_file())
        .unwrap();
    assert_eq!(effect_count(&run_root), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resume_rejects_loop_identity_drift_before_effects() {
    let (root, receipt) = run(profile_with(
        vec![
            json!({"calls": [{"id":"call-search","name":"search_code","args":{"query":"needle"}}]}),
            finish(json!({"answer":"done"})),
        ],
        Some(loop_policy()),
    ));
    let receipt = receipt.unwrap();
    let protected = ["events.jsonl", "effects.sqlite", "checkpoint.sqlite"]
        .map(|name| receipt.run_root().join(name));
    let before = protected.each_ref().map(|path| fs::read(path).unwrap());
    let profile_path = receipt.run_root().join("execution-profile.json");
    let mut changed: Value = serde_json::from_slice(&fs::read(&profile_path).unwrap()).unwrap();
    changed["loop_policy"]["max_model_iterations"] = json!(99);
    fs::write(&profile_path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let error = ExecutionBackend::resume(&root, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(
        protected.each_ref().map(|path| fs::read(path).unwrap()),
        before
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn call_id_and_argument_fingerprint_survive_event_and_resume() {
    let args = json!({"query":"needle"});
    let expected = workflow_runtime::argument_fingerprint(&args);
    let (root, receipt) = run(profile_with(
        vec![
            json!({"calls": [{"id":"call-stable","name":"search_code","args":args}]}),
            finish(json!({"answer":"done"})),
        ],
        Some(loop_policy()),
    ));
    let receipt = receipt.unwrap();
    let event_path = receipt.run_root().join("events.jsonl");
    let before = fs::read_to_string(&event_path).unwrap();
    assert!(before.contains("call-stable"));
    assert!(before.contains(&expected));
    let effects = Connection::open(receipt.run_root().join("effects.sqlite"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM kit_effects", [], |row| {
            row.get::<_, u64>(0)
        })
        .unwrap();
    assert_eq!(effects, 1);
    let _ = ExecutionBackend::resume(&root, receipt.run_id());
    assert_eq!(
        fs::read_to_string(event_path)
            .unwrap()
            .matches("call-stable")
            .count(),
        1
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resume_wall_time_limit_includes_pending_replay_and_is_typed() {
    if let Ok(root) = env::var("M3_04_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let mut policy = loop_policy();
        policy["wall_time_ms"] = json!(25);
        policy["tool_time_ms"] = json!(1000);
        let _ = ExecutionBackend::run(
            workflow,
            profile_with_delays(
                vec![
                    json!({"calls": [{"id":"call-wall","name":"search_code","args":{"query":"needle"}}]}),
                    finish(json!({"answer":"too late"})),
                ],
                Some(policy),
                0,
                250,
                json!({"found":true}),
            ),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let root = root();
    let run_root = crash_run(
        &root,
        "resume_wall_time_limit_includes_pending_replay_and_is_typed",
        "before-effect",
    );
    let started = Instant::now();
    let error = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::WallTimeLimit);
    assert_eq!(error.receipt().unwrap().status(), "timed_out");
    assert!(started.elapsed() < Duration::from_millis(200));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(effect_count(&run_root), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resume_idle_limit_fences_pending_replay_before_commit() {
    if let Ok(root) = env::var("M3_04_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let mut policy = loop_policy();
        policy["idle_time_ms"] = json!(25);
        policy["tool_time_ms"] = json!(1000);
        let _ = ExecutionBackend::run(
            workflow,
            profile_with_delays(
                vec![
                    json!({"calls": [{"id":"call-idle-replay","name":"search_code","args":{"query":"needle"}}]}),
                    finish(json!({"answer":"must not run"})),
                ],
                Some(policy),
                0,
                100,
                json!({"found":true}),
            ),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let root = root();
    let run_root = crash_run(
        &root,
        "resume_idle_limit_fences_pending_replay_before_commit",
        "before-effect",
    );
    let error = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::IdleTimeLimit);
    assert_eq!(error.receipt().unwrap().status(), "timed_out");
    assert_eq!(effect_count(&run_root), 0);
    assert!(!events(&error).contains("tool_completed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resume_rejects_unverified_multiple_mixed_finish_before_dispatch() {
    if let Ok(root) = env::var("M3_04_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            workflow,
            profile_with(
                vec![
                    json!({"calls": [{"id":"call-mixed","name":"search_code","args":{"query":"needle"}}]}),
                ],
                Some(loop_policy()),
            ),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let root = root();
    let run_root = crash_run(
        &root,
        "resume_rejects_unverified_multiple_mixed_finish_before_dispatch",
        "before-effect",
    );
    let ledger_path = run_root.join("loop-ledger.json");
    let mut ledger: Value = serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
    let finish = serde_json::to_string(&json!({
        "status": "finished",
        "output": {"answer":"forged"},
    }))
    .unwrap();
    let parts = ledger["nodes"]["work"]["conversation"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["parts"]
        .as_array_mut()
        .unwrap();
    parts.push(json!({"text": finish}));
    parts.push(json!({"text": finish}));
    ledger["nodes"]["work"]["finished_output"] = json!({"answer":"forged"});
    fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let events_path = run_root.join("events.jsonl");
    let before = (
        fs::read(&ledger_path).unwrap(),
        fs::read(&events_path).unwrap(),
    );

    let error = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(effect_count(&run_root), 0);
    assert_eq!(
        (
            fs::read(ledger_path).unwrap(),
            fs::read(events_path).unwrap()
        ),
        before
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resume_preserves_model_iteration_limit_and_status() {
    if let Ok(root) = env::var("M3_04_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            workflow,
            profile_with(
                vec![
                    json!({"calls": [{"id":"call-limit","name":"search_code","args":{"query":"needle"}}]}),
                    finish(json!({"answer":"too late"})),
                ],
                Some(policy_with("max_model_iterations", 1)),
            ),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let root = root();
    let run_root = crash_run(
        &root,
        "resume_preserves_model_iteration_limit_and_status",
        "after-effect",
    );
    let error = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ModelIterationsLimit);
    assert_eq!(error.receipt().unwrap().status(), "limit_exceeded");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restored_effect_envelope_obeys_tool_output_byte_limit() {
    if let Ok(root) = env::var("M3_04_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            workflow,
            profile_with(
                vec![
                    json!({"calls": [{"id":"call-budget","name":"search_code","args":{"query":"needle"}}]}),
                    finish(json!({"answer":"must not run"})),
                ],
                Some(policy_with("max_tool_output_bytes", 64)),
            ),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let root = root();
    let run_root = crash_run(
        &root,
        "restored_effect_envelope_obeys_tool_output_byte_limit",
        "after-effect",
    );
    let error = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ToolOutputBytesLimit);
    assert_eq!(error.receipt().unwrap().status(), "limit_exceeded");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resume_rejects_tampered_pending_ledger_before_effect() {
    if let Ok(root) = env::var("M3_04_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            workflow,
            profile_with(
                vec![
                    json!({"calls": [{"id":"call-tampered","name":"search_code","args":{"query":"needle"}}]}),
                    finish(json!({"answer":"must not run"})),
                ],
                Some(loop_policy()),
            ),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let root = root();
    let run_root = crash_run(
        &root,
        "resume_rejects_tampered_pending_ledger_before_effect",
        "before-effect",
    );
    let ledger_path = run_root.join("loop-ledger.json");
    let mut ledger: Value = serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
    let call = &mut ledger["nodes"]["work"]["pending_calls"][0];
    call["args"] = json!({"query":"forged"});
    call["fingerprint"] = json!(workflow_runtime::argument_fingerprint(&call["args"]));
    ledger["nodes"]["work"]["total_tool_calls"] = json!(2);
    ledger["nodes"]["work"]["tool_calls"]["search_code"] = json!(2);
    ledger["nodes"]["work"]["tool_output_bytes"] = json!(1);
    fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();

    let error = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(effect_count(&run_root), 0);
    assert!(
        !fs::read_to_string(run_root.join("events.jsonl"))
            .unwrap()
            .contains("tool_completed")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn effect_after_crash_before_node_checkpoint_resumes_from_loop_ledger() {
    if let Ok(root) = env::var("M3_04_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            workflow,
            profile_with(
                vec![
                    json!({"calls": [{"id":"call-crash","name":"search_code","args":{"query":"needle"}}]}),
                    finish(json!({"answer":"resumed"})),
                ],
                Some(loop_policy()),
            ),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let (baseline_root, baseline) = run(profile_with(
        vec![
            json!({"calls": [{"id":"call-crash","name":"search_code","args":{"query":"needle"}}]}),
            finish(json!({"answer":"resumed"})),
        ],
        Some(loop_policy()),
    ));
    let baseline = baseline.unwrap();
    let expected_response = function_response_bytes(baseline.run_root());
    fs::remove_dir_all(baseline_root).unwrap();

    let root = root();
    let run_root = crash_run(
        &root,
        "effect_after_crash_before_node_checkpoint_resumes_from_loop_ledger",
        "after-effect",
    );
    let receipt = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap();
    assert_eq!(receipt.status(), "succeeded");
    let expected_fingerprint = workflow_runtime::argument_fingerprint(&json!({"query":"needle"}));
    let completed = fs::read_to_string(run_root.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["kind"] == "tool_completed")
        .unwrap();
    let correlation = &completed["payload"]["structured_output"][0];
    assert_eq!(correlation["tool_call_id"], "call-crash");
    assert_eq!(correlation["tool_name"], "search_code");
    assert_eq!(correlation["argument_fingerprint"], expected_fingerprint);
    assert_eq!(function_response_bytes(&run_root), expected_response);
    assert_eq!(
        Connection::open(run_root.join("effects.sqlite"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM kit_effects", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
        1
    );
    let ledger: Value =
        serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).unwrap()).unwrap();
    assert_eq!(ledger["nodes"]["work"]["model_iterations"], 2);
    assert_eq!(ledger["nodes"]["work"]["pending_calls"], json!([]));
    assert!(
        ledger["nodes"]["work"]["tool_output_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(ledger.to_string().contains("call-crash"));
    assert!(ledger.to_string().contains("resumed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn finish_after_crash_resumes_without_another_model_request() {
    if let Ok(root) = env::var("M3_04_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            workflow,
            profile_with(
                vec![finish(json!({"answer":"final"}))],
                Some(policy_with("max_model_iterations", 1)),
            ),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let expected = serde_json::to_vec(&json!({
        "status": "succeeded",
        "output": {"answer":"final"},
    }))
    .unwrap();
    let (baseline_root, baseline) = run(profile_with(
        vec![finish(json!({"answer":"final"}))],
        Some(policy_with("max_model_iterations", 1)),
    ));
    let baseline = baseline.unwrap();
    assert_eq!(finish_status_bytes(baseline.run_root()), expected);
    fs::remove_dir_all(baseline_root).unwrap();

    let root = root();
    let run_root = crash_run(
        &root,
        "finish_after_crash_resumes_without_another_model_request",
        "after-result",
    );
    let receipt = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap();
    assert_eq!(receipt.status(), "succeeded");
    assert_eq!(finish_status_bytes(&run_root), expected);
    let ledger: Value =
        serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).unwrap()).unwrap();
    assert_eq!(ledger["nodes"]["work"]["model_iterations"], 1);
    fs::remove_dir_all(root).unwrap();
}
