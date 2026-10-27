//! Actual CLI -> compiler -> ADK -> loopback HTTP. Scripted transport, not live inference.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[path = "issue_230_telemetry/aggregate.rs"]
mod aggregate;
#[path = "issue_230_telemetry/kv.rs"]
mod kv;
#[path = "issue_230_telemetry/measured.rs"]
mod measured;
#[path = "issue_230_telemetry/semantic.rs"]
mod semantic;
#[path = "issue_230_telemetry/sentinel.rs"]
mod sentinel;
#[path = "issue_230_telemetry/sentinel_finite.rs"]
mod sentinel_finite;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bench-230"))
        .current_dir(repo())
        .args(args)
        .env("BENCH230_WIRE_TEST_KEY", "WIRE_SECRET_NEVER_REPORT")
        .env("HTTP_PROXY", "")
        .env("HTTPS_PROXY", "")
        .env("ALL_PROXY", "")
        .env("NO_PROXY", "*")
        .output()
        .unwrap()
}
fn assert_cli_success(output: &Output) {
    assert!(
        output.status.success(),
        "CLI failed: status={}; stdout_bytes={}; stdout_sha256={:x}; stderr_bytes={}; stderr_sha256={:x}",
        output.status,
        output.stdout.len(),
        Sha256::digest(&output.stdout),
        output.stderr.len(),
        Sha256::digest(&output.stderr)
    );
}

fn success(output: Output) -> Value {
    assert_cli_success(&output);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn cli_failure_diagnostic_retains_status_without_payloads() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    for (raw_status, stdout, stderr, stdout_sha256, stderr_sha256) in [
        (
            1 << 8,
            b"PRIVATE_STDOUT_NEVER_REPORT".as_slice(),
            b"".as_slice(),
            "1c28776d9e3d54b0935ef54952c6e441e2b323309ca9b0ef2b7e661900821e85",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            9,
            b"\xffPRIVATE_STDOUT_NEVER_REPORT\0".as_slice(),
            b"PRIVATE_STDERR_NEVER_REPORT\xff".as_slice(),
            "a081440631878f683fa8004de94ba3f75c6b0f055b3971023742a4fea1fa3bef",
            "5b5e80440085e8bf8e5f13cffaa805dbf53100783a1cf559f2281334ebac9737",
        ),
    ] {
        let status = ExitStatus::from_raw(raw_status);
        let output = Output {
            status,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        };
        let panic = std::panic::catch_unwind(|| assert_cli_success(&output)).unwrap_err();
        let message = panic.downcast_ref::<String>().unwrap();
        assert!(!message.contains("PRIVATE_STDOUT_NEVER_REPORT"));
        assert!(!message.contains("PRIVATE_STDERR_NEVER_REPORT"));
        assert!(message.contains(&format!("status={status}")));
        assert!(message.contains(&format!("stdout_bytes={}", stdout.len())));
        assert!(message.contains(&format!("stderr_bytes={}", stderr.len())));
        assert!(message.contains(&format!("stdout_sha256={stdout_sha256}")));
        assert!(message.contains(&format!("stderr_sha256={stderr_sha256}")));
    }
    assert_cli_success(&Output {
        status: ExitStatus::from_raw(0),
        stdout: b"1 passed; 0 failed".to_vec(),
        stderr: b"PRIVATE_STDERR_NEVER_REPORT".to_vec(),
    });
    assert_eq!(
        success(Output {
            status: ExitStatus::from_raw(0),
            stdout: br#"{"ready":true}"#.to_vec(),
            stderr: b"PRIVATE_STDERR_NEVER_REPORT".to_vec(),
        }),
        json!({"ready": true})
    );
}

fn measured(usage: Option<Value>) -> (PathBuf, Value, Value) {
    let (root, output, request) = wire_attempt(usage, false);
    (root, success(output), request)
}

const MAX_WIRE_REQUEST_BYTES: usize = 64 * 1024;

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "wire fixture deadline"))
}

fn wire_error(error: io::Error) -> io::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        io::Error::new(io::ErrorKind::TimedOut, "wire fixture deadline")
    } else {
        error
    }
}

fn accept_request(listener: &TcpListener, deadline: Instant) -> io::Result<TcpStream> {
    loop {
        let left = remaining(deadline)?;
        match listener.accept() {
            Ok((socket, _)) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(left.min(Duration::from_millis(10)));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn read_bytes(socket: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        socket.set_read_timeout(Some(remaining(deadline)?))?;
        match socket.read(buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete request",
                ));
            }
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(wire_error(error)),
        }
    }
}

// One cap covers headers plus body; every read spends the same fixture deadline.
fn read_request(socket: &mut TcpStream, deadline: Instant) -> io::Result<Value> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid or oversized request");
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let offset = loop {
        let left = MAX_WIRE_REQUEST_BYTES
            .checked_sub(bytes.len())
            .filter(|n| *n > 0)
            .ok_or_else(invalid)?;
        let limit = left.min(buffer.len());
        let count = read_bytes(socket, &mut buffer[..limit], deadline)?;
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let length = String::from_utf8_lossy(&bytes[..offset])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(invalid)?;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= MAX_WIRE_REQUEST_BYTES)
        .ok_or_else(invalid)?;
    while bytes.len() < end {
        let limit = (end - bytes.len()).min(buffer.len());
        let count = read_bytes(socket, &mut buffer[..limit], deadline)?;
        bytes.extend_from_slice(&buffer[..count]);
    }
    let mut request: Value = serde_json::from_slice(&bytes[offset..end]).map_err(|_| invalid())?;
    request["wire_body_bytes"] = json!(length);
    let headers = std::str::from_utf8(&bytes[..offset]).map_err(|_| invalid())?;
    // Finite synthetic observations only; never retain arbitrary authorization bytes.
    let carries = |expected| {
        headers.lines().any(|line| {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };
            let mut fields = value.split_ascii_whitespace();
            name.eq_ignore_ascii_case("authorization")
                && fields
                    .next()
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer"))
                && fields.next() == Some(expected)
                && fields.next().is_none()
        })
    };
    request["wire_caller_credential"] = json!(carries("CALLER_AUTH_NEVER_REPORT"));
    request["wire_fixture_credential"] = json!(carries("WIRE_SECRET_NEVER_REPORT"));
    request["wire_proxy_form"] = json!(headers.lines().next().is_some_and(|line| {
        line.split_whitespace()
            .nth(1)
            .is_some_and(|target| target.starts_with("http://"))
    }));
    remaining(deadline)?;
    Ok(request)
}

fn write_reply(socket: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        socket.set_write_timeout(Some(remaining(deadline)?))?;
        match socket.write(bytes) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "incomplete reply")),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(wire_error(error)),
        }
    }
    remaining(deadline)?;
    Ok(())
}

// Joining in Drop also covers CLI spawn failures and assertions during fixture setup.
struct WireServer(Option<thread::JoinHandle<Result<Value, String>>>);
impl WireServer {
    fn finish(mut self) -> thread::Result<Result<Value, String>> {
        self.0.take().expect("owned fixture thread").join()
    }
}

impl Drop for WireServer {
    fn drop(&mut self) {
        if let Some(thread) = self.0.take() {
            let _ = thread.join();
        }
    }
}

fn wire_attempt(usage: Option<Value>, retry: bool) -> (PathBuf, Output, Value) {
    let (root, output, request) = wire_options(usage, retry, json!({"reasoning_effort":"low"}));
    (root, output, request.unwrap())
}

fn wire_options(
    usage: Option<Value>,
    retry: bool,
    options: Value,
) -> (PathBuf, Output, Result<Value, String>) {
    wire_case(
        usage,
        retry,
        options,
        "examples/00-runtime-smoke/workflow.toml",
        "m3-00-fake",
        json!({"request":"PRIVATE_INPUT_NEVER_REPORT"}),
        json!("PRIVATE_OUTPUT_NEVER_REPORT"),
    )
}

fn wire_case(
    usage: Option<Value>,
    retry: bool,
    options: Value,
    workflow: &str,
    model_name: &str,
    input: Value,
    response_output: Value,
) -> (PathBuf, Output, Result<Value, String>) {
    wire_scenario(
        usage,
        retry,
        options,
        (workflow, model_name, input, response_output),
        1,
        |path, output| cli(&["measure", path.to_str().unwrap(), output.to_str().unwrap()]),
    )
}

fn wire_scenario(
    usage: Option<Value>,
    retry: bool,
    options: Value,
    case: (&str, &str, Value, Value),
    replies: usize,
    run: impl FnOnce(&std::path::Path, &std::path::Path) -> Output,
) -> (PathBuf, Output, Result<Value, String>) {
    wire_scenario_with_windows(
        usage,
        retry,
        options,
        case,
        replies,
        FixtureWindows::Shared(Duration::from_secs(20)),
        |path, output, _| run(path, output),
    )
}

enum FixtureWindows {
    Shared(Duration),
    PerCli(Duration),
}

fn wire_scenario_with_windows(
    usage: Option<Value>,
    retry: bool,
    options: Value,
    case: (&str, &str, Value, Value),
    replies: usize,
    windows: FixtureWindows,
    run: impl FnOnce(&std::path::Path, &std::path::Path, &dyn Fn()) -> Output,
) -> (PathBuf, Output, Result<Value, String>) {
    let separate_cli_windows = matches!(&windows, FixtureWindows::PerCli(_));
    let budget = match windows {
        FixtureWindows::Shared(budget) | FixtureWindows::PerCli(budget) => budget,
    };
    assert!((1..=2).contains(&replies));
    assert!(!separate_cli_windows || (replies == 2 && !retry));
    let (workflow, model_name, input, response_output) = case;
    let sentinel = workflow == "examples/03-sentinel-preparation/workflow.toml";
    assert!(!separate_cli_windows || !sentinel);
    let sentinel_reply = if sentinel {
        match response_output.as_str() {
            None if response_output.is_null() => "cln",
            Some("cln") => "cln",
            Some("inj") => "inj",
            Some("sus") => "sus",
            _ => panic!("Sentinel fixture requires cln, inj, sus, or the default null"),
        }
    } else {
        "cln"
    };
    let scratch = std::env::var_os("TMPDIR").expect("explicit SSD TMPDIR");
    let root = PathBuf::from(scratch).join(format!(
        "wire230-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let deadline = Instant::now() + budget;
    let (window_sender, admitted_window) = std::sync::mpsc::channel::<Instant>();
    let server = WireServer(Some(thread::spawn(move || {
        let mut deadline = deadline;
        let mut last = None;
        let mut salts = Vec::new();
        let mut requests = Vec::new();
        for attempt in 0..replies + usize::from(retry && !sentinel) {
            if separate_cli_windows && attempt == 1 {
                deadline = admitted_window
                    .recv()
                    .map_err(|_| "second fixture window was not admitted".to_owned())?;
            }
            let mut socket = match accept_request(&listener, deadline) {
                Ok(socket) => socket,
                Err(_) if sentinel && retry && last.is_some() => break,
                Err(error) => return Err(error.to_string()),
            };
            let mut request = read_request(&mut socket, deadline).map_err(|e| e.to_string())?;
            request["wire_request_count"] = json!(attempt + 1);
            salts.push(request.get("cache_salt").cloned().unwrap_or(Value::Null));
            requests.push(request.clone());
            last = Some(request.clone());
            if retry && attempt == 0 {
                write_reply(&mut socket, b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", deadline).map_err(|e| e.to_string())?;
                continue;
            }
            let content = if sentinel {
                let schema = &request["response_format"]["json_schema"]["schema"];
                schema["enum"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|value| value["payload"]["verdict"] == sentinel_reply)
                    .unwrap()
                    .to_string()
            } else {
                serde_json::to_string(&json!({"status":"finished","output":response_output}))
                    .unwrap()
            };
            let mut response = json!({"id":"wire-fixture", "object":"chat.completion", "created":0,"model":"wire-fixture-model", "choices":[{"index":0,"message":{"role":"assistant","content":content},"finish_reason":"stop"}]});
            if let Some(usage) = &usage {
                response["usage"] = if sentinel && usage.is_array() {
                    let shuffled = request["messages"].to_string().contains("/shuffled;");
                    usage[usize::from(shuffled)].clone()
                } else {
                    usage.clone()
                };
            }
            let body = serde_json::to_vec(&response).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if let Err(error) = write_reply(&mut socket, header.as_bytes(), deadline)
                .and_then(|()| write_reply(&mut socket, &body, deadline))
            {
                if sentinel && retry {
                    break;
                }
                return Err(error.to_string());
            }
            last = Some(request);
        }
        last.map(|mut request| {
            request["wire_cache_salts"] = json!(salts);
            request["wire_requests"] = json!(requests);
            request
        })
        .ok_or_else(|| "no request served".to_owned())
    })));
    // Drop the sender before WireServer joins if the client closure unwinds.
    let next_window = window_sender;
    let mut profile: Value = serde_json::from_slice(
        &fs::read(repo().join("examples/00-runtime-smoke/profiles/fake.json")).unwrap(),
    )
    .unwrap();
    profile["model"] = json!({"provider":"openai-compatible","name":model_name,"version":"1","model":"wire-fixture-model","base_url":format!("http://{address}/v1"),"credential_env":"BENCH230_WIRE_TEST_KEY","runtime":{"timeout_ms":10000,"provider_extensions":{"openai":options}}});
    let manifest = json!({"schema_version":1,"origin":"local_wire_test","workflow_source":workflow,"profile":profile,"input":input});
    let path = root.join("binding.json");
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let output = run(&path, &root.join("run"), &|| {
        next_window.send(Instant::now() + budget).unwrap();
    });
    drop(next_window);
    // Join even on a missing CLI command; never leak the listener thread.
    let request = server.finish().unwrap();
    (root, output, request)
}

#[test]
fn wire_measurement_is_runtime_evidence_and_rejects_tampering() {
    let (root, report, request) = measured(Some(
        json!({"prompt_tokens":19,"completion_tokens":11,"total_tokens":30,"prompt_tokens_details":{"cached_tokens":7},"completion_tokens_details":{"reasoning_tokens":3}}),
    ));
    assert_eq!(request["model"], "wire-fixture-model");
    assert_eq!(request["reasoning_effort"], "low");
    assert_eq!(report["evidence_kind"], "local_wire_execution");
    assert_eq!(report["live_executed"], false);
    assert_eq!(report["case"]["status"], "succeeded");
    let digest = |bytes: &[u8]| format!("sha256:{:x}", Sha256::digest(bytes));
    let binding_bytes = fs::read(root.join("binding.json")).unwrap();
    let binding: Value = serde_json::from_slice(&binding_bytes).unwrap();
    assert_eq!(report["binding_digest"], digest(&binding_bytes));
    let manifest = &report["case"]["manifest"];
    for (key, value) in [
        ("config_digest", binding["profile"].clone()),
        ("dataset_digest", binding["input"].clone()),
        (
            "model_digest",
            json!({"worker":binding["profile"]["model"],"reviewer":null}),
        ),
    ] {
        assert_eq!(manifest[key], digest(&serde_json::to_vec(&value).unwrap()));
    }
    let revision = Command::new("git")
        .current_dir(repo())
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert_cli_success(&revision);
    assert_eq!(
        manifest["source_revision"],
        String::from_utf8(revision.stdout).unwrap().trim()
    );
    assert_eq!(
        manifest["workflow_digest"],
        digest(&fs::read(repo().join(manifest["workflow_source"].as_str().unwrap())).unwrap())
    );
    assert_eq!(
        manifest["executable_digest"],
        digest(&fs::read(env!("CARGO_BIN_EXE_bench-230")).unwrap())
    );
    let calls = report["model_calls"].as_array().unwrap();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(
        call["telemetry"]["route"]["resolved_model"],
        "wire-fixture-model"
    );
    assert_eq!(call["telemetry"]["reasoning_mode"], "low");
    assert_eq!(call["telemetry"]["input_tokens"], 19);
    assert_eq!(call["telemetry"]["cached_input_count"], 7);
    assert_eq!(call["telemetry"]["output_tokens"], 11);
    assert_eq!(call["telemetry"]["reasoning_count"], 3);
    assert_eq!(call["telemetry"]["retries"], 0);
    for field in [
        "prefill_ns",
        "decode_ns",
        "provider_cost_usd",
        "kv_cache_hit",
        "visible_output_count",
    ] {
        assert!(call["telemetry"][field].is_null(), "{field}");
    }
    assert!(!report["unavailable"].as_object().unwrap().is_empty());
    let text = serde_json::to_string(&report).unwrap();
    for secret in [
        "PRIVATE_INPUT_NEVER_REPORT",
        "PRIVATE_OUTPUT_NEVER_REPORT",
        "WIRE_SECRET_NEVER_REPORT",
        "127.0.0.1",
        "BENCH230_WIRE_TEST_KEY",
    ] {
        assert!(!text.contains(secret), "leak: {secret}");
    }
    let run = root.join("run");
    assert_eq!(
        success(cli(&["measure-report", run.to_str().unwrap()])),
        report
    );
    let plan_path = run.join("measurement-plan.json");
    let original_plan = fs::read(&plan_path).unwrap();
    let mut edited_plan: Value = serde_json::from_slice(&original_plan).unwrap();
    edited_plan["manifest"]["config_digest"] = json!("sha256:tampered");
    fs::write(&plan_path, serde_json::to_vec(&edited_plan).unwrap()).unwrap();
    assert!(
        !cli(&["measure-report", run.to_str().unwrap()])
            .status
            .success()
    );
    fs::write(&plan_path, original_plan).unwrap();
    let completion = run.join("measurement.json");
    let original = fs::read(&completion).unwrap();
    let mut edited: Value = serde_json::from_slice(&original).unwrap();
    edited["model_calls"][0]["telemetry"]["input_tokens"] = json!(1);
    fs::write(&completion, serde_json::to_vec(&edited).unwrap()).unwrap();
    assert!(
        !cli(&["measure-report", run.to_str().unwrap()])
            .status
            .success()
    );
    fs::write(&completion, &original).unwrap();
    let execution = run.join("execution.json");
    let original_execution = fs::read(&execution).unwrap();
    let mut invalid_completion: Value = serde_json::from_slice(&original_execution).unwrap();
    invalid_completion["hard_invariant_failures"] = json!(["semantic evidence rejected"]);
    fs::write(&execution, serde_json::to_vec(&invalid_completion).unwrap()).unwrap();
    assert!(
        !cli(&["measure-report", run.to_str().unwrap()])
            .status
            .success(),
        "a successful receipt cannot erase failed semantic admission"
    );
    fs::write(&execution, original_execution).unwrap();
    let evidence: Value =
        serde_json::from_slice(&fs::read(run.join("execution.json")).unwrap()).unwrap();
    let events =
        PathBuf::from(evidence["receipt"]["run_root"].as_str().unwrap()).join("events.jsonl");
    let original_events = fs::read(&events).unwrap();
    let mut rows: Vec<Value> = String::from_utf8(original_events.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let event = rows
        .iter_mut()
        .find(|e| e["payload"]["model_telemetry"].is_object())
        .unwrap();
    assert_eq!(event["event_id"], call["event_id"]);
    assert_eq!(event["payload"]["model_telemetry"], call["telemetry"]);
    event["payload"]["model_telemetry"]["input_tokens"] = json!(1);
    fs::write(
        &events,
        rows.iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    assert!(
        !cli(&["measure-report", run.to_str().unwrap()])
            .status
            .success()
    );
    fs::write(&events, original_events).unwrap();
    assert_eq!(
        success(cli(&["measure-report", run.to_str().unwrap()])),
        report
    );
}

#[test]
fn retry_is_measured_at_the_host_boundary_and_missing_details_remain_absent() {
    let (_, output, request) = wire_attempt(
        Some(json!({"prompt_tokens":0,"completion_tokens":0,"total_tokens":0})),
        true,
    );
    let report = success(output);
    assert_eq!(request["wire_request_count"], 2);
    let telemetry = &report["model_calls"][0]["telemetry"];
    assert_eq!(telemetry["retries"], 1);
    assert_eq!(telemetry["input_tokens"], 0);
    assert_eq!(telemetry["output_tokens"], 0);
    assert_eq!(telemetry.get("cached_input_count"), Some(&Value::Null));
    assert_eq!(telemetry.get("reasoning_count"), Some(&Value::Null));
}

#[test]
fn invalid_usage_fields_remain_absent_without_discarding_valid_counts() {
    let (_, output, _) = wire_attempt(
        Some(json!({"prompt_tokens":-1,"completion_tokens":1,"total_tokens":0})),
        false,
    );
    let report = success(output);
    assert_eq!(report["case"]["status"], "succeeded");
    assert!(report["case"]["admitted_run_id"].is_string());
    let telemetry = &report["model_calls"][0]["telemetry"];
    assert!(telemetry["input_tokens"].is_null());
    assert_eq!(telemetry["output_tokens"], 1);
    assert_eq!(telemetry["total_count"], 0);
}

#[test]
fn admission_rejects_origin_route_and_profile_overrides_without_provider_work() {
    let scratch = PathBuf::from(std::env::var_os("TMPDIR").expect("explicit SSD TMPDIR"));
    let root = scratch.join(format!("wire230-admission-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let mut profile: Value = serde_json::from_slice(
        &fs::read(repo().join("examples/00-runtime-smoke/profiles/fake.json")).unwrap(),
    )
    .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    profile["model"] = json!({"provider":"openai-compatible","name":"m3-00-fake","version":"1","model":"wire-fixture-model","base_url":format!("http://{}/v1",listener.local_addr().unwrap()),"credential_env":"BENCH230_WIRE_TEST_KEY"});
    let base = json!({"schema_version":1,"origin":"local_wire_test","workflow_source":"templates/minimal/workflow.toml","profile":profile,"input":{}});
    let path = root.join("binding.json");
    let output = root.join("run");
    for (index, (pointer, value, mode)) in [
        ("/origin", json!("local_wire_test"), "measure-live"),
        ("/origin", json!("live_provider"), "measure"),
        (
            "/profile/model/base_url",
            json!("https://example.invalid/v1"),
            "measure",
        ),
        ("/profile/model/provider", json!("fake"), "measure"),
        ("/schema_version", json!(2), "measure"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut value_binding = base.clone();
        *value_binding.pointer_mut(pointer).unwrap() = value;
        fs::write(&path, serde_json::to_vec(&value_binding).unwrap()).unwrap();
        let result = cli(&[mode, path.to_str().unwrap(), output.to_str().unwrap()]);
        assert_eq!(result.status.code(), Some(1), "negative {index}");
        assert!(!output.exists());
    }
    for options in [
        json!({"model":"silent-route-override"}),
        json!({"messages":[]}),
        json!({"stream":true}),
        json!({"cache_salt":1}),
        json!({"cache_salt":""}),
        json!({"cache_salt":"private value with spaces"}),
        json!({"cache_salt":"x".repeat(129)}),
        json!({"return_token_ids":"true"}),
        json!({"reasoning_effort":"invented"}),
    ] {
        let mut overridden = base.clone();
        overridden["profile"]["model"]["runtime"] =
            json!({"provider_extensions":{"openai":options}});
        fs::write(&path, serde_json::to_vec(&overridden).unwrap()).unwrap();
        assert!(
            !cli(&["measure", path.to_str().unwrap(), output.to_str().unwrap()])
                .status
                .success()
        );
        assert!(!output.exists());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    // A legal profile with an unmatched model identity cannot fabricate measurements.
    fs::write(&path, serde_json::to_vec(&base).unwrap()).unwrap();
    let result = cli(&["measure", path.to_str().unwrap(), output.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("measurement lacks durable receipt"));
}

#[test]
fn missing_usage_is_absent_not_zero() {
    let (_, report, _) = measured(None);
    let telemetry = &report["model_calls"][0]["telemetry"];
    for field in [
        "input_tokens",
        "output_tokens",
        "reasoning_count",
        "cached_input_count",
        "provider_cost_usd",
    ] {
        assert!(telemetry[field].is_null(), "{field}");
    }
    assert_eq!(report["live_executed"], false);
}

#[test]
fn measurement_parent_sync_failure_precedes_admission_and_provider_work() {
    use std::os::unix::fs::PermissionsExt;
    struct PrivateRoot(PathBuf);
    impl Drop for PrivateRoot {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!("wire230-parent-sync-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    let root = PrivateRoot(path);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut profile: Value = serde_json::from_slice(
        &fs::read(repo().join("examples/00-runtime-smoke/profiles/fake.json")).unwrap(),
    )
    .unwrap();
    profile["model"] = json!({"provider":"openai-compatible","name":"minimal-worker","version":"1","model":"wire-fixture-model","base_url":format!("http://{address}/v1"),"credential_env":"BENCH230_WIRE_TEST_KEY","runtime":{"timeout_ms":10000}});
    let binding = json!({"schema_version":1,"origin":"local_wire_test","workflow_source":"templates/minimal/workflow.toml","profile":profile,"input":{"request":"Check the measurement parent durability barrier."}});
    let path = root.0.join("binding.json");
    fs::write(&path, serde_json::to_vec(&binding).unwrap()).unwrap();
    // mkdir and pathname traversal remain legal, but opening the parent for fsync fails.
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o300)).unwrap();
    assert_eq!(
        fs::File::open(&root.0).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied,
        "this control requires the ordinary non-root test owner"
    );
    let run = root.0.join("run");
    let output = cli(&["measure", path.to_str().unwrap(), run.to_str().unwrap()]);
    let admitted = run.join("measurement-admission.json").exists();
    let provider_connected = match listener.accept() {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("unexpected listener error: {error}"),
    };
    eprintln!(
        "parent-sync boundary: admission={admitted}, provider_connected={provider_connected}"
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(!admitted, "parent sync must precede durable admission");
    assert!(
        !provider_connected,
        "parent sync must precede provider work"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Permission denied"));
    assert!(output.stdout.is_empty());
}

fn fixture_request(
    bytes: &[u8],
    budget: Duration,
    client_setup: impl FnOnce(std::net::SocketAddr) -> TcpStream,
) -> thread::Result<io::Result<Value>> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    // Start before client setup: scope unwinding must also bound a missing connection.
    let deadline = Instant::now() + budget;
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let mut socket = accept_request(&listener, deadline)?;
            read_request(&mut socket, deadline)
        });
        let mut client = client_setup(address);
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        // Rejection may close the socket before an oversized body finishes writing.
        let _ = client.write_all(bytes);
        let _ = client.shutdown(std::net::Shutdown::Write);
        drop(client);
        server.join()
    })
}

#[test]
fn fixture_rejects_oversized_request_before_accepting_json() {
    let body = serde_json::to_vec(&json!({"padding":"x".repeat(64 * 1024)})).unwrap();
    let mut request =
        format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    request.extend(body);
    assert_eq!(
        fixture_request(&request, Duration::from_secs(1), |address| {
            TcpStream::connect(address).unwrap()
        })
        .unwrap()
        .map(|_| ())
        .expect_err("oversized request must fail")
        .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn fixture_rejects_content_length_overflow_without_panicking() {
    let request = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", usize::MAX);
    assert_eq!(
        fixture_request(request.as_bytes(), Duration::from_secs(1), |address| {
            TcpStream::connect(address).unwrap()
        })
        .unwrap()
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn fixture_eof_is_an_owned_error_in_headers_and_body() {
    for request in [
        b"POST / HTTP/1.1\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{",
    ] {
        assert_eq!(
            fixture_request(request, Duration::from_secs(1), |address| {
                TcpStream::connect(address).unwrap()
            })
            .unwrap()
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[test]
fn fixture_second_cli_owns_a_new_fixed_window_on_the_same_listener() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    let (_, _, served) = wire_scenario_with_windows(
        None,
        false,
        json!({}),
        (
            "templates/minimal/workflow.toml",
            "minimal-worker",
            json!({"request":"Return ready."}),
            json!({"status":"ready"}),
        ),
        2,
        FixtureWindows::PerCli(Duration::from_millis(200)),
        |binding, _, admit_next_window| {
            let binding: Value = serde_json::from_slice(&fs::read(binding).unwrap()).unwrap();
            let address = binding["profile"]["model"]["base_url"]
                .as_str()
                .unwrap()
                .strip_prefix("http://")
                .unwrap()
                .strip_suffix("/v1")
                .unwrap();
            let exchange = || -> io::Result<()> {
                let mut socket = TcpStream::connect(address)?;
                socket.set_read_timeout(Some(Duration::from_secs(1)))?;
                socket.write_all(
                    b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
                )?;
                let mut reply = Vec::new();
                socket.read_to_end(&mut reply)?;
                if !reply.starts_with(b"HTTP/1.1 200 OK") {
                    return Err(io::Error::other("missing fixture reply"));
                }
                Ok(())
            };
            exchange().expect("first owned window");
            thread::sleep(Duration::from_millis(250));
            admit_next_window();
            exchange().expect("second owned window on the same listener");
            Output {
                status: ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        },
    );
    let served = served.unwrap();
    assert_eq!(served["wire_request_count"], 2);
    assert_eq!(served["wire_requests"].as_array().unwrap().len(), 2);
}

#[test]
fn fixture_missing_second_window_settles_on_return_and_unwind() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    for panic_after_first in [false, true] {
        let outcome = std::panic::catch_unwind(|| {
            wire_scenario_with_windows(
                None,
                false,
                json!({}),
                (
                    "templates/minimal/workflow.toml",
                    "minimal-worker",
                    json!({"request":"Return ready."}),
                    json!({"status":"ready"}),
                ),
                2,
                FixtureWindows::PerCli(Duration::from_millis(200)),
                |binding, _, _| {
                    let binding: Value =
                        serde_json::from_slice(&fs::read(binding).unwrap()).unwrap();
                    let address = binding["profile"]["model"]["base_url"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("http://")
                        .unwrap()
                        .strip_suffix("/v1")
                        .unwrap();
                    let mut socket = TcpStream::connect(address).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    socket
                        .write_all(
                            b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
                        )
                        .unwrap();
                    let mut reply = Vec::new();
                    socket.read_to_end(&mut reply).unwrap();
                    assert!(reply.starts_with(b"HTTP/1.1 200 OK"));
                    if panic_after_first {
                        panic!("synthetic client assertion failure");
                    }
                    Output {
                        status: ExitStatus::from_raw(0),
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    }
                },
            )
        });
        if panic_after_first {
            assert_eq!(
                outcome.unwrap_err().downcast_ref::<&str>(),
                Some(&"synthetic client assertion failure")
            );
        } else {
            assert_eq!(
                outcome.unwrap().2.unwrap_err(),
                "second fixture window was not admitted"
            );
        }
    }
}

#[test]
fn fixture_slow_body_cannot_renew_the_absolute_deadline() {
    let result = fixture_request(b"", Duration::from_millis(200), |address| {
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nContent-Length: 6\r\n\r\n")
            .unwrap();
        for byte in b"    {}" {
            if client.write_all(&[*byte]).is_err() {
                break;
            }
            // Deliberate slow peer: each gap is below the old renewable read timeout.
            thread::sleep(Duration::from_millis(60));
        }
        client
    })
    .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[test]
fn fixture_setup_panic_settles_before_rescue_with_original_payload() {
    let mut naturally_settled = Vec::new();
    for budget in [Duration::from_secs(1), Duration::from_millis(200)] {
        let (address_tx, address_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let (settled, original_panic) = thread::scope(|owner| {
            let worker = owner.spawn(move || {
                let outcome = std::panic::catch_unwind(|| {
                    let _ = fixture_request(b"", budget, |address| {
                        address_tx.send(address).unwrap();
                        panic!("synthetic client setup failure");
                    });
                });
                let original = outcome.err().is_some_and(|payload| {
                    payload.downcast_ref::<&str>() == Some(&"synthetic client setup failure")
                });
                done_tx.send(original).unwrap();
            });
            let address = address_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            // Observation headroom is outside the fixture's unchanged 1s/200ms deadline.
            let observed = done_rx.recv_timeout(budget + Duration::from_secs(1));
            let (settled, original) = match observed {
                Ok(original) => (true, original),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Old-RED-only rescue: release this known owned listener before asserting.
                    if let Ok(mut rescue) =
                        TcpStream::connect_timeout(&address, Duration::from_secs(1))
                    {
                        rescue
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let _ = rescue.write_all(b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}");
                    }
                    (
                        false,
                        done_rx
                            .recv_timeout(budget + Duration::from_secs(1))
                            .unwrap(),
                    )
                }
                Err(error) => panic!("fixture owner disconnected: {error}"),
            };
            worker.join().unwrap();
            assert!(TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err());
            (settled, original)
        });
        eprintln!(
            "setup-panic boundary: budget_ms={}, naturally_settled={settled}, rescued={}, original_panic={original_panic}",
            budget.as_millis(),
            !settled
        );
        assert!(
            original_panic,
            "the original client panic must survive cleanup"
        );
        naturally_settled.push(settled);
    }
    assert!(
        naturally_settled.into_iter().all(|settled| settled),
        "both fixture budgets must settle before rescue"
    );
}

#[test]
fn fixture_owner_joins_and_closes_listener_during_client_unwind() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let result = std::panic::catch_unwind(|| {
        let _server = WireServer(Some(thread::spawn(move || {
            // A bounded owned worker lets the control also settle the old detached thread.
            thread::sleep(Duration::from_millis(100));
            drop(listener);
            done_tx.send(()).unwrap();
            Err("fixture stopped".to_owned())
        })));
        panic!("synthetic client assertion failure");
    });
    assert!(result.is_err());
    let joined_before_return = done_rx.try_recv().is_ok();
    if !joined_before_return {
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    assert!(TcpStream::connect(address).is_err(), "listener must close");
    assert!(
        joined_before_return,
        "unwind must join the owned fixture thread"
    );
}
