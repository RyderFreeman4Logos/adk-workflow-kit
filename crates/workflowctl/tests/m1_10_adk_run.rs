use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_runtime::{
    ArtifactStore, CheckpointManifestV1, FilesystemArtifactStore, PageRequest, RunId,
    SqliteCheckpointStore, WorkflowRuntimeEventV1,
};

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "m1-10-adk"
version = "1"
entry = "agent"
[[nodes]]
id = "agent"
kind = "agent"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "agent"
to = "done"
"#;

const HETEROGENEOUS_WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "m1-10-heterogeneous"
version = "1"
entry = "agent"
[[nodes]]
id = "agent"
kind = "agent"
[[nodes]]
id = "action"
kind = "action"
[[nodes]]
id = "validator"
kind = "validator"
[[nodes]]
id = "registered"
kind = "registered"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "agent"
to = "action"
[[edges]]
from = "action"
to = "validator"
[[edges]]
from = "validator"
to = "registered"
[[edges]]
from = "registered"
to = "done"
"#;

const IDENTITY_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/transform_identity.wasm"
);

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "workflowctl-m1-10-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("test root must be unique");
    root
}

fn write_fixture(root: &Path, profile: Value) -> (PathBuf, PathBuf, PathBuf) {
    let workflow = root.join("workflow.toml");
    let profile_path = root.join("profile.json");
    let runs = root.join("runs");
    fs::write(&workflow, WORKFLOW).expect("workflow fixture must write");
    fs::write(
        &profile_path,
        serde_json::to_vec(&profile).expect("profile fixture must serialize"),
    )
    .expect("profile fixture must write");
    fs::create_dir(&runs).expect("run base must exist");
    (workflow, profile_path, runs)
}

fn fake_profile() -> Value {
    json!({
        "schema_version": 1,
        "model": {
            "provider": "fake",
            "name": "worker",
            "version": "1",
            "model": "fixture-model",
            "responses": ["model-ok"]
        },
        "tool": {
            "name": "echo",
            "result": {"echo": "tool-ok"},
            "required_capabilities": []
        },
        "sandbox": {"capabilities": []}
    })
}

fn run_adk(workflow: &Path, profile: &Path, runs: &Path) -> Output {
    run_adk_with_input(workflow, profile, runs, r#"{"value":7}"#)
}

fn run_adk_with_input(workflow: &Path, profile: &Path, runs: &Path, input: &str) -> Output {
    binary()
        .args([
            "--json",
            "run",
            workflow.to_str().expect("UTF-8 workflow path"),
            "--profile",
            profile.to_str().expect("UTF-8 profile path"),
            "--input",
            input,
            "--workdir",
            runs.to_str().expect("UTF-8 run base"),
        ])
        .output()
        .expect("workflowctl run must start")
}

fn non_agent_workflow(node_count: usize) -> String {
    let mut workflow = String::from(
        "schema_version = 1\n[workflow]\nid = \"m1-10-large-outputs\"\nversion = \"1\"\nentry = \"node-0\"\n",
    );
    for index in 0..node_count {
        workflow.push_str(&format!(
            "[[nodes]]\nid = \"node-{index}\"\nkind = \"action\"\nmax_visits = 2\n"
        ));
    }
    workflow.push_str("[[nodes]]\nid = \"done\"\nkind = \"terminal\"\n");
    for index in 0..node_count {
        let target = if index + 1 == node_count {
            "done".to_owned()
        } else {
            format!("node-{}", index + 1)
        };
        workflow.push_str(&format!(
            "[[edges]]\nfrom = \"node-{index}\"\nto = \"{target}\"\n"
        ));
    }
    workflow
}

fn large_input() -> (Value, String) {
    let value = json!({"payload": "x".repeat(40 * 1024)});
    let encoded = serde_json::to_string(&value).expect("large input must serialize");
    assert!(
        encoded.len() < 64 * 1024,
        "canonical input must remain bounded"
    );
    (value, encoded)
}

fn terminal_artifact(run_root: &Path) -> (Vec<u8>, Value) {
    let manifest: Value = serde_json::from_slice(
        &fs::read(run_root.join("run-manifest.json")).expect("manifest must be readable"),
    )
    .expect("manifest must be JSON");
    let artifact_id = manifest["artifact_id"]
        .as_str()
        .expect("manifest must reference the terminal artifact");
    let bytes = fs::read(run_root.join("artifacts").join(artifact_id))
        .expect("terminal artifact must be readable");
    let value = serde_json::from_slice(&bytes).expect("terminal artifact must be JSON");
    (bytes, value)
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must be JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn run_root(runs: &Path) -> PathBuf {
    let roots = fs::read_dir(runs)
        .expect("run base must be readable")
        .map(|entry| entry.expect("run entry must be readable").path())
        .collect::<Vec<_>>();
    assert_eq!(roots.len(), 1, "one invocation must allocate one run root");
    roots[0].clone()
}

#[derive(Debug)]
struct RequestObservation {
    method: String,
    path: String,
    authorization_headers: usize,
    canary_occurrences: usize,
}

const ORACLE_TIMEOUT: Duration = Duration::from_secs(5);
const ORACLE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const ORACLE_SOCKET_TIMEOUT: Duration = Duration::from_millis(100);
const ORACLE_MAX_REQUEST_BYTES: usize = 64 * 1024;
const ORACLE_MAX_CHILD_OUTPUT_BYTES: usize = 64 * 1024;
const ORACLE_SCAN_MAX_DEPTH: usize = 8;
const ORACLE_SCAN_MAX_ENTRIES: usize = 512;
const ORACLE_SCAN_MAX_FILES: usize = 256;
const ORACLE_SCAN_MAX_FILE_BYTES: usize = 1024 * 1024;
const ORACLE_SCAN_MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const ORACLE_SCAN_CHUNK_BYTES: usize = 8192;
const ORACLE_SCAN_MAX_CANARY_BYTES: usize = 256;

fn read_model_request(
    socket: &mut std::net::TcpStream,
    deadline: Instant,
    canary: &str,
) -> Result<RequestObservation, &'static str> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 8192];
    let header_end = loop {
        if Instant::now() >= deadline {
            return Err("oracle request headers timed out");
        }
        let bytes = match socket.read(&mut buffer) {
            Ok(0) => return Err("oracle request ended before headers"),
            Ok(bytes) => bytes,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => return Err("oracle request header read failed"),
        };
        if request.len().saturating_add(bytes) > ORACLE_MAX_REQUEST_BYTES {
            return Err("oracle request headers exceeded size limit");
        }
        request.extend_from_slice(&buffer[..bytes]);
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };

    let content_length = {
        let header_text = String::from_utf8_lossy(&request[..header_end]);
        header_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or("oracle request content length missing or invalid")?
    };
    if content_length > ORACLE_MAX_REQUEST_BYTES.saturating_sub(header_end) {
        return Err("oracle request body exceeded size limit");
    }
    let request_end = header_end + content_length;
    while request.len() < request_end {
        if Instant::now() >= deadline {
            return Err("oracle request body timed out");
        }
        let bytes = match socket.read(&mut buffer) {
            Ok(0) => return Err("oracle request ended before body"),
            Ok(bytes) => bytes,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => return Err("oracle request body read failed"),
        };
        if request.len().saturating_add(bytes) > ORACLE_MAX_REQUEST_BYTES {
            return Err("oracle request exceeded size limit");
        }
        request.extend_from_slice(&buffer[..bytes]);
    }

    let header_text = String::from_utf8_lossy(&request[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().ok_or("oracle request line missing")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let path = request_parts.next().unwrap_or_default().to_owned();
    let mut authorization_headers = 0;
    let mut canary_occurrences = 0;
    for line in lines {
        match line.split_once(':') {
            Some((name, value)) if name.eq_ignore_ascii_case("authorization") => {
                authorization_headers += 1;
                canary_occurrences += value.matches(canary).count();
            }
            _ => {}
        }
    }
    Ok(RequestObservation {
        method,
        path,
        authorization_headers,
        canary_occurrences,
    })
}

fn serve_oracle_request(
    listener: std::net::TcpListener,
    canary: &'static str,
) -> Result<RequestObservation, &'static str> {
    listener
        .set_nonblocking(true)
        .map_err(|_| "oracle listener setup failed")?;
    let deadline = Instant::now() + ORACLE_TIMEOUT;
    let (mut socket, _) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("oracle listener accept timed out");
                }
                thread::yield_now();
            }
            Err(_) => return Err("oracle listener accept failed"),
        }
    };
    socket
        .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
        .map_err(|_| "oracle socket read timeout setup failed")?;
    socket
        .set_write_timeout(Some(ORACLE_SOCKET_TIMEOUT))
        .map_err(|_| "oracle socket write timeout setup failed")?;
    let observation = read_model_request(&mut socket, deadline, canary)?;
    let body = r#"{"choices":[{"message":{"role":"assistant","content":"oracle-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    write!(
        socket,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .map_err(|_| "oracle response write failed")?;
    socket.flush().map_err(|_| "oracle response flush failed")?;
    Ok(observation)
}

fn read_child_output(path: &Path) -> Result<Vec<u8>, &'static str> {
    let mut output = Vec::new();
    fs::File::open(path)
        .map_err(|_| "oracle child output open failed")?
        .take((ORACLE_MAX_CHILD_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| "oracle child output read failed")?;
    if output.len() > ORACLE_MAX_CHILD_OUTPUT_BYTES {
        return Err("oracle child output exceeded size limit");
    }
    Ok(output)
}

fn append_output_errors(
    diagnostics: &mut Vec<&'static str>,
    stdout_path: &Path,
    stderr_path: &Path,
) {
    if let Err(error) = read_child_output(stdout_path) {
        diagnostics.push(error);
    }
    if let Err(error) = read_child_output(stderr_path) {
        diagnostics.push(error);
    }
}

fn clean_up_child(mut child: Child) -> Vec<&'static str> {
    let mut diagnostics = Vec::new();
    if child.kill().is_err() {
        diagnostics.push("oracle child kill failed");
    }
    let deadline = Instant::now() + ORACLE_CLEANUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                diagnostics.push("oracle child reaped after kill");
                return diagnostics;
            }
            Ok(None) if Instant::now() < deadline => thread::yield_now(),
            Err(_) if Instant::now() < deadline => {
                if !diagnostics.contains(&"oracle child reap check failed") {
                    diagnostics.push("oracle child reap check failed");
                }
                thread::yield_now();
            }
            Ok(None) | Err(_) => {
                let diagnostic = match thread::Builder::new()
                    .name("oracle-delayed-reaper".to_owned())
                    .spawn(move || {
                        let _ = child.wait();
                    }) {
                    Ok(_) => "oracle child cleanup timed out; delayed reaper started",
                    Err(_) => "oracle child cleanup timed out; delayed reaper start failed",
                };
                diagnostics.push(diagnostic);
                return diagnostics;
            }
        }
    }
}

fn wait_bounded_child(
    mut child: Child,
    stdout_path: &Path,
    stderr_path: &Path,
    deadline: Instant,
) -> Result<Output, String> {
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::yield_now(),
            Ok(None) => {
                let mut diagnostics = clean_up_child(child);
                append_output_errors(&mut diagnostics, stdout_path, stderr_path);
                return Err(format!(
                    "oracle child timed out; {}",
                    diagnostics.join("; ")
                ));
            }
            Err(_) => {
                let mut diagnostics = clean_up_child(child);
                append_output_errors(&mut diagnostics, stdout_path, stderr_path);
                return Err(format!(
                    "oracle child wait failed; {}",
                    diagnostics.join("; ")
                ));
            }
        }
    };
    let stdout = read_child_output(stdout_path).map_err(str::to_owned)?;
    let stderr = read_child_output(stderr_path).map_err(str::to_owned)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn command_json(args: &[&str]) -> Output {
    let output = binary()
        .args(args)
        .output()
        .expect("workflowctl must start");
    assert!(
        output.status.success(),
        "command must succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn subprocess_adk_run_needs_no_transform_module_and_persists_state() {
    let root = temp_root("run");
    let (workflow, profile, runs) = write_fixture(&root, fake_profile());

    let output = run_adk(&workflow, &profile, &runs);
    assert!(
        output.status.success(),
        "ADK run must succeed without --module, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt = json_stdout(&output);
    assert_eq!(receipt["status"], "succeeded");
    assert!(receipt["run_id"].as_str().is_some_and(|id| !id.is_empty()));

    let run_root = run_root(&runs);
    assert!(run_root.join("run-manifest.json").is_file());
    assert!(run_root.join("events.jsonl").is_file());
    let artifacts = fs::read_dir(run_root.join("artifacts"))
        .expect("artifact directory must exist")
        .collect::<Result<Vec<_>, _>>()
        .expect("artifact entries must be readable");
    assert!(
        !artifacts.is_empty(),
        "successful run must persist an artifact"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn fake_model_and_tool_execute_end_to_end_through_adk_events() {
    let root = temp_root("fake-graph");
    let (workflow, profile, runs) = write_fixture(&root, fake_profile());

    let output = run_adk(&workflow, &profile, &runs);
    assert!(output.status.success());
    let events =
        fs::read_to_string(run_root(&runs).join("events.jsonl")).expect("events must be persisted");
    assert!(events.contains("\"kind\":\"model_request_completed\""));
    assert!(events.contains("model-ok"));
    assert!(events.contains("\"kind\":\"tool_completed\""));
    assert!(events.contains("tool-ok"));

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn profile_graph_runs_non_agent_nodes_through_the_wasm_backend() {
    let root = temp_root("heterogeneous");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] = json!({"module": IDENTITY_WASM});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, HETEROGENEOUS_WORKFLOW).expect("workflow fixture must write");

    let output = run_adk(&workflow, &profile, &runs);
    assert!(
        output.status.success(),
        "heterogeneous ADK run must succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run_root = run_root(&runs);
    let (_, terminal) = terminal_artifact(&run_root);
    let node_outputs = terminal["node_output_refs"]
        .as_object()
        .expect("terminal artifact must reference non-Agent node outputs");
    for node in ["action", "validator", "registered"] {
        let artifact_id = node_outputs[node]["artifact_id"]
            .as_str()
            .expect("node output must have an artifact reference");
        let output: Value = serde_json::from_slice(
            &fs::read(run_root.join("artifacts").join(artifact_id))
                .expect("referenced node output must be readable"),
        )
        .expect("node output artifact must be JSON");
        assert_eq!(
            output,
            json!({"value": 7}),
            "{node} must preserve the WASM transform output instead of a true placeholder"
        );
    }

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn large_non_agent_outputs_are_individually_persisted_and_inspectable() {
    let root = temp_root("large-node-outputs");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] = json!({"module": IDENTITY_WASM});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, non_agent_workflow(2)).expect("workflow fixture must write");
    let (input_value, input) = large_input();

    let output = run_adk_with_input(&workflow, &profile, &runs, &input);
    assert!(
        output.status.success(),
        "large multi-node run must succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt = json_stdout(&output);
    let run_id = receipt["run_id"].as_str().expect("run ID must be text");
    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().expect("UTF-8 run base"),
    ]);
    assert_eq!(json_stdout(&inspect), receipt);

    let run_root = run_root(&runs);
    let (terminal_bytes, terminal) = terminal_artifact(&run_root);
    assert!(terminal_bytes.len() <= 64 * 1024);
    assert!(terminal.get("node_outputs").is_none());
    let refs = terminal["node_output_refs"]
        .as_object()
        .expect("terminal artifact must contain node output references");
    assert_eq!(refs.len(), 2);
    let mut combined_bytes = 0_u64;
    for node in ["node-0", "node-1"] {
        let reference = &refs[node];
        let artifact_id = reference["artifact_id"]
            .as_str()
            .expect("reference must contain an artifact ID");
        assert_eq!(reference["sha256"], format!("sha256:{artifact_id}"));
        combined_bytes += reference["byte_len"]
            .as_u64()
            .expect("reference must contain a byte length");
        let persisted: Value = serde_json::from_slice(
            &fs::read(run_root.join("artifacts").join(artifact_id))
                .expect("node artifact must be readable"),
        )
        .expect("node artifact must be JSON");
        assert_eq!(persisted, input_value);
    }
    assert!(combined_bytes > 64 * 1024);

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn oversized_node_output_reference_aggregate_remains_bounded_and_inspectable() {
    let root = temp_root("oversized-node-reference-aggregate");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] = json!({"module": IDENTITY_WASM});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, non_agent_workflow(350)).expect("workflow fixture must write");

    let output = run_adk(&workflow, &profile, &runs);
    assert!(
        !output.status.success(),
        "large reference aggregate must fail closed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt = json_stdout(&output);
    assert_eq!(receipt["status"], "failed");
    let run_id = receipt["run_id"].as_str().expect("run ID must be text");
    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().expect("UTF-8 run base"),
    ]);
    assert_eq!(json_stdout(&inspect), receipt);

    let run_root = run_root(&runs);
    let (terminal_bytes, terminal) = terminal_artifact(&run_root);
    assert!(terminal_bytes.len() <= 64 * 1024);
    assert_eq!(terminal["node_output_refs"], json!({}));
    assert_eq!(terminal["node_output_refs_summary"]["count"], 350);
    assert!(
        terminal["node_output_refs_summary"]["sha256"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn post_execution_artifact_failure_still_persists_the_returned_receipt() {
    let root = temp_root("node-output-persistence-failure");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] = json!({"module": IDENTITY_WASM});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, non_agent_workflow(16)).expect("workflow fixture must write");
    let (input_value, input) = large_input();
    let output_digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&input_value).expect("node output must serialize"))
    );

    let mut child = binary()
        .args([
            "--json",
            "run",
            workflow.to_str().expect("UTF-8 workflow path"),
            "--profile",
            profile.to_str().expect("UTF-8 profile path"),
            "--input",
            &input,
            "--workdir",
            runs.to_str().expect("UTF-8 run base"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("workflowctl run must start");
    let deadline = Instant::now() + Duration::from_secs(5);
    let artifact_root = loop {
        let candidate = fs::read_dir(&runs)
            .expect("run base must be readable")
            .next()
            .transpose()
            .expect("run entry must be readable")
            .map(|entry| entry.path().join("artifacts"));
        if let Some(path) = candidate
            && path.is_dir()
        {
            break path;
        }
        if Instant::now() >= deadline {
            child.kill().expect("timed-out child must stop");
            let _ = child.wait();
            panic!("artifact store was not allocated before the deadline");
        }
        thread::yield_now();
    };
    fs::create_dir(artifact_root.join(output_digest))
        .expect("collision fixture must make node artifact persistence fail");

    let failed = child
        .wait_with_output()
        .expect("workflowctl run must finish after persistence failure");
    assert_eq!(failed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("workflow.run.failed"));
    let failed_receipt = json_stdout(&failed);
    assert_eq!(
        failed_receipt["status"], "succeeded",
        "artifact persistence failure must occur after graph execution"
    );
    let run_id = failed_receipt["run_id"]
        .as_str()
        .expect("persistence failure must return the allocated run ID");
    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().expect("UTF-8 run base"),
    ]);
    assert_eq!(json_stdout(&inspect), failed_receipt);

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn invalid_profile_fails_closed_with_stable_exit_code() {
    let root = temp_root("invalid-profile");
    let invalid = json!({
        "schema_version": 1,
        "model": {"provider": "unknown"},
        "sandbox": {"capabilities": []}
    });
    let (workflow, profile, runs) = write_fixture(&root, invalid);

    let output = run_adk(&workflow, &profile, &runs);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("workflow.run.unsupported_input"));
    assert!(
        fs::read_dir(&runs)
            .expect("run base must be readable")
            .next()
            .is_none(),
        "invalid profile must fail before allocating run state"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn sandbox_denial_fails_before_backend_spawn() {
    let root = temp_root("sandbox-denial");
    let mut profile_value = fake_profile();
    profile_value["tool"]["required_capabilities"] = json!(["process.spawn"]);
    let (workflow, profile, runs) = write_fixture(&root, profile_value);

    let output = run_adk(&workflow, &profile, &runs);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("workflow.run.failed"));
    assert!(
        fs::read_dir(&runs)
            .expect("run base must be readable")
            .next()
            .is_none(),
        "sandbox denial must happen before workdir allocation or backend spawn"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn failed_profile_run_persists_and_remains_inspectable() {
    let root = temp_root("failed-run");
    let invalid_module = root.join("invalid.wasm");
    fs::write(&invalid_module, b"not wasm").expect("invalid module fixture must write");
    let mut profile_value = fake_profile();
    profile_value["pure_transform"] =
        json!({"module": invalid_module.to_str().expect("UTF-8 module path")});
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    fs::write(&workflow, HETEROGENEOUS_WORKFLOW).expect("workflow fixture must write");

    let failed = run_adk(&workflow, &profile, &runs);
    assert_eq!(failed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("workflow.run.failed"));
    let failed_receipt = json_stdout(&failed);
    let run_id = failed_receipt["run_id"]
        .as_str()
        .expect("failed receipt must carry the allocated run ID");
    assert_eq!(failed_receipt["status"], "failed");

    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().expect("UTF-8 run base"),
    ]);
    let inspected = json_stdout(&inspect);
    assert_eq!(inspected["run_id"], run_id);
    assert_eq!(inspected["status"], "failed");
    let events = fs::read_to_string(run_root(&runs).join("events.jsonl"))
        .expect("failed events must be persisted");
    assert!(events.contains("\"kind\":\"workflow_failed\""));
    assert!(
        fs::read_dir(run_root(&runs).join("artifacts"))
            .expect("failed artifact directory must exist")
            .next()
            .is_some(),
        "failed run must persist a terminal artifact"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn oversized_agent_only_profile_input_fails_before_run_allocation() {
    let root = temp_root("oversized-input");
    let (workflow, profile, runs) = write_fixture(&root, fake_profile());
    let input = serde_json::to_string(&json!({"payload": "x".repeat(64 * 1024)}))
        .expect("oversized input must serialize");

    let output = run_adk_with_input(&workflow, &profile, &runs, &input);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("workflow.run.unsupported_input"));
    assert!(
        fs::read_dir(&runs)
            .expect("run base must be readable")
            .next()
            .is_none(),
        "oversized input must fail before allocating run state"
    );

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn resume_and_inspect_reuse_the_original_run_identity() {
    let root = temp_root("resume-inspect");
    let (workflow, profile, runs) = write_fixture(&root, fake_profile());
    let run = run_adk(&workflow, &profile, &runs);
    assert!(run.status.success());
    let run_receipt = json_stdout(&run);
    let run_id = run_receipt["run_id"].as_str().expect("run ID must be text");
    let runs_text = runs.to_str().expect("UTF-8 run base");

    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs_text,
    ]);
    let inspected = json_stdout(&inspect);
    assert_eq!(inspected["run_id"], run_id);
    assert_eq!(inspected["status"], "succeeded");

    let resume = command_json(&[
        "--json",
        "resume",
        "--run-id",
        run_id,
        "--workdir",
        runs_text,
    ]);
    let resumed = json_stdout(&resume);
    assert_eq!(resumed["run_id"], run_id);
    assert_eq!(resumed["status"], "succeeded");

    let events = fs::read_to_string(run_root(&runs).join("events.jsonl"))
        .expect("resumed events must be readable");
    assert!(events.contains("\"kind\":\"workflow_resumed\""));

    fs::remove_dir_all(root).expect("test root must be removed");
}

#[test]
fn oracle_request_reader_rejects_early_eof() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let client = std::net::TcpStream::connect(address).expect("oracle client");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("oracle client shutdown");
    let (mut socket, _) = listener.accept().expect("oracle request");
    socket
        .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
        .expect("oracle socket read timeout");
    assert!(
        read_model_request(
            &mut socket,
            Instant::now() + ORACLE_TIMEOUT,
            "synthetic-credential-canary-m3-01-7f3c",
        )
        .is_err(),
        "early EOF must fail instead of spinning"
    );
}

#[test]
fn oracle_request_reader_rejects_oversized_body() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let mut client = std::net::TcpStream::connect(address).expect("oracle client");
    write!(
        client,
        "POST /v1/chat/completions HTTP/1.1\r\ncontent-length: {ORACLE_MAX_REQUEST_BYTES}\r\n\r\n"
    )
    .expect("oversized request header");
    let (mut socket, _) = listener.accept().expect("oracle request");
    socket
        .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
        .expect("oracle socket read timeout");
    assert!(matches!(
        read_model_request(
            &mut socket,
            Instant::now() + ORACLE_TIMEOUT,
            "synthetic-credential-canary-m3-01-7f3c",
        ),
        Err("oracle request body exceeded size limit")
    ));
}

const SUPERVISOR_FIXTURE_ENV: &str = "WORKFLOWCTL_ORACLE_SUPERVISOR_FIXTURE";

#[test]
fn oracle_supervisor_fixture_blocks() {
    if std::env::var_os(SUPERVISOR_FIXTURE_ENV).is_none() {
        return;
    }
    std::io::stdout()
        .write_all(&vec![b'x'; ORACLE_MAX_CHILD_OUTPUT_BYTES + 1])
        .expect("fixture output");
    std::io::stdout().flush().expect("fixture output flush");
    thread::park();
}

#[test]
fn oracle_child_timeout_is_primary_and_directly_reaped() {
    let root = temp_root("oracle-child-timeout");
    let stdout_path = root.join("stdout");
    let stderr_path = root.join("stderr");
    let child = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "oracle_supervisor_fixture_blocks", "--nocapture"])
        .env(SUPERVISOR_FIXTURE_ENV, "1")
        .stdout(Stdio::from(
            fs::File::create(&stdout_path).expect("fixture stdout"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).expect("fixture stderr"),
        ))
        .spawn()
        .expect("fixture child");
    let ready_deadline = Instant::now() + ORACLE_TIMEOUT;
    loop {
        if fs::metadata(&stdout_path)
            .is_ok_and(|metadata| metadata.len() > ORACLE_MAX_CHILD_OUTPUT_BYTES as u64)
        {
            break;
        }
        if Instant::now() >= ready_deadline {
            let diagnostics = clean_up_child(child);
            panic!(
                "fixture child output readiness timed out; {}",
                diagnostics.join("; ")
            );
        }
        thread::yield_now();
    }
    let pid = child.id();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let supervisor = thread::spawn(move || {
        let result = wait_bounded_child(
            child,
            &stdout_path,
            &stderr_path,
            Instant::now() + Duration::from_millis(100),
        );
        result_tx.send(result).expect("supervisor result receiver");
    });
    let error = result_rx
        .recv_timeout(ORACLE_TIMEOUT)
        .expect("supervisor must finish boundedly")
        .expect_err("fixture child must time out");
    supervisor.join().expect("supervisor thread must finish");
    assert!(error.starts_with("oracle child timed out"));
    assert!(error.contains("oracle child reaped after kill"));
    assert!(error.contains("oracle child output exceeded size limit"));
    // SAFETY: signal 0 only probes whether the directly owned child PID still exists.
    let probe = unsafe { libc::kill(pid as libc::pid_t, 0) };
    assert_eq!(probe, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    fs::remove_dir_all(root).expect("fixture root removal");
}

#[test]
fn oracle_run_root_scan_rejects_boundary_canary_and_symlink() {
    const CANARY: &str = "synthetic-credential-canary-m3-01-7f3c";
    let root = temp_root("oracle-run-root-scan");
    let split = ORACLE_SCAN_CHUNK_BYTES - CANARY.len() / 2;
    let mut bytes = vec![b'x'; split];
    bytes.extend_from_slice(CANARY.as_bytes());
    fs::write(root.join("boundary"), bytes).expect("boundary fixture");
    assert_eq!(
        scan_run_root(&root, CANARY),
        Err("oracle run-root canary detected")
    );
    fs::remove_file(root.join("boundary")).expect("boundary fixture removal");
    std::os::unix::fs::symlink(root.join("missing"), root.join("link")).expect("symlink fixture");
    assert_eq!(
        scan_run_root(&root, CANARY),
        Err("oracle run-root symlink rejected")
    );
    fs::remove_dir_all(root).expect("scan fixture removal");
}

#[test]
fn credential_value_is_absent_from_production_run_readback_surfaces() {
    const HANDLE: &str = "WORKFLOWCTL_CREDENTIAL_ORACLE_HANDLE";
    const CANARY: &str = "synthetic-credential-canary-m3-01-7f3c";

    let root = temp_root("credential-oracle");
    let stdout_path = root.join("workflowctl.stdout");
    let stderr_path = root.join("workflowctl.stderr");
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let profile_value = json!({
        "schema_version": 1,
        "model": {
            "provider": "openai-compatible",
            "name": "oracle-model",
            "version": "1",
            "model": "oracle",
            "base_url": format!("http://{address}/v1"),
            "credential_env": HANDLE
        },
        "sandbox": {"capabilities": []}
    });
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    let stdout = fs::File::create(&stdout_path).expect("oracle stdout file");
    let stderr = fs::File::create(&stderr_path).expect("oracle stderr file");
    let (request_tx, request_rx) = mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        let result = serve_oracle_request(listener, CANARY);
        let _ = request_tx.send(result);
    });
    let child = binary()
        .args([
            "--json",
            "run",
            workflow.to_str().expect("UTF-8 workflow path"),
            "--profile",
            profile.to_str().expect("UTF-8 profile path"),
            "--input",
            r#"{"request":"public"}"#,
            "--workdir",
            runs.to_str().expect("UTF-8 run base"),
        ])
        .env(HANDLE, CANARY)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn();
    let child_result = match child {
        Ok(child) => wait_bounded_child(
            child,
            &stdout_path,
            &stderr_path,
            Instant::now() + ORACLE_TIMEOUT,
        ),
        Err(_) => Err("oracle child spawn failed".to_owned()),
    };
    let observation_result = request_rx.recv_timeout(ORACLE_TIMEOUT);
    let server_result = server.join();

    let child = match child_result {
        Ok(child) => child,
        Err(error) => {
            let server_diagnostic = match (&observation_result, &server_result) {
                (_, Err(_)) => "oracle server thread failed",
                (Ok(Err(error)), _) => error,
                (Err(_), _) => "oracle request observation unavailable",
                (Ok(Ok(_)), Ok(())) => "oracle server completed",
            };
            panic!("oracle child supervision failed: {error}; {server_diagnostic}");
        }
    };
    assert!(
        child.status.success(),
        "oracle child must succeed (stdout={}, stderr={})",
        String::from_utf8_lossy(&child.stdout).replace(CANARY, "[REDACTED]"),
        String::from_utf8_lossy(&child.stderr).replace(CANARY, "[REDACTED]")
    );
    assert_no_canary_bytes(&child.stdout, CANARY);
    assert_no_canary_bytes(&child.stderr, CANARY);
    assert!(server_result.is_ok(), "oracle server should finish");
    let observation = observation_result
        .expect("oracle request observation receive")
        .expect("oracle request observation");
    assert_eq!(observation.method, "POST");
    assert_eq!(observation.path, "/v1/chat/completions");
    assert_eq!(observation.authorization_headers, 1);
    assert_eq!(observation.canary_occurrences, 1);

    let run_root = run_root(&runs);
    let manifest_bytes = fs::read(run_root.join("run-manifest.json")).expect("run manifest");
    assert_no_canary_bytes(&manifest_bytes, CANARY);
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("manifest JSON");
    assert_eq!(manifest["status"], "succeeded");
    assert_eq!(manifest["profile_identity"], "oracle-model:1");
    assert!(
        !manifest["plan_hash"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
    assert!(
        !manifest["resume_identity"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );

    let source = fs::read(run_root.join("workflow.toml")).expect("canonical source");
    assert_eq!(source, WORKFLOW.as_bytes());
    assert_no_canary_bytes(&source, CANARY);

    let stored_profile = fs::read(run_root.join("execution-profile.json")).expect("stored profile");
    assert_no_canary_bytes(&stored_profile, CANARY);
    let stored_profile: Value = serde_json::from_slice(&stored_profile).expect("profile JSON");
    assert_eq!(stored_profile["model"]["credential_env"], HANDLE);
    assert_ne!(stored_profile["model"]["credential_env"], CANARY);

    let run_id = manifest["run_id"].as_str().expect("run ID");
    let inspect = command_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().expect("UTF-8 runs path"),
    ]);
    assert_no_canary_bytes(&inspect.stdout, CANARY);
    assert_no_canary_bytes(&inspect.stderr, CANARY);
    let inspected = json_stdout(&inspect);
    assert_eq!(inspected["status"], "succeeded");
    assert_eq!(inspected["run_id"], run_id);

    let checkpoint_manifest: CheckpointManifestV1 =
        serde_json::from_value(manifest["checkpoint_manifest"].clone())
            .expect("checkpoint manifest");
    assert_eq!(checkpoint_manifest.run_id(), run_id);
    assert_no_canary_bytes(
        &serde_json::to_vec(&checkpoint_manifest).expect("checkpoint manifest bytes"),
        CANARY,
    );
    let checkpoint_store =
        SqliteCheckpointStore::open(run_root.join("checkpoint.sqlite"), checkpoint_manifest)
            .expect("checkpoint store");
    let checkpoint = checkpoint_store
        .load_latest(&RunId::new(run_id.to_owned()).expect("valid run ID"))
        .expect("checkpoint read")
        .expect("checkpoint exists");
    assert_no_canary_bytes(checkpoint.state(), CANARY);
    let checkpoint_state: Value =
        serde_json::from_slice(checkpoint.state()).expect("checkpoint JSON");
    assert_no_canary(&checkpoint_state, CANARY);

    let events_bytes = fs::read(run_root.join("events.jsonl")).expect("events");
    assert_no_canary_bytes(&events_bytes, CANARY);
    let events = std::str::from_utf8(&events_bytes)
        .expect("events UTF-8")
        .lines()
        .map(serde_json::from_str::<WorkflowRuntimeEventV1>)
        .collect::<Result<Vec<_>, _>>()
        .expect("events structurally readable");
    assert!(!events.is_empty());
    for event in &events {
        assert_no_canary(event.payload(), CANARY);
    }

    let artifact_store = FilesystemArtifactStore::try_new(
        run_root.join("artifacts"),
        std::num::NonZeroU64::new(64 * 1024).expect("artifact limit"),
        std::num::NonZeroU64::new(64 * 1024).expect("page limit"),
    )
    .expect("artifact store");
    let artifact_id = workflow_runtime::ArtifactId::parse(
        manifest["artifact_id"]
            .as_str()
            .expect("terminal artifact ID"),
    )
    .expect("artifact ID");
    let page = artifact_store
        .read_page(
            &artifact_id,
            PageRequest::new(0, std::num::NonZeroU64::new(64 * 1024).expect("page size")),
        )
        .expect("artifact readback");
    assert!(page.next_offset().is_none());
    assert_no_canary_bytes(page.bytes(), CANARY);
    let replay_artifacts = vec![json!({
        "id": artifact_id.as_str(),
        "bytes": page.bytes()
    })];

    let input = fs::read(run_root.join("execution-input.json")).expect("execution input");
    assert_no_canary_bytes(&input, CANARY);
    let workflow_digest = format!("sha256:{:x}", Sha256::digest(&source));
    let input_digest = format!("sha256:{:x}", Sha256::digest(&input));
    let replay_value = json!({
        "schema_version": 1,
        "workflow_lock": {"toml": String::from_utf8(source).expect("workflow UTF-8"), "sha256": workflow_digest},
        "input_sha256": input_digest.clone(),
        "events": [
            {"type": "node_started", "node_id": "agent"},
            {"type": "terminal", "status": "completed", "outcome_sha256": input_digest}
        ],
        "fixtures": [{"sha256": input_digest}],
        "artifacts": replay_artifacts
    });
    let replay_bytes = serde_json::to_vec(&replay_value).expect("replay bytes");
    assert_no_canary_bytes(&replay_bytes, CANARY);
    let replay = workflow_testkit::ReplayBundle::from_json(&replay_bytes)
        .expect("replay-facing data should read back");
    assert_eq!(replay.replay().events().len(), 2);

    assert_no_canary_in_run_root(&run_root, CANARY);
    fs::remove_dir_all(root).expect("oracle root should be removed");
}

fn assert_no_canary(value: &Value, canary: &str) {
    assert!(!value.to_string().contains(canary));
}

fn assert_no_canary_bytes(bytes: &[u8], canary: &str) {
    assert!(
        !bytes
            .windows(canary.len())
            .any(|window| window == canary.as_bytes())
    );
}

fn scan_run_root(root: &Path, canary: &str) -> Result<(), &'static str> {
    if canary.is_empty() || canary.len() > ORACLE_SCAN_MAX_CANARY_BYTES {
        return Err("oracle run-root canary length rejected");
    }
    let mut pending = vec![(root.to_owned(), 0_usize)];
    let mut entries = 0_usize;
    let mut files = 0_usize;
    let mut total_bytes = 0_usize;
    let mut buffer = [0_u8; ORACLE_SCAN_CHUNK_BYTES];
    while let Some((path, depth)) = pending.pop() {
        if depth > ORACLE_SCAN_MAX_DEPTH {
            return Err("oracle run-root depth exceeded");
        }
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "oracle run-root metadata read failed")?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err("oracle run-root symlink rejected");
        }
        if file_type.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| "oracle run-root directory read failed")? {
                entries += 1;
                if entries > ORACLE_SCAN_MAX_ENTRIES {
                    return Err("oracle run-root entry count exceeded");
                }
                pending.push((
                    entry
                        .map_err(|_| "oracle run-root entry read failed")?
                        .path(),
                    depth + 1,
                ));
            }
            continue;
        }
        if !file_type.is_file() {
            return Err("oracle run-root special file rejected");
        }
        files += 1;
        if files > ORACLE_SCAN_MAX_FILES {
            return Err("oracle run-root file count exceeded");
        }
        let mut file = fs::File::open(path).map_err(|_| "oracle run-root file open failed")?;
        let mut file_bytes = 0_usize;
        let mut overlap = Vec::with_capacity(canary.len() - 1);
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| "oracle run-root file read failed")?;
            if read == 0 {
                break;
            }
            file_bytes = file_bytes.saturating_add(read);
            total_bytes = total_bytes.saturating_add(read);
            if file_bytes > ORACLE_SCAN_MAX_FILE_BYTES {
                return Err("oracle run-root file bytes exceeded");
            }
            if total_bytes > ORACLE_SCAN_MAX_TOTAL_BYTES {
                return Err("oracle run-root total bytes exceeded");
            }
            overlap.extend_from_slice(&buffer[..read]);
            if overlap
                .windows(canary.len())
                .any(|window| window == canary.as_bytes())
            {
                return Err("oracle run-root canary detected");
            }
            let keep = overlap.len().min(canary.len() - 1);
            overlap.drain(..overlap.len() - keep);
        }
    }
    Ok(())
}

fn assert_no_canary_in_run_root(root: &Path, canary: &str) {
    scan_run_root(root, canary).expect("bounded run-root scan");
}
