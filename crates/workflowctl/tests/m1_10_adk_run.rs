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

#[path = "support/owned_tree.rs"]
mod owned_tree;

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
model = { role = "worker", id = "worker", version = "1" }
tools = [{ id = "echo", version = "1" }]
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

struct TempRoot {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl TempRoot {
    fn new(label: &str) -> Self {
        use std::os::unix::fs::MetadataExt;

        let path = std::env::temp_dir().join(format!(
            "workflowctl-m1-10-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("test root must be unique");
        let metadata = fs::symlink_metadata(&path).expect("test root metadata");
        Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn cleanup(&self) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;

        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("test root cleanup metadata failed"),
        };
        if !metadata.file_type().is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err("test root cleanup identity mismatch");
        }
        owned_tree::remove_dir_all(&self.path).map_err(|_| "test root cleanup failed")
    }
}

impl std::ops::Deref for TempRoot {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn temp_root(label: &str) -> TempRoot {
    TempRoot::new(label)
}

fn write_fixture(root: &Path, profile: Value) -> (PathBuf, PathBuf, PathBuf) {
    let workflow = root.join("workflow.toml");
    let profile_path = root.join("profile.json");
    let runs = root.join("runs");
    let model = &profile["model"];
    let mut binding = format!(
        "kind = \"agent\"\nmodel = {{ role = \"worker\", id = {:?}, version = {:?} }}",
        model["name"].as_str().unwrap_or("worker"),
        model["version"].as_str().unwrap_or("1")
    );
    if let Some(tool) = profile.get("tool").and_then(|tool| tool["name"].as_str()) {
        binding.push_str(&format!(
            "\ntools = [{{ id = {:?}, version = \"1\" }}]",
            tool
        ));
    }
    fs::write(
        &workflow,
        WORKFLOW.replacen("kind = \"agent\"", &binding, 1),
    )
    .expect("workflow fixture must write");
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
            "responses": [
                {"calls":[{"id":"call-echo","name":"echo","args":{}}]},
                "{\"status\":\"finished\",\"output\":\"model-ok\"}"
            ]
        },
        "tool": {
            "name": "echo",
            "result": {"echo": "tool-ok"},
            "input_schema": {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"additionalProperties":false},
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

fn sole_run_root(runs: &Path) -> Result<PathBuf, &'static str> {
    let mut roots = fs::read_dir(runs).map_err(|_| "oracle run base read failed")?;
    let root = roots
        .next()
        .transpose()
        .map_err(|_| "oracle run entry read failed")?
        .ok_or("oracle run root missing")?
        .path();
    if roots
        .next()
        .transpose()
        .map_err(|_| "oracle run entry read failed")?
        .is_some()
    {
        return Err("oracle run root count rejected");
    }
    Ok(root)
}

fn run_root(runs: &Path) -> PathBuf {
    sole_run_root(runs).expect("one invocation must allocate one run root")
}

#[derive(Debug)]
struct RequestObservation {
    method: String,
    path: String,
    authorization_headers: usize,
    authorization_canary_occurrences: usize,
    request_canary_occurrences: usize,
}

const ORACLE_TIMEOUT: Duration = Duration::from_secs(5);
const ORACLE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const ORACLE_SOCKET_TIMEOUT: Duration = Duration::from_millis(100);
const ORACLE_TERMINAL_QUIET_WINDOW: Duration = Duration::from_millis(25);
const ORACLE_MAX_REQUEST_BYTES: usize = 64 * 1024;
const ORACLE_MAX_CHILD_OUTPUT_BYTES: usize = 64 * 1024;

fn oracle_remaining_duration(
    deadline: Instant,
    now: Instant,
    maximum: Duration,
    timeout: &'static str,
) -> Result<Duration, &'static str> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(maximum))
        .ok_or(timeout)
}

#[derive(Clone, Copy)]
struct ScanLimits {
    depth: usize,
    entries: usize,
    files: usize,
    file_bytes: usize,
    total_bytes: usize,
    chunk_bytes: usize,
    canary_bytes: usize,
}

const ORACLE_SCAN_LIMITS: ScanLimits = ScanLimits {
    depth: 8,
    entries: 512,
    files: 256,
    file_bytes: 1024 * 1024,
    total_bytes: 8 * 1024 * 1024,
    chunk_bytes: 8192,
    canary_bytes: 256,
};

fn read_model_request(
    socket: &mut std::net::TcpStream,
    deadline: Instant,
    canary: &str,
) -> Result<RequestObservation, &'static str> {
    if canary.is_empty() {
        return Err("oracle request canary length rejected");
    }
    let mut request = Vec::new();
    let mut buffer = [0_u8; 8192];
    let header_end = loop {
        socket
            .set_read_timeout(Some(oracle_remaining_duration(
                deadline,
                Instant::now(),
                ORACLE_SOCKET_TIMEOUT,
                "oracle request headers timed out",
            )?))
            .map_err(|_| "oracle socket read timeout setup failed")?;
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
        if Instant::now() >= deadline {
            return Err("oracle request headers timed out");
        }
        if request.len().saturating_add(bytes) > ORACLE_MAX_REQUEST_BYTES {
            return Err("oracle request headers exceeded size limit");
        }
        request.extend_from_slice(&buffer[..bytes]);
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };

    let mut lines = request[..header_end].split(|byte| *byte == b'\n');
    let request_line = lines
        .next()
        .and_then(|line| line.strip_suffix(b"\r"))
        .ok_or("oracle request line rejected")?;
    if request_line != b"POST /v1/chat/completions HTTP/1.1" {
        return Err("oracle request line rejected");
    }

    let mut content_length = None;
    let mut authorization_headers = 0;
    let mut authorization_canary_occurrences = 0;
    for line in lines {
        let line = line
            .strip_suffix(b"\r")
            .ok_or("oracle request header rejected")?;
        if line.is_empty() {
            break;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or("oracle request header rejected")?;
        let name = &line[..colon];
        if name.is_empty()
            || !name.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return Err("oracle request header rejected");
        }
        let mut value = &line[colon + 1..];
        while value
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            value = &value[1..];
        }
        while value
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            value = &value[..value.len() - 1];
        }
        if !value
            .iter()
            .all(|byte| matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff))
        {
            return Err("oracle request header value rejected");
        }
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err("oracle request transfer encoding rejected");
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err("oracle request content length duplicated");
            }
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err("oracle request content length invalid");
            }
            let length = value.iter().try_fold(0_usize, |length, digit| {
                length
                    .checked_mul(10)?
                    .checked_add(usize::from(*digit - b'0'))
            });
            content_length = Some(length.ok_or("oracle request content length invalid")?);
        }
        if name.eq_ignore_ascii_case(b"authorization") {
            authorization_headers += 1;
            authorization_canary_occurrences += value
                .windows(canary.len())
                .filter(|window| *window == canary.as_bytes())
                .count();
        }
    }
    let content_length = content_length.ok_or("oracle request content length missing")?;
    if content_length > ORACLE_MAX_REQUEST_BYTES.saturating_sub(header_end) {
        return Err("oracle request body exceeded size limit");
    }
    let request_end = header_end + content_length;
    while request.len() < request_end {
        socket
            .set_read_timeout(Some(oracle_remaining_duration(
                deadline,
                Instant::now(),
                ORACLE_SOCKET_TIMEOUT,
                "oracle request body timed out",
            )?))
            .map_err(|_| "oracle socket read timeout setup failed")?;
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
        if Instant::now() >= deadline {
            return Err("oracle request body timed out");
        }
        if request.len().saturating_add(bytes) > ORACLE_MAX_REQUEST_BYTES {
            return Err("oracle request exceeded size limit");
        }
        request.extend_from_slice(&buffer[..bytes]);
    }
    if request.len() != request_end {
        return Err("oracle request trailing bytes rejected");
    }

    let request_canary_occurrences = request
        .windows(canary.len())
        .filter(|window| *window == canary.as_bytes())
        .count();
    Ok(RequestObservation {
        method: "POST".to_owned(),
        path: "/v1/chat/completions".to_owned(),
        authorization_headers,
        authorization_canary_occurrences,
        request_canary_occurrences,
    })
}

fn serve_oracle_request_until_child_done(
    listener: std::net::TcpListener,
    canary: &'static str,
    child_done: mpsc::Receiver<()>,
    terminal_probe: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
    deadline: Instant,
) -> Result<RequestObservation, &'static str> {
    listener
        .set_nonblocking(true)
        .map_err(|_| "oracle listener setup failed")?;
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
    let observation = read_model_request(&mut socket, deadline, canary)?;
    let body = r#"{"choices":[{"message":{"role":"assistant","content":"{\"status\":\"finished\",\"output\":\"oracle-ok\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    socket
        .set_write_timeout(Some(oracle_remaining_duration(
            deadline,
            Instant::now(),
            ORACLE_SOCKET_TIMEOUT,
            "oracle response write timed out",
        )?))
        .map_err(|_| "oracle socket write timeout setup failed")?;
    socket
        .write_all(response.as_bytes())
        .map_err(|_| "oracle response write failed")?;
    if Instant::now() >= deadline {
        return Err("oracle response write timed out");
    }
    socket
        .set_nonblocking(true)
        .map_err(|_| "oracle socket nonblocking setup failed")?;

    let mut quiet_deadline = None;
    loop {
        let child_complete = if quiet_deadline.is_none() {
            match child_done.try_recv() {
                Ok(()) => true,
                Err(mpsc::TryRecvError::Empty) => false,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("oracle child completion unavailable");
                }
            }
        } else {
            false
        };
        match listener.accept() {
            Ok(_) => return Err("oracle request count rejected"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("oracle listener accept failed"),
        }
        let mut trailing = [0_u8; 1];
        match socket.read(&mut trailing) {
            Ok(0) => {}
            Ok(_) => return Err("oracle request trailing bytes rejected"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("oracle request trailing read failed"),
        }
        if child_complete {
            if let Some((observed, release)) = &terminal_probe {
                observed
                    .send(())
                    .map_err(|_| "oracle terminal probe unavailable")?;
                release
                    .recv_timeout(oracle_remaining_duration(
                        deadline,
                        Instant::now(),
                        ORACLE_TIMEOUT,
                        "oracle terminal probe timed out",
                    )?)
                    .map_err(|_| "oracle terminal probe timed out")?;
            }
            let now = Instant::now();
            quiet_deadline = now
                .checked_add(ORACLE_TERMINAL_QUIET_WINDOW)
                .filter(|quiet_deadline| *quiet_deadline <= deadline);
            if quiet_deadline.is_none() {
                return Err("oracle child completion timed out");
            }
        }
        let now = Instant::now();
        if quiet_deadline.is_some_and(|quiet_deadline| now >= quiet_deadline) {
            return Ok(observation);
        }
        if now >= deadline {
            return Err("oracle child completion timed out");
        }
        thread::yield_now();
    }
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

fn diagnostics_after_cleanup(
    mut diagnostics: Vec<&'static str>,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Vec<&'static str> {
    append_output_errors(&mut diagnostics, stdout_path, stderr_path);
    diagnostics
}

fn clean_up_child(mut child: Child) -> Vec<&'static str> {
    let mut diagnostics = Vec::new();
    if child.kill().is_err() {
        diagnostics.push("oracle child kill failed");
    }
    if std::env::var_os(UNPROVEN_REAP_FIXTURE_ENV).is_some() {
        abort_unproven_reap();
    }
    let cleanup_deadline = Instant::now() + ORACLE_CLEANUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                diagnostics.push("oracle child reaped after kill");
                return diagnostics;
            }
            Ok(None) => {}
            Err(_) => {
                if !diagnostics.contains(&"oracle child reap check failed") {
                    diagnostics.push("oracle child reap check failed");
                }
            }
        }
        let now = Instant::now();
        if now >= cleanup_deadline {
            abort_unproven_reap();
        }
        thread::sleep(
            cleanup_deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(10)),
        );
    }
}

fn abort_unproven_reap() -> ! {
    let _ = writeln!(
        std::io::stderr().lock(),
        "oracle child terminal reap not proven; aborting"
    );
    std::process::abort();
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
                let diagnostics =
                    diagnostics_after_cleanup(clean_up_child(child), stdout_path, stderr_path);
                return Err(format!(
                    "oracle child timed out; {}",
                    diagnostics.join("; ")
                ));
            }
            Err(_) => {
                let diagnostics =
                    diagnostics_after_cleanup(clean_up_child(child), stdout_path, stderr_path);
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

fn run_oracle_operation(
    root: &Path,
    label: &str,
    args: &[&str],
    credential: (&str, Option<&str>),
    deadline: Instant,
) -> Result<Output, String> {
    let stdout_path = root.join(format!("workflowctl-{label}.stdout"));
    let stderr_path = root.join(format!("workflowctl-{label}.stderr"));
    let mut command = binary();
    command.args(args);
    if let Some(value) = credential.1 {
        command.env(credential.0, value);
    } else {
        command.env_remove(credential.0);
    }
    let child = command
        .stdout(Stdio::from(
            fs::File::create(&stdout_path).map_err(|_| "oracle child stdout create failed")?,
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).map_err(|_| "oracle child stderr create failed")?,
        ))
        .spawn()
        .map_err(|_| "oracle child spawn failed")?;
    wait_bounded_child(child, &stdout_path, &stderr_path, deadline)
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

#[test]
fn oracle_request_reader_counts_canary_across_complete_request() {
    const CANARY: &str = "synthetic-credential-canary-m3-01-7f3c";
    let requests = [
        (
            "duplicate-header",
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer {CANARY}\r\nx-extra: {CANARY}\r\ncontent-length: 0\r\n\r\n"
            ),
        ),
        (
            "duplicate-body",
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer {CANARY}\r\ncontent-length: {}\r\n\r\n{CANARY}",
                CANARY.len()
            ),
        ),
    ];

    for (name, request) in requests {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
        let address = listener.local_addr().expect("oracle listener address");
        let mut client = std::net::TcpStream::connect(address).expect("oracle client");
        client
            .write_all(request.as_bytes())
            .expect("oracle request write");
        let (mut socket, _) = listener.accept().expect("oracle request");
        socket
            .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
            .expect("oracle socket read timeout");
        let observation = read_model_request(&mut socket, Instant::now() + ORACLE_TIMEOUT, CANARY)
            .expect("oracle request observation");
        assert_eq!(observation.authorization_headers, 1, "{name}");
        assert_eq!(observation.authorization_canary_occurrences, 1, "{name}");
        assert_eq!(observation.request_canary_occurrences, 2, "{name}");
    }
}

#[test]
fn oracle_request_reader_rejects_ambiguous_http_framing() {
    const CANARY: &str = "synthetic-credential-canary-m3-01-7f3c";
    let requests = [
        (
            "request-line-extra-token",
            "POST /v1/chat/completions HTTP/1.1 extra\r\ncontent-length: 0\r\n\r\n".to_owned(),
            "oracle request line rejected",
        ),
        (
            "request-line-version",
            "POST /v1/chat/completions HTTP/2\r\ncontent-length: 0\r\n\r\n".to_owned(),
            "oracle request line rejected",
        ),
        (
            "duplicate-content-length",
            "POST /v1/chat/completions HTTP/1.1\r\ncontent-length: 0\r\ncontent-length: 0\r\n\r\n".to_owned(),
            "oracle request content length duplicated",
        ),
        (
            "conflicting-content-length",
            "POST /v1/chat/completions HTTP/1.1\r\ncontent-length: 0\r\ncontent-length: 1\r\n\r\nx".to_owned(),
            "oracle request content length duplicated",
        ),
        (
            "malformed-content-length",
            "POST /v1/chat/completions HTTP/1.1\r\ncontent-length: nope\r\n\r\n".to_owned(),
            "oracle request content length invalid",
        ),
        (
            "overflow-content-length",
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\ncontent-length: {}0\r\n\r\n",
                usize::MAX
            ),
            "oracle request content length invalid",
        ),
        (
            "transfer-encoding-with-content-length",
            "POST /v1/chat/completions HTTP/1.1\r\ntransfer-encoding: chunked\r\ncontent-length: 0\r\n\r\n".to_owned(),
            "oracle request transfer encoding rejected",
        ),
        (
            "transfer-encoding-only",
            "POST /v1/chat/completions HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n".to_owned(),
            "oracle request transfer encoding rejected",
        ),
        (
            "missing-framing",
            "POST /v1/chat/completions HTTP/1.1\r\nhost: localhost\r\n\r\n".to_owned(),
            "oracle request content length missing",
        ),
        (
            "trailing-byte",
            "POST /v1/chat/completions HTTP/1.1\r\ncontent-length: 0\r\n\r\nx".to_owned(),
            "oracle request trailing bytes rejected",
        ),
        (
            "pipelined-request",
            "POST /v1/chat/completions HTTP/1.1\r\ncontent-length: 0\r\n\r\nPOST /v1/chat/completions HTTP/1.1\r\ncontent-length: 0\r\n\r\n".to_owned(),
            "oracle request trailing bytes rejected",
        ),
    ];

    for (name, request, expected) in requests {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
        let address = listener.local_addr().expect("oracle listener address");
        let mut client = std::net::TcpStream::connect(address).expect("oracle client");
        client
            .write_all(request.as_bytes())
            .expect("oracle request write");
        let (mut socket, _) = listener.accept().expect("oracle request");
        socket
            .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
            .expect("oracle socket read timeout");
        assert!(
            matches!(
                read_model_request(&mut socket, Instant::now() + ORACLE_TIMEOUT, CANARY),
                Err(error) if error == expected
            ),
            "{name}: unexpected request parser result"
        );
    }
}

#[test]
fn oracle_request_reader_enforces_header_syntax_and_ows() {
    const CANARY: &str = "synthetic-credential-canary-m3-01-7f3c";
    let cases = [
        (
            "content-length-space-before-colon",
            b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length : 1\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header rejected",
        ),
        (
            "transfer-encoding-tab-before-colon",
            b"POST /v1/chat/completions HTTP/1.1\r\ntransfer-encoding\t: chunked\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header rejected",
        ),
        (
            "space-obs-fold",
            b"POST /v1/chat/completions HTTP/1.1\r\n folded: value\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header rejected",
        ),
        (
            "tab-obs-fold",
            b"POST /v1/chat/completions HTTP/1.1\r\n\tfolded: value\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header rejected",
        ),
        (
            "empty-field-name",
            b"POST /v1/chat/completions HTTP/1.1\r\n: value\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header rejected",
        ),
        (
            "separator-in-field-name",
            b"POST /v1/chat/completions HTTP/1.1\r\nx/name: value\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header rejected",
        ),
        (
            "control-in-field-name",
            b"POST /v1/chat/completions HTTP/1.1\r\nx\x01name: value\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header rejected",
        ),
        (
            "control-in-ordinary-field-value",
            b"POST /v1/chat/completions HTTP/1.1\r\nx-test: value\x01\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header value rejected",
        ),
        (
            "control-in-authorization-field-value",
            b"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer synthetic-credential-canary-m3-01-7f3c\x7f\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request header value rejected",
        ),
        (
            "vertical-tab-around-length",
            b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length:\x0b0\x0b\r\n\r\n".as_slice(),
            "oracle request header value rejected",
        ),
        (
            "form-feed-around-length",
            b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length:\x0c0\x0c\r\n\r\n".as_slice(),
            "oracle request header value rejected",
        ),
        (
            "carriage-return-around-length",
            b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length: \r0\r\n\r\n".as_slice(),
            "oracle request header value rejected",
        ),
        (
            "mixed-case-transfer-encoding",
            b"POST /v1/chat/completions HTTP/1.1\r\nTrAnSfEr-EnCoDiNg: chunked\r\ncontent-length: 0\r\n\r\n".as_slice(),
            "oracle request transfer encoding rejected",
        ),
    ];

    for (name, request, expected) in cases {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
        let address = listener.local_addr().expect("oracle listener address");
        let mut client = std::net::TcpStream::connect(address).expect("oracle client");
        client.write_all(request).expect("oracle request write");
        let (mut socket, _) = listener.accept().expect("oracle request");
        socket
            .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
            .expect("oracle socket read timeout");
        assert!(
            matches!(
                read_model_request(&mut socket, Instant::now() + ORACLE_TIMEOUT, CANARY),
                Err(error) if error == expected
            ),
            "{name}: unexpected static diagnostic"
        );
    }

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let mut client = std::net::TcpStream::connect(address).expect("oracle client");
    client
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nx!#$%&'*+-.^_`|~: value:with:colons\r\nCoNtEnT-LeNgTh:\t 0 \t\r\n\r\n",
        )
        .expect("oracle request write");
    let (mut socket, _) = listener.accept().expect("oracle request");
    socket
        .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
        .expect("oracle socket read timeout");
    assert!(
        read_model_request(&mut socket, Instant::now() + ORACLE_TIMEOUT, CANARY).is_ok(),
        "legal tchar names, value colons, case folding, and SP/HTAB OWS must remain valid"
    );
}

#[test]
fn oracle_server_rejects_second_physical_request() {
    const CANARY: &str = "synthetic-credential-canary-m3-01-7f3c";
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let mut clients = Vec::new();
    for _ in 0..2 {
        let mut client = std::net::TcpStream::connect(address).expect("oracle client");
        write!(
            client,
            "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer {CANARY}\r\ncontent-length: 0\r\n\r\n"
        )
        .expect("oracle request write");
        clients.push(client);
    }
    let (_child_done_tx, child_done_rx) = mpsc::sync_channel(1);

    assert!(matches!(
        serve_oracle_request_until_child_done(
            listener,
            CANARY,
            child_done_rx,
            None,
            Instant::now() + ORACLE_TIMEOUT,
        ),
        Err("oracle request count rejected")
    ));
}

#[test]
fn oracle_server_enforces_terminal_quiescence_and_cardinality_edges() {
    const CANARY: &str = "synthetic-credential-canary-m3-01-7f3c";

    fn connect_and_read_response(
        address: std::net::SocketAddr,
        canary: &str,
    ) -> std::net::TcpStream {
        let mut client = std::net::TcpStream::connect(address).expect("oracle client");
        client
            .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
            .expect("oracle client read timeout");
        write!(
            client,
            "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer {canary}\r\ncontent-length: 0\r\n\r\n"
        )
        .expect("oracle request write");
        let deadline = Instant::now() + ORACLE_TIMEOUT;
        let mut response = Vec::new();
        let mut chunk = [0_u8; 512];
        while !response
            .windows(b"oracle-ok".len())
            .any(|window| window == b"oracle-ok")
        {
            match client.read(&mut chunk) {
                Ok(0) => panic!("oracle response ended early"),
                Ok(read) => response.extend_from_slice(&chunk[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => panic!("oracle response read failed"),
            }
            assert!(Instant::now() < deadline, "oracle response timed out");
        }
        client
    }

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let (child_done_tx, child_done_rx) = mpsc::sync_channel(1);
    let deadline = Instant::now() + ORACLE_TIMEOUT;
    let server = thread::spawn(move || {
        serve_oracle_request_until_child_done(listener, CANARY, child_done_rx, None, deadline)
    });
    let mut client = connect_and_read_response(address, CANARY);
    client.write_all(b"x").expect("delayed same-stream byte");
    child_done_tx.send(()).expect("child completion signal");
    assert!(matches!(
        server.join().expect("oracle server thread"),
        Err("oracle request trailing bytes rejected")
    ));

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let (child_done_tx, child_done_rx) = mpsc::sync_channel(1);
    let (observed_tx, observed_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let deadline = Instant::now() + ORACLE_TIMEOUT;
    let server = thread::spawn(move || {
        serve_oracle_request_until_child_done(
            listener,
            CANARY,
            child_done_rx,
            Some((observed_tx, release_rx)),
            deadline,
        )
    });
    let mut client = connect_and_read_response(address, CANARY);
    child_done_tx.send(()).expect("child completion signal");
    let barrier_result = oracle_remaining_duration(
        deadline,
        Instant::now(),
        ORACLE_TIMEOUT,
        "oracle terminal probe timed out",
    )
    .and_then(|remaining| {
        observed_rx
            .recv_timeout(remaining)
            .map_err(|_| "oracle terminal probe timed out")
    });
    let terminal_probe_result = barrier_result.and_then(|()| {
        client
            .write_all(b"x")
            .map_err(|_| "terminal-race write failed")?;
        release_tx
            .send(())
            .map_err(|_| "terminal probe release failed")
    });
    drop(release_tx);
    let server_result = server.join().expect("oracle server thread");
    assert!(
        terminal_probe_result.is_ok(),
        "terminal observation barrier must use the overall remaining deadline"
    );
    assert!(matches!(
        server_result,
        Err("oracle request trailing bytes rejected")
    ));

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let mut client = std::net::TcpStream::connect(address).expect("oracle client");
    client
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length: 0\r\n\r\n")
        .expect("oracle request write");
    let (mut socket, _) = listener.accept().expect("oracle request");
    socket
        .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
        .expect("oracle socket read timeout");
    assert!(matches!(
        read_model_request(&mut socket, Instant::now() + ORACLE_TIMEOUT, ""),
        Err("oracle request canary length rejected")
    ));

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("oracle listener");
    let address = listener.local_addr().expect("oracle listener address");
    let mut client = std::net::TcpStream::connect(address).expect("oracle client");
    client
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer aaaa\r\ncontent-length: 0\r\n\r\n")
        .expect("oracle request write");
    let (mut socket, _) = listener.accept().expect("oracle request");
    socket
        .set_read_timeout(Some(ORACLE_SOCKET_TIMEOUT))
        .expect("oracle socket read timeout");
    let observation = read_model_request(&mut socket, Instant::now() + ORACLE_TIMEOUT, "aaa")
        .expect("overlapping canary observation");
    assert_eq!(observation.authorization_canary_occurrences, 2);
    assert_eq!(observation.request_canary_occurrences, 2);
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

const UNPROVEN_REAP_FIXTURE_ENV: &str = "WORKFLOWCTL_ORACLE_UNPROVEN_REAP_FIXTURE";
const UNPROVEN_REAP_ROOT_ENV: &str = "WORKFLOWCTL_ORACLE_UNPROVEN_REAP_ROOT";

#[test]
fn oracle_unproven_reap_abort_fixture() {
    if std::env::var_os(UNPROVEN_REAP_FIXTURE_ENV).is_none() {
        return;
    }
    let root = temp_root("oracle-unproven-reap-fixture");
    fs::write(root.join("sentinel"), b"survives-abort").expect("abort sentinel");
    fs::write(
        std::env::var_os(UNPROVEN_REAP_ROOT_ENV).expect("abort root receipt path"),
        root.as_os_str().as_encoded_bytes(),
    )
    .expect("abort root receipt");
    let stdout_path = root.join("stdout");
    let stderr_path = root.join("stderr");
    let child = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "oracle_supervisor_fixture_blocks", "--nocapture"])
        .env(SUPERVISOR_FIXTURE_ENV, "1")
        .env_remove(UNPROVEN_REAP_FIXTURE_ENV)
        .stdout(Stdio::from(
            fs::File::create(&stdout_path).expect("abort fixture stdout"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).expect("abort fixture stderr"),
        ))
        .spawn()
        .expect("abort fixture owned child");
    let _ = wait_bounded_child(child, &stdout_path, &stderr_path, Instant::now());
}

#[test]
fn oracle_unproven_reap_aborts_without_root_cleanup() {
    let receipt_root = temp_root("oracle-unproven-reap-parent");
    let receipt_path = receipt_root.join("root-path");
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "oracle_unproven_reap_abort_fixture",
            "--nocapture",
        ])
        .env(UNPROVEN_REAP_FIXTURE_ENV, "1")
        .env(UNPROVEN_REAP_ROOT_ENV, &receipt_path)
        .output()
        .expect("abort fixture child");
    let fixture_root = PathBuf::from(
        std::str::from_utf8(&fs::read(&receipt_path).expect("abort root receipt"))
            .expect("UTF-8 abort root"),
    );
    let sentinel_survived = fixture_root.join("sentinel").is_file();
    let _ = owned_tree::remove_dir_all(&fixture_root);

    assert!(!output.status.success(), "unproven reap must abort");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("oracle child terminal reap not proven; aborting")
    );
    assert!(sentinel_survived, "abort must not unwind root cleanup");
}

#[test]
fn oracle_remaining_duration_rejects_expiry_and_clamps_socket_io() {
    let now = Instant::now();
    assert!(matches!(
        oracle_remaining_duration(
            now,
            now,
            ORACLE_SOCKET_TIMEOUT,
            "oracle request headers timed out",
        ),
        Err("oracle request headers timed out")
    ));
    assert_eq!(
        oracle_remaining_duration(
            now + Duration::from_millis(50),
            now,
            ORACLE_SOCKET_TIMEOUT,
            "oracle request headers timed out",
        ),
        Ok(Duration::from_millis(50))
    );
    assert_eq!(
        oracle_remaining_duration(
            now + ORACLE_TIMEOUT,
            now,
            ORACLE_SOCKET_TIMEOUT,
            "oracle request headers timed out",
        ),
        Ok(ORACLE_SOCKET_TIMEOUT)
    );
}

#[test]
fn temp_root_cleanup_refuses_replacement_directory() {
    let root = temp_root("replacement-cleanup");
    let original = root.to_path_buf();
    let owned = original.with_extension("owned");
    fs::rename(&original, &owned).expect("move owned root");
    fs::create_dir(&original).expect("create substitute root");
    fs::write(original.join("sentinel"), b"substitute").expect("substitute sentinel");
    let cleanup_result = root.cleanup();
    drop(root);
    let substitute_survived = original.join("sentinel").is_file();
    let _ = owned_tree::remove_dir_all(&original);
    let _ = owned_tree::remove_dir_all(&owned);
    assert!(matches!(
        cleanup_result,
        Err("test root cleanup identity mismatch")
    ));
    assert!(
        substitute_survived,
        "cleanup must refuse a replacement directory"
    );
}

#[test]
fn temp_root_cleanup_result_is_observable() {
    let root = temp_root("observable-cleanup");
    let path = root.to_path_buf();
    assert_eq!(root.cleanup(), Ok(()));
    assert!(!path.exists());
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
    let error = wait_bounded_child(
        child,
        &stdout_path,
        &stderr_path,
        Instant::now() + Duration::from_millis(100),
    )
    .expect_err("fixture child must time out");
    assert!(error.starts_with("oracle child timed out"));
    assert!(error.contains("oracle child reaped after kill"));
    assert!(error.contains("oracle child output exceeded size limit"));
    assert!(!error.contains("reaper"));
    assert!(!error.contains("handoff"));
}

#[test]
fn oracle_output_diagnostics_require_proven_reap() {
    let root = temp_root("oracle-output-diagnostics");
    let stdout_path = root.join("stdout");
    let stderr_path = root.join("stderr");
    fs::write(&stdout_path, vec![b'x'; ORACLE_MAX_CHILD_OUTPUT_BYTES + 1])
        .expect("proven stdout fixture");
    fs::write(&stderr_path, []).expect("proven stderr fixture");
    let proven = diagnostics_after_cleanup(
        vec!["oracle child reaped after kill"],
        &stdout_path,
        &stderr_path,
    );
    assert!(proven.contains(&"oracle child output exceeded size limit"));
}

#[test]
fn oracle_run_root_scan_enforces_tiny_boundary_matrix() {
    enum Fixture {
        Empty,
        Files(&'static [usize]),
        Depth(usize),
        RootSymlink,
        DescendantSymlink,
        Special,
        Bytes(&'static [u8]),
    }

    const TINY: ScanLimits = ScanLimits {
        depth: 4,
        entries: 8,
        files: 8,
        file_bytes: 8,
        total_bytes: 16,
        chunk_bytes: 4,
        canary_bytes: 4,
    };
    let cases = [
        (
            "depth-exact",
            Fixture::Depth(2),
            ScanLimits { depth: 2, ..TINY },
            "safe",
            Ok(()),
        ),
        (
            "depth-plus-one",
            Fixture::Depth(3),
            ScanLimits { depth: 2, ..TINY },
            "safe",
            Err("oracle run-root depth exceeded"),
        ),
        (
            "entries-exact",
            Fixture::Files(&[0, 0]),
            ScanLimits { entries: 2, ..TINY },
            "safe",
            Ok(()),
        ),
        (
            "entries-plus-one",
            Fixture::Files(&[0, 0, 0]),
            ScanLimits { entries: 2, ..TINY },
            "safe",
            Err("oracle run-root entry count exceeded"),
        ),
        (
            "files-exact",
            Fixture::Files(&[0, 0]),
            ScanLimits { files: 2, ..TINY },
            "safe",
            Ok(()),
        ),
        (
            "files-plus-one",
            Fixture::Files(&[0, 0, 0]),
            ScanLimits { files: 2, ..TINY },
            "safe",
            Err("oracle run-root file count exceeded"),
        ),
        (
            "file-bytes-exact",
            Fixture::Files(&[4]),
            ScanLimits {
                file_bytes: 4,
                ..TINY
            },
            "safe",
            Ok(()),
        ),
        (
            "file-bytes-plus-one",
            Fixture::Files(&[5]),
            ScanLimits {
                file_bytes: 4,
                ..TINY
            },
            "safe",
            Err("oracle run-root file bytes exceeded"),
        ),
        (
            "total-bytes-exact",
            Fixture::Files(&[3, 3]),
            ScanLimits {
                total_bytes: 6,
                ..TINY
            },
            "safe",
            Ok(()),
        ),
        (
            "total-bytes-plus-one",
            Fixture::Files(&[3, 4]),
            ScanLimits {
                total_bytes: 6,
                ..TINY
            },
            "safe",
            Err("oracle run-root total bytes exceeded"),
        ),
        ("canary-exact", Fixture::Empty, TINY, "safe", Ok(())),
        (
            "canary-plus-one",
            Fixture::Empty,
            TINY,
            "safex",
            Err("oracle run-root canary length rejected"),
        ),
        (
            "canary-empty",
            Fixture::Empty,
            TINY,
            "",
            Err("oracle run-root canary length rejected"),
        ),
        (
            "root-symlink",
            Fixture::RootSymlink,
            TINY,
            "safe",
            Err("oracle run-root symlink rejected"),
        ),
        (
            "descendant-symlink",
            Fixture::DescendantSymlink,
            TINY,
            "safe",
            Err("oracle run-root symlink rejected"),
        ),
        (
            "special-file",
            Fixture::Special,
            TINY,
            "safe",
            Err("oracle run-root special file rejected"),
        ),
        (
            "cross-chunk-canary",
            Fixture::Bytes(b"xxxsafe"),
            TINY,
            "safe",
            Err("oracle run-root canary detected"),
        ),
    ];

    for (name, fixture, limits, canary, expected) in cases {
        let root = temp_root(name);
        let mut scan_root = root.to_path_buf();
        let mut socket = None;
        match fixture {
            Fixture::Empty => {}
            Fixture::Files(sizes) => {
                for (index, size) in sizes.iter().enumerate() {
                    fs::write(root.join(format!("file-{index}")), vec![b'x'; *size])
                        .expect("file fixture");
                }
            }
            Fixture::Depth(depth) => {
                let mut directory = root.to_path_buf();
                for index in 0..depth {
                    directory = directory.join(format!("depth-{index}"));
                    fs::create_dir(&directory).expect("depth fixture");
                }
            }
            Fixture::RootSymlink => {
                fs::create_dir(root.join("target")).expect("symlink target");
                scan_root = root.join("link");
                std::os::unix::fs::symlink(root.join("target"), &scan_root)
                    .expect("root symlink fixture");
            }
            Fixture::DescendantSymlink => {
                std::os::unix::fs::symlink(root.join("missing"), root.join("link"))
                    .expect("descendant symlink fixture");
            }
            Fixture::Special => {
                socket = Some(
                    std::os::unix::net::UnixListener::bind(root.join("socket"))
                        .expect("socket fixture"),
                );
            }
            Fixture::Bytes(bytes) => fs::write(root.join("bytes"), bytes).expect("byte fixture"),
        }
        assert_eq!(
            scan_run_root_with_limits(&scan_root, canary, limits),
            expected,
            "{name}"
        );
        drop(socket);
    }

    let mut exact = usize::MAX - 1;
    assert!(!scan_bytes_exceeded(&mut exact, 1, usize::MAX));
    assert_eq!(exact, usize::MAX);
    let mut saturated = usize::MAX - 1;
    assert!(scan_bytes_exceeded(&mut saturated, 2, usize::MAX - 1));
    assert_eq!(saturated, usize::MAX);
}

#[test]
fn oracle_run_root_admission_is_bounded_before_readback() {
    let runs = temp_root("run-root-admission");
    assert!(matches!(
        sole_run_root(&runs),
        Err("oracle run root missing")
    ));

    let only = runs.join("only");
    fs::create_dir(&only).expect("sole run root fixture");
    assert_eq!(sole_run_root(&runs).expect("sole run root"), only);

    fs::create_dir(runs.join("extra")).expect("extra run root fixture");
    assert!(matches!(
        sole_run_root(&runs),
        Err("oracle run root count rejected")
    ));
    fs::remove_dir(runs.join("extra")).expect("remove extra run root fixture");

    fs::write(only.join("oversized"), b"12345").expect("oversized persisted fixture");
    let limits = ScanLimits {
        depth: 2,
        entries: 2,
        files: 1,
        file_bytes: 4,
        total_bytes: 8,
        chunk_bytes: 2,
        canary_bytes: 4,
    };
    assert!(matches!(
        scan_run_root_with_limits(&only, "safe", limits),
        Err("oracle run-root file bytes exceeded")
    ));
}

#[test]
fn credential_value_is_absent_from_production_run_readback_surfaces() {
    const HANDLE: &str = "WORKFLOWCTL_CREDENTIAL_ORACLE_HANDLE";
    const CANARY: &str = "synthetic-credential-canary-m3-01-7f3c";

    let root = temp_root("credential-oracle");
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
    let expected_source = fs::read(&workflow).expect("workflow fixture");
    let run_listener = listener.try_clone().expect("oracle run listener clone");
    let (child_done_tx, child_done_rx) = mpsc::sync_channel(1);
    let run_deadline = Instant::now() + ORACLE_TIMEOUT;
    let server = thread::spawn(move || {
        serve_oracle_request_until_child_done(
            run_listener,
            CANARY,
            child_done_rx,
            None,
            run_deadline,
        )
    });
    let child_result = run_oracle_operation(
        &root,
        "run",
        &[
            "--json",
            "run",
            workflow.to_str().expect("UTF-8 workflow path"),
            "--profile",
            profile.to_str().expect("UTF-8 profile path"),
            "--input",
            r#"{"request":"public"}"#,
            "--workdir",
            runs.to_str().expect("UTF-8 run base"),
        ],
        (HANDLE, Some(CANARY)),
        run_deadline,
    );
    let _ = child_done_tx.send(());
    let server_result = server.join();

    let child = match child_result {
        Ok(child) => child,
        Err(error) => {
            let server_diagnostic = match &server_result {
                Err(_) => "oracle server thread failed",
                Ok(Err(error)) => error,
                Ok(Ok(_)) => "oracle server completed",
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
    let run_receipt = json_stdout(&child);
    assert_eq!(run_receipt["status"], "succeeded");
    let observation = server_result
        .expect("oracle server thread")
        .expect("oracle request observation");
    assert_eq!(observation.method, "POST");
    assert_eq!(observation.path, "/v1/chat/completions");
    assert_eq!(observation.authorization_headers, 1);
    assert_eq!(observation.authorization_canary_occurrences, 1);
    assert_eq!(observation.request_canary_occurrences, 1);

    let run_root = sole_run_root(&runs).expect("sole oracle run root");
    assert_no_canary_in_run_root(&run_root, CANARY);
    let manifest_bytes = fs::read(run_root.join("run-manifest.json")).expect("run manifest");
    assert_no_canary_bytes(&manifest_bytes, CANARY);
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("manifest JSON");
    assert_eq!(manifest["status"], "succeeded");
    assert_eq!(manifest["profile_identity"], "worker=oracle-model:1");
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
    assert_eq!(source, expected_source);
    assert_no_canary_bytes(&source, CANARY);

    let stored_profile = fs::read(run_root.join("execution-profile.json")).expect("stored profile");
    assert_no_canary_bytes(&stored_profile, CANARY);
    let stored_profile: Value = serde_json::from_slice(&stored_profile).expect("profile JSON");
    assert_eq!(stored_profile["model"]["credential_env"], HANDLE);
    assert_ne!(stored_profile["model"]["credential_env"], CANARY);

    let run_id = manifest["run_id"].as_str().expect("run ID");
    assert_eq!(run_receipt["run_id"], run_id);
    let inspect = run_oracle_operation(
        &root,
        "inspect",
        &[
            "--json",
            "inspect",
            "--run-id",
            run_id,
            "--workdir",
            runs.to_str().expect("UTF-8 runs path"),
        ],
        (HANDLE, None),
        Instant::now() + ORACLE_TIMEOUT,
    )
    .expect("bounded oracle inspect child");
    assert!(
        inspect.status.success(),
        "oracle inspect must succeed (stdout={}, stderr={})",
        String::from_utf8_lossy(&inspect.stdout).replace(CANARY, "[REDACTED]"),
        String::from_utf8_lossy(&inspect.stderr).replace(CANARY, "[REDACTED]")
    );
    assert_no_canary_bytes(&inspect.stdout, CANARY);
    assert_no_canary_bytes(&inspect.stderr, CANARY);
    let inspected = json_stdout(&inspect);
    assert_eq!(inspected["status"], "succeeded");
    assert_eq!(inspected["run_id"], run_id);
    assert_no_canary_in_run_root(&run_root, CANARY);

    drop(listener);
    let before_missing_resume =
        bounded_run_root_snapshot(&run_root, CANARY).expect("bounded pre-resume run-root snapshot");
    let missing_resume = run_oracle_operation(
        &root,
        "resume-missing-credential",
        &[
            "--json",
            "resume",
            "--run-id",
            run_id,
            "--workdir",
            runs.to_str().expect("UTF-8 runs path"),
        ],
        (HANDLE, None),
        Instant::now() + ORACLE_TIMEOUT,
    )
    .expect("bounded missing-credential resume child");
    assert_eq!(missing_resume.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&missing_resume.stderr).contains("workflow.run.failed"),
        "missing credential must retain the static workflow failure category"
    );
    assert_no_canary_bytes(&missing_resume.stdout, CANARY);
    assert_no_canary_bytes(&missing_resume.stderr, CANARY);
    assert_no_canary_in_run_root(&run_root, CANARY);
    assert_eq!(
        bounded_run_root_snapshot(&run_root, CANARY)
            .expect("bounded post-failure run-root snapshot"),
        before_missing_resume,
        "missing-credential resume must not mutate the run root"
    );

    let resume = run_oracle_operation(
        &root,
        "resume",
        &[
            "--json",
            "resume",
            "--run-id",
            run_id,
            "--workdir",
            runs.to_str().expect("UTF-8 runs path"),
        ],
        (HANDLE, Some(CANARY)),
        Instant::now() + ORACLE_TIMEOUT,
    )
    .expect("bounded credential-backed resume child");
    assert!(
        resume.status.success(),
        "completed resume must succeed without a model request (stdout={}, stderr={})",
        String::from_utf8_lossy(&resume.stdout).replace(CANARY, "[REDACTED]"),
        String::from_utf8_lossy(&resume.stderr).replace(CANARY, "[REDACTED]")
    );
    assert_no_canary_bytes(&resume.stdout, CANARY);
    assert_no_canary_bytes(&resume.stderr, CANARY);
    let resumed = json_stdout(&resume);
    assert_eq!(resumed["status"], "succeeded");
    assert_eq!(resumed["run_id"], run_id);
    assert_no_canary_in_run_root(&run_root, CANARY);
    let resumed_events =
        fs::read(run_root.join("events.jsonl")).expect("resume events must be readable");
    assert_no_canary_bytes(&resumed_events, CANARY);
    assert!(
        std::str::from_utf8(&resumed_events)
            .expect("resume events UTF-8")
            .contains("\"kind\":\"workflow_resumed\""),
        "credential oracle must exercise completed-run resume"
    );
    assert_no_canary_in_run_root(&run_root, CANARY);

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
    root.cleanup().expect("credential oracle root cleanup");
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

fn scan_bytes_exceeded(total: &mut usize, read: usize, limit: usize) -> bool {
    *total = total.saturating_add(read);
    *total > limit
}

fn scan_run_root(root: &Path, canary: &str) -> Result<(), &'static str> {
    scan_run_root_with_limits(root, canary, ORACLE_SCAN_LIMITS)
}

fn scan_run_root_with_limits(
    root: &Path,
    canary: &str,
    limits: ScanLimits,
) -> Result<(), &'static str> {
    if canary.is_empty() || canary.len() > limits.canary_bytes {
        return Err("oracle run-root canary length rejected");
    }
    let mut pending = vec![(root.to_owned(), 0_usize)];
    let mut entries = 0_usize;
    let mut files = 0_usize;
    let mut total_bytes = 0_usize;
    let mut buffer = vec![0_u8; limits.chunk_bytes];
    while let Some((path, depth)) = pending.pop() {
        if depth > limits.depth {
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
                if entries > limits.entries {
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
        if files > limits.files {
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
            if scan_bytes_exceeded(&mut file_bytes, read, limits.file_bytes) {
                return Err("oracle run-root file bytes exceeded");
            }
            if scan_bytes_exceeded(&mut total_bytes, read, limits.total_bytes) {
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

fn bounded_run_root_snapshot(root: &Path, canary: &str) -> Result<[u8; 32], &'static str> {
    scan_run_root(root, canary)?;
    let mut pending = vec![root.to_owned()];
    let mut digest = Sha256::new();
    while let Some(path) = pending.pop() {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "oracle run-root snapshot path rejected")?;
        digest.update(relative.to_string_lossy().as_bytes());
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "oracle run-root snapshot read failed")?;
        if metadata.file_type().is_dir() {
            digest.update([0]);
            let mut children = fs::read_dir(path)
                .map_err(|_| "oracle run-root snapshot read failed")?
                .map(|entry| {
                    entry
                        .map(|entry| entry.path())
                        .map_err(|_| "oracle run-root snapshot read failed")
                })
                .collect::<Result<Vec<_>, _>>()?;
            children.sort();
            pending.extend(children.into_iter().rev());
        } else if metadata.file_type().is_file() {
            digest.update([1]);
            let bytes = fs::read(path).map_err(|_| "oracle run-root snapshot read failed")?;
            digest.update(bytes.len().to_le_bytes());
            digest.update(bytes);
        } else {
            return Err("oracle run-root snapshot type rejected");
        }
    }
    let digest = digest.finalize();
    let mut snapshot = [0_u8; 32];
    snapshot.copy_from_slice(&digest);
    Ok(snapshot)
}

fn assert_no_canary_in_run_root(root: &Path, canary: &str) {
    scan_run_root(root, canary).expect("bounded run-root scan");
}
