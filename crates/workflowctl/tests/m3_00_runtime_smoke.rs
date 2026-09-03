use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "support/owned_tree.rs"]
mod owned_tree;

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
static NON_REAPING_OBSERVATION_USED: AtomicBool = AtomicBool::new(false);

const MAX_FIXTURE_BYTES: usize = 64 * 1024;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024;
const MAX_TREE_DEPTH: usize = 4;
const MAX_TREE_ENTRIES: usize = 32;
const MAX_TREE_BYTES: usize = 256 * 1024;
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
struct TreeLimits {
    depth: usize,
    entries: usize,
    file_bytes: usize,
    total_bytes: usize,
}

const EXAMPLE_LIMITS: TreeLimits = TreeLimits {
    depth: MAX_TREE_DEPTH,
    entries: MAX_TREE_ENTRIES,
    file_bytes: MAX_FIXTURE_BYTES,
    total_bytes: MAX_TREE_BYTES,
};

struct TempRoot(PathBuf);

impl TempRoot {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = owned_tree::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
}

fn example_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/00-runtime-smoke")
}

fn repository_root() -> PathBuf {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).expect("repository root")
}

fn documented_shell_block(readme: &str) -> &str {
    assert_eq!(
        readme.matches("```bash\n").count(),
        1,
        "README must have one authoritative Bash block"
    );
    let (_, block) = readme.split_once("```bash\n").expect("README Bash block");
    block
        .split_once("\n```")
        .map(|(block, _)| block)
        .expect("README Bash block terminator")
}

fn documented_path() -> std::ffi::OsString {
    let binary = Path::new(env!("CARGO_BIN_EXE_workflowctl"));
    let mut path_entries = vec![
        binary
            .parent()
            .expect("workflowctl binary directory")
            .to_path_buf(),
    ];
    if let Some(path) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&path));
    }
    std::env::join_paths(path_entries).expect("workflowctl PATH")
}

fn executable_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn spawn_capped_reader(
    mut pipe: impl Read + Send + 'static,
    limit: usize,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut output = Vec::with_capacity(limit.min(8_192));
        let mut buffer = [0_u8; 8_192];
        loop {
            let read = pipe.read(&mut buffer)?;
            if read == 0 {
                return Ok(output);
            }
            let retained = read.min(limit.saturating_sub(output.len()));
            output.extend_from_slice(&buffer[..retained]);
            if retained != read {
                exceeded.store(true, Ordering::Release);
                return Ok(output);
            }
        }
    })
}

fn kill_process_group(process_group: u32) {
    // SAFETY: the child is spawned as leader of its own process group.
    unsafe {
        libc::kill(-(process_group as i32), libc::SIGKILL);
    }
}

fn abort_incomplete_cleanup() -> ! {
    eprintln!("bounded subprocess cleanup deadline elapsed");
    std::process::abort();
}

fn reap_after_kill(child: &mut Child, process_group: u32) -> ExitStatus {
    kill_process_group(process_group);
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if Instant::now() < deadline => thread::yield_now(),
            Ok(None) => abort_incomplete_cleanup(),
            Err(_) => abort_incomplete_cleanup(),
        }
    }
}

fn join_capped_reader(
    reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    deadline: Instant,
    panic_message: &'static str,
    read_message: &'static str,
) -> Result<Vec<u8>, &'static str> {
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            abort_incomplete_cleanup();
        }
        thread::yield_now();
    }
    reader
        .join()
        .map_err(|_| panic_message)?
        .map_err(|_| read_message)
}

fn join_capped_readers(
    stdout_reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    stderr_reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let stdout = join_capped_reader(
        stdout_reader,
        deadline,
        "subprocess stdout reader panicked",
        "subprocess stdout read failed",
    );
    let stderr = join_capped_reader(
        stderr_reader,
        deadline,
        "subprocess stderr reader panicked",
        "subprocess stderr read failed",
    );
    match (stdout, stderr) {
        (Ok(stdout), Ok(stderr)) => Ok((stdout, stderr)),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn observe_child_exit_without_reaping(
    child_pid: u32,
    deadline: Instant,
) -> Result<bool, &'static str> {
    if Instant::now() >= deadline {
        return Ok(false);
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid writable siginfo buffer and `child_pid` is the direct child.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child_pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if result != 0 {
        return Err("subprocess wait failed");
    }
    // SAFETY: waitid initialized the siginfo buffer on success.
    let exited = unsafe { info.si_pid() } == child_pid as libc::pid_t;
    if exited {
        NON_REAPING_OBSERVATION_USED.store(true, Ordering::Release);
    }
    Ok(exited)
}

// Keep the helper live for the serial historical-order mutation proof.
const _: fn(u32, Instant) -> Result<bool, &'static str> = observe_child_exit_without_reaping;

fn bounded_output(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
) -> Result<Output, &'static str> {
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| "subprocess spawn failed")?;
    let process_group = child.id();
    let stdout_pipe = match child.stdout.take() {
        Some(pipe) => pipe,
        None => {
            let _ = reap_after_kill(&mut child, process_group);
            return Err("subprocess stdout unavailable");
        }
    };
    let stderr_pipe = match child.stderr.take() {
        Some(pipe) => pipe,
        None => {
            let _ = reap_after_kill(&mut child, process_group);
            return Err("subprocess stderr unavailable");
        }
    };
    let stdout_exceeded = Arc::new(AtomicBool::new(false));
    let stderr_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_reader =
        spawn_capped_reader(stdout_pipe, output_limit, Arc::clone(&stdout_exceeded));
    let stderr_reader =
        spawn_capped_reader(stderr_pipe, output_limit, Arc::clone(&stderr_exceeded));
    let deadline = Instant::now() + timeout;
    let (status, failure) = loop {
        if stdout_exceeded.load(Ordering::Acquire) || stderr_exceeded.load(Ordering::Acquire) {
            break (
                reap_after_kill(&mut child, process_group),
                Some("subprocess output limit exceeded"),
            );
        }
        match observe_child_exit_without_reaping(child.id(), deadline) {
            Ok(true) => {
                kill_process_group(process_group);
                let status = match child.wait() {
                    Ok(status) => status,
                    Err(_) => {
                        let _ = reap_after_kill(&mut child, process_group);
                        return Err("subprocess wait failed");
                    }
                };
                break (status, None);
            }
            Ok(false) if Instant::now() >= deadline => {
                break (
                    reap_after_kill(&mut child, process_group),
                    Some("subprocess timed out"),
                );
            }
            Ok(false) => thread::yield_now(),
            Err(_) => {
                let _ = reap_after_kill(&mut child, process_group);
                return Err("subprocess wait failed");
            }
        }
    };
    let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
    let (stdout, stderr) = join_capped_readers(stdout_reader, stderr_reader, cleanup_deadline)?;
    let failure = failure.or_else(|| {
        (stdout_exceeded.load(Ordering::Acquire) || stderr_exceeded.load(Ordering::Acquire))
            .then_some("subprocess output limit exceeded")
    });
    if let Some(failure) = failure {
        return Err(failure);
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn run_documented_shell_block_with_path(
    block: &str,
    workdir: &Path,
    path: &std::ffi::OsStr,
) -> Result<Output, &'static str> {
    let mut command =
        Command::new(executable_on_path("bash").ok_or("Bash executable unavailable")?);
    command
        .args(["-c", block])
        .current_dir(repository_root())
        .env("PATH", path)
        .env("WORKDIR", workdir);
    bounded_output(&mut command, SUBPROCESS_TIMEOUT, MAX_FIXTURE_BYTES)
}

fn run_documented_shell_block(block: &str, workdir: &Path) -> Result<Output, &'static str> {
    run_documented_shell_block_with_path(block, workdir, &documented_path())
}

fn temp_root(label: &str) -> TempRoot {
    let root = std::env::temp_dir().join(format!(
        "workflowctl-m3-00-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("test root must be unique");
    TempRoot(root)
}

fn command(args: &[&str]) -> Output {
    bounded_output(binary().args(args), SUBPROCESS_TIMEOUT, MAX_FIXTURE_BYTES)
        .unwrap_or_else(|error| panic!("workflowctl failed before exit: {error}"))
}

fn read_bounded_regular(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "file metadata unavailable")?;
    if !metadata.file_type().is_file() {
        return Err("path is not a regular file");
    }
    if metadata.len() > limit as u64 {
        return Err("file exceeds size limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .map_err(|_| "file open failed")?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "file read failed")?;
    if bytes.len() > limit {
        return Err("file exceeds size limit");
    }
    Ok(bytes)
}

fn collect_regular_tree(
    root: &Path,
    limits: TreeLimits,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, &'static str> {
    fn visit(
        root: &Path,
        directory: &Path,
        depth: usize,
        limits: TreeLimits,
        entries: &mut usize,
        total_bytes: &mut usize,
        files: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<(), &'static str> {
        if depth > limits.depth {
            return Err("example tree exceeds depth limit");
        }
        for entry in fs::read_dir(directory).map_err(|_| "example directory read failed")? {
            let entry = entry.map_err(|_| "example entry read failed")?;
            *entries = entries
                .checked_add(1)
                .ok_or("example entry count overflow")?;
            if *entries > limits.entries {
                return Err("example tree exceeds entry limit");
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| "example metadata failed")?;
            if metadata.file_type().is_dir() {
                visit(root, &path, depth + 1, limits, entries, total_bytes, files)?;
            } else if metadata.file_type().is_file() {
                let file_bytes =
                    usize::try_from(metadata.len()).map_err(|_| "example file size overflow")?;
                if file_bytes > limits.file_bytes {
                    return Err("example file exceeds size limit");
                }
                *total_bytes = total_bytes
                    .checked_add(file_bytes)
                    .ok_or("example total size overflow")?;
                if *total_bytes > limits.total_bytes {
                    return Err("example tree exceeds total size limit");
                }
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "example path escaped root")?
                    .to_path_buf();
                files.insert(relative, read_bounded_regular(&path, limits.file_bytes)?);
            } else {
                return Err("example tree contains non-regular entry");
            }
        }
        Ok(())
    }

    let metadata = fs::symlink_metadata(root).map_err(|_| "example root metadata failed")?;
    if !metadata.file_type().is_dir() {
        return Err("example root is not a directory");
    }
    let mut files = BTreeMap::new();
    visit(root, root, 0, limits, &mut 0, &mut 0, &mut files)?;
    Ok(files)
}

fn require_intended_example_files(files: &BTreeMap<PathBuf, Vec<u8>>) -> Result<(), &'static str> {
    let intended = [
        "README.md",
        "expected-output.md",
        "input.example.json",
        "profiles/fake.json",
        "profiles/openai-compatible.template.json",
        "replay.json",
        "run.sh",
        "traces/scripted.json",
        "workflow.lock.toml",
        "workflow.toml",
    ];
    let actual = files
        .keys()
        .map(|path| path.to_str().ok_or("example path is not UTF-8"))
        .collect::<Result<Vec<_>, _>>()?;
    if actual != intended {
        return Err("example committed file set changed");
    }
    Ok(())
}

fn validate_committed_bytes(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.is_empty() {
        return Err("committed example file is empty");
    }
    std::str::from_utf8(bytes).map_err(|_| "committed example file is not UTF-8")?;
    if forbidden_value(bytes, &COMMITTED_FORBIDDEN).is_some() {
        return Err("committed example file contains forbidden material");
    }
    Ok(())
}

fn assert_receipt_shape(receipt: &Value) {
    for field in [
        "run_id",
        "workflow_id",
        "status",
        "artifact_id",
        "run_root",
        "plan_hash",
        "resume_identity",
    ] {
        assert!(
            receipt[field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "receipt field {field} must be non-empty"
        );
    }
    assert_eq!(receipt["status"], "succeeded");
    assert_eq!(receipt["resume_count"], 0);
    assert!(receipt["run_id"].as_str().unwrap().starts_with("run-"));
    assert_eq!(receipt["workflow_id"], "m3-00-runtime-smoke");
}

const RUNTIME_FORBIDDEN: [&str; 6] = ["/home/", "/Users/", "Bearer ", "sk-", "api_key", "password"];
const SECRET_FORBIDDEN: [&str; 4] = ["Bearer ", "sk-", "api_key", "password"];
const COMMITTED_FORBIDDEN: [&str; 9] = [
    "/home/",
    "/tmp/",
    "/Users/",
    "C:\\\\",
    "Bearer ",
    "sk-",
    "api_key",
    "password",
    "authorization",
];

fn decode_json_escapes(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'/') {
            decoded.push(b'/');
            index += 2;
        } else if bytes[index] == b'\\'
            && bytes.get(index + 1) == Some(&b'u')
            && index + 6 <= bytes.len()
        {
            let hex = std::str::from_utf8(&bytes[index + 2..index + 6]).ok();
            let value = hex.and_then(|hex| u32::from_str_radix(hex, 16).ok());
            if let Some(character) = value.and_then(char::from_u32) {
                let mut encoded = [0_u8; 4];
                decoded.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                index += 6;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    decoded
}

fn forbidden_value(bytes: &[u8], forbidden: &[&'static str]) -> Option<&'static str> {
    let decoded = decode_json_escapes(bytes);
    [bytes, decoded.as_slice()]
        .into_iter()
        .find_map(|candidate| {
            let text = String::from_utf8_lossy(candidate);
            forbidden
                .iter()
                .copied()
                .find(|value| text.contains(*value))
        })
}

fn assert_no_forbidden_bytes(bytes: &[u8]) {
    if let Some(forbidden) = forbidden_value(bytes, &RUNTIME_FORBIDDEN) {
        panic!("runtime output leaked {forbidden:?}");
    }
}

fn value_contains_forbidden(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            forbidden_value(key.as_bytes(), &RUNTIME_FORBIDDEN).is_some()
                || value_contains_forbidden(value)
        }),
        Value::Array(values) => {
            let byte_array = (!values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_u64().is_some_and(|byte| byte <= u8::MAX as u64)))
            .then(|| {
                values
                    .iter()
                    .map(|value| value.as_u64().unwrap() as u8)
                    .collect::<Vec<_>>()
            });
            byte_array
                .as_deref()
                .is_some_and(|bytes| forbidden_value(bytes, &RUNTIME_FORBIDDEN).is_some())
                || values.iter().any(value_contains_forbidden)
        }
        Value::String(text) => forbidden_value(text.as_bytes(), &RUNTIME_FORBIDDEN).is_some(),
        _ => false,
    }
}

fn run_root_is_owned(workdir: &Path, run_root: &Path) -> bool {
    workdir.is_absolute() && run_root.is_absolute() && run_root.parent() == Some(workdir)
}

fn check_walkthrough_privacy(
    bytes: &[u8],
    expected_workdir: &Path,
) -> Result<Vec<Value>, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "walkthrough output is not UTF-8")?;
    let mut envelopes = Vec::new();
    let mut non_json = Vec::new();
    for line in text.lines() {
        match serde_json::from_str::<Value>(line) {
            Ok(value) if value.is_object() => envelopes.push(value),
            _ => {
                non_json.extend_from_slice(line.as_bytes());
                non_json.push(b'\n');
            }
        }
    }
    if envelopes.len() != 4 {
        return Err("walkthrough must contain exactly four JSON envelopes");
    }
    if forbidden_value(&non_json, &RUNTIME_FORBIDDEN).is_some() {
        return Err("non-JSON walkthrough output contains forbidden material");
    }

    let mut expected_root: Option<String> = None;
    for envelope in &envelopes[..3] {
        let root = envelope
            .get("run_root")
            .and_then(Value::as_str)
            .filter(|root| !root.is_empty())
            .ok_or("receipt run_root is missing or empty")?;
        if forbidden_value(root.as_bytes(), &SECRET_FORBIDDEN).is_some() {
            return Err("receipt run_root contains secret material");
        }
        if !run_root_is_owned(expected_workdir, Path::new(root)) {
            return Err("receipt run_root is not owned by selected workdir");
        }
        match &expected_root {
            Some(expected) if expected != root => return Err("receipt run_root values differ"),
            None => expected_root = Some(root.to_owned()),
            _ => {}
        }
    }
    let mut sanitized = envelopes.clone();
    for envelope in &mut sanitized[..3] {
        envelope
            .as_object_mut()
            .expect("envelope object")
            .remove("run_root");
    }
    if sanitized.iter().any(value_contains_forbidden) {
        return Err("decoded walkthrough envelope contains forbidden material");
    }
    Ok(envelopes)
}

fn scan_replay_payloads(replay: &Value) -> Result<usize, &'static str> {
    let mut count = 0;
    for section in ["fixtures", "artifacts"] {
        let entries = replay
            .get(section)
            .and_then(Value::as_array)
            .ok_or("replay payload section is missing")?;
        for entry in entries {
            let numbers = entry
                .get("bytes")
                .and_then(Value::as_array)
                .ok_or("replay payload bytes are missing")?;
            if numbers.len() > MAX_ARTIFACT_BYTES {
                return Err("replay payload exceeds size limit");
            }
            let bytes = numbers
                .iter()
                .map(|number| {
                    number
                        .as_u64()
                        .filter(|byte| *byte <= u8::MAX as u64)
                        .map(|byte| byte as u8)
                        .ok_or("replay payload byte is out of range")
                })
                .collect::<Result<Vec<_>, _>>()?;
            let digest = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or("replay payload digest is missing")?;
            if digest != format!("sha256:{:x}", Sha256::digest(&bytes)) {
                return Err("replay payload digest mismatch");
            }
            if forbidden_value(&bytes, &COMMITTED_FORBIDDEN).is_some() {
                return Err("decoded replay payload contains forbidden material");
            }
            count += 1;
        }
    }
    Ok(count)
}

fn documented_invocation_kinds(block: &str) -> Result<Vec<&'static str>, &'static str> {
    let mut kinds = Vec::new();
    for line in block.lines() {
        let occurrences = line.match_indices("workflowctl ").collect::<Vec<_>>();
        for (position, _) in occurrences {
            if line[..position].trim_end().ends_with("command -v") {
                continue;
            }
            let words = line[position..]
                .split(|character: char| character.is_whitespace() || "\"'$()".contains(character))
                .filter(|word| !word.is_empty())
                .collect::<Vec<_>>();
            let kind = match words.as_slice() {
                ["workflowctl", "--json", command, ..] => *command,
                ["workflowctl", command, ..] => *command,
                _ => return Err("workflowctl invocation is malformed"),
            };
            kinds.push(match kind {
                "validate" => "validate",
                "graph" => "graph",
                "lock" => "lock",
                "run" => "run",
                "inspect" => "inspect",
                "resume" => "resume",
                "replay" => "replay",
                _ => return Err("workflowctl invocation is unexpected"),
            });
        }
    }
    if kinds
        != [
            "validate", "graph", "lock", "run", "inspect", "resume", "replay",
        ]
    {
        return Err("workflowctl invocation sequence is not exact");
    }
    Ok(kinds)
}

fn single_run_directory(workdir: &Path) -> Result<PathBuf, &'static str> {
    let mut directories = Vec::new();
    for entry in fs::read_dir(workdir).map_err(|_| "run workdir read failed")? {
        let path = entry.map_err(|_| "run workdir entry failed")?.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| "run entry metadata failed")?;
        if !metadata.file_type().is_dir() {
            return Err("run workdir contains a non-directory entry");
        }
        directories.push(path);
        if directories.len() > 1 {
            return Err("run workdir contains more than one run directory");
        }
    }
    directories
        .pop()
        .ok_or("run workdir contains no run directory")
}

#[test]
fn privacy_oracle_allows_validated_home_run_root() {
    fn render(values: &[Value]) -> String {
        values
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }

    let workdir = Path::new("/home/user/tmp/workflowctl-m3-00/runs");
    let run_root = "/home/user/tmp/workflowctl-m3-00/runs/run-123";
    let receipts = vec![
        json!({"run_id": "run-123", "run_root": run_root, "resume_count": 0}),
        json!({"run_id": "run-123", "run_root": run_root, "resume_count": 0}),
        json!({"run_id": "run-123", "run_root": run_root, "resume_count": 1}),
        json!({"disposition": "replay_run"}),
    ];
    assert_eq!(
        check_walkthrough_privacy(render(&receipts).as_bytes(), workdir)
            .expect("validated home run root")
            .len(),
        4
    );

    let reordered = format!(
        "{{\"run_root\":\"{run_root}\",\"run_id\":\"run-123\"}}\n{}\n{}\n{}",
        serde_json::to_string(&receipts[1]).unwrap(),
        serde_json::to_string(&receipts[2]).unwrap(),
        serde_json::to_string(&receipts[3]).unwrap(),
    );
    assert!(check_walkthrough_privacy(reordered.as_bytes(), workdir).is_ok());

    for leak in [
        run_root.to_owned(),
        format!("{run_root}-private"),
        format!("prefix-{run_root}"),
        format!("{run_root}/private"),
        r"\u002fhome\u002fother".to_owned(),
        "/Users/other/private".to_owned(),
        "api_key".to_owned(),
    ] {
        let mut leaked = receipts.clone();
        leaked[0]["diagnostic"] = Value::String(leak);
        assert!(check_walkthrough_privacy(render(&leaked).as_bytes(), workdir).is_err());
    }

    let diagnostic = format!("{}\ndiagnostic={run_root}", render(&receipts));
    assert!(check_walkthrough_privacy(diagnostic.as_bytes(), workdir).is_err());
    let mut extra = receipts.clone();
    extra.push(json!({"diagnostic": "public"}));
    assert!(check_walkthrough_privacy(render(&extra).as_bytes(), workdir).is_err());

    let mut missing = receipts.clone();
    missing[1].as_object_mut().unwrap().remove("run_root");
    assert!(check_walkthrough_privacy(render(&missing).as_bytes(), workdir).is_err());
    let mut empty = receipts.clone();
    empty[1]["run_root"] = Value::String(String::new());
    assert!(check_walkthrough_privacy(render(&empty).as_bytes(), workdir).is_err());
    let mut different = receipts.clone();
    different[2]["run_root"] = Value::String(format!("{}/run-456", workdir.display()));
    assert!(check_walkthrough_privacy(render(&different).as_bytes(), workdir).is_err());
    assert!(!run_root_is_owned(
        Path::new("/tmp/runs"),
        Path::new("/tmp/runs-foreign/run-1")
    ));
}

#[test]
fn executable_prerequisite_contract_is_explicit_and_fail_closed() {
    let readme = String::from_utf8(
        read_bounded_regular(&example_root().join("README.md"), MAX_FIXTURE_BYTES).expect("README"),
    )
    .expect("README UTF-8");
    assert_eq!(readme.matches("```bash\n").count(), 1);
    for prerequisite in ["Bash", "Python 3", "workflowctl", "PATH", "repository root"] {
        assert!(readme.contains(prerequisite), "README omits {prerequisite}");
    }
    let block = documented_shell_block(&readme);
    let mutation = block.find("mkdir -p").expect("first filesystem mutation");
    for prerequisite in [
        "BASH_VERSION",
        "command -v python3",
        "command -v workflowctl",
    ] {
        let check = block
            .find(prerequisite)
            .unwrap_or_else(|| panic!("block omits {prerequisite}"));
        assert!(check < mutation, "{prerequisite} must fail before mutation");
    }

    let root = temp_root("missing-workflowctl");
    let prerequisite_bin = root.path().join("prerequisite-bin");
    fs::create_dir(&prerequisite_bin).expect("prerequisite bin");
    let python = executable_on_path("python3").expect("python3 prerequisite");
    std::os::unix::fs::symlink(python, prerequisite_bin.join("python3"))
        .expect("python3 prerequisite link");
    let workdir = root.path().join("must-not-exist");
    let path = std::env::join_paths([prerequisite_bin]).expect("missing workflowctl PATH");
    let output = run_documented_shell_block_with_path(block, &workdir, &path)
        .expect("missing prerequisite shell must exit");
    assert!(!output.status.success());
    assert_eq!(output.stderr, b"prerequisite missing: workflowctl\n");
    assert!(
        !workdir.exists(),
        "prerequisite failure must not mutate workdir"
    );
}

#[test]
fn committed_example_privacy_is_recursive_and_bounded() {
    let secret = b"/home/user/private";
    let replay = json!({
        "fixtures": [{
            "sha256": format!("sha256:{:x}", Sha256::digest(secret)),
            "bytes": secret,
        }],
        "artifacts": [],
    });
    assert!(scan_replay_payloads(&replay).is_err());
    let mut bad_digest = replay.clone();
    bad_digest["fixtures"][0]["bytes"] = json!([112, 117, 98, 108, 105, 99]);
    assert!(scan_replay_payloads(&bad_digest).is_err());
    let mut bad_byte = replay.clone();
    bad_byte["fixtures"][0]["bytes"] = json!([256]);
    assert!(scan_replay_payloads(&bad_byte).is_err());
    assert!(validate_committed_bytes(&[0xff]).is_err());

    let nested = temp_root("recursive-nested");
    fs::create_dir(nested.path().join("extra")).expect("nested directory");
    fs::write(nested.path().join("extra/private.txt"), b"public").expect("nested file");
    let files = collect_regular_tree(nested.path(), EXAMPLE_LIMITS).expect("recursive tree");
    assert!(files.contains_key(Path::new("extra/private.txt")));
    assert!(require_intended_example_files(&files).is_err());

    let symlink = temp_root("recursive-symlink");
    fs::write(symlink.path().join("target"), b"public").expect("symlink target");
    std::os::unix::fs::symlink("target", symlink.path().join("link")).expect("symlink");
    assert!(collect_regular_tree(symlink.path(), EXAMPLE_LIMITS).is_err());

    let bounded = temp_root("recursive-limits");
    fs::write(bounded.path().join("one"), b"1234").expect("oversized file");
    let tiny = TreeLimits {
        depth: 1,
        entries: 1,
        file_bytes: 3,
        total_bytes: 3,
    };
    assert!(collect_regular_tree(bounded.path(), tiny).is_err());
    assert!(read_bounded_regular(&bounded.path().join("one"), 3).is_err());
    fs::remove_file(bounded.path().join("one")).expect("remove oversized file");
    fs::write(bounded.path().join("one"), b"12").expect("first bounded file");
    fs::write(bounded.path().join("two"), b"34").expect("second bounded file");
    assert!(collect_regular_tree(bounded.path(), tiny).is_err());

    let deep = temp_root("recursive-depth");
    fs::create_dir_all(deep.path().join("a/b")).expect("deep directory");
    fs::write(deep.path().join("a/b/file"), b"x").expect("deep file");
    assert!(collect_regular_tree(deep.path(), tiny).is_err());
}

#[test]
fn subprocess_and_file_helpers_are_bounded() {
    let mut normal = Command::new("bash");
    normal.args(["-c", "printf ok; printf err >&2"]);
    let output = bounded_output(&mut normal, Duration::from_secs(1), 32).expect("bounded output");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ok");
    assert_eq!(output.stderr, b"err");

    let mut oversized = Command::new("bash");
    oversized.args(["-c", "while :; do printf 12345678; done"]);
    assert_eq!(
        bounded_output(&mut oversized, Duration::from_secs(1), 32),
        Err("subprocess output limit exceeded")
    );

    let mut timed_out = Command::new("bash");
    timed_out.args(["-c", "sleep 30 & wait"]);
    let started = Instant::now();
    assert_eq!(
        bounded_output(&mut timed_out, Duration::from_millis(50), 32),
        Err("subprocess timed out")
    );
    assert!(started.elapsed().as_secs() < 2);
}

#[test]
fn reader_error_still_joins_both_reader_handles() {
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("forced reader error"))
        }
    }

    struct BoundedReader {
        release: mpsc::Receiver<()>,
        finished: Arc<AtomicBool>,
    }

    impl Read for BoundedReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            let _ = self.release.recv_timeout(Duration::from_millis(100));
            self.finished.store(true, Ordering::Release);
            Ok(0)
        }
    }

    let (_release, release_receiver) = mpsc::channel();
    let stderr_finished = Arc::new(AtomicBool::new(false));
    let result = join_capped_readers(
        spawn_capped_reader(FailingReader, 1, Arc::new(AtomicBool::new(false))),
        spawn_capped_reader(
            BoundedReader {
                release: release_receiver,
                finished: Arc::clone(&stderr_finished),
            },
            1,
            Arc::new(AtomicBool::new(false)),
        ),
        Instant::now() + CLEANUP_TIMEOUT,
    );

    assert_eq!(result, Err("subprocess stdout read failed"));
    assert!(stderr_finished.load(Ordering::Acquire));
}

#[test]
fn normal_completion_signals_owned_group_before_reaping_leader() {
    let root = temp_root("signal-before-reap");
    let hold = root.path().join("hold");
    let marker = root.path().join("descendant.pid");
    fs::write(&hold, b"hold").expect("descendant hold");
    let script = format!(
        "(read -r descendant_pid command_name state parent_pid process_group session < /proc/$BASHPID/stat; printf '%s %s %s' \"$descendant_pid\" \"$process_group\" \"$$\" > '{}'; while test -e '{}'; do :; done) & while ! test -s '{}'; do :; done; exit 0",
        marker.display(),
        hold.display(),
        marker.display(),
    );
    let mut command = Command::new("bash");
    command.args(["-c", &script]);

    let timeout = Duration::from_secs(1);
    let absolute_bound = timeout + CLEANUP_TIMEOUT;
    NON_REAPING_OBSERVATION_USED.store(false, Ordering::Release);
    let started = Instant::now();
    let result = bounded_output(&mut command, timeout, MAX_FIXTURE_BYTES);
    let elapsed = started.elapsed();
    assert!(
        NON_REAPING_OBSERVATION_USED.load(Ordering::Acquire),
        "bounded_output normal completion did not use non-reaping observation"
    );
    let identity = fs::read(&marker)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| {
            let mut fields = text.split_whitespace();
            Some((
                fields.next()?.parse::<u32>().ok()?,
                fields.next()?.parse::<u32>().ok()?,
                fields.next()?.parse::<u32>().ok()?,
            ))
        })
        .expect("descendant fixture must publish its identity");
    let (descendant, descendant_group, leader) = identity;
    assert_eq!(descendant_group, leader);
    if result.is_err() {
        let process_group = unsafe { libc::getpgid(descendant as libc::pid_t) };
        if process_group > 0 {
            kill_process_group(process_group as u32);
        }
    }
    let output = result.expect("normal completion must return output");

    assert!(
        elapsed <= absolute_bound,
        "bounded_output exceeded its absolute bound: {elapsed:?} > {absolute_bound:?}"
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.len() <= MAX_FIXTURE_BYTES);
    assert!(output.stderr.len() <= MAX_FIXTURE_BYTES);

    let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
    let descendant_gone = loop {
        if unsafe { libc::kill(descendant as libc::pid_t, 0) } == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            break true;
        }
        if Instant::now() >= cleanup_deadline {
            break false;
        }
        thread::yield_now();
    };
    if !descendant_gone {
        let process_group = unsafe { libc::getpgid(descendant as libc::pid_t) };
        if process_group > 0 {
            kill_process_group(process_group as u32);
        }
    }
    assert!(
        descendant_gone,
        "actual bounded_output normal completion left descendant alive"
    );
}

#[test]
fn documented_execution_has_exactly_one_run_and_owned_identity() {
    let readme = String::from_utf8(
        read_bounded_regular(&example_root().join("README.md"), MAX_FIXTURE_BYTES).expect("README"),
    )
    .expect("README UTF-8");
    let block = documented_shell_block(&readme);
    let kinds = documented_invocation_kinds(block).expect("exact command sequence");
    assert_eq!(kinds.iter().filter(|kind| **kind == "run").count(), 1);
    let duplicated = block.replace(
        "workflowctl lock workflow.toml",
        "workflowctl lock workflow.toml\nworkflowctl --json run workflow.toml >/dev/null",
    );
    assert!(documented_invocation_kinds(&duplicated).is_err());
    assert!(!run_root_is_owned(
        Path::new("/tmp/runs"),
        Path::new("/tmp/runs-foreign/run-1")
    ));
}

#[test]
fn runtime_smoke_example_executes_full_provider_free_sequence() {
    let example = example_root();
    let workflow = example.join("workflow.toml");
    let files = collect_regular_tree(&example, EXAMPLE_LIMITS).expect("bounded example tree");
    require_intended_example_files(&files).expect("intended committed file set");
    for bytes in files.values() {
        validate_committed_bytes(bytes).expect("committed example privacy");
    }
    let workflow_bytes = &files[Path::new("workflow.toml")];
    let input_bytes = &files[Path::new("input.example.json")];
    let profile_bytes = &files[Path::new("profiles/fake.json")];
    let replay_bytes = &files[Path::new("replay.json")];
    let readme = std::str::from_utf8(&files[Path::new("README.md")]).expect("README UTF-8");
    let expected = std::str::from_utf8(&files[Path::new("expected-output.md")])
        .expect("expected output UTF-8");

    assert_eq!(
        serde_json::from_slice::<Value>(input_bytes).unwrap(),
        json!({"request": "runtime smoke"})
    );
    let profile_value: Value = serde_json::from_slice(profile_bytes).expect("fake profile JSON");
    assert_eq!(profile_value["model"]["provider"], "fake");
    assert!(
        !profile_value["model"]["responses"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(profile_value["tool"]["name"], "echo");
    assert_eq!(profile_value["sandbox"]["capabilities"], json!([]));
    assert_eq!(
        workflow_bytes.iter().filter(|byte| **byte == b'[').count(),
        8
    );

    let replay_value: Value = serde_json::from_slice(replay_bytes).expect("replay JSON");
    assert_eq!(replay_value["schema_version"], 1);
    assert_eq!(
        scan_replay_payloads(&replay_value).expect("replay payloads"),
        5
    );
    assert!(!replay_value["events"].as_array().unwrap().is_empty());
    assert_eq!(replay_value["events"][0]["type"], "node_started");
    assert_eq!(
        replay_value["events"].as_array().unwrap().last().unwrap()["type"],
        "terminal"
    );
    let lock_toml = replay_value["workflow_lock"]["toml"]
        .as_str()
        .expect("replay lock TOML");
    assert_eq!(
        replay_value["workflow_lock"]["sha256"],
        format!("sha256:{:x}", Sha256::digest(lock_toml.as_bytes()))
    );
    assert_eq!(
        replay_value["input_sha256"],
        format!("sha256:{:x}", Sha256::digest(input_bytes))
    );

    let root = temp_root("run");
    let runs = root.path().join("runs");
    fs::create_dir(&runs).expect("run base");
    let runs = fs::canonicalize(runs).expect("canonical run base");
    let input_text = String::from_utf8(input_bytes.to_vec()).expect("input UTF-8");
    let block = documented_shell_block(readme);
    documented_invocation_kinds(block).expect("exact documented command sequence");
    let walkthrough = run_documented_shell_block(block, &runs)
        .unwrap_or_else(|error| panic!("documented walkthrough failed before exit: {error}"));
    assert!(
        walkthrough.status.success(),
        "documented walkthrough failed: stdout={} stderr={}",
        String::from_utf8_lossy(&walkthrough.stdout),
        String::from_utf8_lossy(&walkthrough.stderr)
    );
    assert!(walkthrough.stdout.len() <= MAX_FIXTURE_BYTES);
    let walkthrough_text = String::from_utf8(walkthrough.stdout).expect("walkthrough UTF-8");
    assert!(walkthrough_text.lines().any(|line| line == "valid"));
    assert!(walkthrough_text.contains("agent"));
    assert!(walkthrough_text.contains("terminal"));
    assert_eq!(
        walkthrough_text.matches(lock_toml).count(),
        1,
        "walkthrough must visibly emit the committed lock"
    );
    let json_outputs = check_walkthrough_privacy(walkthrough_text.as_bytes(), &runs)
        .unwrap_or_else(|error| panic!("runtime output privacy check failed: {error}"));
    for field in [
        "run_id",
        "status",
        "run_root",
        "plan_hash",
        "resume_identity",
        "artifact_id",
        "resume_count",
        "disposition",
        "fixture_count",
        "payload_len",
    ] {
        assert!(expected.contains(field), "expected output omits {field}");
    }
    let run = &json_outputs[0];
    assert_receipt_shape(run);

    let run_root_text = run["run_root"].as_str().unwrap();
    let run_root = fs::canonicalize(run_root_text).expect("canonical run root");
    assert!(run_root_is_owned(&runs, &run_root));
    assert_eq!(
        single_run_directory(&runs).expect("one run directory"),
        run_root
    );
    for surface in [
        "workflow.toml",
        "execution-profile.json",
        "execution-input.json",
        "events.jsonl",
        "checkpoint.sqlite",
        "effects.sqlite",
        "run-manifest.json",
    ] {
        assert!(
            run_root.join(surface).is_file(),
            "missing run surface {surface}"
        );
    }
    assert!(run_root.join("artifacts").is_dir());

    let manifest_bytes =
        read_bounded_regular(&run_root.join("run-manifest.json"), MAX_FIXTURE_BYTES)
            .expect("bounded manifest");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("manifest JSON");
    for field in [
        "run_id",
        "status",
        "plan_hash",
        "resume_identity",
        "artifact_id",
    ] {
        assert_eq!(
            manifest[field], run[field],
            "manifest/receipt mismatch for {field}"
        );
    }

    let artifact_id = run["artifact_id"].as_str().unwrap();
    assert_eq!(artifact_id.len(), 64);
    assert!(artifact_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let artifact = read_bounded_regular(
        &run_root.join("artifacts").join(artifact_id),
        MAX_ARTIFACT_BYTES,
    )
    .expect("bounded terminal artifact");
    assert!(!artifact.is_empty());
    assert_eq!(format!("{:x}", Sha256::digest(&artifact)), artifact_id);
    assert_no_forbidden_bytes(&artifact);
    let events = read_bounded_regular(&run_root.join("events.jsonl"), MAX_FIXTURE_BYTES)
        .expect("bounded events");
    assert!(!events.is_empty());
    assert_no_forbidden_bytes(&events);

    let inspect = &json_outputs[1];
    assert_eq!(inspect, run);

    let resumed = &json_outputs[2];
    for field in [
        "run_id",
        "workflow_id",
        "artifact_id",
        "run_root",
        "plan_hash",
        "resume_identity",
    ] {
        assert_eq!(resumed[field], run[field], "resume mismatch for {field}");
    }
    assert_eq!(resumed["resume_count"], 1);
    assert_eq!(resumed["status"], "succeeded");

    let replay_result = &json_outputs[3];
    assert_eq!(replay_result["disposition"], "replay_run");
    assert!(replay_result["fixture_count"].as_u64().unwrap() > 0);
    assert_eq!(
        replay_result["payload_len"].as_u64().unwrap(),
        replay_bytes.len() as u64
    );
    assert!(replay_result.get("run_id").is_none());

    let missing_profile = root.path().join("missing-profile.json");
    let missing = command(&[
        "--json",
        "run",
        workflow.to_str().unwrap(),
        "--profile",
        missing_profile.to_str().unwrap(),
        "--input",
        input_text.trim(),
        "--workdir",
        runs.to_str().unwrap(),
    ]);
    assert!(!missing.status.success());

    let invalid_profile = root.path().join("invalid-profile.json");
    fs::write(&invalid_profile, b"{}").expect("invalid profile");
    let invalid = command(&[
        "--json",
        "run",
        workflow.to_str().unwrap(),
        "--profile",
        invalid_profile.to_str().unwrap(),
        "--input",
        input_text.trim(),
        "--workdir",
        runs.to_str().unwrap(),
    ]);
    assert!(!invalid.status.success());

    assert_eq!(documented_invocation_kinds(block).unwrap().len(), 7);
    assert!(readme.contains("runtime smoke example"));
    assert!(readme.contains("model-directed multi-tool"));
    assert!(readme.contains("committed redacted replay bundle"));
    assert!(expected.contains("<run-id>"));
    assert!(expected.contains("<run-root>"));
    assert!(expected.contains("<artifact-id>"));
}
