use std::{
    ffi::OsString,
    fs,
    io::Read,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

const HELP: &str = "Thin workflow CLI over reusable libraries\n\nUsage: workflowctl [OPTIONS] <COMMAND>\n\nCommands:\n  validate <PATH>\n  graph <PATH> --format mermaid\n  lock <PATH>\n  skill lint <PATH>\n  skill test <PATH>\n  test <PATH>\n  eval <PATH>\n  replay <PATH>\n  audit\n  run <PATH> --module <PATH> --input <JSON> --workdir <DIR>\n  explain-run <PATH> --module <PATH> --input <JSON>\n  reload <PATH> --module <PATH> --input <JSON>\n\nOptions:\n      --json  Emit diagnostics as JSON\n  -h, --help  Print help\n";
const HUMAN_ERROR: &str =
    "[workflow.cli.invalid_arguments] invalid command-line arguments location=null details={}\n";
const JSON_ERROR: &str = "{\"diagnostic_version\":1,\"code\":\"workflow.cli.invalid_arguments\",\"message\":\"invalid command-line arguments\",\"location\":null,\"details\":{}}\n";
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const SUBPROCESS_TIMEOUT_MESSAGE: &str = "workflowctl contract subprocess timed out";
const MINIMAL_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/minimal.workflow.toml"
);
const IDENTITY_MODULE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/transform_identity.wasm"
);

static TEMP_FILE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct ChildGuard {
    child: Option<Child>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn output(command: &mut Command) -> Output {
    output_with_stdout(command, true)
}

#[cfg(unix)]
fn output_with_closed_stdout(command: &mut Command) -> Output {
    use std::os::{
        fd::{FromRawFd, IntoRawFd, OwnedFd},
        unix::net::UnixStream,
    };

    let (stdout, peer) = UnixStream::pair().expect("stdout socket pair should be creatable");
    drop(peer);
    // SAFETY: `into_raw_fd` transfers sole ownership of `stdout` to the new `OwnedFd`.
    let stdout = unsafe { OwnedFd::from_raw_fd(stdout.into_raw_fd()) };
    command.stdout(Stdio::from(stdout));
    output_with_stdout(command, false)
}

fn output_with_stdout(command: &mut Command, read_stdout: bool) -> Output {
    if read_stdout {
        command.stdout(Stdio::piped());
    }
    let mut child = ChildGuard {
        child: Some(
            command
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("workflowctl should start: {error}")),
        ),
    };
    let mut stderr = child
        .child
        .as_mut()
        .expect("workflowctl child missing")
        .stderr
        .take()
        .expect("workflowctl stderr missing");
    let stdout_reader = read_stdout.then(|| {
        let mut stdout = child
            .child
            .as_mut()
            .expect("workflowctl child missing")
            .stdout
            .take()
            .expect("workflowctl stdout missing");
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .read_to_end(&mut bytes)
                .expect("workflowctl stdout read failed");
            bytes
        })
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .read_to_end(&mut bytes)
            .expect("workflowctl stderr read failed");
        bytes
    });

    let deadline = Instant::now() + SUBPROCESS_TIMEOUT;
    let (status, timed_out) = loop {
        let child_process = child.child.as_mut().expect("workflowctl child missing");
        match child_process.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() >= deadline => {
                child_process
                    .kill()
                    .unwrap_or_else(|error| panic!("workflowctl kill failed: {error}"));
                break (
                    child_process
                        .wait()
                        .unwrap_or_else(|error| panic!("workflowctl wait failed: {error}")),
                    true,
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("workflowctl wait failed: {error}"),
        }
    };
    child.child = None;

    let output = Output {
        status,
        stdout: stdout_reader.map_or_else(Vec::new, |reader| {
            reader.join().expect("workflowctl stdout reader failed")
        }),
        stderr: stderr_reader
            .join()
            .expect("workflowctl stderr reader failed"),
    };
    if timed_out {
        panic!("{SUBPROCESS_TIMEOUT_MESSAGE}");
    }
    output
}

fn assert_error(output: Output, expected_stderr: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, expected_stderr.as_bytes());
}

fn temporary_fixture_path(name: &str) -> PathBuf {
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "workflowctl-cli-contract-{name}-{}-{sequence}.workflow.toml",
        std::process::id()
    ))
}

#[test]
fn help_is_deterministic_success_with_empty_stderr_and_no_dispatch() {
    for arguments in [
        ["-h"].as_slice(),
        ["--help"].as_slice(),
        ["--json", "--help"].as_slice(),
        ["--help", "--json"].as_slice(),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        command.args(arguments);
        let output = output(&mut command);

        assert!(output.status.success());
        assert_eq!(output.stdout, HELP.as_bytes());
        assert!(output.stderr.is_empty());
    }

    let mut timeout_command = Command::new("sleep");
    timeout_command.arg((SUBPROCESS_TIMEOUT.as_secs() + 1).to_string());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        output(&mut timeout_command)
    }))
    .expect_err("timed-out subprocess should fail the test");
    assert_eq!(
        panic.downcast_ref::<String>().map(String::as_str),
        Some(SUBPROCESS_TIMEOUT_MESSAGE)
    );
}

#[test]
fn json_error_is_stable_and_redacts_untrusted_arguments() {
    let secret = "secret-token-should-not-appear";
    let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    command.args(["--json", secret]);
    let output = output(&mut command);

    assert_error(output, JSON_ERROR);
}

#[test]
fn empty_and_hostile_arguments_fail_closed_without_panic_or_echo() {
    let hostile = [
        OsString::new(),
        OsString::from("\u{001f}"),
        OsString::from("\u{007f}"),
        OsString::from("\u{0080}"),
        OsString::from("\u{061c}"),
        OsString::from("\u{200e}"),
        OsString::from("\u{200f}"),
        OsString::from("\u{2028}"),
        OsString::from("\u{2029}"),
        OsString::from("\u{202a}"),
        OsString::from("\u{202e}"),
        OsString::from("\u{2066}"),
        OsString::from("\u{2069}"),
        OsString::from_vec(vec![0xff]),
    ];

    for argument in hostile {
        let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        command.arg(argument);
        assert_error(output(&mut command), HUMAN_ERROR);
    }
}

#[test]
fn oversized_argument_is_rejected_before_dispatch() {
    let accepted = "a".repeat(4096);
    let rejected = "a".repeat(4097);

    let mut accepted_command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    accepted_command.arg(accepted);
    assert_error(output(&mut accepted_command), HUMAN_ERROR);

    let mut rejected_command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    rejected_command.args(["--json", rejected.as_str()]);
    assert_error(output(&mut rejected_command), JSON_ERROR);
}

#[test]
fn minimal_fixture_validates_and_emits_exact_graph_and_lock_bytes() {
    let mut validate = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    validate.args(["validate", MINIMAL_FIXTURE]);
    let validate_output = output(&mut validate);
    assert!(validate_output.status.success());
    assert_eq!(validate_output.stdout, b"valid\n");
    assert!(validate_output.stderr.is_empty());

    let mut graph = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    graph.args(["graph", MINIMAL_FIXTURE, "--format", "mermaid"]);
    let graph_output = output(&mut graph);
    assert!(graph_output.status.success());
    assert_eq!(
        graph_output.stdout,
        b"graph TD\n  n646f6e65[\"done (terminal)\"]\n  n7374617274[\"start (agent)\"]\n  n7374617274 --> n646f6e65\n"
    );
    assert!(graph_output.stderr.is_empty());

    let mut lock = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    lock.args(["lock", MINIMAL_FIXTURE]);
    let lock_output = output(&mut lock);
    assert!(lock_output.status.success());
    assert_eq!(
        lock_output.stdout,
        b"lock_version = 1\ncanonical_ir_wire_version = 1\nir_schema_version = 1\nworkflow_id = \"minimal\"\nworkflow_version = \"1\"\nir_hash = \"sha256:46959e152a1ba0d913d74b1c18a5f19f8a9655394275494e0f508f2e4c0a9b5c\"\nsemantic_resource_hashes = []\n"
    );
    assert!(lock_output.stderr.is_empty());

    #[cfg(unix)]
    {
        let mut closed_stdout = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        closed_stdout.args(["validate", MINIMAL_FIXTURE]);
        assert_error(
            output_with_closed_stdout(&mut closed_stdout),
            "[workflow.cli.stdout_write_failed] failed to write command output location=null details={}\n",
        );
    }
}

#[test]
fn graph_percent_encodes_hostile_ids_in_canonical_order() {
    let fixture = temporary_fixture_path("hostile");
    fs::write(
        &fixture,
        r#"schema_version = 1

[workflow]
id = "hostile"
version = "1"
entry = "start %é"

[[nodes]]
id = "start %é"
kind = "agent"

[[nodes]]
id = "done/✓"
kind = "terminal"

[[edges]]
from = "start %é"
to = "done/✓"
"#,
    )
    .expect("hostile fixture should be writable");

    let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    command.args([
        "graph",
        fixture.to_str().expect("temporary path should be UTF-8"),
        "--format",
        "mermaid",
    ]);
    let graph = output(&mut command);
    assert!(graph.status.success());
    assert_eq!(
        graph.stdout,
        b"graph TD\n  n646f6e652fe29c93[\"done%2F%E2%9C%93 (terminal)\"]\n  n73746172742025c3a9[\"start%20%25%C3%A9 (agent)\"]\n  n73746172742025c3a9 --> n646f6e652fe29c93\n"
    );
    assert!(graph.stderr.is_empty());
    fs::remove_file(fixture).expect("hostile fixture should be removable");
}

#[test]
fn subcommand_usage_errors_preserve_cli_001_contract() {
    for arguments in [
        ["validate"].as_slice(),
        ["graph", MINIMAL_FIXTURE].as_slice(),
        ["graph", MINIMAL_FIXTURE, "--format", "dot"].as_slice(),
        ["lock", MINIMAL_FIXTURE, "extra"].as_slice(),
        ["--unknown"].as_slice(),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        command.args(arguments);
        assert_error(output(&mut command), HUMAN_ERROR);
    }

    let mut json_command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    json_command.args(["graph", MINIMAL_FIXTURE, "--json"]);
    assert_error(output(&mut json_command), JSON_ERROR);

    let separator_directory = temporary_fixture_path("separator");
    fs::create_dir(&separator_directory).expect("separator directory should be creatable");
    for arguments in [
        ["validate", "--", "--json"].as_slice(),
        ["graph", "--format", "mermaid", "--", "--json"].as_slice(),
        ["lock", "--", "--json"].as_slice(),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        command.current_dir(&separator_directory).args(arguments);
        assert_error(
            output(&mut command),
            "[workflow.source.read_failed] failed to read workflow source location={field_path=\".\", span=null} details={}\n",
        );
    }
    fs::remove_dir(separator_directory).expect("separator directory should be removable");
}

#[test]
fn source_and_compile_failures_are_redacted_diagnostics_without_partial_stdout() {
    let missing = temporary_fixture_path("secret-missing");
    let invalid_utf8 = temporary_fixture_path("secret-invalid-utf8");
    let decode = temporary_fixture_path("secret-decode");
    let graph = temporary_fixture_path("secret-graph");
    let oversized = temporary_fixture_path("secret-oversized");
    #[cfg(unix)]
    let writerless_fifo = temporary_fixture_path("secret-writerless-fifo");
    fs::write(&invalid_utf8, [0xff]).expect("invalid UTF-8 fixture should be writable");
    fs::write(&decode, "schema_version = [").expect("decode fixture should be writable");
    fs::write(&oversized, vec![b'x'; 1_048_577]).expect("oversized fixture should be writable");
    fs::write(
        &graph,
        r#"schema_version = 1
edges = []

[workflow]
id = "invalid"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "orphan"
kind = "agent"
"#,
    )
    .expect("graph fixture should be writable");
    #[cfg(unix)]
    {
        let creation = Command::new("mkfifo")
            .arg(&writerless_fifo)
            .status()
            .expect("writerless FIFO fixture should be creatable");
        assert!(
            creation.success(),
            "writerless FIFO fixture creation failed"
        );
    }

    for (path, code) in [
        (&missing, "workflow.source.read_failed"),
        (&invalid_utf8, "workflow.source.invalid_utf8"),
        (&decode, "workflow.source.decode_failed"),
        (&graph, "workflow.graph.unreachable_node"),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        command.args([
            "validate",
            path.to_str().expect("temporary path should be UTF-8"),
        ]);
        let failure = output(&mut command);
        assert_eq!(failure.status.code(), Some(2));
        assert!(failure.stdout.is_empty());
        let stderr = String::from_utf8(failure.stderr).expect("diagnostic should be UTF-8");
        assert!(stderr.starts_with(&format!("[{code}]")));
        assert!(!stderr.contains("secret-"));
    }

    let mut json_command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    json_command.args([
        "--json",
        "validate",
        missing.to_str().expect("temporary path should be UTF-8"),
    ]);
    let json_failure = output(&mut json_command);
    assert_eq!(json_failure.status.code(), Some(2));
    assert!(json_failure.stdout.is_empty());
    let json_stderr = String::from_utf8(json_failure.stderr).expect("diagnostic should be UTF-8");
    assert!(json_stderr.contains("\"code\":\"workflow.source.read_failed\""));
    assert!(!json_stderr.contains("secret-"));

    let mut unsafe_paths = vec![oversized.as_path()];
    #[cfg(unix)]
    unsafe_paths.push(writerless_fifo.as_path());
    for path in unsafe_paths {
        let path = path.to_str().expect("unsafe fixture path should be UTF-8");
        for arguments in [
            ["validate", path].as_slice(),
            ["graph", path, "--format", "mermaid"].as_slice(),
            ["lock", path].as_slice(),
        ] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
            command.args(arguments);
            let failure = output(&mut command);
            assert_eq!(failure.status.code(), Some(2));
            assert!(failure.stdout.is_empty());
            let stderr = String::from_utf8(failure.stderr).expect("diagnostic should be UTF-8");
            assert!(stderr.starts_with("[workflow.source.read_failed]"));
            assert!(!stderr.contains("secret-"));
        }
    }

    for path in [invalid_utf8, decode, graph, oversized] {
        fs::remove_file(path).expect("temporary fixture should be removable");
    }
    #[cfg(unix)]
    fs::remove_file(writerless_fifo).expect("writerless FIFO fixture should be removable");
}

#[cfg(unix)]
#[test]
fn skill_fifo_paths_fail_closed_with_typed_diagnostics_without_blocking() {
    let root = std::env::temp_dir().join(format!(
        "workflowctl-cli-contract-fifo-skill-{}-{}",
        std::process::id(),
        TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("FIFO skill root should be creatable");
    let fifo = root.join("SKILL.md");
    let creation = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("FIFO skill fixture should be creatable");
    assert!(creation.success(), "FIFO skill fixture creation failed");

    for subcommand in ["lint", "test"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        command.args([
            "--json",
            "skill",
            subcommand,
            root.to_str().expect("FIFO skill root should be UTF-8"),
        ]);
        let failure = output(&mut command);
        assert_eq!(failure.status.code(), Some(2));
        assert!(failure.stdout.is_empty());
        let stderr = String::from_utf8(failure.stderr).expect("diagnostic should be UTF-8");
        assert!(stderr.contains("\"code\":\"skill.cli.invalid_manifest\""));
    }

    fs::remove_dir_all(&root).expect("FIFO skill root should be removable");
}

#[test]
fn hostile_and_oversized_paths_fail_before_dispatch_without_echo() {
    let hostile = OsString::from("\u{001f}");
    let mut hostile_command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    hostile_command.arg("validate").arg(hostile);
    assert_error(output(&mut hostile_command), HUMAN_ERROR);

    let oversized = "a".repeat(4097);
    let mut oversized_command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    oversized_command.args(["--json", "validate", oversized.as_str()]);
    assert_error(output(&mut oversized_command), JSON_ERROR);
}

#[test]
fn reload_dispatch_publishes_an_immutable_bind() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    command.args([
        "reload",
        MINIMAL_FIXTURE,
        "--module",
        IDENTITY_MODULE,
        "--input",
        r#"{"value":7}"#,
    ]);
    let result = output(&mut command);
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let stdout = String::from_utf8(result.stdout).expect("reload output must be UTF-8");
    assert!(stdout.starts_with("reloaded old=sha256:"));
    assert!(stdout.contains(" new=sha256:"));
}
