use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

#[path = "support/owned_tree.rs"]
mod owned_tree;

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

const WORKFLOW_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/cli003_transform.workflow.toml"
);
const MODULE_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/transform_identity.wasm"
);

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "workflowctl-cli003-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("temp root must be created");
    root
}

fn run_output(arguments: &[&str], current_dir: Option<&std::path::Path>) -> Output {
    let mut command = binary();
    command.args(arguments);
    if let Some(directory) = current_dir {
        command.current_dir(directory);
    }
    command
        .output()
        .unwrap_or_else(|error| panic!("workflowctl should start: {error}"))
}

fn artifact_files(workdir: &std::path::Path) -> Vec<PathBuf> {
    let root = workdir.join("artifacts");
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut files = entries
        .filter_map(|entry| {
            entry
                .ok()
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn wait_for_fifo_module_exit(child: &mut Child, deadline: std::time::Instant) -> ExitStatus {
    loop {
        if let Some(status) = child.try_wait().expect("wait must not fail") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let killed = child.kill();
            let reaped = child.wait();
            panic!(
                "workflowctl must not block on a non-regular module path; kill={killed:?}; reap={reaped:?}"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn fifo_module_timeout_reaps_child_before_panicking() {
    struct RescueChild(Child);

    impl Drop for RescueChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            if let Err(error) = self.0.wait() {
                let _ = writeln!(std::io::stderr(), "timeout fixture rescue failed: {error}");
            }
        }
    }

    // SAFETY: zero initializes the output action; the null second argument
    // queries SIGCHLD without changing process-wide signal disposition.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: the action pointer is valid, and the null input requests only a query.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) },
        0,
        "SIGCHLD disposition must be readable"
    );
    assert!(
        action.sa_sigaction == libc::SIG_DFL && action.sa_flags & libc::SA_NOCLDWAIT == 0,
        "timeout fixture requires retained direct-child status"
    );
    let mut fixture = RescueChild(
        Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("timeout fixture must start"),
    );
    assert!(
        fixture
            .0
            .try_wait()
            .expect("fixture status must be readable")
            .is_none()
    );
    let pid = fixture.0.id();
    // SAFETY: zero is valid initialization for the waitid output structure.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let started = std::time::Instant::now();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_for_fifo_module_exit(&mut fixture.0, started - std::time::Duration::from_secs(1))
    }));
    // SAFETY: this exact positive PID belongs to our direct fixture child;
    // WNOWAIT observes its status without performing the missing reap.
    let observed = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error();
    // SAFETY: info was initialized before waitid, including its error path.
    let observed_pid = unsafe { info.si_pid() };
    let elapsed = started.elapsed();

    // Save the non-consuming observation before independent rescue can reap.
    let _ = fixture.0.kill();
    let rescued = fixture
        .0
        .wait()
        .expect("independent rescue must reap the fixture");
    eprintln!(
        "timeout custody: pre_rescue_waitid={observed}; errno={errno:?}; si_pid={observed_pid}; elapsed={elapsed:?}; rescue={rescued:?}"
    );
    let panic = panic.expect_err("expired FIFO deadline must panic");
    let message = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
    assert!(message.is_some_and(|message| {
        message.starts_with("workflowctl must not block on a non-regular module path")
    }));
    assert_eq!(
        (observed, errno),
        (-1, Some(libc::ECHILD)),
        "timeout helper must reap before independent rescue; observed pid={observed_pid}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "controlled direct-sleeper timeout must complete within two seconds"
    );
}

#[test]
fn run_executes_fixture_and_publishes_non_empty_artifact() {
    let root = temp_root("run");
    let workdir = root.join("workdir");
    fs::create_dir_all(&workdir).expect("workdir must be created");

    let output = run_output(
        &[
            "run",
            WORKFLOW_FIXTURE,
            "--module",
            MODULE_FIXTURE,
            "--input",
            r#"{"value":7}"#,
            "--workdir",
            workdir.to_str().expect("workdir must be UTF-8"),
        ],
        None,
    );
    assert!(
        output.status.success(),
        "run must succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("artifact="),
        "run must print the published artifact id, stdout: {stdout}"
    );

    let files = artifact_files(&workdir);
    assert!(
        !files.is_empty(),
        "run must persist a non-empty artifact in the workdir artifacts store"
    );
    for file in &files {
        let metadata = fs::metadata(file).expect("artifact metadata must be readable");
        assert!(
            metadata.len() > 0,
            "published artifact must be non-empty: {}",
            file.display()
        );
    }

    owned_tree::remove_dir_all(&root).expect("temp root must be removed");
}

#[test]
fn explain_run_emits_deterministic_plan_without_mutating_artifact_state() {
    let root = temp_root("explain");
    fs::create_dir_all(root.join("artifacts")).expect("sentinel artifact store must be created");
    fs::write(root.join("artifacts/keep.bin"), b"sentinel-bytes")
        .expect("sentinel must be written");

    let output = run_output(
        &[
            "explain-run",
            WORKFLOW_FIXTURE,
            "--module",
            MODULE_FIXTURE,
            "--input",
            r#"{"value":7}"#,
        ],
        Some(&root),
    );
    assert!(
        output.status.success(),
        "explain-run must succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("plan_version=1"),
        "explain-run must emit a deterministic plan, stdout: {stdout}"
    );
    assert!(
        stdout.contains("execution=not_started"),
        "explain-run must never start execution, stdout: {stdout}"
    );

    let sentinel = fs::read(root.join("artifacts/keep.bin")).expect("sentinel must still exist");
    assert_eq!(
        sentinel, b"sentinel-bytes",
        "explain-run must leave existing artifact state unchanged"
    );
    assert_eq!(
        artifact_files(&root).as_slice(),
        &[root.join("artifacts/keep.bin")],
        "explain-run must not add or remove artifact files"
    );

    owned_tree::remove_dir_all(&root).expect("temp root must be removed");
}

#[test]
fn run_rejects_oversized_module_with_typed_diagnostic_before_execution() {
    let root = temp_root("oversized-module");
    let workdir = root.join("workdir");
    fs::create_dir_all(&workdir).expect("workdir must be created");
    let module = root.join("oversized.wasm");
    fs::write(&module, vec![0u8; 1024 * 1024 + 1]).expect("oversized module must be written");

    let output = run_output(
        &[
            "run",
            WORKFLOW_FIXTURE,
            "--module",
            module.to_str().expect("module must be UTF-8"),
            "--input",
            r#"{"value":7}"#,
            "--workdir",
            workdir.to_str().expect("workdir must be UTF-8"),
        ],
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "oversized module must exit 2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workflow.run.unsupported_input"),
        "oversized module must be rejected as unsupported input, stderr: {stderr}"
    );

    owned_tree::remove_dir_all(&root).expect("temp root must be removed");
}

#[test]
fn run_rejects_non_regular_module_without_blocking() {
    let root = temp_root("fifo-module");
    let workdir = root.join("workdir");
    fs::create_dir_all(&workdir).expect("workdir must be created");
    let fifo = root.join("module.fifo");
    let mkfifo = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must run");
    assert!(mkfifo.success(), "mkfifo must succeed");

    let stdout_path = root.join("stdout");
    let stderr_path = root.join("stderr");
    let mut child = binary()
        .args([
            "run",
            WORKFLOW_FIXTURE,
            "--module",
            fifo.to_str().expect("fifo must be UTF-8"),
            "--input",
            r#"{"value":7}"#,
            "--workdir",
            workdir.to_str().expect("workdir must be UTF-8"),
        ])
        .stdout(std::process::Stdio::from(
            fs::File::create(&stdout_path).expect("stdout capture must open"),
        ))
        .stderr(std::process::Stdio::from(
            fs::File::create(&stderr_path).expect("stderr capture must open"),
        ))
        .spawn()
        .expect("workflowctl must start");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = wait_for_fifo_module_exit(&mut child, deadline);
    assert_eq!(
        status.code(),
        Some(2),
        "non-regular module must exit 2 without blocking"
    );
    let stderr = fs::read_to_string(&stderr_path).expect("captured stderr must be readable");
    assert!(
        stderr.contains("workflow.run.unsupported_input"),
        "non-regular module must be rejected as unsupported input, stderr: {stderr}"
    );

    owned_tree::remove_dir_all(&root).expect("temp root must be removed");
}

#[test]
fn run_fails_with_typed_diagnostic_when_artifact_root_is_unusable() {
    let root = temp_root("artifact-blocked");
    let workdir = root.join("workdir");
    fs::create_dir_all(&workdir).expect("workdir must be created");
    fs::write(workdir.join("artifacts"), b"not a directory")
        .expect("artifact blocker must be written");

    let output = run_output(
        &[
            "run",
            WORKFLOW_FIXTURE,
            "--module",
            MODULE_FIXTURE,
            "--input",
            r#"{"value":7}"#,
            "--workdir",
            workdir.to_str().expect("workdir must be UTF-8"),
        ],
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "unusable artifact root must exit 2"
    );
    assert!(
        output.stdout.is_empty(),
        "unusable artifact root must not simulate success, stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workflow.run.failed"),
        "typed run.failed diagnostic expected, stderr: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "artifact root failure must not panic, stderr: {stderr}"
    );

    owned_tree::remove_dir_all(&root).expect("temp root must be removed");
}

#[test]
fn run_fails_with_typed_diagnostic_when_execution_input_is_unsupported() {
    let root = temp_root("unsupported");
    let workdir = root.join("workdir");
    fs::create_dir_all(&workdir).expect("workdir must be created");

    let output = run_output(
        &[
            "run",
            WORKFLOW_FIXTURE,
            "--module",
            MODULE_FIXTURE,
            "--input",
            "not-json",
            "--workdir",
            workdir.to_str().expect("workdir must be UTF-8"),
        ],
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "unsupported input must exit 2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workflow.run"),
        "typed run diagnostic expected, stderr: {stderr}"
    );

    owned_tree::remove_dir_all(&root).expect("temp root must be removed");
}
