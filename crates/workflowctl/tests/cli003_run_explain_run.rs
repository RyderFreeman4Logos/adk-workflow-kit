use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

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

    fs::remove_dir_all(&root).expect("temp root must be removed");
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

    fs::remove_dir_all(&root).expect("temp root must be removed");
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

    fs::remove_dir_all(&root).expect("temp root must be removed");
}
