use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "workflowctl-m3-08-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("unique temporary root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn package_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/00-runtime-smoke")
}

fn runner() -> PathBuf {
    package_root().join("run.sh")
}

fn run(mode: &str, workdir: &Path) -> Output {
    Command::new("bash")
        .arg(runner())
        .arg(mode)
        .env("WORKFLOWCTL", env!("CARGO_BIN_EXE_workflowctl"))
        .env("WORKDIR", workdir)
        .output()
        .expect("reference runner must execute")
}

#[test]
fn minimal_scripted_runs_have_identical_terminal_artifacts() {
    let first = TempRoot::new("scripted-first");
    let second = TempRoot::new("scripted-second");
    let first_runs = first.path().join("runs");
    let second_runs = second.path().join("runs");
    let first_output = run("--scripted", &first_runs);
    assert!(
        first_output.status.success(),
        "first scripted run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&first_output.stdout),
        String::from_utf8_lossy(&first_output.stderr)
    );
    let second_output = run("--scripted", &second_runs);
    assert!(
        second_output.status.success(),
        "second scripted run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&second_output.stdout),
        String::from_utf8_lossy(&second_output.stderr)
    );
    assert_eq!(
        fs::read(first_runs.join("terminal-artifact.json")).expect("first artifact"),
        fs::read(second_runs.join("terminal-artifact.json")).expect("second artifact")
    );
}

#[test]
fn replay_mode_invokes_only_offline_replay() {
    let root = TempRoot::new("replay");
    let spy = root.path().join("workflowctl-spy");
    let log = root.path().join("invocations.log");
    fs::write(
        &spy,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec \"$REAL_WORKFLOWCTL\" \"$@\"\n",
            log.display(),
        ),
    )
    .expect("spy");
    let mut permissions = fs::metadata(&spy).expect("spy metadata").permissions();
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o700);
    }
    fs::set_permissions(&spy, permissions).expect("executable spy");

    let output = Command::new("bash")
        .arg(runner())
        .arg("--replay")
        .env("WORKFLOWCTL", &spy)
        .env("REAL_WORKFLOWCTL", env!("CARGO_BIN_EXE_workflowctl"))
        .output()
        .expect("replay runner must execute");
    assert!(
        output.status.success(),
        "replay failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let invocation = fs::read_to_string(log).expect("replay invocation log");
    assert!(invocation.contains("replay replay.json"));
    assert!(!invocation.contains(" run "));
    assert!(!invocation.contains("model"));
    assert!(!invocation.contains("network"));
}

#[test]
fn live_mode_requires_endpoint_and_credential_configuration() {
    let root = TempRoot::new("live-missing-config");
    let output = Command::new("bash")
        .arg(runner())
        .arg("--live")
        .env("WORKFLOWCTL", env!("CARGO_BIN_EXE_workflowctl"))
        .env("WORKDIR", root.path().join("runs"))
        .env_remove("WORKFLOW_KIT_LIVE_BASE_URL")
        .env_remove("WORKFLOW_KIT_LIVE_API_KEY")
        .output()
        .expect("live runner must execute");
    assert!(!output.status.success());
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostics.contains("WORKFLOW_KIT_LIVE_BASE_URL"));
    assert!(diagnostics.contains("WORKFLOW_KIT_LIVE_API_KEY"));
    assert!(diagnostics.contains("set"));
}
