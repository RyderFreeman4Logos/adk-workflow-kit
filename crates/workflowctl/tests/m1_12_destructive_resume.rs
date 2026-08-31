//! Core M1-12 evidence: real workflowctl crashes, fresh-process resume, and
//! one durable local effect for every logical tool call.

use std::{
    fs, io,
    os::unix::{process::CommandExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use serde_json::Value;
use sha2::Digest;
use workflow_runtime::EffectJournal;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "workflowctl-m1-12-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("test root must be unique");
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn workflow(root: &Path) -> PathBuf {
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../workflowctl/tests/fixtures/minimal.workflow.toml"),
    )
    .expect("minimal workflow")
    .replace(
        "kind = \"agent\"",
        "kind = \"agent\"\ntool = { id = \"send\", version = \"1\" }",
    );
    let path = root.join("workflow.toml");
    fs::write(&path, source).expect("workflow write");
    path
}

fn profile(root: &Path) -> PathBuf {
    let path = root.join("profile.json");
    fs::write(
        &path,
        br#"{"schema_version":1,"model":{"provider":"fake","name":"fake-model","version":"1","model":"fake","responses":["done"]},"tool":{"name":"send","result":{"accepted":true}},"sandbox":{"capabilities":[]}}"#,
    )
    .expect("profile write");
    path
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    command.env_remove("WORKFLOW_KIT_TEST_CRASH_BARRIER");
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

fn child_identity(pid: u32) -> Option<(u32, u64)> {
    let contents = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = contents
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let process_group = fields.get(2)?.parse().ok()?;
    let start_time = fields.get(19)?.parse().ok()?;
    Some((process_group, start_time))
}

fn spawn_and_capture(mut command: Command) -> (Child, (u32, u64)) {
    let mut child = command.spawn().expect("workflowctl must spawn");
    let pid = child.id();
    for _ in 0..100 {
        if let Some(identity) = child_identity(pid) {
            return (child, identity);
        }
        thread::sleep(Duration::from_millis(1));
    }
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    let _ = child.wait();
    panic!("workflowctl process identity must be observable");
}

fn wait(child: Child) -> Output {
    let pid = child.id();
    let output = child
        .wait_with_output()
        .expect("workflowctl must be reaped");
    // The child has its own process group; this is the cleanup path even when
    // the barrier already killed the leader.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    assert!(
        child_identity(pid).is_none(),
        "workflowctl process must be gone"
    );
    output
}

fn run_args(profile: &Path, workdir: &Path) -> Command {
    let mut command = command();
    command
        .arg("run")
        .arg(workflow(profile.parent().expect("profile parent")))
        .arg("--profile")
        .arg(profile)
        .arg("--input")
        .arg(r#"{"request":"public"}"#)
        .arg("--workdir")
        .arg(workdir);
    command
}

fn run_root(workdir: &Path) -> PathBuf {
    let roots = fs::read_dir(workdir)
        .expect("workdir")
        .map(|entry| entry.expect("run entry").path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(roots.len(), 1, "one independent run root is required");
    roots.into_iter().next().expect("run root")
}

fn run_id(root: &Path) -> String {
    let value: Value =
        serde_json::from_slice(&fs::read(root.join("run-manifest.json")).expect("manifest"))
            .expect("valid run manifest");
    value["run_id"].as_str().expect("run id").to_owned()
}

fn resume(workdir: &Path, id: &str) -> (Output, (u32, u64)) {
    let mut command = command();
    command
        .arg("resume")
        .arg("--run-id")
        .arg(id)
        .arg("--workdir")
        .arg(workdir);
    let (child, identity) = spawn_and_capture(command);
    (wait(child), identity)
}

#[test]
fn relative_workdir_run_then_fresh_process_resume_succeeds() {
    let root = TestRoot::new();
    let profile = profile(&root.0);
    let workdir = Path::new("runs");
    fs::create_dir(root.0.join(workdir)).expect("workdir");
    let mut run = run_args(&profile, workdir);
    run.current_dir(&root.0);
    let (child, _) = spawn_and_capture(run);
    assert!(wait(child).status.success());

    let persisted_workdir = root.0.join(workdir);
    let run_root = run_root(&persisted_workdir);
    let id = run_id(&run_root);
    let mut resume_command = command();
    resume_command
        .current_dir(&root.0)
        .arg("resume")
        .arg("--run-id")
        .arg(id)
        .arg("--workdir")
        .arg(workdir);
    let (child, _) = spawn_and_capture(resume_command);
    let resumed = wait(child);
    assert!(resumed.status.success(), "relative resume: {resumed:?}");
}

#[test]
fn sigkill_matrix_resumes_in_fresh_process_without_duplicate_effects() {
    for barrier in [
        "before-effect",
        "after-effect",
        "before-checkpoint",
        "after-checkpoint",
    ] {
        let root = TestRoot::new();
        let profile = profile(&root.0);
        let workdir = root.0.join("runs");
        fs::create_dir(&workdir).expect("workdir");
        let mut run = run_args(&profile, &workdir);
        run.env("WORKFLOW_KIT_TEST_CRASH_BARRIER", barrier);
        let (child, original_identity) = spawn_and_capture(run);
        let crashed = wait(child);
        assert_eq!(
            crashed.status.signal(),
            Some(libc::SIGKILL),
            "barrier {barrier}"
        );

        let run_root = run_root(&workdir);
        let id = run_id(&run_root);
        let (resumed, resumed_identity) = resume(&workdir, &id);
        assert!(resumed.status.success(), "resume at {barrier}: {resumed:?}");
        assert_ne!(
            original_identity, resumed_identity,
            "resume must be a fresh process"
        );

        let journal = EffectJournal::open(run_root.join("effects.sqlite")).expect("journal");
        assert_eq!(
            journal.committed_count().expect("effect count"),
            1,
            "barrier {barrier}"
        );
        let manifest: Value = serde_json::from_slice(
            &fs::read(run_root.join("run-manifest.json")).expect("manifest"),
        )
        .expect("manifest JSON");
        assert_eq!(manifest["status"], "succeeded");
        let artifact_id = manifest["artifact_id"].as_str().expect("artifact id");
        let artifact =
            fs::read(run_root.join("artifacts").join(artifact_id)).expect("terminal artifact");
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(&artifact)),
            artifact_id
        );

        let events = fs::read_to_string(run_root.join("events.jsonl")).expect("events");
        let values = events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
            .collect::<Vec<_>>();
        assert!(!values.is_empty());
        for (index, event) in values.iter().enumerate() {
            assert_eq!(event["sequence"], index as u64 + 1);
        }
        let kinds = values
            .iter()
            .map(|event| event["kind"].as_str().expect("event kind"))
            .collect::<Vec<_>>();
        assert_eq!(kinds.first(), Some(&"workflow_started"));
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == "tool_completed")
                .count(),
            1
        );
        assert_eq!(kinds.last(), Some(&"workflow_completed"));
    }
}

#[test]
fn corrupt_checkpoint_fails_closed_after_a_real_run() {
    let root = TestRoot::new();
    let profile = profile(&root.0);
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("workdir");
    let (child, _) = spawn_and_capture(run_args(&profile, &workdir));
    assert!(wait(child).status.success());
    let run_root = run_root(&workdir);
    let id = run_id(&run_root);
    fs::remove_file(run_root.join("checkpoint.sqlite-wal")).ok();
    fs::remove_file(run_root.join("checkpoint.sqlite-shm")).ok();
    fs::write(run_root.join("checkpoint.sqlite"), b"corrupt checkpoint")
        .expect("corrupt checkpoint");
    let (resumed, _) = resume(&workdir, &id);
    assert!(!resumed.status.success());
}
