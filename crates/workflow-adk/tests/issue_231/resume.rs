use super::{ExecutionBackend, Root, WORKFLOW, events, input, run};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
use workflow_adk::execution::ExecutionErrorKind;

struct ResumeChild(Child);

impl ResumeChild {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().expect("resume child status") {
                return status;
            }
            assert!(Instant::now() < deadline, "resume refusal must be bounded");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ResumeChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // SAFETY: the unreaped child owns the process group created at spawn.
            unsafe { libc::kill(-(self.0.id() as libc::pid_t), libc::SIGKILL) };
        }
        let _ = self.0.wait();
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).expect("run directory") {
            let entry = entry.expect("run entry");
            if entry.file_type().expect("run entry type").is_dir() {
                collect(root, &entry.path(), files);
            } else {
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).expect("durable run file"),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

#[test]
fn fresh_process_resume_entry() {
    let Some(root) = std::env::var_os("WORKFLOW_231_RESUME_ROOT") else {
        return;
    };
    let run_id = std::env::var("WORKFLOW_231_RESUME_ID").expect("parent run identity");
    let root = PathBuf::from(root);
    let error =
        ExecutionBackend::resume(&root, &run_id).expect_err("one-shot preparation cannot resume");
    fs::write(
        root.join("resume-result.json"),
        serde_json::to_vec(&serde_json::json!({
            "kind":format!("{:?}", error.kind()),
            "receipt":error.receipt().is_some(),
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn public_resume_preserves_completed_sentinel_history() {
    let root = Root::new();
    let (_, path) = run(&root, WORKFLOW, input(b"1"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("run-manifest.json")).unwrap()).unwrap();
    let run_id = manifest["run_id"].as_str().unwrap();
    let runs = root.0.join("runs");
    let before_receipt = ExecutionBackend::inspect(&runs, run_id).unwrap();
    assert_eq!(before_receipt.status(), "succeeded");
    let before = snapshot(&path);
    assert!(before.contains_key(Path::new("checkpoint.sqlite")));
    let mut child = ResumeChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "resume::fresh_process_resume_entry",
                "--nocapture",
            ])
            .env("WORKFLOW_231_RESUME_ROOT", &runs)
            .env("WORKFLOW_231_RESUME_ID", run_id)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn()
            .expect("fresh process resume"),
    );
    assert!(child.wait().success());
    let after = snapshot(&path);
    let changed: Vec<_> = before
        .keys()
        .chain(after.keys())
        .filter(|name| before.get(*name) != after.get(*name))
        .collect();
    assert!(
        changed.is_empty(),
        "resume changed durable files: {changed:?}"
    );
    let refused: serde_json::Value =
        serde_json::from_slice(&fs::read(runs.join("resume-result.json")).unwrap()).unwrap();
    assert_eq!(refused["kind"], "InvalidRunState");
    assert_eq!(refused["receipt"], false, "refusal is not a new execution");
    assert_eq!(
        ExecutionBackend::inspect(&runs, run_id).unwrap(),
        before_receipt
    );
    assert!(!events(&path).iter().any(|event| {
        event["kind"]
            .as_str()
            .is_some_and(|kind| kind.starts_with("model_") || kind.starts_with("tool_"))
    }));
    assert_eq!(
        ExecutionBackend::resume(&runs, "missing")
            .unwrap_err()
            .kind(),
        ExecutionErrorKind::RunNotFound
    );
}
