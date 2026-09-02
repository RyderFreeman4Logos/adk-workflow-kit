use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::Value;

#[path = "support/owned_tree.rs"]
mod owned_tree;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = owned_tree::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
}

fn example_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/01-code-investigation")
}

fn command(args: &[&str]) -> Output {
    binary()
        .args(args)
        .output()
        .expect("workflowctl must execute")
}

fn temp_root() -> TempRoot {
    let path = std::env::temp_dir().join(format!(
        "m3-06-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).expect("temp root");
    TempRoot(path)
}

fn json_receipt(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "json receipt: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn canonical_package_validates_graphs_and_locks() {
    let example = example_root();
    let workflow = example.join("workflow.toml");
    for relative in [
        "README.md",
        "expected-output.md",
        "input.example.json",
        "profiles/fake.json",
        "replay.json",
        "workflow.toml",
        "prompts/planner.md",
        "prompts/reviewer.md",
        "prompts/reviser.md",
        "schemas/investigation-input.json",
        "schemas/investigation-output.json",
        "skills/code-investigation/SKILL.md",
        "skills/code-investigation/references/grounding.md",
        "skills/code-investigation/scripts/digest.py",
        "repo/Cargo.toml",
        "repo/src/lib.rs",
        "repo/src/retry.rs",
    ] {
        assert!(
            example.join(relative).is_file(),
            "missing canonical package file {relative}"
        );
    }

    let validate = command(&["validate", workflow.to_str().unwrap()]);
    assert!(
        validate.status.success(),
        "validate failed: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert_eq!(validate.stdout, b"valid\n");

    let graph = command(&["graph", workflow.to_str().unwrap(), "--format", "mermaid"]);
    assert!(
        graph.status.success(),
        "graph failed: {}",
        String::from_utf8_lossy(&graph.stderr)
    );
    let mermaid = String::from_utf8(graph.stdout).expect("mermaid UTF-8");
    for node in [
        "planner",
        "search_code",
        "inspect_evidence",
        "review",
        "revise",
        "publish",
        "abstain",
    ] {
        assert!(mermaid.contains(node), "graph omits {node}");
    }

    let lock = command(&["lock", workflow.to_str().unwrap()]);
    assert!(
        lock.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let lock_toml = String::from_utf8(lock.stdout).expect("lock UTF-8");
    assert!(lock_toml.contains("workflow_id = \"code.investigation\""));
}

#[test]
fn fake_profile_covers_run_inspect_resume_and_replay() {
    let example = example_root();
    let workflow = example.join("workflow.toml");
    let profile = example.join("profiles/fake.json");
    let replay = example.join("replay.json");
    let input = fs::read_to_string(example.join("input.example.json")).expect("input");
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");

    let run = command(&[
        "--json",
        "run",
        workflow.to_str().unwrap(),
        "--profile",
        profile.to_str().unwrap(),
        "--input",
        input.trim(),
        "--workdir",
        workdir.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let run_receipt = json_receipt(&run);
    assert_eq!(run_receipt["workflow_id"], "code.investigation");
    assert_eq!(run_receipt["status"], "succeeded");
    assert_eq!(run_receipt["resume_count"], 0);
    let run_id = run_receipt["run_id"].as_str().expect("run_id");

    let inspect = command(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        workdir.to_str().unwrap(),
    ]);
    assert!(
        inspect.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_receipt = json_receipt(&inspect);
    assert_eq!(inspect_receipt["run_id"], run_id);
    assert_eq!(inspect_receipt["status"], "succeeded");

    let resume = command(&[
        "--json",
        "resume",
        "--run-id",
        run_id,
        "--workdir",
        workdir.to_str().unwrap(),
    ]);
    assert!(
        resume.status.success(),
        "resume failed: {}",
        String::from_utf8_lossy(&resume.stderr)
    );
    let resume_receipt = json_receipt(&resume);
    assert_eq!(resume_receipt["run_id"], run_id);
    assert_eq!(resume_receipt["resume_count"], 1);
    assert_eq!(resume_receipt["status"], "succeeded");

    let replayed = command(&["--json", "replay", replay.to_str().unwrap()]);
    assert!(
        replayed.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let replay_receipt = json_receipt(&replayed);
    assert_eq!(replay_receipt["disposition"], "replay_run");
    assert!(replay_receipt["fixture_count"].as_u64().unwrap() > 0);
}
