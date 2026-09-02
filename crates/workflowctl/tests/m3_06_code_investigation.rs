use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

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
