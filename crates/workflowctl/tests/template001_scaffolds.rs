use std::{fs, path::Path, process::Command};

#[path = "support/owned_tree.rs"]
mod owned_tree;

const CANARY_SCAFFOLD_NEW_57: &str = "CANARY_SCAFFOLD_NEW_57";
const CANARY_SCAFFOLD_MISS_57: &str = "CANARY_SCAFFOLD_MISS_57";
const CANARY_SKILL_INVALID_57: &str = "CANARY_SKILL_INVALID_57";

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../");
const WORKFLOW: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/minimal/workflow.toml"
);
const TEST_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/minimal/tests/offline.json"
);
const SKILL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../skills/offline-workflow");

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
        .args(args)
        .output()
        .expect("workflowctl should start")
}

#[test]
fn new_workflow_scaffold_passes_offline_validation_and_test() {
    let validation = run(&["validate", WORKFLOW]);
    assert!(
        validation.status.success(),
        "{CANARY_SCAFFOLD_NEW_57}: validation failed: {}",
        String::from_utf8_lossy(&validation.stderr)
    );
    let offline_test = run(&["test", TEST_FIXTURE]);
    assert!(
        offline_test.status.success(),
        "{CANARY_SCAFFOLD_NEW_57}: offline test failed: {}",
        String::from_utf8_lossy(&offline_test.stderr)
    );
}

#[test]
fn missing_scaffold_is_a_typed_miss_not_a_success() {
    let missing = Path::new(ROOT).join("templates/missing-57/workflow.toml");
    let output = run(&["validate", missing.to_str().expect("UTF-8 path")]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{CANARY_SCAFFOLD_MISS_57}");
    assert!(stderr.contains("workflow.source.read_failed"));
    assert!(!stderr.contains(CANARY_SCAFFOLD_MISS_57));
}

#[test]
fn invalid_developer_skill_fails_closed_without_clean_load() {
    let output = run(&["skill", "lint", SKILL]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{CANARY_SKILL_INVALID_57}: scaffold skill must be valid: {stderr}"
    );
    assert!(!stderr.contains(CANARY_SKILL_INVALID_57));

    let invalid = tempfile_skill();
    fs::write(invalid.join("SKILL.md"), CANARY_SKILL_INVALID_57).expect("write invalid skill");
    let invalid_output = run(&["skill", "lint", invalid.to_str().expect("UTF-8 path")]);
    let invalid_stderr = String::from_utf8_lossy(&invalid_output.stderr);
    assert_eq!(invalid_output.status.code(), Some(2));
    assert!(invalid_stderr.contains("skill.cli.invalid_manifest"));
    assert!(!invalid_stderr.contains(CANARY_SKILL_INVALID_57));
    owned_tree::remove_dir_all(&invalid).expect("remove invalid skill");
}

fn tempfile_skill() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("template001-invalid-57-{}", std::process::id()));
    fs::create_dir_all(&path).expect("create invalid skill directory");
    path
}
