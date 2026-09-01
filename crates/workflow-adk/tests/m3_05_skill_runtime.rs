use std::{
    env, fs,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::json;
use sha2::{Digest, Sha256};
use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "skill-tools"
version = "1"
entry = "work"
[[nodes]]
id = "work"
kind = "agent"
model = { role = "worker", id = "worker", version = "1" }
skills = [{ id = "code-investigation", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "work"
to = "done"
"#;

const SKILL: &[u8] = b"---\nname: code-investigation\ndescription: A test skill.\n---\n# Instructions\nUse the declared tools.\n";
const SCRIPT: &[u8] =
    b"import json, sys\nprint(json.dumps({'value': json.load(sys.stdin)['value']}))\n";
const SCHEMA: &[u8] = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}"#;
const GUIDE: &[u8] = b"Declared guide\n";

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "m3-05-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    root
}

fn cleanup_test_root(path: &Path) {
    let metadata = fs::symlink_metadata(path).expect("test root metadata");
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        for entry in fs::read_dir(path).expect("test root entries") {
            cleanup_test_root(&entry.expect("test root entry").path());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("test root directory unlock");
    }
}

fn any_file_contains(root: &Path, marker: &str) -> bool {
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                any_file_contains(&path, marker)
            } else {
                fs::read(&path).is_ok_and(|bytes| String::from_utf8_lossy(&bytes).contains(marker))
            }
        })
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn skill_package(root: &std::path::Path) -> PathBuf {
    let package = root.join("code-investigation");
    fs::create_dir(&package).unwrap();
    fs::create_dir(package.join("scripts")).unwrap();
    fs::create_dir(package.join("references")).unwrap();
    fs::create_dir(package.join("assets")).unwrap();
    fs::write(package.join("SKILL.md"), SKILL).unwrap();
    fs::write(package.join("scripts/content.bin"), SCRIPT).unwrap();
    fs::write(package.join("references/schema.json"), SCHEMA).unwrap();
    fs::write(package.join("assets/guide.txt"), GUIDE).unwrap();
    fs::write(
        package.join("skill.runtime.toml"),
        format!(
            "schema_version = 1\n\
             [skill]\n\
             id = \"code-investigation\"\n\
             version = \"1\"\n\
             [[scripts]]\n\
             id = \"answer\"\n\
             path = \"scripts/content.bin\"\n\
             runtime = \"python3\"\n\
             sha256 = \"{}\"\n\
             input_schema = \"references/schema.json\"\n\
             output_schema = \"references/schema.json\"\n\
             capabilities = [\"filesystem.read\", \"process.spawn\", \"limit.output_bytes\"]\n\
             [[resources]]\n\
             id = \"references/schema.json\"\n\
             sha256 = \"{}\"\n\
             [[resources]]\n\
             id = \"assets/guide.txt\"\n\
             sha256 = \"{}\"\n",
            digest(SCRIPT),
            digest(SCHEMA),
            digest(GUIDE),
        ),
    )
    .unwrap();
    package
}

fn skill_package_named(root: &std::path::Path, id: &str) -> PathBuf {
    let package = root.join(id);
    fs::create_dir(&package).unwrap();
    fs::create_dir(package.join("scripts")).unwrap();
    fs::create_dir(package.join("references")).unwrap();
    fs::create_dir(package.join("assets")).unwrap();
    fs::write(
        package.join("SKILL.md"),
        String::from_utf8(SKILL.to_vec())
            .unwrap()
            .replace("code-investigation", id),
    )
    .unwrap();
    fs::write(package.join("scripts/content.bin"), SCRIPT).unwrap();
    fs::write(package.join("references/schema.json"), SCHEMA).unwrap();
    fs::write(package.join("assets/guide.txt"), GUIDE).unwrap();
    fs::write(
        package.join("skill.runtime.toml"),
        format!(
            "schema_version = 1\n\
             [skill]\n\
             id = \"{id}\"\n\
             version = \"1\"\n\
             [[scripts]]\n\
             id = \"answer\"\n\
             path = \"scripts/content.bin\"\n\
             runtime = \"python3\"\n\
             sha256 = \"{}\"\n\
             input_schema = \"references/schema.json\"\n\
             output_schema = \"references/schema.json\"\n\
             capabilities = [\"filesystem.read\", \"process.spawn\", \"limit.output_bytes\"]\n\
             [[resources]]\n\
             id = \"references/schema.json\"\n\
             sha256 = \"{}\"\n\
             [[resources]]\n\
             id = \"assets/guide.txt\"\n\
             sha256 = \"{}\"\n",
            digest(SCRIPT),
            digest(SCHEMA),
            digest(GUIDE),
        ),
    )
    .unwrap();
    package
}

fn profile(package: &std::path::Path) -> ExecutionProfileV1 {
    let profile = json!({
        "schema_version": 1,
        "model": {
            "provider": "fake",
            "name": "worker",
            "version": "1",
            "model": "worker",
            "responses": [
                {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]},
                {"calls": [{"id":"read","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/guide.txt","offset":0,"limit":64}}]},
                {"calls": [{"id":"run","name":"run_skill_script","args":{"skill_id":"code-investigation","script_id":"answer","input":{"value":"done"}}}]},
                serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
            ]
        },
        "skills": [{"id":"code-investigation","version":"1","root":package}],
        "sandbox": {"capabilities":["filesystem.read","process.spawn","limit.output_bytes"]}
    });
    ExecutionProfileV1::parse(&serde_json::to_vec(&profile).unwrap()).unwrap()
}

fn resume_profile(package: &std::path::Path) -> ExecutionProfileV1 {
    let mut value = serde_json::to_value(profile(package)).unwrap();
    value["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]},
        {"calls": [{"id":"read","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/guide.txt","offset":0,"limit":64}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
    ]);
    ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn script_only_profile(package: &std::path::Path) -> ExecutionProfileV1 {
    let mut value = serde_json::to_value(profile(package)).unwrap();
    value["model"]["responses"] = json!([
        {"calls": [{"id":"run","name":"run_skill_script","args":{"skill_id":"code-investigation","script_id":"answer","input":{"value":"admitted-script-input-must-not-persist"}}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
    ]);
    ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

#[test]
fn fake_model_activates_reads_and_runs_declared_skill() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();

    let receipt = ExecutionBackend::run(&workflow, profile(&package), json!({}), &root).unwrap();
    let events = fs::read_to_string(receipt.run_root().join("events.jsonl")).unwrap();
    let ledger = fs::read_to_string(receipt.run_root().join("loop-ledger.json")).unwrap();
    assert_eq!(receipt.status(), "succeeded");
    for name in ["activate_skill", "read_skill_resource", "run_skill_script"] {
        assert!(events.contains(name), "missing {name} event");
        assert!(ledger.contains(name), "missing {name} ledger entry");
    }
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn activate_and_read_deliver_bounded_content_to_agent() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();

    let receipt = ExecutionBackend::run(&workflow, profile(&package), json!({}), &root).unwrap();
    let events = fs::read_to_string(receipt.run_root().join("events.jsonl")).unwrap();
    assert!(events.contains("# Instructions"));
    assert!(events.contains("Declared guide"));
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn undeclared_skill_resource_or_capability_fails_before_effect() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();

    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["model"]["responses"] = json!([
        {"calls": [{"id":"read","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/undeclared.txt","offset":0,"limit":64}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"must_not":"run"}})).unwrap()
    ]);
    let denied_profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    let error = ExecutionBackend::run(&workflow, denied_profile, json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::AuthorizationDenied);
    assert!(
        !fs::read_to_string(error.receipt().unwrap().run_root().join("events.jsonl"))
            .unwrap()
            .contains("run_skill_script")
    );

    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["sandbox"]["capabilities"] = json!(["filesystem.read"]);
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    let error = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::SandboxDenied);
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn child_sandbox_denies_widening_and_bounds_output() {
    let root = root();
    let package = skill_package(&root);
    let script = b"import json\nprint(json.dumps({'value': 'x' * 1024}))\n";
    fs::write(package.join("scripts/content.bin"), script).unwrap();
    let runtime_path = package.join("skill.runtime.toml");
    let runtime = fs::read_to_string(&runtime_path).unwrap();
    fs::write(
        &runtime_path,
        runtime.replace(&digest(SCRIPT), &digest(script)),
    )
    .unwrap();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();

    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["sandbox"]["capabilities"] = json!([
        "filesystem.read",
        "process.spawn",
        "limit.output_bytes",
        "network"
    ]);
    value["loop_policy"] = json!({
        "schema_version": 1,
        "max_model_iterations": 4,
        "max_total_tool_calls": 4,
        "max_tool_calls_per_tool": 4,
        "wall_time_ms": 1_000,
        "idle_time_ms": 1_000,
        "tool_time_ms": 1_000,
        "max_tool_output_bytes": 32
    });
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    let error = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ToolOutputBytesLimit);
    assert!(
        !fs::read_to_string(error.receipt().unwrap().run_root().join("events.jsonl"))
            .unwrap()
            .contains("tool_completed")
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn unchanged_skill_package_resumes_from_snapshot() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();

    let receipt = ExecutionBackend::run(&workflow, profile(&package), json!({}), &root).unwrap();
    let resumed = ExecutionBackend::resume(&root, receipt.run_id()).unwrap();
    assert_eq!(resumed.status(), "succeeded");
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn crashed_unchanged_skill_package_resumes_from_snapshot() {
    if let Ok(root) = env::var("M3_05_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            &workflow,
            profile(&root.join("code-investigation")),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let root = root();
    skill_package(&root);
    let status = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "crashed_unchanged_skill_package_resumes_from_snapshot",
            "--nocapture",
        ])
        .env("M3_05_CRASH_RUN_ROOT", &root)
        .env("WORKFLOW_KIT_TEST_CRASH_BARRIER", "after-checkpoint")
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    let run_root = fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("run-manifest.json").is_file())
        .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"], "running");
    let resumed = ExecutionBackend::resume(&root, manifest["run_id"].as_str().unwrap()).unwrap();
    assert_eq!(resumed.status(), "succeeded");
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn reviewer_skill_rejection_precedes_run_effects() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(
        &workflow,
        WORKFLOW.replace("role = \"worker\"", "role = \"reviewer\""),
    )
    .unwrap();
    let entries_before = fs::read_dir(&root).unwrap().count();
    let error = ExecutionBackend::run(&workflow, profile(&package), json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Compile);
    assert_eq!(fs::read_dir(&root).unwrap().count(), entries_before);
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn changed_skill_content_rejects_resume() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let receipt = ExecutionBackend::run(&workflow, profile(&package), json!({}), &root).unwrap();

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["implementation_identities"]["skill.code-investigation.activation"],
        "code-investigation:1"
    );
    assert_eq!(
        manifest["resource_hashes"]["skill.code-investigation.skill_markdown"],
        digest(SKILL)
    );
    assert_eq!(
        manifest["resource_hashes"]["skill.code-investigation.script.answer"],
        digest(SCRIPT)
    );
    assert_eq!(
        manifest["resource_hashes"]["skill.code-investigation.resource.assets/guide.txt"],
        digest(GUIDE)
    );

    fs::write(receipt.run_root().join("sealed-skill-snapshot.json"), b"{}").unwrap();
    let error = ExecutionBackend::resume(&root, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn node_skill_subset_denies_sibling_skill_before_effect() {
    let root = root();
    let allowed = skill_package(&root);
    let sibling = skill_package_named(&root, "sibling-skill");
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let mut value = serde_json::to_value(profile(&allowed)).unwrap();
    value["skills"] = json!([
        {"id":"code-investigation","version":"1","root":allowed},
        {"id":"sibling-skill","version":"1","root":sibling}
    ]);
    value["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"sibling-skill"}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"must_not":"run"}})).unwrap()
    ]);
    let denied_profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();

    let error = ExecutionBackend::run(&workflow, denied_profile, json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::AuthorizationDenied);
    assert!(
        !fs::read_to_string(error.receipt().unwrap().run_root().join("events.jsonl"))
            .unwrap()
            .contains("skill_activated")
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn skill_tool_unknown_fields_fail_before_effect() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation","unexpected":true}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"must_not":"run"}})).unwrap()
    ]);
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();

    let error = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::AuthorizationDenied);
    assert!(
        !fs::read_to_string(error.receipt().unwrap().run_root().join("events.jsonl"))
            .unwrap()
            .contains("skill_activated")
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn skill_instructions_are_not_loaded_before_activate() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["model"]["responses"] = json!([
        {"calls": [{"id":"read","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/guide.txt","offset":0,"limit":64}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"must_not":"run"}})).unwrap()
    ]);
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();

    let error = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::AuthorizationDenied);
    assert!(
        !fs::read_to_string(error.receipt().unwrap().run_root().join("events.jsonl"))
            .unwrap()
            .contains("# Instructions")
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn run_skill_script_is_not_read_only_when_script_declares_effects() {
    let root = root();
    let package = skill_package(&root);
    let runtime_path = package.join("skill.runtime.toml");
    let runtime = fs::read_to_string(&runtime_path).unwrap();
    fs::write(
        &runtime_path,
        runtime.replace(
            "capabilities = [\"filesystem.read\", \"process.spawn\", \"limit.output_bytes\"]",
            "capabilities = [\"filesystem.read\", \"filesystem.write\", \"process.spawn\", \"limit.output_bytes\"]",
        ),
    )
    .unwrap();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["sandbox"]["capabilities"] = json!([
        "filesystem.read",
        "filesystem.write",
        "process.spawn",
        "limit.output_bytes"
    ]);
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();

    let error = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::AuthorizationDenied);
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn selected_script_id_not_lexicographic_first_is_executed() {
    let root = root();
    let package = skill_package(&root);
    let selected = b"import json, sys\nprint(json.dumps({'value': 'selected'}))\n";
    fs::write(package.join("scripts/z-selected.bin"), selected).unwrap();
    let runtime_path = package.join("skill.runtime.toml");
    let runtime = fs::read_to_string(&runtime_path).unwrap();
    fs::write(
        &runtime_path,
        format!(
            "{runtime}[[scripts]]\nid = \"z-selected\"\npath = \"scripts/z-selected.bin\"\nruntime = \"python3\"\nsha256 = \"{}\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\ncapabilities = [\"filesystem.read\", \"process.spawn\", \"limit.output_bytes\"]\n",
            digest(selected),
        ),
    )
    .unwrap();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]},
        {"calls": [{"id":"run","name":"run_skill_script","args":{"skill_id":"code-investigation","script_id":"z-selected","input":{"value":"done"}}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
    ]);
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();

    let receipt = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap();
    assert_eq!(receipt.status(), "succeeded");
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn durable_surfaces_omit_paths_raw_args_and_stdout() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]},
        {"calls": [{"id":"run","name":"run_skill_script","args":{"skill_id":"code-investigation","script_id":"answer","input":{"value":"raw-argument-marker"}}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
    ]);
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();

    let receipt = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap();
    let durable = [
        "events.jsonl",
        "loop-ledger.json",
        "checkpoint-manifest.json",
        "execution-profile.json",
        "run-manifest.json",
    ]
    .into_iter()
    .map(|name| fs::read(receipt.run_root().join(name)).unwrap())
    .collect::<Vec<_>>();
    for marker in [package.to_string_lossy().as_ref(), "raw-argument-marker"] {
        assert!(
            durable
                .iter()
                .all(|bytes| !String::from_utf8_lossy(bytes).contains(marker)),
            "durable surface retained {marker}",
        );
    }
    assert!(
        durable
            .iter()
            .any(|bytes| String::from_utf8_lossy(bytes).contains(&digest(SCRIPT))),
        "durable surfaces lost script identity",
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn large_skill_stdout_is_absent_from_every_durable_file() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let canary = format!("skill-stdout-canary-{}", "x".repeat(4_096));
    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]},
        {"calls": [{"id":"run","name":"run_skill_script","args":{"skill_id":"code-investigation","script_id":"answer","input":{"value":canary}}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
    ]);
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();

    let receipt = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap();
    assert!(
        !any_file_contains(receipt.run_root(), &canary),
        "durable run files retained Skill stdout"
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn crashed_skill_admission_or_activation_resumes_without_widening() {
    if let Ok(root) = env::var("M3_05_SKILL_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            &workflow,
            resume_profile(&root.join("code-investigation")),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    for barrier in ["after-skill-call-admission", "after-skill-activation"] {
        let root = root();
        skill_package(&root);
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "crashed_skill_admission_or_activation_resumes_without_widening",
                "--nocapture",
            ])
            .env("M3_05_SKILL_CRASH_RUN_ROOT", &root)
            .env("WORKFLOW_KIT_TEST_CRASH_BARRIER", barrier)
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{barrier}");
        let run_root = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("run-manifest.json").is_file())
            .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
        let resumed =
            ExecutionBackend::resume(&root, manifest["run_id"].as_str().unwrap()).unwrap();
        assert_eq!(resumed.status(), "succeeded", "{barrier}");
        let events = fs::read_to_string(run_root.join("events.jsonl")).unwrap();
        assert!(events.contains("read_skill_resource"), "{barrier}");
        assert!(!events.contains("authorization_denied"), "{barrier}");
        cleanup_test_root(&root);
        fs::remove_dir_all(root).expect("test cleanup");
    }
}

#[test]
fn admitted_script_call_is_bound_or_resume_fails_closed() {
    if let Ok(root) = env::var("M3_05_SCRIPT_CRASH_RUN_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let _ = ExecutionBackend::run(
            &workflow,
            script_only_profile(&root.join("code-investigation")),
            json!({}),
            root,
        );
        panic!("crash barrier did not terminate the child");
    }

    let root = root();
    skill_package(&root);
    let status = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "admitted_script_call_is_bound_or_resume_fails_closed",
            "--nocapture",
        ])
        .env("M3_05_SCRIPT_CRASH_RUN_ROOT", &root)
        .env(
            "WORKFLOW_KIT_TEST_CRASH_BARRIER",
            "after-skill-call-admission",
        )
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    let run_root = fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("run-manifest.json").is_file())
        .unwrap();
    let ledger = fs::read_to_string(run_root.join("loop-ledger.json")).unwrap();
    assert!(ledger.contains("run_skill_script"));
    assert!(!ledger.contains("admitted-script-input-must-not-persist"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
    let error = ExecutionBackend::resume(&root, manifest["run_id"].as_str().unwrap()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[cfg(unix)]
#[test]
fn package_file_symlinks_fail_closed_before_effect() {
    for intermediate in [false, true] {
        let root = root();
        let package = skill_package(&root);
        let profile = profile(&package);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let outside = root.join("outside");
        if intermediate {
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("content.bin"), SCRIPT).unwrap();
            fs::remove_file(package.join("scripts/content.bin")).unwrap();
            fs::remove_dir(package.join("scripts")).unwrap();
            std::os::unix::fs::symlink(&outside, package.join("scripts")).unwrap();
        } else {
            fs::write(&outside, SCRIPT).unwrap();
            fs::remove_file(package.join("scripts/content.bin")).unwrap();
            std::os::unix::fs::symlink(&outside, package.join("scripts/content.bin")).unwrap();
        }

        let error = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap_err();
        assert_eq!(error.kind(), ExecutionErrorKind::ImplementationBinding);
        cleanup_test_root(&root);
        fs::remove_dir_all(root).expect("test cleanup");
    }
}

#[test]
fn symlink_or_replaced_package_fails_closed_before_effect() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let profile = profile(&package);
    let replacement_root = root.join("replacement");
    fs::create_dir(&replacement_root).unwrap();
    let replacement = skill_package(&replacement_root);
    fs::remove_dir_all(&package).unwrap();
    std::os::unix::fs::symlink(&replacement, &package).unwrap();

    let error = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ImplementationBinding);
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}
