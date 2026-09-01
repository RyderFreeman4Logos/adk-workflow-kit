use std::{
    env, fs,
    io::Write,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::Connection;
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

const MIXED_WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "mixed-skill-tools"
version = "1"
entry = "work"
[[nodes]]
id = "work"
kind = "agent"
model = { role = "worker", id = "worker", version = "1" }
tools = [{ id = "search_code", version = "1" }]
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

fn assert_paired_skill_transcript(ledger: &serde_json::Value) {
    let mut calls = std::collections::BTreeSet::new();
    for content in ledger["nodes"]["work"]["conversation"]
        .as_array()
        .expect("durable Skill transcript")
    {
        for part in content["parts"]
            .as_array()
            .expect("durable transcript parts")
        {
            if let Some(call) = part.get("function_call") {
                calls.insert(call["id"].as_str().expect("Skill call ID"));
            }
            if let Some(response) = part.get("function_response") {
                assert!(
                    calls.contains(response["id"].as_str().expect("Skill response ID")),
                    "resumed model request contains an orphan Skill response"
                );
            }
        }
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

fn large_read_profile(
    package: &std::path::Path,
    page_bytes: u64,
    read_count: u64,
) -> ExecutionProfileV1 {
    let mut value = serde_json::to_value(profile(package)).unwrap();
    value["loop_policy"] = json!({
        "schema_version": 1,
        "max_model_iterations": 4,
        "max_total_tool_calls": 3,
        "max_tool_calls_per_tool": 3,
        "wall_time_ms": 1_000,
        "idle_time_ms": 1_000,
        "tool_time_ms": 1_000,
        "max_tool_output_bytes": 262_144
    });
    let mut responses = vec![
        json!({"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]}),
        json!({"calls": [{"id":"read-0","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/guide.txt","offset":0,"limit":page_bytes}}]}),
    ];
    if read_count == 2 {
        responses.push(json!({"calls": [{"id":"read-1","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/guide.txt","offset":page_bytes,"limit":page_bytes}}]}));
    }
    responses.push(json!(
        serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
    ));
    value["model"]["responses"] = json!(responses);
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

fn mixed_profile(package: &std::path::Path) -> ExecutionProfileV1 {
    let mut value = serde_json::to_value(profile(package)).unwrap();
    value["tools"] = json!([{
        "name": "search_code",
        "result": {"found": true},
        "input_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": false
        }
    }]);
    value["model"]["responses"] = json!([
        {"calls": [
            {"id":"ordinary","name":"search_code","args":{"query":"must-not-persist"}},
            {"id":"skill","name":"run_skill_script","args":{"skill_id":"code-investigation","script_id":"answer","input":{"value":"must-not-run"}}}
        ]},
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
fn read_skill_resource_enforces_one_budget_per_activation() {
    let root = root();
    let package = skill_package(&root);
    let guide = vec![b'x'; 65_536];
    fs::write(package.join("assets/guide.txt"), &guide).unwrap();
    let runtime_path = package.join("skill.runtime.toml");
    let runtime = fs::read_to_string(&runtime_path).unwrap();
    fs::write(
        &runtime_path,
        runtime.replace(&digest(GUIDE), &digest(&guide)),
    )
    .unwrap();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let mut value = serde_json::to_value(profile(&package)).unwrap();
    value["loop_policy"] = json!({
        "schema_version": 1,
        "max_model_iterations": 5,
        "max_total_tool_calls": 4,
        "max_tool_calls_per_tool": 4,
        "wall_time_ms": 1_000,
        "idle_time_ms": 1_000,
        "tool_time_ms": 1_000,
        "max_tool_output_bytes": 262_144
    });
    value["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]},
        {"calls": [{"id":"read-first","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/guide.txt","offset":0,"limit":32768}}]},
        {"calls": [{"id":"read-second","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/guide.txt","offset":32768,"limit":32768}}]},
        {"calls": [{"id":"read-over-budget","name":"read_skill_resource","args":{"skill_id":"code-investigation","resource_id":"assets/guide.txt","offset":0,"limit":1}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
    ]);

    let error = ExecutionBackend::run(
        &workflow,
        ExecutionProfileV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap(),
        json!({}),
        &root,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Tool);
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
fn selected_read_only_script_runs_while_effectful_sibling_requires_approval() {
    let root = root();
    let package = skill_package(&root);
    let runtime_path = package.join("skill.runtime.toml");
    let runtime = fs::read_to_string(&runtime_path).unwrap();
    fs::write(package.join("scripts/write.bin"), SCRIPT).unwrap();
    fs::write(
        &runtime_path,
        format!(
            "{runtime}[[scripts]]\nid = \"write\"\npath = \"scripts/write.bin\"\nruntime = \"python3\"\nsha256 = \"{}\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\ncapabilities = [\"filesystem.read\", \"filesystem.write\", \"process.spawn\", \"limit.output_bytes\"]\n",
            digest(SCRIPT),
        ),
    )
    .unwrap();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();

    let mut read_only = serde_json::to_value(profile(&package)).unwrap();
    read_only["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]},
        {"calls": [{"id":"run","name":"run_skill_script","args":{"skill_id":"code-investigation","script_id":"answer","input":{"value":"done"}}}]},
        serde_json::to_string(&json!({"status":"finished","output":{"ok":true}})).unwrap()
    ]);
    let receipt = ExecutionBackend::run(
        &workflow,
        ExecutionProfileV1::parse(&serde_json::to_vec(&read_only).unwrap()).unwrap(),
        json!({}),
        &root,
    )
    .unwrap();
    assert_eq!(receipt.status(), "succeeded");

    let mut effectful = serde_json::to_value(profile(&package)).unwrap();
    effectful["sandbox"]["capabilities"] = json!([
        "filesystem.read",
        "filesystem.write",
        "process.spawn",
        "limit.output_bytes"
    ]);
    effectful["model"]["responses"] = json!([
        {"calls": [{"id":"activate","name":"activate_skill","args":{"skill_id":"code-investigation"}}]},
        {"calls": [{"id":"run","name":"run_skill_script","args":{"skill_id":"code-investigation","script_id":"write","input":{"value":"must-not-run"}}}]}
    ]);
    let error = ExecutionBackend::run(
        &workflow,
        ExecutionProfileV1::parse(&serde_json::to_vec(&effectful).unwrap()).unwrap(),
        json!({}),
        &root,
    )
    .unwrap_err();
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

    let baseline_root = root();
    let baseline_package = skill_package(&baseline_root);
    let baseline_workflow = baseline_root.join("workflow.toml");
    fs::write(&baseline_workflow, WORKFLOW).unwrap();
    unsafe {
        env::set_var("WORKFLOW_KIT_TEST_MODEL_CONTENTS_DIGEST", "1");
    }
    let baseline = ExecutionBackend::run(
        &baseline_workflow,
        resume_profile(&baseline_package),
        json!({}),
        &baseline_root,
    )
    .unwrap();
    unsafe {
        env::remove_var("WORKFLOW_KIT_TEST_MODEL_CONTENTS_DIGEST");
    }
    let baseline_digest =
        fs::read_to_string(baseline.run_root().join("model-contents-digest")).unwrap();
    assert_eq!(baseline.status(), "succeeded");
    cleanup_test_root(&baseline_root);
    fs::remove_dir_all(baseline_root).expect("baseline cleanup");

    for (barrier, exact_transcript) in [
        ("after-skill-call-admission", false),
        ("after-skill-activation", false),
        ("after-skill-call-completion-activate_skill", true),
        ("after-skill-call-completion-read_skill_resource", true),
    ] {
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
            .env("WORKFLOW_KIT_TEST_MODEL_CONTENTS_DIGEST", "1")
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{barrier}");
        let run_root = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("run-manifest.json").is_file())
            .unwrap();
        let digest_path = run_root.join("model-contents-digest");
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
        unsafe {
            env::set_var("WORKFLOW_KIT_TEST_MODEL_CONTENTS_DIGEST", "1");
        }
        let resumed =
            ExecutionBackend::resume(&root, manifest["run_id"].as_str().unwrap()).unwrap();
        unsafe {
            env::remove_var("WORKFLOW_KIT_TEST_MODEL_CONTENTS_DIGEST");
        }
        assert_eq!(resumed.status(), "succeeded", "{barrier}");
        let events = fs::read_to_string(run_root.join("events.jsonl")).unwrap();
        if exact_transcript {
            assert_eq!(
                fs::read_to_string(&digest_path).unwrap(),
                baseline_digest,
                "{barrier}"
            );
        } else {
            assert!(events.contains("read_skill_resource"), "{barrier}");
        }
        assert!(!events.contains("authorization_denied"), "{barrier}");
        let ledger: serde_json::Value =
            serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).unwrap()).unwrap();
        assert_paired_skill_transcript(&ledger);
        cleanup_test_root(&root);
        fs::remove_dir_all(root).expect("test cleanup");
    }
}

#[test]
fn completed_skill_resource_reads_resume_without_recharging_budget() {
    if let Ok(root) = env::var("M3_05_LARGE_READ_CRASH_ROOT") {
        let root = PathBuf::from(root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let page_bytes = env::var("M3_05_LARGE_READ_BYTES").unwrap().parse().unwrap();
        let read_count = env::var("M3_05_LARGE_READ_COUNT").unwrap().parse().unwrap();
        match ExecutionBackend::run(
            &workflow,
            large_read_profile(&root.join("code-investigation"), page_bytes, read_count),
            json!({}),
            root,
        ) {
            Ok(_) => panic!("crash barrier did not terminate the child"),
            Err(error) => panic!("crash barrier was not reached: {:?}", error.kind()),
        }
    }

    for (page_bytes, read_count) in [(40 * 1_024, 1), (32 * 1_024, 2)] {
        let root = root();
        let package = skill_package(&root);
        let charged_bytes = page_bytes * read_count;
        let guide = vec![b'x'; charged_bytes];
        fs::write(package.join("assets/guide.txt"), &guide).unwrap();
        let runtime_path = package.join("skill.runtime.toml");
        fs::write(
            &runtime_path,
            format!(
                "schema_version = 1\n\
                 [skill]\n\
                 id = \"code-investigation\"\n\
                 version = \"1\"\n\
                 [[resources]]\n\
                 id = \"assets/guide.txt\"\n\
                 sha256 = \"{}\"\n",
                digest(&guide),
            ),
        )
        .unwrap();
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "completed_skill_resource_reads_resume_without_recharging_budget",
                "--nocapture",
            ])
            .env("M3_05_LARGE_READ_CRASH_ROOT", &root)
            .env("M3_05_LARGE_READ_BYTES", page_bytes.to_string())
            .env("M3_05_LARGE_READ_COUNT", read_count.to_string())
            .env(
                "WORKFLOW_KIT_TEST_CRASH_BARRIER",
                if read_count == 1 {
                    "after-skill-call-completion-read_skill_resource"
                } else {
                    "after-skill-call-completion-read_skill_resource#2"
                },
            )
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{charged_bytes}");
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
        assert_eq!(resumed.status(), "succeeded", "{charged_bytes}");
        let ledger: serde_json::Value =
            serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).unwrap()).unwrap();
        assert_eq!(
            ledger["nodes"]["work"]["skill_resource_read_bytes"]["code-investigation"],
            charged_bytes,
            "completed read must not be charged twice"
        );
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
        let crash_barrier = env::var("M3_05_SCRIPT_CRASH_BARRIER").unwrap();
        let profile = if crash_barrier == "after-skill-call-completion-run_skill_script" {
            profile(&root.join("code-investigation"))
        } else {
            script_only_profile(&root.join("code-investigation"))
        };
        let _ = ExecutionBackend::run(&workflow, profile, json!({}), root);
        panic!("crash barrier did not terminate the child");
    }

    for barrier in [
        "after-skill-call-admission",
        "after-skill-call-completion-run_skill_script",
    ] {
        let root = root();
        skill_package(&root);
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "admitted_script_call_is_bound_or_resume_fails_closed",
                "--nocapture",
            ])
            .env("M3_05_SCRIPT_CRASH_RUN_ROOT", &root)
            .env("M3_05_SCRIPT_CRASH_BARRIER", barrier)
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
        let ledger = fs::read_to_string(run_root.join("loop-ledger.json")).unwrap();
        assert!(ledger.contains("run_skill_script"), "{barrier}");
        assert!(
            !ledger.contains("admitted-script-input-must-not-persist"),
            "{barrier}"
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
        let error =
            ExecutionBackend::resume(&root, manifest["run_id"].as_str().unwrap()).unwrap_err();
        assert_eq!(
            error.kind(),
            ExecutionErrorKind::InvalidRunState,
            "{barrier}"
        );
        cleanup_test_root(&root);
        fs::remove_dir_all(root).expect("test cleanup");
    }
}

#[test]
fn changed_skill_sandbox_capabilities_reject_crash_resume_before_effect() {
    if let Ok(root) = env::var("M3_05_SANDBOX_CRASH_RUN_ROOT") {
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
            "changed_skill_sandbox_capabilities_reject_crash_resume_before_effect",
            "--nocapture",
        ])
        .env("M3_05_SANDBOX_CRASH_RUN_ROOT", &root)
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
    let profile_path = run_root.join("execution-profile.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&profile_path).unwrap()).unwrap();
    stored["sandbox"]["capabilities"] = json!([
        "filesystem.read",
        "network",
        "process.spawn",
        "limit.output_bytes"
    ]);
    fs::write(&profile_path, serde_json::to_vec(&stored).unwrap()).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
    let error = ExecutionBackend::resume(&root, manifest["run_id"].as_str().unwrap()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(
        Connection::open(run_root.join("effects.sqlite"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM kit_effects", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
        0
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn mixed_ordinary_and_skill_calls_fail_before_effect_when_not_durable() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, MIXED_WORKFLOW).unwrap();

    let error =
        ExecutionBackend::run(&workflow, mixed_profile(&package), json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Persistence);
    let run_root = error.receipt().unwrap().run_root();
    assert_eq!(
        Connection::open(run_root.join("effects.sqlite"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM kit_effects", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert!(
        !fs::read_to_string(run_root.join("loop-ledger.json"))
            .unwrap()
            .contains("ordinary")
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn same_inode_same_size_package_mutation_fails_closed() {
    for relative in ["SKILL.md", "skill.runtime.toml"] {
        let root = root();
        let package = skill_package(&root);
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let profile = profile(&package);
        let barrier = root.join("package-file-barrier");
        fs::create_dir(&barrier).unwrap();
        fs::write(barrier.join("target"), relative).unwrap();
        let target = package.join(relative);
        let worker_barrier = barrier.clone();
        let mutation_worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !worker_barrier.join("ready").is_file() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(worker_barrier.join("ready").is_file());
            let original = fs::read_to_string(&target).unwrap();
            let mutated = if relative == "SKILL.md" {
                original.replace("Use the declared tools.", "Run the declared tools.")
            } else {
                original.replace(
                    "\"filesystem.read\", \"process.spawn\"",
                    "\"process.spawn\", \"filesystem.read\"",
                )
            };
            assert_ne!(mutated, original);
            assert_eq!(mutated.len(), original.len());
            fs::write(&target, mutated).unwrap();
            fs::File::options()
                .write(true)
                .open(&target)
                .unwrap()
                .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
                .unwrap();
            fs::write(worker_barrier.join("continue"), b"continue").unwrap();
        });
        let result = ExecutionBackend::run(&workflow, profile, json!({}), &root);
        mutation_worker.join().unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ExecutionErrorKind::ImplementationBinding);
        assert!(
            fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.path().join("sealed-skill-snapshot.json").exists()),
            "{relative} mutation reached snapshot publication"
        );
        cleanup_test_root(&root);
        fs::remove_dir_all(root).expect("test cleanup");
    }
}

#[test]
fn package_replacements_between_validation_and_read_fail_closed() {
    for replacement in ["leaf", "intermediate", "root"] {
        let root = root();
        let package = skill_package(&root);
        let runtime_path = package.join("skill.runtime.toml");
        let runtime = fs::read_to_string(&runtime_path).unwrap();
        fs::write(package.join("scripts/replacement.bin"), SCRIPT).unwrap();
        fs::write(
            &runtime_path,
            format!(
                "{runtime}[[scripts]]\nid = \"replacement\"\npath = \"scripts/replacement.bin\"\nruntime = \"python3\"\nsha256 = \"{}\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\ncapabilities = [\"filesystem.read\", \"process.spawn\", \"limit.output_bytes\"]\n",
                digest(SCRIPT),
            ),
        )
        .unwrap();
        let workflow = root.join("workflow.toml");
        fs::write(&workflow, WORKFLOW).unwrap();
        let profile = profile(&package);
        let barrier = root.join("package-file-barrier");
        fs::create_dir(&barrier).unwrap();
        let replacement_root = root.clone();
        let replacement_package = package.clone();
        let replacement_worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !replacement_root
                .join("package-file-barrier/ready")
                .is_file()
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(
                replacement_root
                    .join("package-file-barrier/ready")
                    .is_file()
            );
            match replacement {
                "leaf" => {
                    fs::rename(
                        replacement_package.join("scripts/replacement.bin"),
                        replacement_package.join("scripts/replacement-original.bin"),
                    )
                    .unwrap();
                    fs::write(replacement_package.join("scripts/replacement.bin"), SCRIPT).unwrap();
                }
                "intermediate" => {
                    fs::rename(
                        replacement_package.join("scripts"),
                        replacement_package.join("scripts-original"),
                    )
                    .unwrap();
                    fs::create_dir(replacement_package.join("scripts")).unwrap();
                    fs::write(replacement_package.join("scripts/content.bin"), SCRIPT).unwrap();
                    fs::write(replacement_package.join("scripts/replacement.bin"), SCRIPT).unwrap();
                }
                "root" => {
                    let displaced = replacement_root.join("displaced-package");
                    fs::rename(&replacement_package, &displaced).unwrap();
                    fs::create_dir(&replacement_package).unwrap();
                    fs::create_dir(replacement_package.join("scripts")).unwrap();
                    fs::write(replacement_package.join("scripts/replacement.bin"), SCRIPT).unwrap();
                }
                _ => unreachable!(),
            }
            fs::write(
                replacement_root.join("package-file-barrier/continue"),
                b"continue",
            )
            .unwrap();
        });
        let error = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap_err();
        replacement_worker.join().unwrap();
        assert_eq!(
            error.kind(),
            ExecutionErrorKind::ImplementationBinding,
            "{replacement}"
        );
        assert!(
            !barrier.join("read-len").exists(),
            "{replacement} package replacement was read before rejection"
        );
        cleanup_test_root(&root);
        fs::remove_dir_all(root).expect("test cleanup");
    }
}

#[test]
fn initial_run_uses_sealed_skill_snapshot_after_package_replacement() {
    let root = root();
    let package = skill_package(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let profile = profile(&package);
    let replacement_root = root.join("replacement");
    fs::create_dir(&replacement_root).unwrap();
    let replacement = skill_package(&replacement_root);
    let replacement_script =
        b"import json\nprint(json.dumps({'value': 'replacement-generation'}))\n";
    fs::write(replacement.join("scripts/content.bin"), replacement_script).unwrap();
    let runtime_path = replacement.join("skill.runtime.toml");
    let runtime = fs::read_to_string(&runtime_path).unwrap();
    fs::write(
        &runtime_path,
        runtime.replace(&digest(SCRIPT), &digest(replacement_script)),
    )
    .unwrap();
    let barrier = root.join("skill-snapshot-barrier");
    fs::create_dir(&barrier).unwrap();
    let replacement_root = root.clone();
    let replacement_package = package.clone();
    let replacement_worker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !replacement_root
            .join("skill-snapshot-barrier/ready")
            .is_file()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            replacement_root
                .join("skill-snapshot-barrier/ready")
                .is_file()
        );
        fs::rename(
            &replacement_package,
            replacement_root.join("displaced-package"),
        )
        .unwrap();
        fs::rename(
            replacement_root.join("replacement/code-investigation"),
            &replacement_package,
        )
        .unwrap();
        fs::write(
            replacement_root.join("skill-snapshot-barrier/continue"),
            b"continue",
        )
        .unwrap();
    });
    unsafe {
        env::set_var("WORKFLOW_KIT_TEST_SKILL_SNAPSHOT_BARRIER", &barrier);
    }
    let receipt = ExecutionBackend::run(&workflow, profile, json!({}), &root).unwrap();
    unsafe {
        env::remove_var("WORKFLOW_KIT_TEST_SKILL_SNAPSHOT_BARRIER");
    }
    replacement_worker.join().unwrap();
    let checkpoint_manifest =
        fs::read_to_string(receipt.run_root().join("checkpoint-manifest.json")).unwrap();
    assert!(checkpoint_manifest.contains(&digest(SCRIPT)));
    assert!(!checkpoint_manifest.contains(&digest(replacement_script)));
    cleanup_test_root(&root);
    fs::remove_dir_all(root).expect("test cleanup");
}

#[test]
fn package_file_growth_is_bounded_before_execution() {
    let root = root();
    let package = skill_package(&root);
    let runtime_path = package.join("skill.runtime.toml");
    let runtime = fs::read_to_string(&runtime_path).unwrap();
    fs::write(package.join("scripts/replacement.bin"), SCRIPT).unwrap();
    fs::write(
        &runtime_path,
        format!(
            "{runtime}[[scripts]]\nid = \"replacement\"\npath = \"scripts/replacement.bin\"\nruntime = \"python3\"\nsha256 = \"{}\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\ncapabilities = [\"filesystem.read\", \"process.spawn\", \"limit.output_bytes\"]\n",
            digest(SCRIPT),
        ),
    )
    .unwrap();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let barrier = root.join("package-file-barrier");
    fs::create_dir(&barrier).unwrap();
    let grown_file = package.join("scripts/replacement.bin");
    let growth_barrier = barrier.clone();
    let growth_worker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !growth_barrier.join("ready").is_file() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(growth_barrier.join("ready").is_file());
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(grown_file)
            .unwrap();
        file.write_all(&vec![b'x'; 65_537]).unwrap();
        fs::write(growth_barrier.join("continue"), b"continue").unwrap();
    });
    let error = ExecutionBackend::run(&workflow, profile(&package), json!({}), &root).unwrap_err();
    growth_worker.join().unwrap();
    assert_eq!(error.kind(), ExecutionErrorKind::ImplementationBinding);
    assert!(
        !barrier.join("read-len").exists(),
        "package file read was not capped before rejection"
    );
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
