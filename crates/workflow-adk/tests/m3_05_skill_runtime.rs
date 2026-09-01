use std::{
    fs,
    path::PathBuf,
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
    let _ = fs::remove_dir_all(root);
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
    let _ = fs::remove_dir_all(root);
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
    let _ = fs::remove_dir_all(root);
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

    let changed = b"import json\nprint(json.dumps({'value': 'changed'}))\n";
    fs::write(package.join("scripts/content.bin"), changed).unwrap();
    let runtime_path = package.join("skill.runtime.toml");
    let runtime = fs::read_to_string(&runtime_path).unwrap();
    fs::write(
        &runtime_path,
        runtime.replace(&digest(SCRIPT), &digest(changed)),
    )
    .unwrap();
    let error = ExecutionBackend::resume(&root, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    let _ = fs::remove_dir_all(root);
}
