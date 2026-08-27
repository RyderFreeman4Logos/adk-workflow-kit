use std::{
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};
use workflow_adk::tool_bridge::{AdkToolBridge, RegisteredSkillScript};
use workflow_compiler::{
    ScriptDeniedKind, ScriptExecutionErrorKind, SkillResourceId, SkillRuntimeLock,
    SkillRuntimeManifest,
};
use workflow_runtime::{
    CapabilityIntersection, InMemoryArtifactStore, Materialization, RunContext, RunId, RunLimits,
    RunSandbox, SandboxCapability, SandboxExecutionError, ToolCall, ToolEnvelope, ToolFlags,
    ToolProvenance, ToolRegistration, WorkdirManager,
};

const SCRIPT: &[u8] =
    b"from pathlib import Path\nPath('adapter-marker').write_text('sandbox')\nprint('ok')\n";
const SCHEMA: &[u8] = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}"#;
const SKILL_MARKDOWN: &[u8] =
    b"---\nname: valid-skill\ndescription: A bounded skill.\n---\n# Instructions\n";
const SCRIPT_SHA256: &str =
    "sha256:e3727a4aca441dfdaa881bc93aade3d38b42f63c929ca342f900a4d4667117bf";
const SCHEMA_SHA256: &str =
    "sha256:50eb7b6f8f62ad5dd7fa7904c86da5043e69708b67afce66e0457361a1793a92";

static NEXT_BASE: AtomicU64 = AtomicU64::new(0);

struct TestBase(PathBuf);

impl TestBase {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "workflow-adk-tool-bridge-{}-{}",
            std::process::id(),
            NEXT_BASE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("test base must be unique");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestBase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest(capabilities: &[&str]) -> (SkillRuntimeManifest, SkillRuntimeLock) {
    let manifest = SkillRuntimeManifest::parse(
        format!(
            "schema_version = 1\n\
             [skill]\n\
             id = \"valid-skill\"\n\
             version = \"1.2.3\"\n\
             [[scripts]]\n\
             id = \"script\"\n\
             path = \"scripts/adapter.py\"\n\
             runtime = \"python3\"\n\
             sha256 = \"{SCRIPT_SHA256}\"\n\
             input_schema = \"references/schema.json\"\n\
             output_schema = \"references/schema.json\"\n\
             capabilities = {:?}\n\
             [[resources]]\n\
             id = \"references/schema.json\"\n\
             sha256 = \"{SCHEMA_SHA256}\"\n",
            capabilities
        )
        .as_bytes(),
    )
    .expect("fixture manifest must parse");
    let schema_id = SkillResourceId::new("references/schema.json").expect("fixture schema ID");
    let lock = SkillRuntimeLock::try_from_declared_bytes(
        &manifest,
        SKILL_MARKDOWN,
        [("script", SCRIPT)],
        [(&schema_id, SCHEMA)],
    )
    .expect("fixture lock must bind declared script");
    (manifest, lock)
}

fn sandbox(base: &TestBase, id: &str, capabilities: Vec<SandboxCapability>) -> RunSandbox {
    let context = RunContext::new(
        RunId::new(id.to_owned()).expect("fixture run ID"),
        RunLimits::new(
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
        ),
    );
    let workdir = WorkdirManager::new(base.path())
        .expect("fixture base must be trusted")
        .materialize(
            context.run_id(),
            &Materialization {
                skills: Some(SCRIPT.to_vec()),
                ..Materialization::default()
            },
        )
        .expect("fixture workdir must materialize");
    RunSandbox::new(context, workdir, capabilities).expect("fixture sandbox must bind")
}

fn registration() -> ToolRegistration {
    ToolRegistration::for_types::<Value, Value>(
        "script",
        ToolProvenance::new("skill.adapter", "1.0.0"),
        ToolFlags::new(true, true, true),
    )
    .expect("fixture registration")
    .with_required_capabilities([
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ])
}

#[test]
fn adk_adapter_invokes_registered_script_in_its_run_sandbox() {
    let base = TestBase::new();
    let (manifest, lock) = manifest(&["process.spawn", "limit.output_bytes"]);
    let sandbox = sandbox(
        &base,
        "adapter-invoke",
        vec![
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ],
    );
    let marker = sandbox.workdir().work_dir().join("adapter-marker");
    let script = RegisteredSkillScript::new(manifest, lock, "script");
    let adapter = AdkToolBridge::for_registered_script(
        sandbox,
        registration(),
        CapabilityIntersection::all_for_tool(
            "script",
            [
                SandboxCapability::ProcessSpawn,
                SandboxCapability::OutputBytes,
            ],
        ),
        None,
        InMemoryArtifactStore::new(
            NonZeroU64::new(4_096).expect("positive"),
            NonZeroU64::new(1_024).expect("positive"),
        ),
        script,
    )
    .expect("adapter production seam must construct the bridge");

    let result = adapter
        .invoke(ToolCall::new(
            "script",
            "call-1",
            "actor-1",
            json!({ "value": "ok" }),
        ))
        .expect("ADK adapter must invoke the registered script");

    assert!(
        marker.is_file(),
        "script must run in the run sandbox workdir"
    );
    assert!(matches!(result, ToolEnvelope::Success { .. }));
}

#[test]
fn adapter_registered_script_api_denies_unknown_script_id() {
    let base = TestBase::new();
    let (manifest, lock) = manifest(&[]);
    let sandbox = sandbox(&base, "unknown-script", Vec::new());
    let script = RegisteredSkillScript::new(manifest, lock, "unknown");

    let error = script
        .execute(&sandbox, br#"{"value":"ok"}"#)
        .expect_err("unknown script ID must be denied before child sandbox execution");

    assert_eq!(
        error.kind(),
        ScriptExecutionErrorKind::Denied(ScriptDeniedKind::UnknownScript)
    );
}

#[test]
fn adapter_registered_script_api_cannot_expand_child_capabilities() {
    let base = TestBase::new();
    let (manifest, lock) = manifest(&["network"]);
    let sandbox = sandbox(
        &base,
        "child-capabilities",
        vec![
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ],
    );
    let script = RegisteredSkillScript::new(manifest, lock, "script");

    let error = script
        .execute(&sandbox, br#"{"value":"ok"}"#)
        .expect_err("child script must not exceed the run sandbox capabilities");

    assert_eq!(
        error.kind(),
        ScriptExecutionErrorKind::Sandbox(SandboxExecutionError::CapabilityDenied)
    );
}
