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
    RunSandbox, SandboxCapability, SandboxExecutionError, ToolBridgeErrorKind, ToolCall,
    ToolEnvelope, ToolFlags, ToolProvenance, ToolRegistration, WorkdirManager,
};

const SCRIPT: &[u8] = b"import json, sys\nfrom pathlib import Path\nvalue = json.load(sys.stdin)['value']\nPath('adapter-marker').write_text('sandbox')\nprint(json.dumps({'value': value}))\n";
const READ_ONLY_SCRIPT: &[u8] = b"import json, sys\nvalue = json.load(sys.stdin)['value']\nprint(json.dumps({'value': value}))\n";
const INVALID_OUTPUT_SCRIPT: &[u8] =
    b"import json, sys\nfrom pathlib import Path\njson.load(sys.stdin)\nPath('/out/invalid').write_text('unpublished')\nprint(json.dumps({'value': 42}))\n";
const MISMATCH_SCRIPT: &[u8] = b"from pathlib import Path\nPath('mismatch-marker').write_text('spawned')\nprint('{\"value\":\"wrong\"}')\n";
const SCRIPT_SHA256: &str =
    "sha256:845ac6ab6fe2dac6aa1f3ef0fd2d7288bd4b68453552998c5504b466e138434f";
const READ_ONLY_SCRIPT_SHA256: &str =
    "sha256:aaa8acf1bf003612061fb9c497d594f21d8b637e9a4b5765b6e6a7124ae04869";
const INVALID_OUTPUT_SCRIPT_SHA256: &str =
    "sha256:b01d611ca7d7acbdeaffb980242539baa9442edca5d5800616ca833ae790bcfa";
const SCHEMA: &[u8] = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}"#;
const SKILL_MARKDOWN: &[u8] =
    b"---\nname: valid-skill\ndescription: A bounded skill.\n---\n# Instructions\n";
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

fn manifest(
    script: &[u8],
    capabilities: &[SandboxCapability],
) -> (SkillRuntimeManifest, SkillRuntimeLock) {
    let script_sha256 = match script {
        SCRIPT => SCRIPT_SHA256,
        READ_ONLY_SCRIPT => READ_ONLY_SCRIPT_SHA256,
        INVALID_OUTPUT_SCRIPT => INVALID_OUTPUT_SCRIPT_SHA256,
        _ => panic!("unknown script fixture"),
    };
    let capabilities = capabilities
        .iter()
        .map(SandboxCapability::as_str)
        .collect::<Vec<_>>();
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
             sha256 = \"{script_sha256}\"\n\
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
        [("script", script)],
        [(&schema_id, SCHEMA)],
    )
    .expect("fixture lock must bind declared script");
    (manifest, lock)
}

fn sandbox(
    base: &TestBase,
    id: &str,
    script: &[u8],
    capabilities: Vec<SandboxCapability>,
) -> RunSandbox {
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
                skills: Some(script.to_vec()),
                ..Materialization::default()
            },
        )
        .expect("fixture workdir must materialize");
    RunSandbox::new(context, workdir, capabilities).expect("fixture sandbox must bind")
}

fn registration(capabilities: &[SandboxCapability]) -> ToolRegistration {
    ToolRegistration::for_types::<Value, Value>(
        "script",
        ToolProvenance::new("skill.adapter", "1.0.0"),
        ToolFlags::new(true, true, true),
    )
    .expect("fixture registration")
    .with_required_capabilities(capabilities.iter().copied())
}

fn adapter(
    base: &TestBase,
    id: &str,
    locked_script: &[u8],
    materialized_script: &[u8],
    capabilities: Vec<SandboxCapability>,
) -> (AdkToolBridge<InMemoryArtifactStore>, PathBuf) {
    let (manifest, lock) = manifest(locked_script, &capabilities);
    let sandbox = sandbox(base, id, materialized_script, capabilities.clone());
    let root = sandbox.workdir().root().to_path_buf();
    let script = RegisteredSkillScript::new(manifest, lock, "script");
    let adapter = AdkToolBridge::for_registered_script(
        sandbox,
        registration(&capabilities),
        CapabilityIntersection::all_for_tool("script", capabilities),
        None,
        InMemoryArtifactStore::new(
            NonZeroU64::new(4_096).expect("positive"),
            NonZeroU64::new(1_024).expect("positive"),
        ),
        script,
    )
    .expect("adapter production seam must construct the bridge");
    (adapter, root)
}

fn invoke(adapter: &AdkToolBridge<InMemoryArtifactStore>, call_id: &str, value: &str) -> Value {
    let result = adapter
        .invoke(ToolCall::new(
            "script",
            call_id,
            "actor-1",
            json!({ "value": value }),
        ))
        .expect("registered script invocation must succeed");
    match result {
        ToolEnvelope::Success { payload, .. } => payload,
        other => panic!("expected successful tool envelope, got {other:?}"),
    }
}

#[test]
fn adk_adapter_invokes_registered_script_in_its_run_sandbox() {
    let base = TestBase::new();
    let capabilities = vec![
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ];
    let (adapter, root) = adapter(&base, "adapter-invoke", SCRIPT, SCRIPT, capabilities);
    let payload = invoke(&adapter, "call-1", "ok");

    assert!(
        root.join("work/adapter-marker").is_file(),
        "script must run in the run sandbox workdir"
    );
    assert_eq!(payload, json!({ "value": "ok" }));
}

#[test]
fn registered_script_rejects_capabilities_beyond_registration_before_spawn() {
    let base = TestBase::new();
    let lock_capabilities = vec![
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ];
    let (manifest, lock) = manifest(SCRIPT, &lock_capabilities);
    let sandbox = sandbox(
        &base,
        "adapter-capability-mismatch",
        SCRIPT,
        lock_capabilities,
    );
    let marker = sandbox.workdir().work_dir().join("adapter-marker");
    let result = AdkToolBridge::for_registered_script(
        sandbox,
        registration(&[SandboxCapability::FilesystemRead]),
        CapabilityIntersection::all_for_tool("script", [SandboxCapability::FilesystemRead]),
        None,
        InMemoryArtifactStore::new(
            NonZeroU64::new(4_096).expect("positive"),
            NonZeroU64::new(1_024).expect("positive"),
        ),
        RegisteredSkillScript::new(manifest, lock, "script"),
    );

    assert!(matches!(
        result,
        Err(error) if error.kind() == ToolBridgeErrorKind::CapabilityDenied
    ));
    assert!(
        !marker.exists(),
        "capability mismatch must fail before spawn"
    );
}

#[test]
fn registered_script_without_process_spawn_fails_before_backend_spawn() {
    let base = TestBase::new();
    let capabilities = vec![
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::OutputBytes,
    ];
    let (adapter, root) = adapter(&base, "adapter-no-spawn", SCRIPT, SCRIPT, capabilities);

    let error = adapter
        .invoke(ToolCall::new(
            "script",
            "call-no-spawn",
            "actor-1",
            json!({ "value": "blocked" }),
        ))
        .expect_err("registered Python execution without process.spawn must fail");

    assert_eq!(error.kind(), ToolBridgeErrorKind::HandlerFailed);
    assert!(
        !root.join("work/adapter-marker").exists(),
        "the backend must not start without process.spawn"
    );
}

#[test]
fn adapter_registered_script_api_denies_unknown_script_id() {
    let base = TestBase::new();
    let (manifest, lock) = manifest(SCRIPT, &[]);
    let sandbox = sandbox(&base, "unknown-script", SCRIPT, Vec::new());
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
    let (manifest, lock) = manifest(SCRIPT, &[SandboxCapability::Network]);
    let sandbox = sandbox(
        &base,
        "child-capabilities",
        SCRIPT,
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

#[test]
fn adk_adapter_denies_undeclared_filesystem_write() {
    let base = TestBase::new();
    let capabilities = vec![
        SandboxCapability::FilesystemRead,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ];
    let (adapter, root) = adapter(&base, "adapter-no-write", SCRIPT, SCRIPT, capabilities);

    let result = adapter
        .invoke(ToolCall::new(
            "script",
            "call-no-write",
            "actor-1",
            json!({ "value": "blocked" }),
        ))
        .expect("sandbox denial must return a typed failure envelope");

    assert!(matches!(result, ToolEnvelope::Failure { .. }));
    assert!(!root.join("work/adapter-marker").exists());
}

#[test]
fn adk_adapter_denies_undeclared_filesystem_read() {
    let base = TestBase::new();
    let capabilities = vec![
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ];
    let (adapter, _) = adapter(
        &base,
        "adapter-no-read",
        READ_ONLY_SCRIPT,
        READ_ONLY_SCRIPT,
        capabilities,
    );

    let result = adapter
        .invoke(ToolCall::new(
            "script",
            "call-no-read",
            "actor-1",
            json!({ "value": "blocked" }),
        ))
        .expect("sandbox denial must return a typed failure envelope");

    assert!(matches!(result, ToolEnvelope::Failure { .. }));
}

#[test]
fn registered_script_rejects_materialized_bytes_that_do_not_match_its_lock() {
    let base = TestBase::new();
    let capabilities = vec![
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ];
    let (manifest, lock) = manifest(SCRIPT, &capabilities);
    let sandbox = sandbox(&base, "adapter-mismatch", MISMATCH_SCRIPT, capabilities);
    let marker = sandbox.workdir().work_dir().join("mismatch-marker");
    let script = RegisteredSkillScript::new(manifest, lock, "script");

    let error = script
        .execute(&sandbox, br#"{"value":"ok"}"#)
        .expect_err("mismatched materialized bytes must fail before spawn");

    assert_eq!(
        error.kind(),
        ScriptExecutionErrorKind::Sandbox(SandboxExecutionError::ExecutionFailed)
    );
    assert!(!marker.exists(), "mismatched script bytes must never spawn");
}

#[test]
fn validated_input_json_reaches_the_registered_script() {
    let base = TestBase::new();
    let capabilities = vec![
        SandboxCapability::FilesystemRead,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ];
    let (adapter, _) = adapter(
        &base,
        "adapter-input",
        READ_ONLY_SCRIPT,
        READ_ONLY_SCRIPT,
        capabilities,
    );

    assert_eq!(
        invoke(&adapter, "call-first", "first"),
        json!({ "value": "first" })
    );
    assert_eq!(
        invoke(&adapter, "call-second", "second"),
        json!({ "value": "second" })
    );
}

#[test]
fn lock_bound_output_schema_rejects_invalid_script_stdout() {
    let base = TestBase::new();
    let capabilities = vec![
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ];
    let (adapter, root) = adapter(
        &base,
        "adapter-invalid-output",
        INVALID_OUTPUT_SCRIPT,
        INVALID_OUTPUT_SCRIPT,
        capabilities,
    );

    assert!(
        adapter
            .invoke(ToolCall::new(
                "script",
                "call-invalid-output",
                "actor-1",
                json!({ "value": "ok" }),
            ))
            .is_err(),
        "schema-invalid stdout must fail before ToolEnvelope publication"
    );
    assert_eq!(
        fs::read_dir(root.join("out"))
            .expect("visible output directory must remain readable")
            .count(),
        0,
        "schema-invalid stdout must not publish staged output"
    );
}
