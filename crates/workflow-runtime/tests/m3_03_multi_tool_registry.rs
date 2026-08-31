use std::{
    fs,
    num::NonZeroU64,
    sync::{Arc, Mutex},
    time::Duration,
};

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use workflow_runtime::{
    CapabilityIntersection, ChildSandbox, EffectCommit, EffectJournal, EffectKey,
    InMemoryArtifactStore, RunContext, RunId, RunLimits, RunSandbox, SandboxCapability, ToolBridge,
    ToolBridgeError, ToolBridgeErrorKind, ToolCall, ToolCallContext, ToolEnvelope, ToolFlags,
    ToolHandler, ToolProvenance, ToolRegistration, WorkdirManager, selection_identity,
};

fn sandbox() -> RunSandbox {
    let root = std::env::temp_dir().join(format!("workflow-runtime-m3-03-{}", std::process::id()));
    fs::create_dir_all(&root).expect("fixture root");
    let context = RunContext::new(
        RunId::new("m3-03-runtime".to_owned()).expect("fixture run ID"),
        RunLimits::new(
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(4_096).expect("positive"),
        ),
    );
    let workdir = WorkdirManager::new(&root)
        .expect("fixture root trusted")
        .allocate(context.run_id())
        .expect("fixture workdir");
    RunSandbox::new(context, workdir, [SandboxCapability::FilesystemRead]).expect("fixture sandbox")
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Input {
    value: String,
}

struct CountingTool(Arc<Mutex<u32>>);

impl ToolHandler for CountingTool {
    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        _arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        *self.0.lock().expect("counter") += 1;
        Ok(ToolEnvelope::success(
            json!({"ok": true}),
            ToolProvenance::new("registry.fixture", "1"),
        ))
    }
}

fn registration(name: &str) -> ToolRegistration {
    ToolRegistration::for_types::<Input, serde_json::Value>(
        name,
        ToolProvenance::new("registry.fixture", "1"),
        ToolFlags::new(true, true, true),
    )
    .expect("registration")
    .with_required_capabilities([SandboxCapability::FilesystemRead])
}

fn authority() -> CapabilityIntersection {
    CapabilityIntersection::new(
        [SandboxCapability::FilesystemRead],
        ["alpha"],
        ["alpha"],
        std::iter::empty::<String>(),
        ["alpha"],
        ["alpha"],
        [SandboxCapability::FilesystemRead],
    )
}

#[test]
fn rejects_unselected_unknown_schema_invalid_and_widened_calls_before_handler() {
    let Input { value } = Input {
        value: "schema".to_owned(),
    };
    assert_eq!(value, "schema");
    let calls = Arc::new(Mutex::new(0));
    let mut registry = ToolBridge::new(sandbox());
    registry
        .register(registration("alpha"), CountingTool(Arc::clone(&calls)))
        .expect("alpha registers");
    registry
        .register(registration("beta"), CountingTool(Arc::clone(&calls)))
        .expect("beta registers");
    let mut bridge = registry.select(["alpha"]).expect("selected subset");
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(4_096).expect("positive"),
        NonZeroU64::new(1_024).expect("positive"),
    );

    for (name, arguments, authority, expected) in [
        (
            "unknown",
            json!({"value": "ok"}),
            authority(),
            ToolBridgeErrorKind::UnknownTool,
        ),
        (
            "beta",
            json!({"value": "ok"}),
            authority(),
            ToolBridgeErrorKind::UnknownTool,
        ),
        (
            "alpha",
            json!({"extra": true}),
            authority(),
            ToolBridgeErrorKind::InvalidInput,
        ),
        (
            "alpha",
            json!({"value": "ok"}),
            authority().with_runtime_capabilities(std::iter::empty()),
            ToolBridgeErrorKind::CapabilityDenied,
        ),
    ] {
        assert_eq!(
            bridge
                .invoke(
                    ToolCall::new(name, "denied", "actor", arguments),
                    &authority,
                    None,
                    Duration::ZERO,
                    &mut artifacts,
                )
                .expect_err("denied before handler")
                .kind(),
            expected,
        );
    }
    assert_eq!(*calls.lock().expect("counter"), 0);

    bridge
        .invoke(
            ToolCall::new("alpha", "allowed", "actor", json!({"value": "ok"})),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("selected call reaches handler");
    assert_eq!(*calls.lock().expect("counter"), 1);
}

struct JournalTool {
    journal: Arc<EffectJournal>,
    commits: Arc<Mutex<u32>>,
}

impl ToolHandler for JournalTool {
    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        match self
            .journal
            .commit(
                &EffectKey::new("run", "node", "alpha", arguments),
                &json!({"ok": true}),
            )
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?
        {
            EffectCommit::Committed => *self.commits.lock().expect("commit counter") += 1,
            EffectCommit::AlreadyCommitted(_) => {}
        }
        Ok(ToolEnvelope::success(
            json!({"ok": true}),
            ToolProvenance::new("registry.fixture", "1"),
        ))
    }
}

#[test]
fn preserves_effect_identity_and_rejects_registry_or_subset_drift_on_resume() {
    let root = std::env::temp_dir().join(format!(
        "workflow-runtime-m3-03-effects-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("effect root");
    let commits = Arc::new(Mutex::new(0));
    let mut registry = ToolBridge::new(sandbox());
    registry
        .register(
            registration("alpha"),
            JournalTool {
                journal: Arc::new(
                    EffectJournal::open(root.join("effects.sqlite")).expect("journal"),
                ),
                commits: Arc::clone(&commits),
            },
        )
        .expect("alpha registers");
    registry
        .register(registration("beta"), CountingTool(Arc::new(Mutex::new(0))))
        .expect("beta registers");
    let recorded = registry
        .selection_identity(["alpha"])
        .expect("recorded selection identity");
    assert_ne!(
        recorded,
        registry
            .selection_identity(["beta"])
            .expect("subset drift identity"),
        "resume must reject a different node subset"
    );
    for registration in [
        registration("alpha").with_required_scopes(["scope-drift"]),
        registration("alpha").with_paging(true),
        registration("alpha").with_implementation_digest("changed"),
    ] {
        assert_ne!(
            recorded,
            selection_identity(std::iter::once((registration.name(), &registration)))
                .expect("metadata drift identity"),
            "resume identity includes complete registration metadata"
        );
    }

    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(4_096).expect("positive"),
        NonZeroU64::new(1_024).expect("positive"),
    );
    for _ in 0..2 {
        registry
            .select(["alpha"])
            .expect("resume selected view")
            .invoke(
                ToolCall::new("alpha", "call", "actor", json!({"value": "ok"})),
                &authority(),
                None,
                Duration::ZERO,
                &mut artifacts,
            )
            .expect("stable effect result");
    }
    assert_eq!(*commits.lock().expect("commit counter"), 1);

    let mut drifted = ToolBridge::new(sandbox());
    drifted
        .register(
            registration("alpha").with_implementation_digest("changed"),
            CountingTool(Arc::new(Mutex::new(0))),
        )
        .expect("drifted alpha registers");
    assert_ne!(
        recorded,
        drifted
            .selection_identity(["alpha"])
            .expect("registry drift identity"),
        "resume must reject registration metadata drift"
    );
}
