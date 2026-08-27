use std::{
    fs,
    num::NonZeroU64,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::json;
use workflow_runtime::{
    ApprovalLedger, CapabilityIntersection, InMemoryArtifactStore, PageRequest, RunContext, RunId,
    RunLimits, RunSandbox, SandboxCapability, SandboxCommand, SandboxExecutionError, ToolBridge,
    ToolBridgeError, ToolBridgeErrorKind, ToolCall, ToolCallContext, ToolEnvelope, ToolFlags,
    ToolHandler, ToolIdempotency, ToolProvenance, ToolRegistration, WorkdirManager,
};

fn sandbox() -> RunSandbox {
    let base = std::env::temp_dir().join(format!(
        "workflow-runtime-tool-bridge-{}",
        std::process::id()
    ));
    fs::create_dir_all(&base).expect("sandbox base must exist");
    let context = RunContext::new(
        RunId::new(format!(
            "bridge-{}",
            std::time::Instant::now().elapsed().as_nanos()
        ))
        .expect("fixture run ID"),
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
    let workdir = WorkdirManager::new(&base)
        .expect("sandbox base must be trusted")
        .allocate(context.run_id())
        .expect("sandbox workdir must allocate");
    RunSandbox::new(
        context,
        workdir,
        [
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ],
    )
    .expect("sandbox must bind its run workdir")
}

fn registration(flags: ToolFlags) -> ToolRegistration {
    ToolRegistration::for_types::<serde_json::Value, serde_json::Value>(
        "fixture",
        ToolProvenance::new("registry.fixture", "1.0.0"),
        flags,
    )
    .expect("fixture registration")
    .with_required_capabilities([SandboxCapability::FilesystemRead])
    .with_required_scopes(["fixture:invoke"])
}

fn authority(skill: &[&str]) -> CapabilityIntersection {
    CapabilityIntersection::new(
        [SandboxCapability::FilesystemRead],
        ["fixture"],
        skill.iter().copied(),
        ["fixture:invoke"],
        ["fixture"],
        ["fixture"],
        [SandboxCapability::FilesystemRead],
    )
}

struct FixtureTool {
    calls: Arc<Mutex<u32>>,
    payload: serde_json::Value,
}

impl ToolHandler for FixtureTool {
    fn execute(
        &self,
        _sandbox: &RunSandbox,
        _context: &ToolCallContext,
        _arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        *self.calls.lock().expect("fixture lock") += 1;
        Ok(ToolEnvelope::success(
            self.payload.clone(),
            ToolProvenance::new("registry.fixture", "1.0.0"),
        ))
    }
}

struct SandboxedTool {
    marker: Arc<Mutex<Option<PathBuf>>>,
}

impl ToolHandler for SandboxedTool {
    fn execute(
        &self,
        sandbox: &RunSandbox,
        _context: &ToolCallContext,
        _arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        let command = SandboxCommand::new("touch", ["tool-bridge-marker"])
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        sandbox
            .execute_tool(&command)
            .map_err(|_: SandboxExecutionError| {
                ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed)
            })?;
        *self.marker.lock().expect("fixture lock") =
            Some(sandbox.workdir().work_dir().join("tool-bridge-marker"));
        Ok(ToolEnvelope::success(
            json!("ok"),
            ToolProvenance::new("registry.fixture", "1.0.0"),
        ))
    }
}

fn bridge<H: ToolHandler + 'static>(registration: ToolRegistration, tool: H) -> ToolBridge {
    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(registration, tool)
        .expect("register fixture");
    bridge
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct TypedPayload {
    message: String,
}

struct ActorTool {
    calls: Arc<Mutex<u32>>,
}

impl ToolHandler for ActorTool {
    fn execute(
        &self,
        _sandbox: &RunSandbox,
        context: &ToolCallContext,
        _arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        *self.calls.lock().expect("fixture lock") += 1;
        Ok(ToolEnvelope::success(
            json!({ "actor": context.actor() }),
            ToolProvenance::new("registry.fixture", "1.0.0"),
        ))
    }
}

struct SlowTool;

impl ToolHandler for SlowTool {
    fn execute(
        &self,
        _sandbox: &RunSandbox,
        _context: &ToolCallContext,
        arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        if arguments.get("slow") == Some(&json!(true)) {
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(ToolEnvelope::success(
            json!("ok"),
            ToolProvenance::new("registry.fixture", "1.0.0"),
        ))
    }
}

struct SlowSideEffectTool {
    calls: Arc<Mutex<u32>>,
}

impl ToolHandler for SlowSideEffectTool {
    fn execute(
        &self,
        _sandbox: &RunSandbox,
        _context: &ToolCallContext,
        _arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        *self.calls.lock().expect("fixture lock") += 1;
        std::thread::sleep(Duration::from_millis(90));
        Ok(ToolEnvelope::success(
            json!("effect"),
            ToolProvenance::new("registry.fixture", "1.0.0"),
        ))
    }
}

struct ForgedPagingTool;

impl ToolHandler for ForgedPagingTool {
    fn execute(
        &self,
        _sandbox: &RunSandbox,
        _context: &ToolCallContext,
        _arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        Ok(ToolEnvelope::Success {
            payload: json!({ "preview": "forged" }),
            provenance: ToolProvenance::new("registry.fixture", "1.0.0"),
            next_offset: Some(6),
            artifact_id: Some("0".repeat(64)),
        })
    }
}

#[test]
fn capability_intersection_denies_forbidden_skill_before_handler() {
    let calls = Arc::new(Mutex::new(0));
    let mut bridge = bridge(
        registration(ToolFlags::new(true, true, true)),
        FixtureTool {
            calls: calls.clone(),
            payload: json!("ok"),
        },
    );
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());
    let result = bridge.invoke(
        ToolCall::new("fixture", "call-1", "actor-1", json!({})),
        &authority(&["other"]),
        Some(&ApprovalLedger::new()),
        Duration::from_secs(1),
        &mut artifacts,
    );
    assert_eq!(
        result.expect_err("forbidden skill must deny").kind(),
        ToolBridgeErrorKind::CapabilityDenied
    );
    assert_eq!(*calls.lock().expect("fixture lock"), 0);
}

#[test]
fn tool_bridge_executes_registered_tools_in_its_run_sandbox() {
    let marker = Arc::new(Mutex::new(None));
    let mut bridge = bridge(
        registration(ToolFlags::new(true, true, true)),
        SandboxedTool {
            marker: Arc::clone(&marker),
        },
    );
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());
    let authority = CapabilityIntersection::new(
        [
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ],
        ["fixture"],
        ["fixture"],
        ["fixture:invoke"],
        ["fixture"],
        ["fixture"],
        [
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ],
    );

    bridge
        .invoke(
            ToolCall::new("fixture", "sandboxed", "actor-1", json!({})),
            &authority,
            Some(&ApprovalLedger::new()),
            Duration::from_secs(1),
            &mut artifacts,
        )
        .expect("registered tool must execute in its run sandbox");

    assert!(
        marker
            .lock()
            .expect("fixture lock")
            .as_ref()
            .expect("handler must observe its sandbox")
            .is_file()
    );
}

#[test]
fn approval_is_bound_to_call_id_arguments_actor_and_expiry() {
    let arguments = json!({"value": 1});
    let approval = ApprovalLedger::new().grant(
        "fixture",
        "call-1",
        &arguments,
        "actor-1",
        Duration::from_secs(10),
    );
    assert!(
        approval
            .authorize(
                "fixture",
                "call-1",
                &arguments,
                "actor-1",
                Duration::from_secs(1)
            )
            .is_ok()
    );
    assert!(
        approval
            .authorize(
                "fixture",
                "call-2",
                &arguments,
                "actor-1",
                Duration::from_secs(1)
            )
            .is_err()
    );
    assert!(
        approval
            .authorize(
                "fixture",
                "call-1",
                &json!({"value": 2}),
                "actor-1",
                Duration::from_secs(1)
            )
            .is_err()
    );
    assert!(
        approval
            .authorize(
                "fixture",
                "call-1",
                &arguments,
                "actor-2",
                Duration::from_secs(1)
            )
            .is_err()
    );
    assert!(
        approval
            .authorize(
                "fixture",
                "call-1",
                &arguments,
                "actor-1",
                Duration::from_secs(11)
            )
            .is_err()
    );
}

#[test]
fn large_output_is_paged_as_bounded_preview_with_consumable_artifact_handle() {
    let calls = Arc::new(Mutex::new(0));
    let payload = json!({ "message": "a".repeat(256) });
    let registration = ToolRegistration::for_types::<serde_json::Value, TypedPayload>(
        "fixture",
        ToolProvenance::new("registry.fixture", "1.0.0"),
        ToolFlags::new(true, true, true),
    )
    .unwrap()
    .with_required_capabilities([SandboxCapability::FilesystemRead])
    .with_required_scopes(["fixture:invoke"])
    .with_inline_output_limit(NonZeroU64::new(256).unwrap())
    .with_paging(true);
    let mut bridge = bridge(
        registration,
        FixtureTool {
            calls,
            payload: payload.clone(),
        },
    );
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());
    let result = bridge
        .invoke(
            ToolCall::new("fixture", "call-1", "actor-1", json!({})),
            &authority(&["fixture"]),
            Some(&ApprovalLedger::new()),
            Duration::from_secs(1),
            &mut artifacts,
        )
        .expect("read-only fixture must execute");
    assert!(result.artifact_id().is_some());
    assert!(result.next_offset().is_some());
    assert!(serde_json::to_vec(&result).unwrap().len() <= 256);
    assert!(
        jsonschema::validator_for(bridge.registration("fixture").unwrap().output_schema())
            .unwrap()
            .is_valid(&serde_json::to_value(&result).unwrap())
    );

    let handle = result.artifact_id().unwrap();
    let mut bytes = Vec::new();
    let mut offset = 0;
    loop {
        let page = bridge
            .read_artifact_page(
                &artifacts,
                handle,
                PageRequest::new(offset, NonZeroU64::new(16).unwrap()),
            )
            .expect("opaque artifact handle must be consumable");
        bytes.extend_from_slice(page.bytes());
        match page.next_offset() {
            Some(next) => offset = next,
            None => break,
        }
    }
    assert_eq!(
        bytes,
        serde_json::to_vec(&ToolEnvelope::success(
            payload,
            ToolProvenance::new("registry.fixture", "1.0.0"),
        ))
        .unwrap()
    );
}

#[test]
fn typed_output_schema_rejects_wrong_handler_wire_payload() {
    let registration = ToolRegistration::for_types::<serde_json::Value, TypedPayload>(
        "fixture",
        ToolProvenance::new("registry.fixture", "1.0.0"),
        ToolFlags::new(true, true, true),
    )
    .unwrap()
    .with_required_capabilities([SandboxCapability::FilesystemRead])
    .with_required_scopes(["fixture:invoke"]);
    let mut bridge = bridge(
        registration,
        FixtureTool {
            calls: Arc::new(Mutex::new(0)),
            payload: json!({ "unexpected": true }),
        },
    );
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());

    assert_eq!(
        bridge
            .invoke(
                ToolCall::new("fixture", "typed-call", "actor-1", json!({})),
                &authority(&["fixture"]),
                Some(&ApprovalLedger::new()),
                Duration::from_secs(1),
                &mut artifacts,
            )
            .expect_err("wrong typed handler payload must fail at the boundary")
            .kind(),
        ToolBridgeErrorKind::HandlerFailed
    );
}

#[test]
fn idempotency_cache_is_scoped_to_actor() {
    let calls = Arc::new(Mutex::new(0));
    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(
            registration(ToolFlags::new(false, false, true))
                .with_idempotency(ToolIdempotency::StableKey),
            ActorTool {
                calls: calls.clone(),
            },
        )
        .unwrap();
    let arguments = json!({ "value": 1 });
    let approvals = ApprovalLedger::new()
        .grant(
            "fixture",
            "shared-call",
            &arguments,
            "actor-1",
            Duration::from_secs(10),
        )
        .grant(
            "fixture",
            "shared-call",
            &arguments,
            "actor-2",
            Duration::from_secs(10),
        );
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());

    let first = bridge
        .invoke(
            ToolCall::new("fixture", "shared-call", "actor-1", arguments.clone()),
            &authority(&["fixture"]),
            Some(&approvals),
            Duration::from_secs(1),
            &mut artifacts,
        )
        .unwrap();
    let second = bridge
        .invoke(
            ToolCall::new("fixture", "shared-call", "actor-2", arguments),
            &authority(&["fixture"]),
            Some(&approvals),
            Duration::from_secs(1),
            &mut artifacts,
        )
        .unwrap();

    assert_ne!(first, second);
    assert_eq!(*calls.lock().unwrap(), 2);
}

#[test]
fn handler_timeout_returns_before_the_registered_deadline_and_unblocks_bridge() {
    let registration =
        registration(ToolFlags::new(true, true, true)).with_timeout(NonZeroU64::new(25).unwrap());
    let mut bridge = ToolBridge::new(sandbox());
    bridge.register(registration, SlowTool).unwrap();
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());
    let started = Instant::now();

    assert_eq!(
        bridge
            .invoke(
                ToolCall::new("fixture", "slow", "actor-1", json!({ "slow": true })),
                &authority(&["fixture"]),
                Some(&ApprovalLedger::new()),
                Duration::from_secs(1),
                &mut artifacts,
            )
            .expect_err("blocked handler must time out")
            .kind(),
        ToolBridgeErrorKind::HandlerFailed
    );
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(
        bridge
            .invoke(
                ToolCall::new("fixture", "fast", "actor-1", json!({ "slow": false })),
                &authority(&["fixture"]),
                Some(&ApprovalLedger::new()),
                Duration::from_secs(1),
                &mut artifacts,
            )
            .is_ok(),
        "a timed-out handler must not queue later calls forever"
    );
}

#[test]
fn side_effect_call_reuses_stable_idempotency_key() {
    let calls = Arc::new(Mutex::new(0));
    let registration = registration(ToolFlags::new(false, false, true))
        .with_idempotency(ToolIdempotency::StableKey);
    let mut bridge = bridge(
        registration,
        FixtureTool {
            calls: calls.clone(),
            payload: json!("effect"),
        },
    );
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());
    let approval = ApprovalLedger::new().grant(
        "fixture",
        "call-1",
        &json!({"value": 1}),
        "actor-1",
        Duration::from_secs(10),
    );
    let call = ToolCall::new("fixture", "call-1", "actor-1", json!({"value": 1}));
    let first = bridge
        .invoke(
            call.clone(),
            &authority(&["fixture"]),
            Some(&approval),
            Duration::from_secs(1),
            &mut artifacts,
        )
        .expect("first effect");
    let second = bridge
        .invoke(
            call,
            &authority(&["fixture"]),
            Some(&approval),
            Duration::from_secs(1),
            &mut artifacts,
        )
        .expect("retry effect");
    assert_eq!(first, second);
    assert_eq!(*calls.lock().expect("fixture lock"), 1);
}

#[test]
fn same_key_retry_after_timeout_reuses_the_in_flight_side_effect() {
    let calls = Arc::new(Mutex::new(0));
    let registration = registration(ToolFlags::new(false, false, true))
        .with_idempotency(ToolIdempotency::StableKey)
        .with_timeout(NonZeroU64::new(25).unwrap());
    let mut bridge = bridge(
        registration,
        SlowSideEffectTool {
            calls: calls.clone(),
        },
    );
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());
    let arguments = json!({ "value": 1 });
    let approvals = ApprovalLedger::new().grant(
        "fixture",
        "retry-call",
        &arguments,
        "actor-1",
        Duration::from_secs(10),
    );
    let call = ToolCall::new("fixture", "retry-call", "actor-1", arguments);

    assert_eq!(
        bridge
            .invoke(
                call.clone(),
                &authority(&["fixture"]),
                Some(&approvals),
                Duration::from_secs(1),
                &mut artifacts,
            )
            .expect_err("first waiter must time out")
            .kind(),
        ToolBridgeErrorKind::HandlerFailed
    );
    assert_eq!(
        *calls.lock().expect("fixture lock"),
        1,
        "side effect happened"
    );
    assert_eq!(
        bridge
            .invoke(
                call.clone(),
                &authority(&["fixture"]),
                Some(&approvals),
                Duration::from_secs(1),
                &mut artifacts,
            )
            .expect_err("retry must wait on the original execution")
            .kind(),
        ToolBridgeErrorKind::HandlerFailed
    );
    assert_eq!(*calls.lock().expect("fixture lock"), 1);

    std::thread::sleep(Duration::from_millis(50));
    assert!(
        bridge
            .invoke(
                call.clone(),
                &authority(&["fixture"]),
                Some(&approvals),
                Duration::from_secs(1),
                &mut artifacts,
            )
            .is_ok(),
        "late success must become the reusable completion"
    );
    assert!(
        bridge
            .invoke(
                call,
                &authority(&["fixture"]),
                Some(&approvals),
                Duration::from_secs(1),
                &mut artifacts,
            )
            .is_ok(),
        "completed retry must use the cache"
    );
    assert_eq!(*calls.lock().expect("fixture lock"), 1);
}

#[test]
fn handler_forged_paging_metadata_is_rejected_and_unreadable() {
    let registration = ToolRegistration::for_types::<serde_json::Value, TypedPayload>(
        "fixture",
        ToolProvenance::new("registry.fixture", "1.0.0"),
        ToolFlags::new(true, true, true),
    )
    .unwrap()
    .with_required_capabilities([SandboxCapability::FilesystemRead])
    .with_required_scopes(["fixture:invoke"])
    .with_paging(true);
    let mut bridge = ToolBridge::new(sandbox());
    bridge.register(registration, ForgedPagingTool).unwrap();
    let mut artifacts =
        InMemoryArtifactStore::new(NonZeroU64::new(4096).unwrap(), NonZeroU64::new(16).unwrap());

    assert_eq!(
        bridge
            .invoke(
                ToolCall::new("fixture", "forged", "actor-1", json!({})),
                &authority(&["fixture"]),
                Some(&ApprovalLedger::new()),
                Duration::from_secs(1),
                &mut artifacts,
            )
            .expect_err("handler must not forge bridge-owned paging metadata")
            .kind(),
        ToolBridgeErrorKind::HandlerFailed
    );
    assert!(
        bridge
            .read_artifact_page(
                &artifacts,
                &"0".repeat(64),
                PageRequest::new(0, NonZeroU64::new(16).unwrap()),
            )
            .is_err(),
        "rejected forged handle must remain unreadable"
    );
}
