use std::{
    num::NonZeroU64,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::json;
use workflow_runtime::{
    ApprovalLedger, CapabilityIntersection, InMemoryArtifactStore, SandboxCapability, ToolBridge,
    ToolBridgeErrorKind, ToolCall, ToolCallContext, ToolEnvelope, ToolFlags, ToolHandler,
    ToolIdempotency, ToolProvenance, ToolRegistration,
};

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
        _context: &ToolCallContext,
        _arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, workflow_runtime::ToolBridgeError> {
        *self.calls.lock().expect("fixture lock") += 1;
        Ok(ToolEnvelope::success(
            self.payload.clone(),
            ToolProvenance::new("registry.fixture", "1.0.0"),
        ))
    }
}

fn bridge(registration: ToolRegistration, tool: FixtureTool) -> ToolBridge {
    let mut bridge = ToolBridge::new();
    bridge
        .register(registration, tool)
        .expect("register fixture");
    bridge
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
fn large_output_is_paged_as_bounded_preview_with_artifact_handle() {
    let calls = Arc::new(Mutex::new(0));
    let mut bridge = bridge(
        registration(ToolFlags::new(true, true, true))
            .with_inline_output_limit(NonZeroU64::new(256).unwrap())
            .with_paging(true),
        FixtureTool {
            calls,
            payload: json!("a".repeat(256)),
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
