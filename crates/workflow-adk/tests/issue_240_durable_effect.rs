use std::{
    fs,
    num::NonZeroU64,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use workflow_adk::tool_bridge::AdkToolBridge;
use workflow_runtime::{
    ApprovalLedger, CapabilityIntersection, InMemoryArtifactStore, RunContext, RunId, RunLimits,
    RunSandbox, SandboxCapability, ToolCall, ToolFlags, ToolIdempotency, ToolProvenance,
    ToolRegistration, WorkdirManager,
    effect_ledger::{
        ApprovalContext, ApprovalRequest, DurableEffectHandler, EffectExecutor, EffectLedger,
        ExecutionOutcome, ExecutorRegistry, Postcondition, RemoteObservation,
    },
    firewall::{FirewallPolicy, ToolProposal, TrustedGoal},
};

struct CounterExecutor {
    calls: Arc<AtomicUsize>,
}

impl EffectExecutor for CounterExecutor {
    fn reconcile(&mut self, _request: &ApprovalRequest) -> RemoteObservation {
        RemoteObservation::Absent
    }

    fn execute(&mut self, _request: &ApprovalRequest) -> ExecutionOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ExecutionOutcome::Committed
    }

    fn verify(&mut self, _request: &ApprovalRequest) -> Postcondition {
        Postcondition::Satisfied
    }
}

fn sandbox() -> RunSandbox {
    let base = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .expect("HOME is set")
        .join("tmp")
        .join(format!("issue-240-adk-{}", std::process::id()));
    fs::create_dir_all(&base).expect("sandbox base must exist");
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
        .expect("sandbox base must be private");
    let context = RunContext::new(
        RunId::new(format!(
            "issue-240-adk-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
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
    RunSandbox::new(context, workdir, [SandboxCapability::Network])
        .expect("sandbox must bind its run workdir")
}

fn fixture() -> (FirewallPolicy, TrustedGoal, ToolProposal) {
    let goal: TrustedGoal = serde_json::from_value(json!({
        "schema_version": 1,
        "id": "goal-1",
        "version": "1",
        "capabilities": ["network"],
        "scopes": ["fake"],
        "destinations": ["local"]
    }))
    .expect("goal fixture");
    let policy: FirewallPolicy = serde_json::from_value(json!({
        "schema_version": 1,
        "version": "policy-1",
        "tools": {
            "increment": {
                "version": "1",
                "capabilities": ["network"],
                "scopes": ["fake"],
                "destinations": ["local"],
                "effect": "write",
                "admission": "human_approval",
                "arguments": {"count": {"kind": "integer", "min": 1, "max": 4}},
                "scope": {"kind": "literal", "value": "fake"},
                "destination": {"kind": "literal", "value": "local"},
                "resource": {"kind": "literal", "value": "counter"}
            }
        },
        "targets": [{
            "scope": "fake",
            "destination": "local",
            "resource": "counter",
            "version": {"schema_version": 1, "revision": "r1"}
        }],
        "forbidden_markers": []
    }))
    .expect("policy fixture");
    let arguments = json!({"count": 1});
    let proposal: ToolProposal = serde_json::from_value(json!({
        "schema_version": 1,
        "intent": {
            "schema_version": 1,
            "goal_id": "goal-1",
            "tool_id": "increment",
            "tool_version": "1",
            "capabilities": ["network"],
            "scope": "fake",
            "destination": "local",
            "resource": "counter",
            "effect": {"schema_version": 1, "class": "write"},
            "target_version": {"schema_version": 1, "revision": "r1"}
        },
        "arguments": arguments,
        "provenance": {
            "source_digest": "a".repeat(64),
            "arguments_digest": workflow_runtime::argument_fingerprint(&arguments),
            "trust_domain": "untrusted_content"
        }
    }))
    .expect("proposal fixture");
    (policy, goal, proposal)
}

fn request(expiry: u64) -> ApprovalRequest {
    let (policy, goal, proposal) = fixture();
    ApprovalRequest::bind(
        &goal,
        &policy,
        proposal,
        ApprovalContext {
            operation_id: "increment-once".into(),
            workflow_lock: "b".repeat(64),
            approver: "operator".into(),
            expires_at_unix_ms: expiry,
        },
    )
    .expect("request fixture")
}

#[test]
fn adk_tool_bridge_runs_durable_effect_and_replays_without_duplicate_executor_call() {
    let root = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .expect("HOME is set")
        .join("tmp")
        .join(format!("issue-240-ledger-{}", std::process::id()));
    fs::create_dir_all(&root).expect("ledger root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("ledger root must be private");
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        + 60_000;
    let request = request(expiry);
    let mut ledger = EffectLedger::open(root.join("ledger.db")).expect("ledger");
    ledger.propose(&request).expect("proposal");
    ledger
        .approve(&request, request.approval_digest(), "operator", 1)
        .expect("durable approval");

    let calls = Arc::new(AtomicUsize::new(0));
    let (policy, _, _) = fixture();
    let mut executors = ExecutorRegistry::new();
    executors
        .register(
            "increment",
            policy.tools.get("increment").expect("rule").clone(),
            CounterExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .expect("executor");
    let registration = ToolRegistration::for_types::<Value, Value>(
        "increment",
        ToolProvenance::new("increment", "1"),
        ToolFlags::new(false, true, true),
    )
    .expect("registration")
    .with_required_capabilities([SandboxCapability::Network])
    .with_required_scopes(["fake"])
    .with_idempotency(ToolIdempotency::StableKey);
    let handler = DurableEffectHandler::new(request, ledger, executors, registration)
        .expect("durable handler binding");
    let approvals = ApprovalLedger::new().grant(
        "increment",
        "call-1",
        &json!({"count": 1}),
        "actor-1",
        Duration::from_secs(60),
    );
    let authority = CapabilityIntersection::new(
        [SandboxCapability::Network],
        ["increment"],
        ["increment"],
        ["fake"],
        ["increment"],
        ["increment"],
        [SandboxCapability::Network],
    );
    let bridge = AdkToolBridge::for_durable_effect(
        sandbox(),
        authority,
        Some(approvals),
        InMemoryArtifactStore::new(
            NonZeroU64::new(4096).expect("positive"),
            NonZeroU64::new(16).expect("positive"),
        ),
        handler,
    )
    .expect("durable ADK bridge");

    let call = ToolCall::new("increment", "call-1", "actor-1", json!({"count": 1}));
    let response = bridge.invoke(call.clone()).expect("first invocation");
    match response {
        workflow_runtime::ToolEnvelope::Success { payload, .. } => {
            assert_eq!(payload["state"], "verified");
        }
        other => panic!("durable effect did not verify: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    bridge.invoke(call).expect("idempotent replay");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let denied = bridge.invoke(ToolCall::new(
        "increment",
        "call-1",
        "actor-1",
        json!({"count": 2}),
    ));
    assert_eq!(
        denied.expect_err("mismatched approval must deny").kind(),
        workflow_runtime::ToolBridgeErrorKind::ApprovalDenied
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    fs::remove_dir_all(root).expect("cleanup");
}
