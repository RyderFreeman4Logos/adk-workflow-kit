use std::{
    fs,
    num::NonZeroU64,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};
use workflow_adk::tool_bridge::AdkToolBridge;
use workflow_runtime::{
    ApprovalLedger, CapabilityIntersection, InMemoryArtifactStore, RunContext, RunId, RunLimits,
    RunSandbox, SandboxCapability, ToolCall, ToolFlags, ToolIdempotency,
    ToolImplementationRegistry, ToolProvenance, ToolRegistration, WorkdirManager,
    effect_ledger::{
        ApprovalContext, ApprovalRequest, DurableEffectHandler, EffectExecutor, EffectLedger,
        ExecutionOutcome, ExecutorRegistry, Postcondition, RemoteObservation,
    },
    firewall::{FirewallPolicy, ToolProposal, TrustedGoal},
};

#[path = "issue_240_durable_effect/completion.rs"]
mod completion;
#[path = "issue_240_durable_effect/resume.rs"]
mod resume;

static NEXT_PRODUCTION_ROOT: AtomicU64 = AtomicU64::new(0);

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

const PRODUCTION_WORKFLOW: &str = r#"
schema_version = 1

[workflow]
id = "issue-240-production"
version = "1"
entry = "work"

[[nodes]]
id = "work"
kind = "agent"
model = { role = "worker", id = "fake-model", version = "1" }
tools = [{ id = "increment", version = "1" }]

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "work"
to = "done"
"#;

fn production_root() -> PathBuf {
    let root = std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME is set")
        .join("tmp")
        .join(format!(
            "issue-240-production-{}-{}",
            std::process::id(),
            NEXT_PRODUCTION_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(root.join("runs")).expect("production root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("production root must be private");
    fs::write(root.join("workflow.toml"), PRODUCTION_WORKFLOW).expect("workflow");
    root
}

fn remove_production_root(root: &Path) {
    fn make_writable(path: &Path) {
        let metadata = fs::symlink_metadata(path).expect("production cleanup metadata");
        if metadata.file_type().is_dir() {
            for entry in fs::read_dir(path).expect("production cleanup directory") {
                make_writable(&entry.expect("production cleanup entry").path());
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("production directory writable");
        } else {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("production file writable");
        }
    }
    make_writable(root);
    fs::remove_dir_all(root).expect("cleanup");
}

fn production_profile(count: u64, approvals: ApprovalLedger) -> ExecutionProfileV1 {
    let responses = vec![
        json!({
            "calls": [{
                "id": "call-1",
                "name": "increment",
                "args": {"count": count}
            }]
        }),
        json!(
            serde_json::to_string(&json!({
                "status": "finished",
                "output": {"done": true}
            }))
            .expect("finish response")
        ),
    ];
    ExecutionProfileV1::parse(
        &serde_json::to_vec(&json!({
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": responses
            },
            "tools": [{
                "name": "increment",
                "input_schema": {"type": "object"},
                "required_capabilities": ["network"]
            }],
            "sandbox": {"capabilities": ["network"]}
        }))
        .expect("profile JSON"),
    )
    .expect("production profile")
    .with_approvals(approvals)
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

struct RecoveryExecutor {
    reconciles: AtomicUsize,
    executions: Arc<AtomicUsize>,
}

impl EffectExecutor for RecoveryExecutor {
    fn reconcile(&mut self, _request: &ApprovalRequest) -> RemoteObservation {
        if self.reconciles.fetch_add(1, Ordering::SeqCst) < 3 {
            RemoteObservation::Unknown
        } else {
            RemoteObservation::Committed
        }
    }

    fn execute(&mut self, _request: &ApprovalRequest) -> ExecutionOutcome {
        self.executions.fetch_add(1, Ordering::SeqCst);
        ExecutionOutcome::Committed
    }

    fn verify(&mut self, _request: &ApprovalRequest) -> Postcondition {
        Postcondition::Satisfied
    }
}

#[test]
fn adk_bridge_retries_nonterminal_durable_result_without_caching_it() {
    let root = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .expect("HOME is set")
        .join("tmp")
        .join(format!("issue-240-recovery-{}", std::process::id()));
    fs::create_dir_all(&root).expect("ledger root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
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
        .expect("approval");
    let executions = Arc::new(AtomicUsize::new(0));
    let (policy, _, _) = fixture();
    let mut executors = ExecutorRegistry::new();
    executors
        .register(
            "increment",
            policy.tools.get("increment").expect("rule").clone(),
            RecoveryExecutor {
                reconciles: AtomicUsize::new(0),
                executions: Arc::clone(&executions),
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
    let handler =
        DurableEffectHandler::new(request, ledger, executors, registration).expect("handler");
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
    .expect("bridge");
    let call = ToolCall::new("increment", "call-1", "actor-1", json!({"count": 1}));
    assert_eq!(
        bridge
            .invoke(call.clone())
            .expect_err("nonterminal is retriable")
            .kind(),
        workflow_runtime::ToolBridgeErrorKind::HandlerFailed
    );
    let response = bridge.invoke(call).expect("observable recovery");
    assert!(matches!(
        response,
        workflow_runtime::ToolEnvelope::Success { .. }
    ));
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn adk_bridge_refreshes_expiry_clock_between_recovery_phases() {
    let root = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .expect("HOME is set")
        .join("tmp")
        .join(format!("issue-240-expiry-{}", std::process::id()));
    fs::create_dir_all(&root).expect("ledger root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        + 1_000;
    let request = request(expiry);
    let mut ledger = EffectLedger::open(root.join("ledger.db")).expect("ledger");
    ledger.propose(&request).expect("proposal");
    ledger
        .approve(&request, request.approval_digest(), "operator", 1)
        .expect("approval");
    let executions = Arc::new(AtomicUsize::new(0));
    let reconciles = Arc::new(AtomicUsize::new(0));
    let (policy, _, _) = fixture();
    let mut executors = ExecutorRegistry::new();
    executors
        .register(
            "increment",
            policy.tools.get("increment").expect("rule").clone(),
            CrossingExpiryExecutor {
                reconciles: Arc::clone(&reconciles),
                executions: Arc::clone(&executions),
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
    let handler =
        DurableEffectHandler::new(request, ledger, executors, registration).expect("handler");
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
    .expect("bridge");
    let call = ToolCall::new("increment", "call-1", "actor-1", json!({"count": 1}));
    // The first reconciliation is an immediate Unknown before the +1 s expiry;
    // the next is Absent after its bounded 1.1 s crossing delay.
    let response = bridge.invoke(call);
    assert!(reconciles.load(Ordering::SeqCst) >= 2);
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert_eq!(
        response
            .expect_err("expired nonterminal result is retriable")
            .kind(),
        workflow_runtime::ToolBridgeErrorKind::HandlerFailed
    );
    fs::remove_dir_all(root).expect("cleanup");
}

struct CrossingExpiryExecutor {
    reconciles: Arc<AtomicUsize>,
    executions: Arc<AtomicUsize>,
}

impl EffectExecutor for CrossingExpiryExecutor {
    fn reconcile(&mut self, _request: &ApprovalRequest) -> RemoteObservation {
        if self.reconciles.fetch_add(1, Ordering::SeqCst) == 1 {
            std::thread::sleep(Duration::from_millis(1_100));
            RemoteObservation::Absent
        } else if self.reconciles.load(Ordering::SeqCst) == 1 {
            RemoteObservation::Unknown
        } else {
            RemoteObservation::Absent
        }
    }

    fn execute(&mut self, _request: &ApprovalRequest) -> ExecutionOutcome {
        self.executions.fetch_add(1, Ordering::SeqCst);
        ExecutionOutcome::Committed
    }

    fn verify(&mut self, _request: &ApprovalRequest) -> Postcondition {
        Postcondition::Satisfied
    }
}

#[test]
fn execution_backend_runs_host_injected_durable_effect_and_rejects_mismatched_retry() {
    let root = production_root();
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        + 60_000;
    let request = request(expiry);
    let mut ledger = EffectLedger::open(root.join("effect-ledger.sqlite")).expect("ledger");
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
    .with_idempotency(ToolIdempotency::StableKey);
    let handler = DurableEffectHandler::new(request, ledger, executors, registration)
        .expect("durable handler binding");
    let mut implementations = ToolImplementationRegistry::new();
    implementations
        .register("increment", "1", Arc::new(handler))
        .expect("implementation registry");

    let approvals = ApprovalLedger::new().grant(
        "increment",
        "call-1",
        &json!({"count": 1}),
        "work",
        Duration::from_secs(60),
    );
    let workflow = root.join("workflow.toml");
    let runs = root.join("runs");
    let receipt = ExecutionBackend::run_with_implementations(
        &workflow,
        production_profile(1, approvals.clone()),
        json!({}),
        &runs,
        &implementations,
    )
    .expect("first production route run");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let report = serde_json::to_value(&receipt).expect("receipt JSON");
    assert_eq!(
        report["effect_audits"][0]["history"],
        json!(["proposed", "approved", "started", "committed", "verified"])
    );
    let manifest: Value = serde_json::from_slice(
        &fs::read(receipt.run_root().join("run-manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert!(manifest["checkpoint_manifest"].is_object());
    assert_eq!(manifest["effect_audits"], report["effect_audits"]);
    let inspected = ExecutionBackend::inspect(&runs, receipt.run_id()).expect("inspect");
    assert_eq!(
        serde_json::to_value(inspected).expect("inspect JSON")["effect_audits"],
        report["effect_audits"]
    );
    let audit = serde_json::to_string(&report["effect_audits"]).expect("audit JSON");
    for private in [
        "operator",
        "counter",
        "local",
        "fake",
        "count",
        "increment-once",
    ] {
        assert!(
            !audit.contains(private),
            "private audit material: {private}"
        );
    }

    ExecutionBackend::run_with_implementations(
        &workflow,
        production_profile(1, approvals.clone()),
        json!({}),
        &runs,
        &implementations,
    )
    .expect("ledger-backed replay");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let denied = ExecutionBackend::run_with_implementations(
        &workflow,
        production_profile(2, approvals),
        json!({}),
        &runs,
        &implementations,
    )
    .expect_err("mismatched host approval must deny");
    assert_eq!(denied.kind(), ExecutionErrorKind::AuthorizationDenied);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        serde_json::to_value(denied.receipt().expect("denial receipt"))
            .expect("receipt JSON")
            .get("effect_audits")
            .is_none(),
        "a denied call cannot report a stale verified effect"
    );
    let mut tampered = manifest;
    tampered["effect_audits"][0]["history"] = json!(["failed"]);
    tampered["effect_audits"][0]["approval_digest"] = json!("0".repeat(64));
    fs::write(
        receipt.run_root().join("run-manifest.json"),
        serde_json::to_vec(&tampered).expect("tampered JSON"),
    )
    .expect("tampered report");
    let resumed =
        ExecutionBackend::resume_with_implementations(&runs, receipt.run_id(), &implementations)
            .expect("live projection on completed resume");
    assert_eq!(
        serde_json::to_value(&resumed).expect("receipt JSON")["effect_audits"],
        report["effect_audits"]
    );
    let refreshed: Value = serde_json::from_slice(
        &fs::read(receipt.run_root().join("run-manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(refreshed["effect_audits"], report["effect_audits"]);
    let roundtrip: workflow_adk::execution::ExecutionReceipt =
        serde_json::from_value(report.clone()).expect("roundtrip");
    assert_eq!(roundtrip, receipt);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(report["effect_audits"][0]["schema_version"], json!(1));
    for field in [
        "effect_key",
        "approval_digest",
        "target_digest",
        "policy_digest",
        "workflow_lock",
        "executor_digest",
    ] {
        let digest = report["effect_audits"][0][field].as_str().expect("digest");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
    let mut idle_profile =
        serde_json::to_value(production_profile(1, ApprovalLedger::new())).expect("profile JSON");
    idle_profile["model"]["responses"] =
        json!([
            serde_json::to_string(&json!({"status":"finished", "output":{"done":true}}))
                .expect("finish JSON")
        ]);
    let idle = ExecutionBackend::run_with_implementations(
        &workflow,
        ExecutionProfileV1::parse(&serde_json::to_vec(&idle_profile).expect("profile bytes"))
            .expect("idle profile"),
        json!({}),
        &runs,
        &implementations,
    )
    .expect("registered but unexecuted effect");
    assert!(
        serde_json::to_value(idle)
            .expect("idle receipt")
            .get("effect_audits")
            .is_none(),
        "registration alone is not effect execution"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    remove_production_root(&root);
}
