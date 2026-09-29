use serde_json::json;

#[test]
fn corrupted_history_cannot_forge_a_terminal_result() {
    for state in ["verified", "approved", "future_state"] {
        let root = TestDir::new();
        let request = request();
        let mut ledger = root.ledger();
        ledger.propose(&request).unwrap();
        drop(ledger);
        let database = rusqlite::Connection::open(root.0.join("ledger.db")).unwrap();
        database
            .execute(
                "UPDATE effect_history SET state=?1",
                [format!("\"{state}\"")],
            )
            .unwrap();
        drop(database);
        assert_eq!(
            root.ledger().history(&request),
            Err(LedgerError::Corrupt),
            "{state}"
        );
    }
}

#[test]
fn storage_rejects_competing_owners_future_schema_and_dangling_sidecars() {
    let root = TestDir::new();
    let ledger = root.ledger();
    assert!(matches!(
        EffectLedger::open(root.0.join("ledger.db")),
        Err(LedgerError::Busy)
    ));
    drop(ledger);
    let database = rusqlite::Connection::open(root.0.join("ledger.db")).unwrap();
    database
        .execute("UPDATE effect_ledger_meta SET version=2", [])
        .unwrap();
    drop(database);
    assert!(matches!(
        EffectLedger::open(root.0.join("ledger.db")),
        Err(LedgerError::Corrupt)
    ));
    let other = TestDir::new();
    std::os::unix::fs::symlink(other.0.join("absent"), other.0.join("new.db-wal")).unwrap();
    assert!(matches!(
        EffectLedger::open(other.0.join("new.db")),
        Err(LedgerError::InvalidInput)
    ));
    assert!(!other.0.join("absent").exists());
}

#[path = "issue_240_effect_ledger/paths.rs"]
mod paths;
#[path = "issue_240_effect_ledger/recovery.rs"]
mod recovery;
#[path = "issue_240_effect_ledger/rejection.rs"]
mod rejection;
#[path = "issue_240_effect_ledger/service.rs"]
mod service;
use service::{FakeService, RemoteExecutor, call};

fn registry(address: std::net::SocketAddr) -> ExecutorRegistry {
    let (mut policy, _, _) = fixture();
    let mut registry = ExecutorRegistry::new();
    registry
        .register(
            "increment",
            policy.tools.remove("increment").unwrap(),
            RemoteExecutor(address),
        )
        .unwrap();
    registry
}
fn approved(root: &TestDir, request: &ApprovalRequest) -> EffectLedger {
    let mut ledger = root.ledger();
    ledger.propose(request).unwrap();
    ledger
        .approve(request, request.approval_digest(), "operator", 10)
        .unwrap();
    ledger
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "subprocess entry point, invoked only by crash matrix"]
fn effect_child() {
    let path = std::env::var("ISSUE_240_LEDGER").unwrap();
    let address = std::env::var("ISSUE_240_SERVICE").unwrap().parse().unwrap();
    let stop = std::env::var("ISSUE_240_STOP").unwrap();
    let mut ledger = EffectLedger::open(path).unwrap();
    let request = request();
    let mut registry = registry(address);
    for _ in 0..4 {
        let state = ledger.advance(&request, &mut registry, 10).unwrap();
        let stage = match state {
            EffectState::Started => "before-request",
            EffectState::Committed => "after-commit",
            EffectState::Verified => "after-verified",
            _ => panic!("unexpected state {state:?}"),
        };
        if stage == stop {
            call(address, json!({"op":"barrier","stage":stage}));
        }
        if state == EffectState::Verified {
            return;
        }
    }
    panic!("effect did not finish");
}

#[test]
fn real_process_kills_reopen_and_reconcile_without_duplicate_remote_effects() {
    for stop in [
        "before-request",
        "after-request",
        "after-commit",
        "before-verify",
        "after-verify",
        "after-verified",
    ] {
        let root = TestDir::new();
        let service = FakeService::start(&root.0, stop);
        let request = request();
        drop(approved(&root, &request));
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "effect_child", "--ignored", "--nocapture"])
                .env("ISSUE_240_LEDGER", root.0.join("ledger.db"))
                .env("ISSUE_240_SERVICE", service.address.to_string())
                .env("ISSUE_240_STOP", stop)
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let release = service.paused(stop);
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        release.send(()).unwrap();
        // Disable the one-shot crash barrier before resuming in this process.
        call(service.address, json!({"op":"disarm"}));
        let mut ledger = root.ledger();
        let initial = ledger.state(&request).unwrap();
        assert_eq!(
            initial,
            match stop {
                "before-request" | "after-request" => EffectState::Started,
                "after-verified" => EffectState::Verified,
                _ => EffectState::Committed,
            },
            "{stop}"
        );
        let mut registry = registry(service.address);
        for _ in 0..3 {
            if ledger.advance(&request, &mut registry, 10).unwrap() == EffectState::Verified {
                break;
            }
        }
        assert_eq!(
            ledger.state(&request).unwrap(),
            EffectState::Verified,
            "{stop}"
        );
        let stats = service.stats();
        assert_eq!(stats["count"], 1, "{stop}");
        assert_eq!(stats["value"], 1, "{stop}");
        assert_eq!(
            stats["applies"], 1,
            "no retry after remote commit at {stop}"
        );
        assert_eq!(
            ledger.history(&request).unwrap(),
            vec![
                EffectState::Proposed,
                EffectState::Approved,
                EffectState::Started,
                EffectState::Committed,
                EffectState::Verified
            ]
        );
        drop(ledger);
        let mut reopened = root.ledger();
        assert_eq!(reopened.propose(&request).unwrap(), EffectState::Verified);
        assert_eq!(
            reopened.advance(&request, &mut registry, 2000).unwrap(),
            EffectState::Verified
        );
        assert_eq!(service.stats(), stats, "verified replay does no remote IO");
    }
}

#[test]
fn ambiguous_request_and_verification_never_blindly_retry_or_claim_success() {
    let root = TestDir::new();
    let service = FakeService::start(&root.0, "lost-response");
    let request = request();
    let mut registry = registry(service.address);
    let mut ledger = approved(&root, &request);
    assert_eq!(
        ledger.advance(&request, &mut registry, 10).unwrap(),
        EffectState::Started
    );
    assert_eq!(
        ledger.advance(&request, &mut registry, 10).unwrap(),
        EffectState::Indeterminate
    );
    call(service.address, json!({"op":"unknown","enabled":true}));
    drop(ledger);
    let mut ledger = root.ledger();
    assert_eq!(
        ledger.advance(&request, &mut registry, 2000).unwrap(),
        EffectState::Indeterminate
    );
    assert_eq!(service.stats()["applies"], 1);
    call(service.address, json!({"op":"unknown","enabled":false}));
    // Expiry forbids new requests, not read-only reconciliation of an existing effect.
    assert_eq!(
        ledger.advance(&request, &mut registry, 2000).unwrap(),
        EffectState::Committed
    );
    call(service.address, json!({"op":"unknown","enabled":true}));
    assert_eq!(
        ledger.advance(&request, &mut registry, 2000).unwrap(),
        EffectState::Committed
    );
    call(service.address, json!({"op":"unknown","enabled":false}));
    call(service.address, json!({"op":"violate"}));
    assert_eq!(
        ledger.advance(&request, &mut registry, 2000).unwrap(),
        EffectState::Failed
    );
    assert_eq!(
        ledger.advance(&request, &mut registry, 2000).unwrap(),
        EffectState::Failed
    );
    assert_eq!(service.stats()["applies"], 1);
}

#[test]
fn admission_expiry_target_drift_and_executor_scope_fail_closed() {
    for mode in [
        "unapproved",
        "expired",
        "expired-started",
        "drift",
        "unknown",
        "unregistered",
        "wrong-rule",
    ] {
        let root = TestDir::new();
        let service = FakeService::start(&root.0, "");
        let request = request();
        let mut ledger = root.ledger();
        ledger.propose(&request).unwrap();
        let mut executors = registry(service.address);
        if mode != "unapproved" {
            ledger
                .approve(&request, request.approval_digest(), "operator", 10)
                .unwrap();
        }
        match mode {
            "expired-started" => {
                ledger.advance(&request, &mut executors, 10).unwrap();
            }
            "drift" => {
                call(service.address, json!({"op":"drift"}));
            }
            "unknown" => {
                call(service.address, json!({"op":"unknown","enabled":true}));
            }
            "unregistered" => executors = ExecutorRegistry::new(),
            "wrong-rule" => {
                executors = ExecutorRegistry::new();
                let (mut policy, _, _) = fixture();
                let mut rule = policy.tools.remove("increment").unwrap();
                rule.capabilities.clear();
                executors
                    .register("increment", rule, RemoteExecutor(service.address))
                    .unwrap();
            }
            _ => {}
        }
        let now = if mode.starts_with("expired") {
            1000
        } else {
            10
        };
        let first = ledger.advance(&request, &mut executors, now);
        match mode {
            "unapproved" => assert_eq!(first, Err(LedgerError::ApprovalRequired)),
            "unregistered" | "wrong-rule" => assert_eq!(first, Err(LedgerError::ExecutorMismatch)),
            "expired" => assert_eq!(first, Ok(EffectState::Failed)),
            "expired-started" => assert_eq!(first, Ok(EffectState::Indeterminate)),
            "drift" => {
                assert_eq!(first, Ok(EffectState::Started));
                assert_eq!(
                    ledger.advance(&request, &mut executors, now).unwrap(),
                    EffectState::Indeterminate
                );
            }
            "unknown" => {
                assert_eq!(first, Ok(EffectState::Started));
                assert_eq!(
                    ledger.advance(&request, &mut executors, now).unwrap(),
                    EffectState::Indeterminate
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(service.stats()["count"], 0, "{mode}");
        assert_eq!(
            service.stats()["applies"],
            if mode == "drift" { 1 } else { 0 },
            "{mode}"
        );
    }
}

use workflow_runtime::{argument_fingerprint, effect_ledger::*, firewall::*};

fn fixture() -> (FirewallPolicy, TrustedGoal, ToolProposal) {
    let goal = serde_json::from_value(json!({"schema_version":1,"id":"goal-1",
        "version":"1","capabilities":["network"],"scopes":["fake"],"destinations":["local"]}))
    .unwrap();
    let policy = serde_json::from_value(json!({"schema_version":1,"version":"policy-1","tools":{
        "increment":{"version":"1","capabilities":["network"],"scopes":["fake"],
        "destinations":["local"],"effect":"write","admission":"human_approval",
        "arguments":{"count":{"kind":"integer","min":1,"max":4}},
        "scope":{"kind":"literal","value":"fake"},
        "destination":{"kind":"literal","value":"local"},
        "resource":{"kind":"literal","value":"counter"}}},
        "targets":[{"scope":"fake","destination":"local","resource":"counter",
        "version":{"schema_version":1,"revision":"r1"}}],"forbidden_markers":[]}))
    .unwrap();
    let args = json!({"count":1});
    let proposal = serde_json::from_value(json!({"schema_version":1,"intent":{
        "schema_version":1,"goal_id":"goal-1","tool_id":"increment","tool_version":"1",
        "capabilities":["network"],"scope":"fake","destination":"local","resource":"counter",
        "effect":{"schema_version":1,"class":"write"},
        "target_version":{"schema_version":1,"revision":"r1"}},"arguments":args,
        "provenance":{"source_digest":"a".repeat(64),"arguments_digest":argument_fingerprint(&args),
        "trust_domain":"untrusted_content"}}))
    .unwrap();
    (policy, goal, proposal)
}

fn request() -> ApprovalRequest {
    let (policy, goal, proposal) = fixture();
    ApprovalRequest::bind(
        &goal,
        &policy,
        proposal,
        ApprovalContext {
            operation_id: "increment-once".into(),
            workflow_lock: "b".repeat(64),
            approver: "operator".into(),
            expires_at_unix_ms: 1000,
        },
    )
    .unwrap()
}

struct TestDir(std::path::PathBuf);
impl TestDir {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .expect("HOME is set")
            .join("tmp")
            .join(format!(
                "issue-240-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn ledger(&self) -> EffectLedger {
        EffectLedger::open(self.0.join("ledger.db")).unwrap()
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn approval_is_exact_durable_and_cannot_be_forged_or_renewed_by_replay() {
    let root = TestDir::new();
    let request = request();
    let mut ledger = root.ledger();
    assert_eq!(ledger.propose(&request).unwrap(), EffectState::Proposed);
    assert_eq!(
        ledger.approve(&request, "wrong", "operator", 10),
        Err(LedgerError::ApprovalMismatch)
    );
    assert_eq!(
        ledger.approve(&request, request.approval_digest(), "other", 10),
        Err(LedgerError::ApprovalMismatch)
    );
    assert_eq!(
        ledger.approve(&request, request.approval_digest(), "operator", 1000),
        Err(LedgerError::Expired)
    );
    ledger
        .approve(&request, request.approval_digest(), "operator", 10)
        .unwrap();
    drop(ledger);
    let mut reopened = root.ledger();
    assert_eq!(reopened.propose(&request).unwrap(), EffectState::Approved);
    assert_eq!(
        reopened.history(&request).unwrap(),
        vec![EffectState::Proposed, EffectState::Approved]
    );
    assert_eq!(
        reopened
            .approve(&request, request.approval_digest(), "operator", 11)
            .unwrap(),
        EffectState::Approved
    );
    let (policy, goal, proposal) = fixture();
    let renewal = ApprovalRequest::bind(
        &goal,
        &policy,
        proposal,
        ApprovalContext {
            operation_id: "increment-once".into(),
            workflow_lock: "b".repeat(64),
            approver: "operator".into(),
            expires_at_unix_ms: 2000,
        },
    )
    .unwrap();
    assert_eq!(request.effect_key(), renewal.effect_key());
    assert_ne!(request.approval_digest(), renewal.approval_digest());
    assert_eq!(
        reopened.propose(&renewal),
        Err(LedgerError::ApprovalMismatch)
    );
}

#[test]
fn approval_identity_binds_every_authority_field_and_hard_deny_stays_denied() {
    let original = request();
    for field in [
        "goal",
        "tool",
        "arguments",
        "target",
        "policy",
        "lock",
        "expiry",
        "approver",
        "operation",
    ] {
        let (mut policy, mut goal, mut proposal) = fixture();
        let mut context = ApprovalContext {
            operation_id: "increment-once".into(),
            workflow_lock: "b".repeat(64),
            approver: "operator".into(),
            expires_at_unix_ms: 1000,
        };
        match field {
            "goal" => goal.version = "2".into(),
            "tool" => {
                proposal.intent.tool_version = "2".into();
                policy.tools.get_mut("increment").unwrap().version = "2".into();
            }
            "arguments" => {
                proposal
                    .arguments
                    .insert("count".into(), ToolArgument::Integer(2));
                proposal.provenance.arguments_digest = proposal.arguments_digest();
            }
            "target" => {
                proposal.intent.target_version.revision = "r2".into();
                let mut target = policy.targets.pop_first().unwrap();
                target.version.revision = "r2".into();
                policy.targets.insert(target);
            }
            "policy" => policy.version = "2".into(),
            "lock" => context.workflow_lock = "c".repeat(64),
            "expiry" => context.expires_at_unix_ms += 1,
            "approver" => context.approver = "other".into(),
            "operation" => context.operation_id = "other".into(),
            _ => unreachable!(),
        }
        let changed = ApprovalRequest::bind(&goal, &policy, proposal, context).unwrap();
        assert_ne!(
            original.approval_digest(),
            changed.approval_digest(),
            "{field}"
        );
    }
    let (policy, goal, mut proposal) = fixture();
    proposal.intent.capabilities.clear();
    assert!(matches!(
        ApprovalRequest::bind(
            &goal,
            &policy,
            proposal,
            ApprovalContext {
                operation_id: "op".into(),
                workflow_lock: "b".repeat(64),
                approver: "operator".into(),
                expires_at_unix_ms: 1000,
            }
        ),
        Err(LedgerError::Denied)
    ));
}
