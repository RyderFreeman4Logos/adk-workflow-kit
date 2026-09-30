use super::*;
use std::process::Command;
use workflow_runtime::{
    ChildSandbox, ToolBridgeError, ToolBridgeErrorKind, ToolCallContext, ToolEnvelope, ToolFailure,
    ToolHandler,
};

struct TerminalExecutor {
    calls: Arc<AtomicUsize>,
    violated: bool,
}
impl EffectExecutor for TerminalExecutor {
    fn reconcile(&mut self, _: &ApprovalRequest) -> RemoteObservation {
        RemoteObservation::Absent
    }
    fn execute(&mut self, _: &ApprovalRequest) -> ExecutionOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ExecutionOutcome::Committed
    }
    fn verify(&mut self, _: &ApprovalRequest) -> Postcondition {
        if self.violated {
            Postcondition::Violated
        } else {
            Postcondition::Satisfied
        }
    }
}

fn registry(
    root: &Path,
    expiry: u64,
    violated: bool,
    calls: Arc<AtomicUsize>,
    operation: &str,
) -> ToolImplementationRegistry {
    let (policy, goal, proposal) = fixture();
    let request = ApprovalRequest::bind(
        &goal,
        &policy,
        proposal,
        ApprovalContext {
            operation_id: operation.into(),
            workflow_lock: "b".repeat(64),
            approver: "operator".into(),
            expires_at_unix_ms: expiry,
        },
    )
    .expect("request");
    let mut ledger =
        EffectLedger::open(root.join(format!("{operation}-effect-ledger.sqlite"))).expect("ledger");
    ledger.propose(&request).expect("proposal");
    ledger
        .approve(&request, request.approval_digest(), "operator", 1)
        .expect("approval");
    let mut executors = ExecutorRegistry::new();
    executors
        .register(
            "increment",
            policy.tools["increment"].clone(),
            TerminalExecutor { calls, violated },
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
    let handler =
        DurableEffectHandler::new(request, ledger, executors, registration).expect("handler");
    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("increment", "1", Arc::new(handler))
        .expect("registry");
    registry
}

fn profile(root: &Path, skill: bool) -> ExecutionProfileV1 {
    let mut wire =
        serde_json::to_value(production_profile(1, ApprovalLedger::new())).expect("profile");
    if skill {
        let package = root.join("audit-skill");
        if !package.exists() {
            fs::create_dir(&package).expect("package");
            fs::write(package.join("SKILL.md"), "---\nname: audit-skill\ndescription: Synthetic privacy fixture.\n---\nKeep arguments private.\n").expect("skill");
            use sha2::{Digest, Sha256};
            fs::create_dir(package.join("assets")).expect("assets");
            fs::write(package.join("assets/guide.txt"), b"Synthetic resource").expect("resource");
            fs::write(package.join("skill.runtime.toml"), format!("schema_version = 1\n[skill]\nid = \"audit-skill\"\nversion = \"1\"\n[[resources]]\nid = \"assets/guide.txt\"\nsha256 = \"sha256:{:x}\"\n", Sha256::digest(b"Synthetic resource"))).expect("runtime");
            fs::write(
                root.join("workflow.toml"),
                PRODUCTION_WORKFLOW.replace(
                    "tools =",
                    "skills = [{ id = \"audit-skill\", version = \"1\" }]\ntools =",
                ),
            )
            .expect("workflow");
        }
        wire["skills"] = json!([{"id":"audit-skill","version":"1","root":package}]);
    }
    ExecutionProfileV1::parse(&serde_json::to_vec(&wire).expect("wire"))
        .expect("profile")
        .with_approvals(ApprovalLedger::new().grant(
            "increment",
            "call-1",
            &json!({"count":1}),
            "work",
            Duration::from_secs(60),
        ))
}
fn expiry() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        + 600_000
}
fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read fixture")).expect("JSON")
}
fn assert_private(run_root: &Path) {
    let ledger = read_json(&run_root.join("loop-ledger.json"));
    let state = &ledger["nodes"]["work"];
    assert_eq!(state["conversation"], json!([]));
    let call = &state["completed_calls"][0]["call"];
    assert_ne!(call["args"], json!({"count":1}));
    assert_eq!(
        call["fingerprint"],
        json!(workflow_runtime::argument_fingerprint(&json!({"count":1})))
    );
    assert_ne!(
        call["fingerprint"],
        json!(workflow_runtime::argument_fingerprint(&call["args"]))
    );
}
fn assert_resume(
    runs: &Path,
    run_id: &str,
    implementations: &ToolImplementationRegistry,
    expected: &Value,
    calls: &AtomicUsize,
    count: usize,
) {
    let resumed = ExecutionBackend::resume_with_implementations(runs, run_id, implementations)
        .expect("completed resume without grant");
    let actual = serde_json::to_value(&resumed).expect("receipt")["effect_audits"].clone();
    assert_eq!(
        actual, *expected,
        "completed-call provenance must survive resume"
    );
    assert_eq!(
        read_json(&resumed.run_root().join("run-manifest.json"))["effect_audits"],
        *expected
    );
    assert_eq!(calls.load(Ordering::SeqCst), count);
}

struct AuditErrorHandler {
    calls: Arc<AtomicUsize>,
    audit_calls: Arc<AtomicUsize>,
    envelope: ToolEnvelope<Value>,
    registration: ToolRegistration,
}

impl ToolHandler for AuditErrorHandler {
    fn effect_audit(
        &self,
        _: &str,
    ) -> Result<Option<workflow_runtime::effect_ledger::EffectAuditReceipt>, ToolBridgeError> {
        self.audit_calls.fetch_add(1, Ordering::SeqCst);
        Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))
    }

    fn required_capabilities(&self, _: &Value) -> Result<Vec<SandboxCapability>, ToolBridgeError> {
        Ok(vec![SandboxCapability::Network])
    }

    fn requires_approval(&self, _: &Value) -> Result<bool, ToolBridgeError> {
        Ok(true)
    }

    fn execute(
        &self,
        _: &ChildSandbox<'_>,
        _: &ToolCallContext,
        _: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.envelope.clone())
    }

    fn implementation_identity(&self) -> String {
        "issue-240-audit-error/v1".into()
    }

    fn registration(&self) -> Option<ToolRegistration> {
        Some(self.registration.clone())
    }
}

fn assert_no_effect_audits(value: &Value) {
    match value.get("effect_audits") {
        None => {}
        Some(Value::Array(audits)) => assert!(audits.is_empty()),
        other => panic!("unavailable advisory audits must not be projected: {other:?}"),
    }
}

fn assert_completed_envelope(run_root: &Path, expected: &Value) {
    let ledger = read_json(&run_root.join("loop-ledger.json"));
    let node = &ledger["nodes"]["work"];
    assert_eq!(node["pending_calls"], json!([]));
    let completed = node["completed_calls"].as_array().expect("completed calls");
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0]["call"]["response"], *expected);
}

fn audit_lookup_error_preserves_envelope(envelope: ToolEnvelope<Value>) {
    let root = production_root();
    let expected = serde_json::to_value(&envelope).expect("expected envelope");
    let calls = Arc::new(AtomicUsize::new(0));
    let audit_calls = Arc::new(AtomicUsize::new(0));
    let registration = ToolRegistration::for_types::<Value, Value>(
        "increment",
        ToolProvenance::new("increment", "1"),
        ToolFlags::new(false, true, true),
    )
    .expect("registration")
    .with_required_capabilities([SandboxCapability::Network])
    .with_idempotency(ToolIdempotency::StableKey);
    let mut implementations = ToolImplementationRegistry::new();
    implementations
        .register(
            "increment",
            "1",
            Arc::new(AuditErrorHandler {
                calls: Arc::clone(&calls),
                audit_calls: Arc::clone(&audit_calls),
                envelope,
                registration,
            }),
        )
        .expect("implementation");

    let receipt = match ExecutionBackend::run_with_implementations(
        root.join("workflow.toml"),
        profile(&root, false),
        json!({}),
        root.join("runs"),
        &implementations,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            remove_production_root(&root);
            panic!("advisory audit error replaced the handler result: {error:?}");
        }
    };
    assert_eq!(receipt.status(), "succeeded");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(audit_calls.load(Ordering::SeqCst) > 0);
    let receipt_json = serde_json::to_value(&receipt).expect("receipt");
    assert_no_effect_audits(&receipt_json);
    assert_completed_envelope(receipt.run_root(), &expected);
    let manifest = read_json(&receipt.run_root().join("run-manifest.json"));
    assert_eq!(manifest["status"], "succeeded");
    assert_no_effect_audits(&manifest);

    let resumed = match ExecutionBackend::resume_with_implementations(
        root.join("runs"),
        receipt.run_id(),
        &implementations,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            remove_production_root(&root);
            panic!("completed resume lost the delivered handler result: {error:?}");
        }
    };
    assert_eq!(resumed.status(), "succeeded");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_completed_envelope(resumed.run_root(), &expected);
    assert_no_effect_audits(&read_json(&resumed.run_root().join("run-manifest.json")));
    remove_production_root(&root);
}

#[test]
fn audit_lookup_error_preserves_success_envelope_on_production_route() {
    audit_lookup_error_preserves_envelope(ToolEnvelope::success(
        json!({"delivered":"success"}),
        ToolProvenance::new("increment", "1"),
    ));
}

#[test]
fn audit_lookup_error_preserves_failure_envelope_on_production_route() {
    audit_lookup_error_preserves_envelope(ToolEnvelope::failure(
        ToolFailure::Unavailable,
        ToolProvenance::new("increment", "1"),
    ));
}

#[test]
fn skill_finished_effect_provenance_survives_completed_resume() {
    let root = production_root();
    let calls = Arc::new(AtomicUsize::new(0));
    let implementations = registry(&root, expiry(), false, Arc::clone(&calls), "original");
    let receipt = ExecutionBackend::run_with_implementations(
        root.join("workflow.toml"),
        profile(&root, true),
        json!({}),
        root.join("runs"),
        &implementations,
    )
    .expect("run");
    let audit = serde_json::to_value(&receipt).expect("receipt")["effect_audits"].clone();
    assert_eq!(
        audit[0]["history"],
        json!(["proposed", "approved", "started", "committed", "verified"])
    );
    assert_private(receipt.run_root());
    assert_resume(
        &root.join("runs"),
        receipt.run_id(),
        &implementations,
        &audit,
        &calls,
        1,
    );
    assert_private(receipt.run_root());
    remove_production_root(&root);
}

#[test]
fn failed_effect_provenance_survives_completed_resume() {
    for (expired, skill) in [(false, false), (true, true)] {
        let root = production_root();
        let calls = Arc::new(AtomicUsize::new(0));
        let expiry = if expired { 2 } else { expiry() };
        let implementations = registry(&root, expiry, !expired, Arc::clone(&calls), "original");
        let receipt = ExecutionBackend::run_with_implementations(
            root.join("workflow.toml"),
            profile(&root, skill),
            json!({}),
            root.join("runs"),
            &implementations,
        )
        .expect("terminal failed effect run");
        let audit = serde_json::to_value(&receipt).expect("receipt")["effect_audits"].clone();
        let expected = if expired {
            json!(["proposed", "approved", "failed"])
        } else {
            json!(["proposed", "approved", "started", "committed", "failed"])
        };
        assert_eq!(audit[0]["history"], expected);
        let count = usize::from(!expired);
        assert_resume(
            &root.join("runs"),
            receipt.run_id(),
            &implementations,
            &audit,
            &calls,
            count,
        );
        // Same tool/version/arguments, but a different operation cannot replace bound evidence.
        let unrelated = registry(&root, expiry, !expired, Arc::clone(&calls), "unrelated");
        let mut manifest = read_json(&receipt.run_root().join("run-manifest.json"));
        manifest["effect_audits"][0]["effect_key"] = json!("0".repeat(64));
        fs::write(
            receipt.run_root().join("run-manifest.json"),
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("tamper report");
        let resumed = ExecutionBackend::resume_with_implementations(
            root.join("runs"),
            receipt.run_id(),
            &unrelated,
        )
        .expect("advisory omission");
        assert!(
            serde_json::to_value(resumed)
                .expect("receipt")
                .get("effect_audits")
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), count);
        assert_resume(
            &root.join("runs"),
            receipt.run_id(),
            &implementations,
            &audit,
            &calls,
            count,
        );
        // Same effect key and arguments but a different approval digest is not
        // the original completed request either.
        let other_root = production_root();
        let rebound = registry(
            &other_root,
            expiry + 1,
            !expired,
            Arc::clone(&calls),
            "original",
        );
        let resumed = ExecutionBackend::resume_with_implementations(
            root.join("runs"),
            receipt.run_id(),
            &rebound,
        )
        .expect("rebound omission");
        assert!(
            serde_json::to_value(resumed)
                .expect("receipt")
                .get("effect_audits")
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), count);
        assert_resume(
            &root.join("runs"),
            receipt.run_id(),
            &implementations,
            &audit,
            &calls,
            count,
        );
        drop(rebound);
        remove_production_root(&other_root);
        let ledger_path = receipt.run_root().join("loop-ledger.json");
        let bytes = fs::read(&ledger_path).expect("ledger");
        let mut ledger: Value = serde_json::from_slice(&bytes).expect("ledger JSON");
        ledger["nodes"]["work"]["completed_calls"][0]["call"]["effect"]["effect_key"] =
            json!("0".repeat(64));
        // Both generations are untrusted unless their exact digest matches the checkpoint.
        ledger["checkpoint_nodes"] = Value::Null;
        fs::write(
            &ledger_path,
            serde_json::to_vec(&ledger).expect("tampered ledger"),
        )
        .expect("write");
        assert_eq!(
            ExecutionBackend::resume_with_implementations(
                root.join("runs"),
                receipt.run_id(),
                &implementations
            )
            .expect_err("tampered checkpoint evidence")
            .kind(),
            ExecutionErrorKind::InvalidRunState
        );
        fs::write(&ledger_path, bytes).expect("restore test fixture");
        if skill {
            assert_private(receipt.run_root());
        }
        remove_production_root(&root);
    }
}

#[test]
fn skill_unfinished_effect_provenance_uses_original_completed_fingerprint() {
    const CHILD: &str = "ISSUE_240_COMPLETED_ROOT";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let expiry = fs::read_to_string(root.join("expiry"))
            .expect("expiry")
            .parse()
            .expect("integer");
        let implementations = registry(
            &root,
            expiry,
            false,
            Arc::new(AtomicUsize::new(0)),
            "original",
        );
        ExecutionBackend::run_with_implementations(
            root.join("workflow.toml"),
            profile(&root, true),
            json!({}),
            root.join("runs"),
            &implementations,
        )
        .expect("interrupted run");
        panic!("completion barrier did not interrupt");
    }
    let root = production_root();
    let expiry = expiry();
    fs::write(root.join("expiry"), expiry.to_string()).expect("expiry");
    let child = Command::new(std::env::current_exe().expect("executable"))
        .args([
            "--exact",
            "completion::skill_unfinished_effect_provenance_uses_original_completed_fingerprint",
            "--nocapture",
        ])
        .env(CHILD, &root)
        .env(
            "WORKFLOW_KIT_TEST_CRASH_BARRIER",
            "after-ordinary-call-completion",
        )
        .spawn()
        .expect("child");
    let status = super::resume::interrupted_child(super::resume::ChildGuard(Some(child)));
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    use std::os::unix::process::ExitStatusExt;
    let runs = root.join("runs");
    let run_root = fs::read_dir(&runs)
        .expect("runs")
        .map(|e| e.expect("entry").path())
        .find(|p| p.join("run-manifest.json").is_file())
        .expect("run");
    assert_private(&run_root);
    assert_eq!(
        read_json(&run_root.join("loop-ledger.json"))["nodes"]["work"]["finish_admitted"],
        json!(false)
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let implementations = registry(&root, expiry, false, Arc::clone(&calls), "original");
    let run_id = read_json(&run_root.join("run-manifest.json"))["run_id"]
        .as_str()
        .expect("run ID")
        .to_owned();
    let resumed = ExecutionBackend::resume_with_implementations(&runs, &run_id, &implementations)
        .expect("resume completed call without grant");
    let audit = serde_json::to_value(&resumed).expect("receipt")["effect_audits"].clone();
    assert_eq!(
        audit[0]["history"],
        json!(["proposed", "approved", "started", "committed", "verified"]),
        "redacted argument rehash must not lose completion evidence"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_resume(&runs, &run_id, &implementations, &audit, &calls, 0);
    assert_private(&run_root);
    remove_production_root(&root);
}
