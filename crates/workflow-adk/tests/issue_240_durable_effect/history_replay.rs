use super::super::super::resume::{ChildGuard, interrupted_child};
use super::*;
use std::os::unix::process::ExitStatusExt;

const CHILD_ROOT: &str = "ISSUE_240_HISTORY_REPLAY_ROOT";
const SELECTOR: &str =
    "completion::history::replay::pending_resume_retains_distinct_same_key_snapshots";
const TWO_AGENTS: &str = r#"
schema_version = 1
[workflow]
id = "issue-240-history-replay"
version = "1"
entry = "z-first"
[[nodes]]
id = "z-first"
kind = "agent"
model = { role = "worker", id = "fake-model", version = "1" }
tools = [{ id = "increment", version = "1" }]
[[nodes]]
id = "a-second"
kind = "agent"
model = { role = "worker", id = "fake-model", version = "1" }
tools = [{ id = "increment", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "z-first"
to = "a-second"
[[edges]]
from = "a-second"
to = "done"
"#;

struct InterruptSecondCall {
    inner: Arc<dyn ToolHandler>,
    root: PathBuf,
    executions: Arc<AtomicUsize>,
}

impl ToolHandler for InterruptSecondCall {
    fn effect_audit(
        &self,
        fingerprint: &str,
    ) -> Result<Option<workflow_runtime::effect_ledger::EffectAuditReceipt>, ToolBridgeError> {
        self.inner.effect_audit(fingerprint)
    }

    fn execute(
        &self,
        sandbox: &ChildSandbox<'_>,
        context: &ToolCallContext,
        args: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        if context.actor() == "a-second" {
            // SAFETY: only this disposable subprocess is killed, after pending publication.
            unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
            unreachable!("SIGKILL terminates the interrupted fixture");
        }
        let result = self.inner.execute(sandbox, context, args);
        fs::write(
            self.root.join("original-executions"),
            self.executions.load(Ordering::SeqCst).to_string(),
        )
        .expect("persist fake service count");
        result
    }

    fn implementation_identity(&self) -> String {
        self.inner.implementation_identity()
    }

    fn registration(&self) -> Option<ToolRegistration> {
        self.inner.registration()
    }
}

fn interrupted_run(root: &Path) {
    let executions = Arc::new(AtomicUsize::new(0));
    let expires = fs::read_to_string(root.join("expiry"))
        .expect("expiry")
        .parse()
        .expect("expiry integer");
    let implementations = registry(
        root,
        expires,
        false,
        Arc::clone(&executions),
        "increment-once",
    );
    let mut interrupted = ToolImplementationRegistry::new();
    interrupted
        .register(
            "increment",
            "1",
            Arc::new(InterruptSecondCall {
                inner: implementations.resolve("increment", "1").expect("handler"),
                root: root.to_owned(),
                executions,
            }),
        )
        .expect("interrupted handler");
    let approvals = ApprovalLedger::new()
        .grant(
            "increment",
            "call-1",
            &json!({"count":1}),
            "z-first",
            Duration::from_secs(60),
        )
        .grant(
            "increment",
            "call-1",
            &json!({"count":1}),
            "a-second",
            Duration::from_secs(60),
        );
    let mut wire =
        serde_json::to_value(production_profile(1, ApprovalLedger::new())).expect("profile");
    let responses = wire["model"]["responses"]
        .as_array_mut()
        .expect("fake response script");
    // Worker nodes share this queue; retain the complete script for resume's turn offset.
    responses.extend(responses.clone());
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&wire).expect("wire"))
        .expect("profile")
        .with_approvals(approvals);
    ExecutionBackend::run_with_implementations(
        root.join("workflow.toml"),
        profile,
        json!({}),
        root.join("runs"),
        &interrupted,
    )
    .expect("child must be interrupted during its second call");
    panic!("child did not reach the pending call");
}

struct ReconciledExecutor {
    executions: Arc<AtomicUsize>,
    verifications: Arc<AtomicUsize>,
    violated: bool,
}

impl EffectExecutor for ReconciledExecutor {
    fn reconcile(&mut self, _: &ApprovalRequest) -> RemoteObservation {
        // The first invocation already committed this same remote deduplication key.
        RemoteObservation::Committed
    }

    fn execute(&mut self, _: &ApprovalRequest) -> ExecutionOutcome {
        self.executions.fetch_add(1, Ordering::SeqCst);
        ExecutionOutcome::Committed
    }

    fn verify(&mut self, _: &ApprovalRequest) -> Postcondition {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        if self.violated {
            Postcondition::Violated
        } else {
            Postcondition::Satisfied
        }
    }
}

fn rebound_registry(
    root: &Path,
    expires: u64,
    violated: bool,
    executions: &Arc<AtomicUsize>,
    verifications: &Arc<AtomicUsize>,
) -> ToolImplementationRegistry {
    let request = request(expires);
    let mut ledger =
        EffectLedger::open(root.join("rebound-ledger.sqlite")).expect("rebound ledger");
    ledger.propose(&request).expect("proposal");
    ledger
        .approve(&request, request.approval_digest(), "operator", 1)
        .expect("approval");
    let (policy, _, _) = fixture();
    let mut executors = ExecutorRegistry::new();
    executors
        .register(
            "increment",
            policy.tools["increment"].clone(),
            ReconciledExecutor {
                executions: Arc::clone(executions),
                verifications: Arc::clone(verifications),
                violated,
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
    let handler =
        DurableEffectHandler::new(request, ledger, executors, registration).expect("handler");
    let mut implementations = ToolImplementationRegistry::new();
    implementations
        .register("increment", "1", Arc::new(handler))
        .expect("registry");
    implementations
}

fn replay_case(changed_approval: bool, handler_error: bool) -> (Value, Value) {
    let root = production_root();
    fs::write(root.join("workflow.toml"), TWO_AGENTS).expect("two sequential agents");
    let expires = expiry();
    fs::write(root.join("expiry"), expires.to_string()).expect("expiry");
    let child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", SELECTOR, "--nocapture"])
        .env(CHILD_ROOT, &root)
        .spawn()
        .expect("disposable child");
    let status = interrupted_child(ChildGuard(Some(child)));
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(
        fs::read_to_string(root.join("original-executions")).expect("effect count"),
        "1"
    );
    let runs = root.join("runs");
    let run_root = fs::read_dir(&runs)
        .expect("runs")
        .map(|entry| entry.expect("run").path())
        .find(|path| path.join("run-manifest.json").is_file())
        .expect("interrupted run");
    let manifest = read_json(&run_root.join("run-manifest.json"));
    let run_id = manifest["run_id"].as_str().expect("run ID");
    let ledger = read_json(&run_root.join("loop-ledger.json"));
    let completed = ledger["nodes"]["z-first"]["completed_calls"]
        .as_array()
        .expect("completed");
    assert_eq!(completed.len(), 1);
    let original = completed[0]["call"]["effect"].clone();
    assert_eq!(
        original["history"],
        json!(["proposed", "approved", "started", "committed", "verified"])
    );
    let pending = ExecutionBackend::inspect_pending_tools(&runs, run_id).expect("pending");
    assert_eq!(pending.len(), 1);
    let pending = &pending[0];
    assert_eq!(pending.call_id, "call-1");
    assert_eq!(pending.actor, "a-second");
    let executions = Arc::new(AtomicUsize::new(0));
    let verifications = Arc::new(AtomicUsize::new(0));
    let implementations = rebound_registry(
        &root,
        expires + u64::from(changed_approval),
        !changed_approval,
        &executions,
        &verifications,
    );
    let lookups = Arc::new(AtomicUsize::new(0));
    let failing = changed_audit(&implementations, AuditMode::HandlerError, &lookups);
    let current = if handler_error {
        &failing
    } else {
        &implementations
    };
    let denied = ExecutionBackend::resume_with_implementations(&runs, run_id, current)
        .expect_err("pending execution still needs fresh authority");
    assert_eq!(denied.kind(), ExecutionErrorKind::AuthorizationDenied);
    assert_eq!(verifications.load(Ordering::SeqCst), 0);
    let grant = ApprovalLedger::new().grant(
        &pending.tool_name,
        &pending.call_id,
        &pending.arguments,
        &pending.actor,
        Duration::from_secs(60),
    );
    let result =
        ExecutionBackend::resume_with_implementations_and_approvals(&runs, run_id, current, grant);
    let receipt = if handler_error {
        let error = result.expect_err("post-effect handler failure is preserved");
        assert_eq!(error.kind(), ExecutionErrorKind::Tool);
        serde_json::to_value(error.receipt().expect("failure receipt")).expect("receipt")
    } else {
        serde_json::to_value(result.expect("pending resume")).expect("receipt")
    };
    assert_eq!(verifications.load(Ordering::SeqCst), 1);
    assert_eq!(
        executions.load(Ordering::SeqCst),
        0,
        "remote effect must not execute twice"
    );
    let actual = receipt["effect_audits"].clone();
    assert_eq!(
        read_json(&run_root.join("run-manifest.json"))["effect_audits"],
        actual
    );
    let rebound = serde_json::to_value(
        implementations
            .effect_audit(
                "increment",
                "1",
                &workflow_runtime::argument_fingerprint(&json!({"count":1})),
            )
            .expect("audit")
            .expect("actual effect"),
    )
    .expect("receipt");
    assert_eq!(original["effect_key"], rebound["effect_key"]);
    if changed_approval {
        assert_ne!(original["approval_digest"], rebound["approval_digest"]);
    } else {
        let mut unchanged_identity = rebound.clone();
        unchanged_identity["history"] = original["history"].clone();
        assert_eq!(unchanged_identity, original);
        assert_ne!(original["history"], rebound["history"]);
    }
    if !handler_error {
        for _ in 0..2 {
            let resumed = ExecutionBackend::resume_with_implementations(&runs, run_id, current)
                .expect("completed resume needs no fresh grant");
            assert_eq!(
                serde_json::to_value(resumed).expect("receipt")["effect_audits"],
                actual
            );
            assert_eq!(
                read_json(&run_root.join("run-manifest.json"))["effect_audits"],
                actual
            );
        }
        assert_eq!(verifications.load(Ordering::SeqCst), 1);
        assert_eq!(executions.load(Ordering::SeqCst), 0);
    }
    drop(failing);
    drop(implementations);
    remove_production_root(&root);
    (actual, json!([original, rebound]))
}

#[test]
fn pending_resume_retains_distinct_same_key_snapshots() {
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        interrupted_run(&PathBuf::from(root));
        return;
    }
    let mut observations = Vec::new();
    for changed_approval in [true, false] {
        for handler_error in [true, false] {
            let (actual, expected) = replay_case(changed_approval, handler_error);
            observations.push((changed_approval, handler_error, actual, expected));
        }
    }
    for (changed_approval, handler_error, actual, expected) in observations {
        let actual = actual.as_array().expect("audit list");
        let expected = expected.as_array().expect("expected snapshots");
        assert_eq!(
            actual.len(),
            2,
            "distinct snapshots: changed_approval={changed_approval} handler_error={handler_error}"
        );
        assert!(
            expected.iter().all(|receipt| actual.contains(receipt)),
            "both full actual receipts survive"
        );
    }
}
