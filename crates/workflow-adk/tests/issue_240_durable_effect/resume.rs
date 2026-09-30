use super::{
    ApprovalLedger, ApprovalRequest, Arc, AtomicUsize, DurableEffectHandler, Duration,
    EffectExecutor, EffectLedger, ExecutionBackend, ExecutionErrorKind, ExecutionOutcome,
    ExecutorRegistry, Ordering, Path, PathBuf, Postcondition, RemoteObservation, SandboxCapability,
    SystemTime, ToolFlags, ToolIdempotency, ToolImplementationRegistry, ToolProvenance,
    ToolRegistration, UNIX_EPOCH, Value, fixture, fs, json, production_profile, production_root,
    remove_production_root, request,
};
use std::{os::unix::process::ExitStatusExt, process::Command, sync::atomic::AtomicBool};
use workflow_adk::execution::PendingToolApproval;

struct ChildGuard(Option<std::process::Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn interrupted_child(mut child: ChildGuard) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child
            .0
            .as_mut()
            .expect("live child")
            .try_wait()
            .expect("wait")
        {
            child.0.take(); // Disarm immediately after reap; never signal a reused PID.
            return status;
        }
        assert!(std::time::Instant::now() < deadline, "child deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn pending_approval_debug_redacts_all_review_material() {
    let markers = [
        "synthetic-run-id-marker",
        "synthetic-checkpoint-marker",
        "synthetic-ledger-marker",
        "synthetic-actor-marker",
        "synthetic-tool-marker",
        "synthetic-call-marker",
        "synthetic-argument-marker",
        "synthetic-fingerprint-marker",
    ];
    let pending = PendingToolApproval {
        run_id: markers[0].to_owned(),
        checkpoint_identity: markers[1].to_owned(),
        ledger_digest: markers[2].to_owned(),
        actor: markers[3].to_owned(),
        tool_name: markers[4].to_owned(),
        call_id: markers[5].to_owned(),
        arguments: json!({"private": markers[6]}),
        argument_fingerprint: markers[7].to_owned(),
    };

    assert!(
        pending.run_id == markers[0],
        "review run ID must stay exact"
    );
    assert!(
        pending.checkpoint_identity == markers[1],
        "checkpoint identity must stay exact"
    );
    assert!(
        pending.ledger_digest == markers[2],
        "ledger digest must stay exact"
    );
    assert!(pending.actor == markers[3], "review actor must stay exact");
    assert!(
        pending.tool_name == markers[4],
        "review tool name must stay exact"
    );
    assert!(
        pending.call_id == markers[5],
        "review call ID must stay exact"
    );
    assert!(
        pending.arguments == json!({"private": markers[6]}),
        "review arguments must stay exact"
    );
    assert!(
        pending.argument_fingerprint == markers[7],
        "argument fingerprint must stay exact"
    );

    let direct = format!("{pending:?}");
    assert!(
        markers.iter().all(|marker| !direct.contains(marker)),
        "PendingToolApproval Debug must redact review values"
    );
    let nested = format!("{:?}", vec![pending]);
    assert!(
        markers.iter().all(|marker| !nested.contains(marker)),
        "nested PendingToolApproval Debug must redact review values"
    );
}

struct ResumeExecutor {
    calls: Arc<AtomicUsize>,
    interrupt: bool,
}

impl EffectExecutor for ResumeExecutor {
    fn reconcile(&mut self, _: &ApprovalRequest) -> RemoteObservation {
        RemoteObservation::Absent
    }
    fn execute(&mut self, _: &ApprovalRequest) -> ExecutionOutcome {
        if self.interrupt {
            // SAFETY: kill only this disposable test subprocess after durable Started.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGKILL);
            }
            unreachable!("SIGKILL must terminate child");
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        ExecutionOutcome::Committed
    }
    fn verify(&mut self, _: &ApprovalRequest) -> Postcondition {
        Postcondition::Satisfied
    }
}

fn registry(
    root: &Path,
    expiry: u64,
    calls: Arc<AtomicUsize>,
    interrupt: bool,
) -> ToolImplementationRegistry {
    let request = request(expiry);
    let mut ledger = EffectLedger::open(root.join("effect-ledger.sqlite")).expect("ledger");
    if interrupt {
        ledger.propose(&request).expect("proposal");
        ledger
            .approve(&request, request.approval_digest(), "operator", 1)
            .expect("durable approval");
    }
    let (policy, _, _) = fixture();
    let mut executors = ExecutorRegistry::new();
    executors
        .register(
            "increment",
            policy.tools["increment"].clone(),
            ResumeExecutor { calls, interrupt },
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

#[test]
fn fresh_approval_resume_preserves_pending_authority_and_deduplicates() {
    const CHILD: &str = "ISSUE_240_RESUME_ROOT";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let expiry = fs::read_to_string(root.join("expiry"))
            .expect("expiry")
            .parse()
            .expect("expiry integer");
        let implementations = registry(&root, expiry, Arc::new(AtomicUsize::new(0)), true);
        let approval = ApprovalLedger::new().grant(
            "increment",
            "call-1",
            &json!({"count":1}),
            "work",
            Duration::from_secs(60),
        );
        ExecutionBackend::run_with_implementations(
            root.join("workflow.toml"),
            production_profile(1, approval),
            json!({}),
            root.join("runs"),
            &implementations,
        )
        .expect("child must be interrupted");
        panic!("child did not reach durable effect");
    }
    let root = production_root();
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        + 600_000;
    fs::write(root.join("expiry"), expiry.to_string()).expect("expiry");
    let child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "resume::fresh_approval_resume_preserves_pending_authority_and_deduplicates",
            "--nocapture",
        ])
        .env(CHILD, &root)
        .spawn()
        .expect("child");
    let status = interrupted_child(ChildGuard(Some(child)));
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    let runs = root.join("runs");
    let run_root = fs::read_dir(&runs)
        .expect("runs")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.join("run-manifest.json").is_file())
        .expect("interrupted run");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).expect("manifest"))
            .expect("manifest JSON");
    let run_id_owned = manifest["run_id"].as_str().expect("run ID").to_owned();
    let run_id = run_id_owned.as_str();
    manifest["effect_audits"] = json!([{
        "schema_version":1,"effect_key":"0".repeat(64),"approval_digest":"0".repeat(64),
        "target_digest":"0".repeat(64),"policy_digest":"0".repeat(64),
        "workflow_lock":"b".repeat(64),"executor_digest":"0".repeat(64),
        "history":["proposed","approved","started","committed","verified"]
    }]);
    fs::write(
        run_root.join("run-manifest.json"),
        serde_json::to_vec(&manifest).expect("tampered JSON"),
    )
    .expect("tampered report");
    let persisted_profile = fs::read(run_root.join("execution-profile.json")).expect("profile");
    let profile_json: Value = serde_json::from_slice(&persisted_profile).expect("profile JSON");
    assert!(profile_json.get("approvals").is_none());
    let calls = Arc::new(AtomicUsize::new(0));
    let implementations = registry(&root, expiry, Arc::clone(&calls), false);
    let pending_bytes = fs::read(run_root.join("loop-ledger.json")).expect("pending ledger");
    let pending = ExecutionBackend::inspect_pending_tools(&runs, run_id).expect("pending review");
    assert_eq!(
        pending.len(),
        1,
        "host needs the exact checkpoint-bound pending proposal"
    );
    let pending = &pending[0];
    assert_eq!(pending.run_id, run_id);
    assert_eq!(pending.actor, "work");
    assert_eq!(pending.call_id, "call-1");
    assert_eq!(pending.tool_name, "increment");
    assert_eq!(pending.arguments, json!({"count":1}));
    assert_eq!(
        pending.argument_fingerprint,
        workflow_runtime::argument_fingerprint(&pending.arguments)
    );
    assert_eq!(
        pending
            .checkpoint_identity
            .strip_prefix("sha256:")
            .expect("digest scheme")
            .len(),
        64
    );
    assert_eq!(
        pending
            .ledger_digest
            .strip_prefix("sha256:")
            .expect("digest scheme")
            .len(),
        64
    );
    // Existing entry points must never revive the original runtime-only grant.
    assert!(ExecutionBackend::resume(&runs, run_id).is_err());
    assert!(
        ExecutionBackend::resume_cancellable(&runs, run_id, Arc::new(AtomicBool::new(false)))
            .is_err()
    );
    let denied = ExecutionBackend::resume_with_implementations(&runs, run_id, &implementations)
        .expect_err("no restored authority");
    assert_eq!(denied.kind(), ExecutionErrorKind::AuthorizationDenied);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        serde_json::to_value(denied.receipt().expect("denial receipt"))
            .expect("receipt JSON")
            .get("effect_audits")
            .is_none(),
        "tampered reports are not live provenance or authority"
    );
    assert_eq!(
        ExecutionBackend::inspect(&runs, run_id)
            .expect("inspect")
            .status(),
        "running",
        "authorization denial must not poison the pending checkpoint"
    );
    for (tool, id, actor, args, expiry) in [
        (
            "increment",
            "call-1",
            "work",
            json!({"count":1}),
            Duration::ZERO,
        ),
        (
            "increment",
            "call-1",
            "other",
            json!({"count":1}),
            Duration::from_secs(60),
        ),
        (
            "increment",
            "other",
            "work",
            json!({"count":1}),
            Duration::from_secs(60),
        ),
        (
            "increment",
            "call-1",
            "work",
            json!({"count":2}),
            Duration::from_secs(60),
        ),
        (
            "other",
            "call-1",
            "work",
            json!({"count":1}),
            Duration::from_secs(60),
        ),
    ] {
        let grant = ApprovalLedger::new().grant(tool, id, &args, actor, expiry);
        let denied = ExecutionBackend::resume_with_implementations_and_approvals(
            &runs,
            run_id,
            &implementations,
            grant,
        )
        .expect_err("nonmatching grant");
        assert_eq!(denied.kind(), ExecutionErrorKind::AuthorizationDenied);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fs::read(run_root.join("loop-ledger.json")).expect("pending ledger"),
            pending_bytes
        );
    }
    let mut tampered: Value = serde_json::from_slice(&pending_bytes).expect("pending JSON");
    tampered["nodes"]["work"]["pending_calls"][0]["args"] = json!({"count":2});
    fs::write(
        run_root.join("loop-ledger.json"),
        serde_json::to_vec(&tampered).expect("tampered JSON"),
    )
    .expect("tampered ledger");
    assert_eq!(
        ExecutionBackend::inspect_pending_tools(&runs, run_id)
            .expect_err("digest mismatch")
            .kind(),
        ExecutionErrorKind::InvalidRunState
    );
    fs::write(run_root.join("loop-ledger.json"), &pending_bytes).expect("restore fixture bytes");
    let grant = ApprovalLedger::new().grant(
        &pending.tool_name,
        &pending.call_id,
        &pending.arguments,
        &pending.actor,
        Duration::from_secs(60),
    );
    let resumed = ExecutionBackend::resume_with_implementations_and_approvals(
        &runs,
        run_id,
        &implementations,
        grant,
    )
    .expect("fresh exact grant must resume");
    assert_eq!(resumed.status(), "succeeded");
    let audit = serde_json::to_value(&resumed).expect("receipt JSON")["effect_audits"].clone();
    assert_eq!(
        audit[0]["history"],
        json!(["proposed", "approved", "started", "committed", "verified"])
    );
    assert_ne!(audit[0]["effect_key"], json!("0".repeat(64)));
    let manifest: Value =
        serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).expect("manifest"))
            .expect("manifest JSON");
    assert_eq!(manifest["effect_audits"], audit);
    assert!(
        ExecutionBackend::inspect_pending_tools(&runs, run_id)
            .expect("completed inspection")
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    ExecutionBackend::resume_with_implementations(&runs, run_id, &implementations)
        .expect("completed replay needs no new authority");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(run_root.join("execution-profile.json")).expect("profile"),
        persisted_profile
    );
    let ledger: Value =
        serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).expect("ledger"))
            .expect("ledger JSON");
    assert_eq!(ledger["nodes"]["work"]["pending_calls"], json!([]));
    assert_eq!(
        ledger["nodes"]["work"]["completed_calls"]
            .as_array()
            .expect("completed")
            .len(),
        1
    );
    let checkpoint = run_root.join("checkpoint.sqlite");
    fs::rename(&checkpoint, run_root.join("saved-checkpoint.sqlite")).expect("hide checkpoint");
    assert!(ExecutionBackend::inspect_pending_tools(&runs, run_id).is_err());
    assert!(
        !checkpoint.exists(),
        "inspection must not create a missing checkpoint"
    );
    remove_production_root(&root);
}
