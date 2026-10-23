use super::*;

#[path = "history_replay.rs"]
mod replay;

fn historical_rebinding(changed_approval: bool) {
    for skill in [false, true] {
        for violated in [false, true] {
            let root = production_root();
            let calls = Arc::new(AtomicUsize::new(0));
            let expires = expiry();
            let implementations =
                registry(&root, expires, violated, Arc::clone(&calls), "original");
            let receipt = ExecutionBackend::run_with_implementations(
                root.join("workflow.toml"),
                profile(&root, skill),
                json!({}),
                root.join("runs"),
                &implementations,
            )
            .expect("completed effect");
            let audit = serde_json::to_value(&receipt).expect("receipt")["effect_audits"].clone();
            assert_eq!(audit.as_array().expect("audits").len(), 1);
            assert_eq!(
                audit[0]["history"],
                if violated {
                    json!(["proposed", "approved", "started", "committed", "failed"])
                } else {
                    json!(["proposed", "approved", "started", "committed", "verified"])
                }
            );
            let other = production_root();
            let rebound = registry(
                &other,
                expires + u64::from(changed_approval),
                violated,
                Arc::clone(&calls),
                if changed_approval {
                    "original"
                } else {
                    "unrelated"
                },
            );
            assert_eq!(implementations.identity(), rebound.identity());
            let current = rebound
                .effect_audit(
                    "increment",
                    "1",
                    &workflow_runtime::argument_fingerprint(&json!({"count": 1})),
                )
                .expect("current audit")
                .expect("current proposal");
            assert_ne!(serde_json::to_value(current).expect("audit"), audit[0]);
            for _ in 0..2 {
                assert_resume(
                    &root.join("runs"),
                    receipt.run_id(),
                    &rebound,
                    &audit,
                    &calls,
                    1,
                );
            }
            if skill {
                assert_private(receipt.run_root());
            }
            drop(rebound);
            remove_production_root(&other);
            drop(implementations);
            remove_production_root(&root);
        }
    }
}

#[test]
fn historical_operation_rebinding_retains_original_receipt() {
    historical_rebinding(false);
}

#[test]
fn historical_approval_rebinding_retains_original_receipt() {
    historical_rebinding(true);
}

#[derive(Clone, Copy)]
enum AuditMode {
    Missing,
    LookupError,
    HandlerError,
    Incompatible,
}

struct ChangedAudit {
    inner: Arc<dyn ToolHandler>,
    mode: AuditMode,
    lookups: Arc<AtomicUsize>,
}

impl ToolHandler for ChangedAudit {
    fn effect_audit(
        &self,
        fingerprint: &str,
    ) -> Result<Option<workflow_runtime::effect_ledger::EffectAuditReceipt>, ToolBridgeError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            AuditMode::Missing => Ok(None),
            AuditMode::LookupError => Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed)),
            _ => self.inner.effect_audit(fingerprint),
        }
    }

    fn required_capabilities(
        &self,
        args: &Value,
    ) -> Result<Vec<SandboxCapability>, ToolBridgeError> {
        self.inner.required_capabilities(args)
    }

    fn requires_approval(&self, args: &Value) -> Result<bool, ToolBridgeError> {
        self.inner.requires_approval(args)
    }

    fn execute(
        &self,
        sandbox: &ChildSandbox<'_>,
        context: &ToolCallContext,
        args: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        let result = self.inner.execute(sandbox, context, args)?;
        if matches!(self.mode, AuditMode::HandlerError) {
            Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))
        } else {
            Ok(result)
        }
    }

    fn implementation_identity(&self) -> String {
        if matches!(self.mode, AuditMode::Incompatible) {
            "incompatible-history-fixture".to_owned()
        } else {
            self.inner.implementation_identity()
        }
    }

    fn registration(&self) -> Option<ToolRegistration> {
        self.inner.registration()
    }
}

fn changed_audit(
    implementations: &ToolImplementationRegistry,
    mode: AuditMode,
    lookups: &Arc<AtomicUsize>,
) -> ToolImplementationRegistry {
    let mut registry = ToolImplementationRegistry::new();
    registry
        .register(
            "increment",
            "1",
            Arc::new(ChangedAudit {
                inner: implementations.resolve("increment", "1").expect("handler"),
                mode,
                lookups: Arc::clone(lookups),
            }),
        )
        .expect("replacement");
    registry
}

#[test]
fn historical_audit_unavailability_keeps_verified_and_failed_snapshots() {
    for skill in [false, true] {
        for violated in [false, true] {
            let root = production_root();
            let calls = Arc::new(AtomicUsize::new(0));
            let implementations =
                registry(&root, expiry(), violated, Arc::clone(&calls), "original");
            let receipt = ExecutionBackend::run_with_implementations(
                root.join("workflow.toml"),
                profile(&root, skill),
                json!({}),
                root.join("runs"),
                &implementations,
            )
            .expect("run");
            let audit = serde_json::to_value(&receipt).expect("receipt")["effect_audits"].clone();
            let ledger = read_json(&receipt.run_root().join("loop-ledger.json"));
            assert_eq!(ledger["schema_version"], json!(6));
            assert_eq!(
                ledger["nodes"]["work"]["completed_calls"][0]["call"]["effect"],
                audit[0]
            );
            for mode in [AuditMode::Missing, AuditMode::LookupError] {
                let lookups = Arc::new(AtomicUsize::new(0));
                let unavailable = changed_audit(&implementations, mode, &lookups);
                assert_eq!(implementations.identity(), unavailable.identity());
                for _ in 0..2 {
                    assert_resume(
                        &root.join("runs"),
                        receipt.run_id(),
                        &unavailable,
                        &audit,
                        &calls,
                        1,
                    );
                }
                assert_eq!(
                    lookups.load(Ordering::SeqCst),
                    0,
                    "history requires no current audit lookup"
                );
            }
            if skill {
                assert_private(receipt.run_root());
            }
            remove_production_root(&root);
        }
    }
}

#[test]
fn historical_snapshots_do_not_relax_registry_or_checkpoint_admission() {
    let root = production_root();
    let calls = Arc::new(AtomicUsize::new(0));
    let implementations = registry(&root, expiry(), false, Arc::clone(&calls), "original");
    let receipt = ExecutionBackend::run_with_implementations(
        root.join("workflow.toml"),
        profile(&root, false),
        json!({}),
        root.join("runs"),
        &implementations,
    )
    .expect("run");
    let audit = serde_json::to_value(&receipt).expect("receipt")["effect_audits"].clone();
    let lookups = Arc::new(AtomicUsize::new(0));
    let incompatible = changed_audit(&implementations, AuditMode::Incompatible, &lookups);
    let manifest = fs::read(receipt.run_root().join("run-manifest.json")).expect("manifest");
    for replacement in [&ToolImplementationRegistry::new(), &incompatible] {
        assert_eq!(
            ExecutionBackend::resume_with_implementations(
                root.join("runs"),
                receipt.run_id(),
                replacement
            )
            .expect_err("registry remains authoritative")
            .kind(),
            ExecutionErrorKind::InvalidRunState
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fs::read(receipt.run_root().join("run-manifest.json")).expect("manifest"),
            manifest
        );
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    let path = receipt.run_root().join("loop-ledger.json");
    let bytes = fs::read(&path).expect("ledger");
    for field in [
        "history",
        "target_digest",
        "policy_digest",
        "workflow_lock",
        "executor_digest",
        "schema_version",
    ] {
        let mut ledger: Value = serde_json::from_slice(&bytes).expect("ledger");
        ledger["checkpoint_nodes"] = Value::Null;
        ledger["nodes"]["work"]["completed_calls"][0]["call"]["effect"][field] = match field {
            "history" => json!(["proposed"]),
            "schema_version" => json!(2),
            _ => json!("0".repeat(64)),
        };
        fs::write(&path, serde_json::to_vec(&ledger).expect("ledger")).expect("tamper");
        assert_eq!(
            ExecutionBackend::resume_with_implementations(
                root.join("runs"),
                receipt.run_id(),
                &implementations
            )
            .expect_err("snapshot is checkpoint bound")
            .kind(),
            ExecutionErrorKind::InvalidRunState,
            "{field}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    let mut legacy: Value = serde_json::from_slice(&bytes).expect("ledger");
    legacy["schema_version"] = json!(5);
    fs::write(&path, serde_json::to_vec(&legacy).expect("legacy")).expect("write legacy");
    assert_eq!(
        ExecutionBackend::resume_with_implementations(
            root.join("runs"),
            receipt.run_id(),
            &implementations
        )
        .expect_err("old identity-only schema is not fabricated history")
        .kind(),
        ExecutionErrorKind::InvalidRunState
    );
    fs::write(&path, bytes).expect("restore");
    assert_resume(
        &root.join("runs"),
        receipt.run_id(),
        &implementations,
        &audit,
        &calls,
        1,
    );
    remove_production_root(&root);
}

#[test]
fn historical_failed_handler_retains_the_effect_that_already_happened() {
    let root = production_root();
    let calls = Arc::new(AtomicUsize::new(0));
    let implementations = registry(&root, expiry(), false, Arc::clone(&calls), "original");
    let lookups = Arc::new(AtomicUsize::new(0));
    let failing = changed_audit(&implementations, AuditMode::HandlerError, &lookups);
    let error = ExecutionBackend::run_with_implementations(
        root.join("workflow.toml"),
        profile(&root, false),
        json!({}),
        root.join("runs"),
        &failing,
    )
    .expect_err("handler failure is preserved");
    let report = serde_json::to_value(error.receipt().expect("failure receipt")).expect("receipt");
    assert_eq!(
        report["effect_audits"][0]["history"],
        json!(["proposed", "approved", "started", "committed", "verified"])
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(lookups.load(Ordering::SeqCst) > 0);
    remove_production_root(&root);
}
