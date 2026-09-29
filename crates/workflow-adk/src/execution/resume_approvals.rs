//! Host review material for fresh, runtime-only resume authority.
use super::ExecutionReceipt;
use super::{
    ExecutionBackend, ExecutionError, ExecutionErrorKind, LOOP_LEDGER_FILE, LoopLedgerStore,
    checkpoint_ledger_digest, find_run, ledger_checkpoint_identity,
};
use serde_json::Value;
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};
use workflow_runtime::{
    ApprovalLedger, RunId, SqliteCheckpointStore, ToolImplementationRegistry, WorkdirManager,
};

/// A pending proposal, not an approval. Authenticate the reviewing human separately.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingToolApproval {
    /// Run whose trusted checkpoint supplied this proposal.
    pub run_id: String,
    /// Digest binding the compatible checkpoint manifest.
    pub checkpoint_identity: String,
    /// Digest of the validated loop state selected by that checkpoint.
    pub ledger_digest: String,
    /// Execution node; this is the tool-call actor, not the reviewing human.
    pub actor: String,
    /// Exact tool name.
    pub tool_name: String,
    /// Exact model call ID admitted by the host.
    pub call_id: String,
    /// Proposal arguments remain untrusted and require human review.
    pub arguments: Value,
    /// Canonical argument digest checked against the persisted pending call.
    pub argument_fingerprint: String,
}

impl ExecutionBackend {
    /// Resumes with host-supplied implementations and fresh call-scoped grants.
    ///
    /// Authenticate the reviewer outside the model and review exact checkpoint-bound
    /// proposals via `inspect_pending_tools`. Grants bind the execution-node actor,
    /// tool, call ID and arguments; expiry uses the bridge's elapsed-time clock for
    /// this resume attempt. They are never persisted and do not renew durable effect
    /// approvals or reopen terminal effects. Existing resume methods supply no grant.
    pub fn resume_with_implementations_and_approvals(
        workdir_base: impl AsRef<Path>,
        run_id: &str,
        implementations: &ToolImplementationRegistry,
        approvals: ApprovalLedger,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        Self::resume_bound(
            workdir_base,
            run_id,
            Arc::new(AtomicBool::new(false)),
            Some(implementations),
            Some(approvals),
        )
    }

    /// Reads checkpoint-bound pending proposals without executing tools or models.
    /// The host must trust its run directory and authenticate human approval; neither
    /// these model-originated arguments nor their digests confer authority. Resume
    /// revalidates the checkpoint and exact call. Redacted calls cannot be reviewed.
    /// No checkpoint or run lifecycle is advanced; opening the existing SQLite
    /// store may maintain journal sidecars. Serialize inspection/resume per run.
    pub fn inspect_pending_tools(
        workdir_base: impl AsRef<Path>,
        run_id: &str,
    ) -> Result<Vec<PendingToolApproval>, ExecutionError> {
        let invalid = || ExecutionError::new(ExecutionErrorKind::InvalidRunState);
        let (root, manifest) = find_run(workdir_base.as_ref(), run_id)?;
        if !matches!(manifest.status.as_str(), "running" | "succeeded") {
            return Err(invalid());
        }
        let checkpoint_manifest = manifest.checkpoint_manifest.ok_or_else(invalid)?;
        let checkpoint_identity = ledger_checkpoint_identity(&checkpoint_manifest)?;
        let run_identity = RunId::new(run_id.to_owned()).map_err(|_| invalid())?;
        let manager =
            WorkdirManager::new(root.parent().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let workdir = manager
            .reopen(&run_identity, &root)
            .map_err(|_| invalid())?;
        if workdir.id().as_str() != manifest.workdir_id {
            return Err(invalid());
        }
        // Inspection must not initialize missing state. The store retains its normal
        // ownership/no-follow checks and may maintain SQLite journal sidecars.
        for name in ["checkpoint.sqlite", "checkpoint-manifest.json"] {
            if !std::fs::symlink_metadata(root.join(name))
                .map_err(|_| invalid())?
                .file_type()
                .is_file()
            {
                return Err(invalid());
            }
        }
        let store = SqliteCheckpointStore::open(
            root.join("checkpoint.sqlite"),
            checkpoint_manifest.clone(),
        )
        .map_err(|_| invalid())?;
        let checkpoint = store
            .load_latest(&run_identity)
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let ledger_digest = checkpoint_ledger_digest(checkpoint.state())?;
        let ledger = LoopLedgerStore::open(
            root.join(LOOP_LEDGER_FILE),
            root.join("checkpoint.sqlite"),
            checkpoint_identity.clone(),
            checkpoint_manifest,
            run_identity,
            &ledger_digest,
            false,
        )?;
        ledger
            .pending_calls()?
            .into_iter()
            .map(|(actor, call)| {
                // Redacted or altered arguments must never become grantable review material.
                if workflow_runtime::argument_fingerprint(&call.args) != call.fingerprint {
                    return Err(invalid());
                }
                Ok(PendingToolApproval {
                    run_id: run_id.to_owned(),
                    checkpoint_identity: checkpoint_identity.clone(),
                    ledger_digest: ledger_digest.clone(),
                    actor,
                    tool_name: call.name,
                    call_id: call.id,
                    arguments: call.args,
                    argument_fingerprint: call.fingerprint,
                })
            })
            .collect()
    }
}
