//! Advisory effect provenance, scoped to real invocations and checkpoint-bound completions.
//! Distinct full snapshots survive collection; identical projections are deduplicated.
use super::{
    CompletedCall, ExecutionError, ExecutionErrorKind, ExecutionReceipt, LoopLedgerStore,
    PendingCall, RunManifestV2, node_cache_inventory,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use workflow_runtime::effect_ledger::EffectAuditReceipt;
use workflow_runtime::{ChildSandbox, ToolBridgeError, ToolCallContext, ToolHandler};
use workflow_runtime::{SandboxCapability, ToolRegistration};

type Invocation = (String, String, String);
#[derive(Clone, Default)]
pub(super) struct EffectAudits(Arc<Mutex<BTreeMap<Invocation, Option<EffectAuditReceipt>>>>);

impl EffectAudits {
    pub(super) fn wrap(
        &self,
        handler: Arc<dyn ToolHandler>,
        registration: &ToolRegistration,
    ) -> Arc<dyn ToolHandler> {
        Arc::new(AuditedHandler {
            handler,
            calls: self.clone(),
            name: registration.name().to_owned(),
            version: registration.provenance().tool_version().to_owned(),
        })
    }

    pub(super) fn collect(
        &self,
        ledger: Option<&LoopLedgerStore>,
    ) -> Result<Vec<EffectAuditReceipt>, ExecutionError> {
        let mut receipts = Vec::new();
        let calls = self
            .0
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        receipts.extend(calls.values().flatten().cloned());
        drop(calls);
        // Preserve the actual invocation's advisory snapshot. Neither a mutable
        // run manifest nor a compatible current handler supplies historical truth.
        // Resume still requires the existing registry and checkpoint admission.
        if let Some(ledger) = ledger {
            let nodes = ledger
                .nodes
                .lock()
                .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
            for call in nodes
                .values()
                .flat_map(|state| &state.completed_calls)
                .map(CompletedCall::call)
            {
                if let Some(receipt) = &call.effect {
                    receipts.push(receipt.clone());
                }
            }
        }
        // A remote deduplication key does not identify an approval or its history.
        // Full serialized values provide stable ordering across invocation/replay sources.
        let mut ordered = receipts
            .into_iter()
            .map(|receipt| {
                serde_json::to_vec(&receipt)
                    .map(|key| (key, receipt))
                    .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ordered.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        ordered.dedup_by(|(_, left), (_, right)| left == right);
        Ok(ordered.into_iter().map(|(_, receipt)| receipt).collect())
    }

    // Both ordinary completion and pending replay retain evidence from the actual
    // invocation, not from a response payload or a newly registered handler.
    pub(super) fn completed(
        &self,
        call: &PendingCall,
        response: Value,
    ) -> Result<CompletedCall, ExecutionError> {
        let version = response
            .pointer("/provenance/tool_version")
            .and_then(Value::as_str);
        let calls = self
            .0
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        let effect = version
            .and_then(|version| {
                calls.get(&(
                    call.name.clone(),
                    version.to_owned(),
                    call.fingerprint.clone(),
                ))
            })
            .cloned()
            .flatten();
        let call = PendingCall {
            response: Some(response),
            effect,
            ..call.clone()
        };
        Ok(
            if matches!(
                call.name.as_str(),
                "activate_skill" | "read_skill_resource" | "run_skill_script"
            ) {
                CompletedCall::Skill(call)
            } else {
                CompletedCall::Ordinary(call)
            },
        )
    }
}

struct AuditedHandler {
    handler: Arc<dyn ToolHandler>,
    calls: EffectAudits,
    name: String,
    version: String,
}

impl ToolHandler for AuditedHandler {
    fn required_capabilities(
        &self,
        arguments: &Value,
    ) -> Result<Vec<SandboxCapability>, ToolBridgeError> {
        self.handler.required_capabilities(arguments)
    }
    fn requires_approval(&self, arguments: &Value) -> Result<bool, ToolBridgeError> {
        self.handler.requires_approval(arguments)
    }
    fn execute(
        &self,
        sandbox: &ChildSandbox<'_>,
        context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<workflow_runtime::ToolEnvelope<Value>, ToolBridgeError> {
        let result = self.handler.execute(sandbox, context, arguments);
        let fingerprint = workflow_runtime::argument_fingerprint(arguments);
        let mut calls = self.calls.0.lock().map_err(|_| {
            ToolBridgeError::new(workflow_runtime::ToolBridgeErrorKind::HandlerFailed)
        })?;
        let binding = calls
            .entry((self.name.clone(), self.version.clone(), fingerprint.clone()))
            .or_default();
        // A handler error may follow a real effect. Retain its advisory evidence
        // too, while an unavailable audit never replaces the handler's result.
        *binding = self.handler.effect_audit(&fingerprint).ok().flatten();
        result
    }
}

impl ExecutionReceipt {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn status(&self) -> &str {
        &self.status
    }
    pub fn run_root(&self) -> &Path {
        &self.run_root
    }
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
    pub fn resume_identity(&self) -> &str {
        &self.resume_identity
    }
}

impl RunManifestV2 {
    pub(super) fn receipt(&self, run_root: PathBuf) -> ExecutionReceipt {
        let node_cache = node_cache_inventory(run_root.parent().unwrap_or(&run_root));
        ExecutionReceipt {
            run_id: self.run_id.clone(),
            workflow_id: self.workflow_id.clone(),
            status: self.status.clone(),
            artifact_id: self.artifact_id.clone(),
            run_root,
            resume_count: self.resume_count,
            plan_hash: self.plan_hash.clone(),
            resume_identity: self.resume_identity.clone(),
            cache_dispositions: self.cache_dispositions.clone(),
            event_counts: self.event_counts.clone(),
            node_cache,
            effect_audits: self.effect_audits.clone(),
        }
    }
}
