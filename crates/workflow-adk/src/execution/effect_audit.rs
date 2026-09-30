//! Advisory effect provenance, scoped to real invocations and checkpoint-bound completions.
use super::{
    ExecutionError, ExecutionErrorKind, ExecutionProfileV1, ExecutionReceipt, LoopLedgerStore,
    RunManifestV2, node_cache_inventory,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use workflow_runtime::effect_ledger::EffectAuditReceipt;
use workflow_runtime::{ChildSandbox, ToolBridgeError, ToolCallContext, ToolHandler};
use workflow_runtime::{SandboxCapability, ToolRegistration};

#[derive(Clone, Default)]
pub(super) struct EffectAudits(Arc<Mutex<BTreeSet<(String, String, String)>>>);

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
        profile: &ExecutionProfileV1,
        ledger: Option<&LoopLedgerStore>,
    ) -> Result<Vec<EffectAuditReceipt>, ExecutionError> {
        let Some(registry) = profile.tool_implementations.as_ref() else {
            return Ok(Vec::new());
        };
        let mut receipts = BTreeMap::new();
        let calls = self
            .0
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::Persistence))?;
        for (name, version, fingerprint) in calls.iter() {
            // Invalid live bindings cannot produce evidence or replace the execution verdict.
            if let Ok(Some(receipt)) = registry.effect_audit(name, version, fingerprint) {
                receipts.insert(receipt.effect_key.clone(), receipt);
            }
        }
        // Never consult run-manifest evidence: only checkpoint-bound completed calls
        // may select a live projection on resume. Reports cannot authorize execution.
        if let Some(ledger) = ledger {
            for (_, _, name, fingerprint, response) in ledger.completed_tool_responses()? {
                if let Some(key) = response
                    .pointer("/payload/effect_key")
                    .and_then(Value::as_str)
                    && let Some(version) = response
                        .pointer("/provenance/tool_version")
                        .and_then(Value::as_str)
                    && let Ok(Some(receipt)) = registry.effect_audit(&name, version, &fingerprint)
                    && receipt.effect_key == key
                {
                    receipts.insert(receipt.effect_key.clone(), receipt);
                }
            }
        }
        Ok(receipts.into_values().collect())
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
        self.calls
            .0
            .lock()
            .map_err(|_| {
                ToolBridgeError::new(workflow_runtime::ToolBridgeErrorKind::HandlerFailed)
            })?
            .insert((
                self.name.clone(),
                self.version.clone(),
                workflow_runtime::argument_fingerprint(arguments),
            ));
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
