//! Injected deterministic Firewall gate for the production ADK graph.
use crate::{AdkGraph, AdkGraphError, AdkGraphTranslator, TranslationError};
use adk_rust::{
    Agent,
    graph::prelude::{GraphError, NodeOutput},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use workflow_compiler::CompiledPlan;
use workflow_runtime::{
    FirewallDecision, argument_fingerprint,
    firewall::{
        FIREWALL_IMPLEMENTATION_VERSION, FIREWALL_SCHEMA_VERSION, FirewallPolicy, ToolDecision,
        ToolProposal, TrustedGoal,
    },
};

/// Immutable trusted application binding. Nothing is loaded from graph/model state.
#[derive(Clone)]
pub struct FirewallInvocation {
    policy: FirewallPolicy,
    goal: TrustedGoal,
    proposal: ToolProposal,
    semantic: Option<crate::semantic_firewall::SemanticFirewall>,
}
impl FirewallInvocation {
    pub fn new(policy: FirewallPolicy, goal: TrustedGoal, proposal: ToolProposal) -> Self {
        Self {
            policy,
            goal,
            proposal,
            semantic: None,
        }
    }
    /// Opt in to semantic evidence. Recompile using the resulting identity.
    pub fn with_semantic(mut self, semantic: crate::semantic_firewall::SemanticFirewall) -> Self {
        self.semantic = Some(semantic);
        self
    }
    /// Bind every policy, schema, goal, target, and proposal byte into compiled IR.
    /// Cache/checkpoint reuse must use that IR identity, not the workflow name alone.
    pub fn identity(&self) -> String {
        let hard = argument_fingerprint(&json!({"implementation":FIREWALL_IMPLEMENTATION_VERSION,
            "schema_version":FIREWALL_SCHEMA_VERSION,"policy":self.policy,
            "goal":self.goal,"proposal":self.proposal,
            "security":workflow_runtime::SECURITY_MODEL_VERSION,
            "secrets":workflow_runtime::SECRET_POLICY_VERSION}));
        match &self.semantic {
            None => hard,
            Some(semantic) => {
                argument_fingerprint(&json!({"hard":hard,"semantic":semantic.identity()}))
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct GateRecord {
    decision: ToolDecision,
    semantic: Option<Value>,
}
pub(crate) type Decisions = Arc<Mutex<BTreeMap<String, GateRecord>>>;

adk_rust::tokio::task_local! {
    // ADK 2.1 polls node futures inline (buffer_unordered), including streamed
    // super-steps. Scope follows the invocation future, not a checkpoint/thread ID.
    // A future executor that spawns gate tasks must explicitly carry this scope;
    // execute fails closed if the scope is absent.
    static RUN_DECISIONS: Decisions;
}

#[cfg(test)]
#[path = "firewall_tests.rs"]
pub(crate) mod tests;

impl AdkGraphTranslator {
    /// Translate an explicitly bound Firewall entry gate. Deny and approval waits
    /// both terminate execution before any downstream model, approval, or action.
    /// No human grant is accepted here; #240 owns future approved execution.
    pub fn translate_with_firewall(
        &self,
        plan: &CompiledPlan,
        invocation: FirewallInvocation,
        agents: &BTreeMap<String, Arc<dyn Agent>>,
    ) -> Result<AdkGraph, TranslationError> {
        self.validate_behavioral_plan(plan)?;
        self.translate_ir(plan.ir(), None, Some(agents), None, None, Some(invocation))
    }
}
impl AdkGraph {
    pub(crate) async fn firewall_run<T>(
        &self,
        run: impl std::future::Future<Output = Result<T, AdkGraphError>>,
    ) -> Result<T, AdkGraphError> {
        if self.firewall_entry.is_none() {
            return run.await;
        }
        let records = Decisions::default();
        let result = RUN_DECISIONS.scope(Arc::clone(&records), run).await;
        // Publish a last-completed snapshot only. Mappers never consume this shared
        // accessor, and cancellation drops the private records without publishing.
        let snapshot = records.lock().map_err(|_| AdkGraphError::Failed)?.clone();
        *self
            .firewall_decisions
            .lock()
            .map_err(|_| AdkGraphError::Failed)? = snapshot;
        result
    }

    pub(crate) fn prepare_firewall_run(
        &self,
        config: &adk_rust::graph::prelude::ExecutionConfig,
    ) -> Result<(), AdkGraphError> {
        // Resume/approval execution needs the fresh-target ledger contract in #240.
        if self.firewall_entry.is_some() && config.resume_from.is_some() {
            return Err(AdkGraphError::AuthorizationDenied);
        }
        Ok(())
    }

    pub(crate) fn observe_firewall<S: workflow_runtime::ArtifactStore>(
        &self,
        observed: &mut std::collections::BTreeSet<String>,
        mapper: &mut crate::events::AdkEventMapper,
        artifacts: &mut S,
    ) -> Result<(), AdkGraphError> {
        use crate::events::AdkRuntimeObservationKindV1 as Kind;
        if self.firewall_entry.is_none() {
            return Ok(());
        }
        let records = RUN_DECISIONS
            .try_with(Arc::clone)
            .map_err(|_| AdkGraphError::Failed)?;
        let snapshot = records.lock().map_err(|_| AdkGraphError::Failed)?.clone();
        for (node, record) in snapshot {
            let decision = record.decision;
            if !observed.insert(node.clone()) {
                continue;
            }
            let kind = match decision.decision() {
                FirewallDecision::Allow => Kind::ToolAuthorized,
                FirewallDecision::Deny => Kind::ToolDenied,
                FirewallDecision::RequireHumanApproval => Kind::ApprovalRequested,
            };
            let output: Value =
                serde_json::from_str(&decision.render_json().map_err(|_| AdkGraphError::Failed)?)
                    .map_err(|_| AdkGraphError::Failed)?;
            let mut structured = json!({"firewall":output});
            if let Some(semantic) = record.semantic {
                structured["semantic_firewall"] = semantic;
            }
            mapper
                .map_stream_observation(Some(node), kind, Some(structured), None, artifacts)
                .map_err(|error| AdkGraphError::Observation(error.kind()))?;
        }
        Ok(())
    }

    /// Privacy-safe reports from the most recently completed invocation (including
    /// errors). Rejected resume publishes an empty snapshot; cancellation does not
    /// publish. Concurrent callers needing attribution must use `invoke_observed`:
    /// its mapper owns only that invocation's reports, independently of this snapshot.
    pub fn firewall_decisions(&self) -> Result<BTreeMap<String, ToolDecision>, AdkGraphError> {
        self.firewall_decisions
            .lock()
            .map(|records| {
                records
                    .iter()
                    .map(|(node, record)| (node.clone(), record.decision.clone()))
                    .collect()
            })
            .map_err(|_| AdkGraphError::Failed)
    }
}

pub(crate) fn validate_binding(
    ir: &workflow_ir::WorkflowIr,
    invocation: Option<&FirewallInvocation>,
) -> Result<(), TranslationError> {
    let gates = ir
        .nodes()
        .iter()
        .filter(|node| node.firewall().is_some())
        .collect::<Vec<_>>();
    match (gates.as_slice(), invocation) {
        ([], None) => Ok(()),
        ([node], Some(invocation))
            if node.kind() == workflow_ir::IrNodeKind::Validator
                && node.id() == ir.entry_node_id()
                && node.firewall().is_some_and(|contract| {
                    contract.schema_version == FIREWALL_SCHEMA_VERSION
                        && contract.identity == invocation.identity()
                }) =>
        {
            Ok(())
        }
        _ => Err(TranslationError::FirewallBinding),
    }
}

pub(crate) async fn execute(
    invocation: &FirewallInvocation,
    node: &str,
) -> Result<NodeOutput, GraphError> {
    let hard = invocation
        .policy
        .evaluate(&invocation.goal, &invocation.proposal);
    let (decision, semantic) = if let Some(judges) = &invocation.semantic {
        if hard.decision() == FirewallDecision::Allow {
            let (reports, metrics) = judges.run().await;
            (
                hard.with_semantic_evidence(judges.impact(), &reports, &invocation.identity()),
                Some(metrics),
            )
        } else {
            (hard, None)
        }
    } else {
        (hard, None)
    };
    let output: Value = serde_json::from_str(
        &decision
            .render_json()
            .map_err(|_| GraphError::Other("Firewall output failed".into()))?,
    )
    .map_err(|_| GraphError::Other("Firewall output failed".into()))?;
    RUN_DECISIONS
        .try_with(Arc::clone)
        .map_err(|_| GraphError::Other("Firewall invocation scope missing".into()))?
        .lock()
        .map_err(|_| GraphError::Other("Firewall observation failed".into()))?
        .insert(
            node.to_owned(),
            GateRecord {
                decision: decision.clone(),
                semantic,
            },
        );
    if decision.decision() != FirewallDecision::Allow {
        return Err(GraphError::Other("tool.bridge.authorization_denied".into()));
    }
    Ok(NodeOutput::new().with_update(&format!("node:{node}"), output))
}
