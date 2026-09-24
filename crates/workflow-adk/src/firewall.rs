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
}
impl FirewallInvocation {
    pub fn new(policy: FirewallPolicy, goal: TrustedGoal, proposal: ToolProposal) -> Self {
        Self {
            policy,
            goal,
            proposal,
        }
    }
    /// Bind every policy, schema, goal, target, and proposal byte into compiled IR.
    /// Cache/checkpoint reuse must use that IR identity, not the workflow name alone.
    pub fn identity(&self) -> String {
        argument_fingerprint(&json!({"implementation":FIREWALL_IMPLEMENTATION_VERSION,
            "schema_version":FIREWALL_SCHEMA_VERSION,"policy":self.policy,
            "goal":self.goal,"proposal":self.proposal,
            "security":workflow_runtime::SECURITY_MODEL_VERSION,
            "secrets":workflow_runtime::SECRET_POLICY_VERSION}))
    }
}

pub(crate) type Decisions = Arc<Mutex<BTreeMap<String, ToolDecision>>>;

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
        self.translate_ir(plan.ir(), None, Some(agents), None, None, Some(invocation))
    }
}
impl AdkGraph {
    pub(crate) fn observe_firewall<S: workflow_runtime::ArtifactStore>(
        &self,
        observed: &mut std::collections::BTreeSet<String>,
        mapper: &mut crate::events::AdkEventMapper,
        artifacts: &mut S,
    ) -> Result<(), AdkGraphError> {
        use crate::events::AdkRuntimeObservationKindV1 as Kind;
        for (node, decision) in self.firewall_decisions()? {
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
            mapper
                .map_stream_observation(
                    Some(node),
                    kind,
                    Some(json!({"firewall":output})),
                    None,
                    artifacts,
                )
                .map_err(|error| AdkGraphError::Observation(error.kind()))?;
        }
        Ok(())
    }

    /// Privacy-safe typed observations emitted by the gate actually executed.
    pub fn firewall_decisions(&self) -> Result<BTreeMap<String, ToolDecision>, AdkGraphError> {
        self.firewall_decisions
            .lock()
            .map(|records| records.clone())
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

pub(crate) fn execute(
    invocation: &FirewallInvocation,
    records: &Decisions,
    node: &str,
) -> Result<NodeOutput, GraphError> {
    let decision = invocation
        .policy
        .evaluate(&invocation.goal, &invocation.proposal);
    let output: Value = serde_json::from_str(
        &decision
            .render_json()
            .map_err(|_| GraphError::Other("Firewall output failed".into()))?,
    )
    .map_err(|_| GraphError::Other("Firewall output failed".into()))?;
    records
        .lock()
        .map_err(|_| GraphError::Other("Firewall observation failed".into()))?
        .insert(node.to_owned(), decision.clone());
    if decision.decision() != FirewallDecision::Allow {
        return Err(GraphError::Other("tool.bridge.authorization_denied".into()));
    }
    Ok(NodeOutput::new().with_update(&format!("node:{node}"), output))
}
