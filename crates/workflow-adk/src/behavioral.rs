//! Public offline ADK entry point for the sealed behavioral simulator.
//!
//! This isolated graph has no model binding, tool registry, checkpointer, observer
//! store, production execution profile, or inherited graph state. It is NOT OS
//! containment. The runtime's bounded data reducer owns the complete trajectory.
use crate::AdkGraphError;
use adk_rust::{
    graph::prelude::{END, ExecutionConfig, GraphAgent, NodeOutput, START, State},
    tokio::sync::mpsc,
};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Instant,
};
use workflow_runtime::behavioral::{BEHAVIORAL_VERSION, BehavioralProbe, ProbeReport};

/// Execute one closed scripted simulation in a fresh ADK graph.
///
/// The host deadline includes graph setup/queue time and may only shorten the
/// runtime ceiling. Cancellation is cooperative; dropping the future discards
/// the in-memory graph/report, not a durable checkpoint. Reports preserve the
/// runtime identity and contain no ADK-generated timestamps or UUIDs.
pub async fn run_simulation(
    probe: BehavioralProbe,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<ProbeReport, AdkGraphError> {
    let probe = Arc::new(probe);
    let (sender, mut receiver) = mpsc::channel(1);
    let graph = GraphAgent::builder(BEHAVIORAL_VERSION)
        .channels(&["delivered"])
        .node_fn("simulate", move |_| {
            let (probe, cancelled, sender) = (probe.clone(), cancelled.clone(), sender.clone());
            async move {
                let report = probe.run_until(&cancelled, deadline);
                let delivered = sender.try_send(report).is_ok();
                Ok(NodeOutput::new().with_update("delivered", serde_json::json!(delivered)))
            }
        })
        .edge(START, "simulate")
        .edge("simulate", END)
        .build()
        .map_err(|_| AdkGraphError::Failed)?;
    let state = graph
        .invoke(
            State::new(),
            ExecutionConfig::new(BEHAVIORAL_VERSION).with_recursion_limit(2),
        )
        .await
        .map_err(|_| AdkGraphError::Failed)?;
    if state.get("delivered").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(AdkGraphError::Failed);
    }
    // Typed private channel, not deserialization of caller-writable graph state.
    receiver.try_recv().map_err(|_| AdkGraphError::Failed)
}
