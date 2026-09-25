//! Host-authorized authored ADK execution and standalone inert simulation.
//!
//! Both routes use the runtime's sealed data reducer, never a model, production
//! tool registry, or IO-bearing executor. Authored execution retains reports via
//! its host observer; the standalone graph has no observer store. Neither is OS
//! containment or source-causal evaluation.
use crate::events::AdkEventMapper;
use crate::{AdkGraph, AdkGraphError, AdkGraphTranslator, TranslationError};
use adk_rust::{
    graph::prelude::{END, ExecutionConfig, GraphAgent, NodeOutput, START, State},
    tokio::sync::mpsc,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Instant,
};
use workflow_compiler::CompiledPlan;
use workflow_ir::WorkflowIr;
use workflow_runtime::behavioral::{BEHAVIORAL_VERSION, BehavioralProbe, ProbeReport};
use workflow_runtime::behavioral::{ProbeLimits, TrustedScript};
use workflow_runtime::{ArtifactId, ArtifactStore, CanonicalUntrustedText, RunId};

impl AdkGraphTranslator {
    /// Consume the same live host capability checked by compilation. No JSON identity
    /// can substitute for it. Rebinding and non-opted plans are rejected.
    pub fn with_sentinel_trusted_script(
        mut self,
        plan: &CompiledPlan,
        script: TrustedScript,
    ) -> Result<Self, TranslationError> {
        if self.sentinel_script.is_some()
            || plan.sentinel_script_identity() != Some(script.identity().as_str())
        {
            return Err(TranslationError::MissingNodeBackend {
                node: plan.ir().entry_node_id().as_str().to_owned(),
            });
        }
        self.sentinel_script = Some(Arc::new(script));
        self.validate_behavioral_translation(plan.ir())?;
        Ok(self)
    }

    pub(crate) fn validate_behavioral_plan(
        &self,
        plan: &CompiledPlan,
    ) -> Result<(), TranslationError> {
        if plan.sentinel_script_identity()
            != self
                .sentinel_script
                .as_ref()
                .map(|script| script.identity())
                .as_deref()
        {
            return Err(TranslationError::MissingNodeBackend {
                node: plan.ir().entry_node_id().as_str().to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn validate_behavioral_translation(
        &self,
        ir: &WorkflowIr,
    ) -> Result<(), TranslationError> {
        let policy = ir
            .nodes()
            .iter()
            .find_map(|node| node.untrusted_text()?.behavioral);
        let admitted = match (policy, &self.sentinel_script) {
            (None, None) => true,
            (Some(policy), Some(script)) => {
                policy.schema_version == 1
                    && script.matches_trajectory_policy(policy.trajectory.map(|p| p.schema_version))
                    && script.matches_approval(
                        &format!("sha256:{}", crate::canonical_ir_hash(ir)),
                        ProbeLimits {
                            max_steps: policy.max_steps,
                            timeout_ms: policy.timeout_ms,
                        },
                    )
            }
            _ => false,
        };
        if admitted {
            Ok(())
        } else {
            Err(TranslationError::MissingNodeBackend {
                node: ir.entry_node_id().as_str().to_owned(),
            })
        }
    }
}

// ADK polls node futures inline. No state/checkpoint/graph-global report slot.
// If upstream starts spawning nodes, absence of this scope fails closed.
adk_rust::tokio::task_local! {
    static RUN: RefCell<Invocation>;
}
struct Invocation {
    script: Arc<TrustedScript>,
    run_id: RunId,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    probe: Option<BehavioralProbe>,
    report: Option<ProbeReport>,
    trajectory: Option<workflow_runtime::behavioral::trajectory::TrajectoryObservation>,
    retained: bool,
}
fn with_run<T>(
    f: impl FnOnce(&mut Invocation) -> Result<T, AdkGraphError>,
) -> Result<T, AdkGraphError> {
    RUN.try_with(|run| f(&mut *run.try_borrow_mut().map_err(|_| AdkGraphError::Failed)?))
        .map_err(|_| AdkGraphError::AuthorizationDenied)?
}
impl AdkGraph {
    /// Execute a host-approved authored terminal with explicit host controls. Returns
    /// its invocation-local typed report only after content-addressed retention.
    /// `thread_id` must match the fresh mapper's run; no checkpoint continuation,
    /// model binding, implicit controls, or caller-state report is accepted.
    /// Cancellation/deadlines are cooperative bounds, not OS containment.
    pub async fn invoke_observed_with_sentinel_script<S: ArtifactStore>(
        &self,
        state: State,
        config: ExecutionConfig,
        mapper: &mut AdkEventMapper,
        artifacts: &mut S,
        cancelled: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<(State, ProbeReport), AdkGraphError> {
        let script = self
            .sentinel_script
            .as_ref()
            .ok_or(AdkGraphError::AuthorizationDenied)?;
        if self.sentinel_model.is_some()
            || config.resume_from.is_some()
            || config.thread_id.trim().is_empty()
            || config.thread_id.len() > 256
            || config.thread_id != mapper.run_id()
            || !mapper.events().is_empty()
            || cancelled.load(std::sync::atomic::Ordering::Acquire)
            || Instant::now() >= deadline
        {
            return Err(AdkGraphError::AuthorizationDenied);
        }
        let timeout_ms = self
            .untrusted_text
            .as_ref()
            .and_then(|workflow| workflow.behavioral_timeout_ms())
            .ok_or(AdkGraphError::Failed)?;
        let invocation = RefCell::new(Invocation {
            script: Arc::clone(script),
            run_id: RunId::new(config.thread_id.clone())
                .map_err(|_| AdkGraphError::AuthorizationDenied)?,
            cancelled,
            deadline: deadline.min(Instant::now() + std::time::Duration::from_millis(timeout_ms)),
            probe: None,
            report: None,
            trajectory: None,
            retained: false,
        });
        RUN.scope(invocation, async {
            let state = self
                .invoke_observed_inner(state, config, mapper, artifacts)
                .await?;
            let report = with_run(|run| {
                if !run.retained {
                    return Err(AdkGraphError::Failed);
                }
                run.report.take().ok_or(AdkGraphError::Failed)
            })?;
            Ok((state, report))
        })
        .await
    }

    pub(crate) fn check_behavioral_invocation(
        &self,
        config: &ExecutionConfig,
        mapper: &AdkEventMapper,
    ) -> Result<(), AdkGraphError> {
        if let Some(script) = &self.sentinel_script {
            with_run(|run| {
                if !Arc::ptr_eq(script, &run.script)
                    || run.run_id.as_str() != config.thread_id
                    || config.thread_id != mapper.run_id()
                {
                    return Err(AdkGraphError::AuthorizationDenied);
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    pub(crate) fn observe_behavioral(
        &self,
        preparation: &mut serde_json::Value,
        mapper: &mut AdkEventMapper,
        artifacts: &mut impl ArtifactStore,
    ) -> Result<(), AdkGraphError> {
        if self.sentinel_script.is_none() {
            return Ok(());
        }
        with_run(|run| {
            if run.retained {
                return Err(AdkGraphError::Failed);
            }
            let report = run.report.as_ref().ok_or(AdkGraphError::Failed)?;
            let bytes = report.to_json().map_err(|_| AdkGraphError::Failed)?;
            let node = &self
                .untrusted_text
                .as_ref()
                .ok_or(AdkGraphError::Failed)?
                .node_id;
            let id = crate::sentinel_workflow::put_verified(
                artifacts,
                bytes.as_bytes(),
                mapper,
                node,
                "behavioral",
            )?;
            let evidence = report
                .evidence()
                .and_then(|evidence| evidence.map(|e| e.to_json()).transpose())
                .map_err(|_| AdkGraphError::Failed)?;
            let evidence: Option<serde_json::Value> = evidence
                .map(|e| serde_json::from_str(&e))
                .transpose()
                .map_err(|_| AdkGraphError::Failed)?;
            preparation["behavioral"] = serde_json::json!({"identity":report.identity(),"artifact_id":id,"evidence":evidence});
            if let Some(observation) = &run.trajectory {
                let bytes = observation.to_json().map_err(|_| AdkGraphError::Failed)?;
                let id = crate::sentinel_workflow::put_verified(
                    artifacts,
                    bytes.as_bytes(),
                    mapper,
                    node,
                    "trajectory",
                )?;
                let evidence = observation
                    .evidence()
                    .and_then(|e| e.map(|e| e.to_json()).transpose())
                    .map_err(|_| AdkGraphError::Failed)?;
                let evidence: Option<serde_json::Value> = evidence
                    .map(|e| serde_json::from_str(&e))
                    .transpose()
                    .map_err(|_| AdkGraphError::Failed)?;
                preparation["trajectory"] =
                    serde_json::json!({"artifact_id": id, "evidence": evidence});
            }
            run.retained = true;
            Ok(())
        })
    }
}

pub(crate) fn admit_source(raw: &[u8]) -> Result<(), AdkGraphError> {
    let source =
        ArtifactId::parse(format!("{:x}", Sha256::digest(raw))).ok_or(AdkGraphError::Failed)?;
    with_run(|run| {
        if !run.script.approves_source(&source)
            || run.cancelled.load(std::sync::atomic::Ordering::Acquire)
            || Instant::now() >= run.deadline
        {
            return Err(AdkGraphError::AuthorizationDenied);
        }
        Ok(())
    })
}
pub(crate) fn prepare_probe(text: &CanonicalUntrustedText) -> Result<String, AdkGraphError> {
    with_run(|run| {
        if run.probe.is_some() || run.report.is_some() {
            return Err(AdkGraphError::Failed);
        }
        let probe = run
            .script
            .bind(text, run.run_id.clone())
            .map_err(|_| AdkGraphError::AuthorizationDenied)?;
        let identity = probe.identity().to_owned();
        run.probe = Some(probe);
        Ok(identity)
    })
}
pub(crate) fn execute_prepared() -> Result<(), AdkGraphError> {
    with_run(|run| {
        if run.report.is_some() {
            return Err(AdkGraphError::Failed);
        }
        let probe = run.probe.take().ok_or(AdkGraphError::Failed)?;
        let report = probe.run_until(&run.cancelled, run.deadline);
        run.trajectory = probe
            .observe_trajectory(&report)
            .map_err(|_| AdkGraphError::Failed)?;
        run.report = Some(report);
        Ok(())
    })
}

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
