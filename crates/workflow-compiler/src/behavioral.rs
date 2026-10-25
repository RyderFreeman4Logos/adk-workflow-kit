//! Independent host admission for the mutually exclusive behavioral modes.

use workflow_ir::WorkflowIr;
use workflow_runtime::behavioral::{ProbeLimits, TrustedModelProbe, TrustedScript};

use super::{BindingValidationError, CompileError};

pub(super) enum BehavioralAdmission<'a> {
    Script(&'a TrustedScript),
    Model(&'a TrustedModelProbe, &'a str),
}

pub(super) fn validate_admission(
    ir: &WorkflowIr,
    admission: Option<BehavioralAdmission<'_>>,
) -> Result<(), CompileError> {
    let policy = ir
        .nodes()
        .iter()
        .find_map(|node| node.untrusted_text()?.behavioral);
    let invalid = if matches!(&admission, Some(BehavioralAdmission::Model(..)))
        || policy.is_some_and(|policy| policy.schema_version == 2)
    {
        BindingValidationError::InvalidSentinelModelProbe
    } else {
        BindingValidationError::InvalidSentinelScript
    };
    let admitted = match (policy, admission) {
        (None, None) => true,
        (Some(policy), Some(admission)) => {
            let hash = format!(
                "sha256:{}",
                ir.canonical_hash()
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let limits = ProbeLimits {
                max_steps: policy.max_steps,
                timeout_ms: policy.timeout_ms,
            };
            match admission {
                BehavioralAdmission::Script(script) => {
                    policy.schema_version == 1
                        && script
                            .matches_trajectory_policy(policy.trajectory.map(|p| p.schema_version))
                        && script.matches_approval(&hash, limits)
                }
                BehavioralAdmission::Model(probe, route) => {
                    policy.schema_version == 2
                        && policy.trajectory.is_none()
                        && probe.matches_approval(&hash, limits, route)
                }
            }
        }
        _ => false,
    };
    if !admitted {
        return Err(CompileError::Binding(invalid));
    }
    Ok(())
}
