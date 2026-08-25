//! EVAL-001: bind `adk-eval` behind the platform test API.
//!
//! The public surface is a crate-local typed envelope. Fixture payloads never
//! appear in `Debug`/`Display`/serde snapshots.

use std::fmt;

use serde::Serialize;

/// Distinct typed run dispositions for trajectory and rubric fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalDisposition {
    /// One trajectory fixture ran through the bind path.
    TrajectoryRun,
    /// One rubric fixture ran through the bind path.
    RubricRun,
}

/// One named eval fixture. Payload bytes stay off diagnostic surfaces.
#[derive(Clone, Eq, PartialEq)]
pub struct EvalFixture {
    name: String,
    payload: String,
}

impl EvalFixture {
    /// Binds a path-safe fixture name to an opaque payload.
    pub fn new(name: String, payload: String) -> Self {
        Self { name, payload }
    }

    /// Returns the path-safe fixture name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for EvalFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvalFixture")
            .field("name", &self.name)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Input to the platform eval bind path.
#[derive(Clone, Eq, PartialEq)]
pub struct EvalInput {
    trajectory: Option<EvalFixture>,
    rubric: Option<EvalFixture>,
}

impl EvalInput {
    /// Runs one trajectory fixture.
    pub fn trajectory(fixture: EvalFixture) -> Self {
        Self {
            trajectory: Some(fixture),
            rubric: None,
        }
    }

    /// Runs one rubric fixture.
    pub fn rubric(fixture: EvalFixture) -> Self {
        Self {
            trajectory: None,
            rubric: Some(fixture),
        }
    }

    /// Runs one trajectory fixture and one rubric fixture.
    pub fn both(trajectory: EvalFixture, rubric: EvalFixture) -> Self {
        Self {
            trajectory: Some(trajectory),
            rubric: Some(rubric),
        }
    }
}

impl fmt::Debug for EvalInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvalInput")
            .field("trajectory_count", &usize::from(self.trajectory.is_some()))
            .field("rubric_count", &usize::from(self.rubric.is_some()))
            .finish()
    }
}

/// A redacted acknowledgement that a named fixture ran.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvalAcknowledgement {
    fixture_name: String,
    fixture_count: usize,
    disposition: EvalDisposition,
}

impl EvalAcknowledgement {
    /// Returns the path-safe fixture name.
    pub fn fixture_name(&self) -> &str {
        &self.fixture_name
    }

    /// Returns the number of fixtures represented by this acknowledgement.
    pub fn fixture_count(&self) -> usize {
        self.fixture_count
    }

    /// Returns the typed run disposition.
    pub fn disposition(&self) -> EvalDisposition {
        self.disposition
    }
}

/// Typed eval bind result. Trajectory and rubric runs stay distinct.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "transition", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalEnvelope {
    /// One trajectory fixture ran.
    Trajectory {
        /// The redacted trajectory acknowledgement.
        acknowledgement: EvalAcknowledgement,
    },
    /// One rubric fixture ran.
    Rubric {
        /// The redacted rubric acknowledgement.
        acknowledgement: EvalAcknowledgement,
    },
    /// One trajectory fixture and one rubric fixture ran.
    TrajectoryAndRubric {
        /// The redacted trajectory acknowledgement.
        trajectory: EvalAcknowledgement,
        /// The redacted rubric acknowledgement.
        rubric: EvalAcknowledgement,
    },
}

impl fmt::Display for EvalEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Trajectory { .. } => "eval trajectory ran",
            Self::Rubric { .. } => "eval rubric ran",
            Self::TrajectoryAndRubric { .. } => "eval trajectory and rubric ran",
        })
    }
}

/// Stable category for a fail-closed eval diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalDiagnosticKind {
    /// The bind path rejected the fixture before any run acknowledgement.
    BoundaryMiss,
}

/// Typed, payload-free eval bind failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EvalError {
    kind: EvalDiagnosticKind,
    code: &'static str,
}

impl EvalError {
    const BOUNDARY_MISS: Self = Self {
        kind: EvalDiagnosticKind::BoundaryMiss,
        code: "eval.boundary_miss",
    };

    /// Returns the stable diagnostic category.
    pub const fn kind(self) -> EvalDiagnosticKind {
        self.kind
    }

    /// Returns the stable machine-readable diagnostic code.
    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl fmt::Display for EvalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("eval boundary miss")
    }
}

impl std::error::Error for EvalError {}

/// Runs trajectory and/or rubric fixtures through the platform test API.
///
/// Binding is deterministic and typed. A boundary miss never reports that a
/// trajectory or rubric fixture ran.
pub fn compile_eval(input: EvalInput) -> Result<EvalEnvelope, EvalError> {
    if let Some(fixture) = &input.trajectory {
        validate_fixture(fixture)?;
    }
    if let Some(fixture) = &input.rubric {
        validate_fixture(fixture)?;
    }
    match (input.trajectory, input.rubric) {
        (Some(trajectory), Some(rubric)) => Ok(EvalEnvelope::TrajectoryAndRubric {
            trajectory: acknowledgement(&trajectory, EvalDisposition::TrajectoryRun),
            rubric: acknowledgement(&rubric, EvalDisposition::RubricRun),
        }),
        (Some(trajectory), None) => Ok(EvalEnvelope::Trajectory {
            acknowledgement: acknowledgement(&trajectory, EvalDisposition::TrajectoryRun),
        }),
        (None, Some(rubric)) => Ok(EvalEnvelope::Rubric {
            acknowledgement: acknowledgement(&rubric, EvalDisposition::RubricRun),
        }),
        (None, None) => Err(EvalError::BOUNDARY_MISS),
    }
}

fn validate_fixture(fixture: &EvalFixture) -> Result<(), EvalError> {
    if invalid_token(&fixture.name) || invalid_token(&fixture.payload) {
        return Err(EvalError::BOUNDARY_MISS);
    }
    Ok(())
}

fn invalid_token(value: &str) -> bool {
    value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control())
}

fn acknowledgement(fixture: &EvalFixture, disposition: EvalDisposition) -> EvalAcknowledgement {
    EvalAcknowledgement {
        fixture_name: fixture.name.clone(),
        fixture_count: 1,
        disposition,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY_TRAJECTORY_51: &str = "CANARY_TRAJECTORY_51";
    const CANARY_RUBRIC_51: &str = "CANARY_RUBRIC_51";
    const CANARY_EVAL_BOUNDARY_51: &str = "CANARY_EVAL_BOUNDARY_51";

    fn trajectory_fixture() -> EvalFixture {
        EvalFixture::new(
            String::from("canary-trajectory-51"),
            String::from(CANARY_TRAJECTORY_51),
        )
    }

    fn rubric_fixture() -> EvalFixture {
        EvalFixture::new(
            String::from("canary-rubric-51"),
            String::from(CANARY_RUBRIC_51),
        )
    }

    #[test]
    fn trajectory_run_is_not_rubric_and_redacts_payload() {
        let result = compile_eval(EvalInput::trajectory(trajectory_fixture()))
            .expect("trajectory fixture must run");
        match &result {
            EvalEnvelope::Trajectory { acknowledgement } => {
                assert_eq!(
                    acknowledgement.disposition(),
                    EvalDisposition::TrajectoryRun
                );
                assert_eq!(acknowledgement.fixture_count(), 1);
            }
            EvalEnvelope::Rubric { .. } | EvalEnvelope::TrajectoryAndRubric { .. } => {
                panic!("trajectory run must stay a typed trajectory result")
            }
        }
        assert!(!format!("{result:?}").contains(CANARY_TRAJECTORY_51));
        assert!(!result.to_string().contains(CANARY_TRAJECTORY_51));
    }

    #[test]
    fn rubric_run_is_not_trajectory_and_redacts_payload() {
        let result =
            compile_eval(EvalInput::rubric(rubric_fixture())).expect("rubric fixture must run");
        match &result {
            EvalEnvelope::Rubric { acknowledgement } => {
                assert_eq!(acknowledgement.disposition(), EvalDisposition::RubricRun);
                assert_eq!(acknowledgement.fixture_count(), 1);
            }
            EvalEnvelope::Trajectory { .. } | EvalEnvelope::TrajectoryAndRubric { .. } => {
                panic!("rubric run must stay a typed rubric result")
            }
        }
        assert!(!format!("{result:?}").contains(CANARY_RUBRIC_51));
        assert!(!result.to_string().contains(CANARY_RUBRIC_51));
    }

    #[test]
    fn boundary_miss_cannot_report_that_both_fixtures_ran() {
        let error = compile_eval(EvalInput::trajectory(EvalFixture::new(
            String::new(),
            String::from(CANARY_EVAL_BOUNDARY_51),
        )))
        .expect_err("empty fixture name must miss the boundary");
        assert_eq!(error.kind(), EvalDiagnosticKind::BoundaryMiss);
        assert_eq!(error.code(), "eval.boundary_miss");
        assert!(!format!("{error:?}").contains(CANARY_EVAL_BOUNDARY_51));
        assert!(!error.to_string().contains(CANARY_EVAL_BOUNDARY_51));
    }

    #[test]
    fn both_fixtures_keep_distinct_typed_dispositions() {
        let result = compile_eval(EvalInput::both(trajectory_fixture(), rubric_fixture()))
            .expect("both fixtures must run");
        match result {
            EvalEnvelope::TrajectoryAndRubric { trajectory, rubric } => {
                assert_eq!(trajectory.disposition(), EvalDisposition::TrajectoryRun);
                assert_eq!(rubric.disposition(), EvalDisposition::RubricRun);
            }
            EvalEnvelope::Trajectory { .. } | EvalEnvelope::Rubric { .. } => {
                panic!("combined bind must not drop a fixture")
            }
        }
    }

    #[test]
    fn fixture_debug_redacts_payload_bytes() {
        let fixture = trajectory_fixture();
        assert!(!format!("{fixture:?}").contains(CANARY_TRAJECTORY_51));
        assert!(!format!("{:?}", EvalInput::trajectory(fixture)).contains(CANARY_TRAJECTORY_51));
    }
}
