//! M1-15's deterministic ADK boundary and failure conformance inventory.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// One documented deterministic failure class and its required fail-closed probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureClass {
    class: &'static str,
    probes: &'static [&'static str],
    aggregate_targets: &'static [&'static str],
}

impl FailureClass {
    /// Returns the stable failure class name.
    pub const fn class(self) -> &'static str {
        self.class
    }

    /// Returns the required deterministic probes for this class.
    pub const fn probes(self) -> &'static [&'static str] {
        self.probes
    }

    /// Returns the aggregate tests that execute this failure class.
    pub const fn aggregate_targets(self) -> &'static [&'static str] {
        self.aggregate_targets
    }
}

const FAILURE_MATRIX: [FailureClass; 6] = [
    FailureClass {
        class: "model",
        probes: &[
            "connection failure",
            "HTTP error",
            "invalid response",
            "malformed tool arguments",
            "empty response",
            "timeout",
            "context limit",
            "rate limit",
            "transient retry then success",
            "retry exhaustion",
        ],
        aggregate_targets: &["workflow-testkit --test fault_injection"],
    },
    FailureClass {
        class: "tool",
        probes: &[
            "unknown tool",
            "invalid arguments",
            "typed empty result",
            "timeout",
            "output too large",
            "sandbox denial",
            "path denial",
            "transient failure",
            "side effect already committed",
            "artifact store failure",
        ],
        aggregate_targets: &["workflow-adk --test tool_bridge"],
    },
    FailureClass {
        class: "graph",
        probes: &[
            "undeclared route",
            "missing node",
            "unbounded cycle rejected before run",
            "recursion/visit limit",
            "fan-in state conflict",
            "validator route mismatch",
            "terminal node reached with invalid output",
        ],
        aggregate_targets: &["workflow-adk --test translation fan_in_state_conflict_is_executable"],
    },
    FailureClass {
        class: "authorization",
        probes: &[
            "capability absent",
            "caller scope absent",
            "skill requests forbidden tool",
            "approval denied",
            "approval call ID mismatch",
            "approval argument fingerprint mismatch",
            "approval expired",
        ],
        aggregate_targets: &[
            "workflow-runtime --test m1_07_tool_bridge caller_scope_and_approval_denial_stop_handler",
        ],
    },
    FailureClass {
        class: "checkpoint",
        probes: &[
            "checkpoint write failure",
            "malformed SQLite",
            "unknown manifest version",
            "workflow hash mismatch",
            "missing artifact",
            "tool implementation drift",
            "resume node no longer exists",
            "effect journal unavailable",
            "crash at each transaction boundary",
        ],
        aggregate_targets: &[
            "workflow-adk --test m1_11_execution_checkpoints resume_failures_map_to_incompatible_terminal_outcome",
        ],
    },
    FailureClass {
        class: "sandbox",
        probes: &[
            "backend unavailable",
            "requested capability unsupported",
            "filesystem escape attempt",
            "network attempt",
            "process spawn denied",
            "memory/time/output limit",
            "child skill script asks for wider authority",
        ],
        aggregate_targets: &["workflow-adk --test tool_bridge"],
    },
];

/// Returns the M1-15 matrix wired by `just conformance` to existing deterministic tests.
pub const fn documented_failure_matrix() -> &'static [FailureClass] {
    &FAILURE_MATRIX
}

/// Final status emitted by the local aggregate command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceStatus {
    Pass,
    Fail,
}

impl ConformanceStatus {
    /// Returns the stable report spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

/// The report location and terminal status produced by the aggregate command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReceipt {
    path: PathBuf,
    status: ConformanceStatus,
}

impl ConformanceReceipt {
    /// Returns the written report path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the report's terminal status.
    pub const fn status(&self) -> ConformanceStatus {
        self.status
    }
}

/// One executed aggregate subgate recorded in the durable report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceSubgate {
    command: String,
    status: ConformanceStatus,
}

impl ConformanceSubgate {
    /// Binds the exact invoked command to its terminal result.
    pub fn new(command: impl Into<String>, status: ConformanceStatus) -> Self {
        Self {
            command: command.into(),
            status,
        }
    }

    /// Returns the exact invoked command.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Returns the command result.
    pub const fn status(&self) -> ConformanceStatus {
        self.status
    }
}

/// Writes an auditable, checkout-bound conformance report.
pub fn write_conformance_report(
    path: impl AsRef<Path>,
    head: &str,
    tree: &str,
    status: ConformanceStatus,
    subgates: &[ConformanceSubgate],
) -> io::Result<ConformanceReceipt> {
    if !is_git_object_id(head) || !is_git_object_id(tree) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conformance report requires full lowercase Git object IDs",
        ));
    }

    if subgates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conformance report requires subgate evidence",
        ));
    }

    let path = path.as_ref().to_path_buf();
    let mut report = format!(
        "# M1-15 ADK boundary/failure conformance\n\nstatus: {}\nhead: {head}\ntree: {tree}\nsubgates:\n",
        status.as_str()
    );
    for subgate in subgates {
        report.push_str(&format!(
            "- command: {}\n  result: {}\n",
            subgate.command(),
            subgate.status().as_str()
        ));
    }
    fs::write(&path, report)?;
    Ok(ConformanceReceipt { path, status })
}

fn is_git_object_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
