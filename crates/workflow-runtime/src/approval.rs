//! Pure approval decision evaluation and terminal classification.

use std::{fmt, time::Duration};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

/// The closed approval decision vocabulary supplied by an external human.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Continue past the approval node.
    Grant,
    /// Stop at the approval node.
    Deny,
}

impl<'de> Deserialize<'de> for ApprovalDecision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "grant" => Ok(Self::Grant),
            "deny" => Ok(Self::Deny),
            _ => Err(D::Error::custom("invalid approval decision")),
        }
    }
}

impl fmt::Display for ApprovalDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Grant => "grant",
            Self::Deny => "deny",
        })
    }
}

/// The successful result of a grant received before the deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalGranted;

impl fmt::Display for ApprovalGranted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("approval granted")
    }
}

/// The closed terminal reasons for an approval node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalTerminalKind {
    /// A human denied the approval.
    Denied,
    /// The approval deadline elapsed without a grant.
    Expired,
    /// The decision or clock input was invalid.
    InvalidDecision,
}

impl fmt::Display for ApprovalTerminalKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::InvalidDecision => "invalid_decision",
        })
    }
}

/// A terminal approval result containing only its closed reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalTerminal {
    kind: ApprovalTerminalKind,
}

impl ApprovalTerminal {
    /// Returns the closed terminal reason.
    pub const fn kind(self) -> ApprovalTerminalKind {
        self.kind
    }
}

impl fmt::Display for ApprovalTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "approval terminal: {}", self.kind)
    }
}

/// Evaluates one external approval decision against a monotonic deadline.
pub fn evaluate_approval(
    timeout: Duration,
    started_at: Duration,
    now: Duration,
    decision: Option<ApprovalDecision>,
) -> Result<ApprovalGranted, ApprovalTerminal> {
    if now < started_at {
        return Err(ApprovalTerminal {
            kind: ApprovalTerminalKind::InvalidDecision,
        });
    }

    let Some(deadline) = started_at.checked_add(timeout) else {
        return Err(ApprovalTerminal {
            kind: ApprovalTerminalKind::InvalidDecision,
        });
    };

    match decision {
        Some(ApprovalDecision::Deny) => Err(ApprovalTerminal {
            kind: ApprovalTerminalKind::Denied,
        }),
        Some(ApprovalDecision::Grant) if now < deadline => Ok(ApprovalGranted),
        Some(ApprovalDecision::Grant) | None => Err(ApprovalTerminal {
            kind: ApprovalTerminalKind::Expired,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{evaluate_approval, ApprovalDecision, ApprovalGranted};

    #[test]
    fn approval_deny_is_terminal_without_echo() {
        let terminal = evaluate_approval(
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Some(ApprovalDecision::Deny),
        )
        .expect_err("denial must terminate the approval node");

        assert_eq!(terminal.kind(), super::ApprovalTerminalKind::Denied);
        assert!(!format!("{terminal:?} {terminal}").contains("grant"));
    }

    #[test]
    fn approval_expire_without_decision_is_expired() {
        let terminal = evaluate_approval(
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_millis(20),
            None,
        )
        .expect_err("missing decisions must terminate closed");

        assert_eq!(terminal.kind(), super::ApprovalTerminalKind::Expired);
    }

    #[test]
    fn malformed_or_unknown_decision_never_grants() {
        for payload in [
            r#""escalate""#,
            r#"{"decision":"grant","secret":"SECRET_PAYLOAD"}"#,
        ] {
            assert!(serde_json::from_str::<ApprovalDecision>(payload).is_err());
        }
    }

    #[test]
    fn denial_redacts_secret_and_payload_markers() {
        let decision = ApprovalDecision::Deny;
        let granted = ApprovalGranted;
        let terminal = evaluate_approval(
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Some(decision),
        )
        .expect_err("denial should produce a terminal result");
        let rendered =
            format!("{decision:?} {decision} {granted:?} {granted} {terminal:?} {terminal}");

        for marker in [
            "SECRET_PROMPT",
            "SECRET_PAYLOAD",
            "TENANT_SECRET",
            "ROLE_SECRET",
        ] {
            assert!(!rendered.contains(marker), "leaked {marker}");
        }
    }

    #[test]
    fn approval_grant_before_deadline_succeeds() {
        let granted = evaluate_approval(
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_millis(50),
            Some(ApprovalDecision::Grant),
        )
        .expect("valid grant before the deadline should succeed");

        assert_eq!(granted, ApprovalGranted);
    }
}
