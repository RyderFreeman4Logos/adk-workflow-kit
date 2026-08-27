//! Pure approval decision evaluation and terminal classification.

use std::{collections::BTreeMap, fmt, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A kit-owned approval bound to one exact function call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallScopedApproval {
    tool_name: String,
    call_id: String,
    argument_fingerprint: String,
    actor: String,
    expires_at_ms: u64,
}

impl CallScopedApproval {
    /// Creates an approval for the supplied call and expiry.
    pub fn new(
        tool_name: impl Into<String>,
        call_id: impl Into<String>,
        arguments: &Value,
        actor: impl Into<String>,
        expires_at: Duration,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            call_id: call_id.into(),
            argument_fingerprint: argument_fingerprint(arguments),
            actor: actor.into(),
            expires_at_ms: expires_at.as_millis().try_into().unwrap_or(u64::MAX),
        }
    }

    /// Returns the call-bound argument fingerprint without exposing arguments.
    pub fn argument_fingerprint(&self) -> &str {
        &self.argument_fingerprint
    }

    /// Returns the expiry in the monotonic millisecond domain.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// A small in-memory ledger for call-scoped approvals.
#[derive(Clone, Debug, Default)]
pub struct ApprovalLedger {
    records: BTreeMap<(String, String, String), CallScopedApproval>,
}

impl ApprovalLedger {
    /// Creates an empty approval ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a grant bound to tool, call ID, actor, arguments, and expiry.
    pub fn grant(
        mut self,
        tool_name: impl Into<String>,
        call_id: impl Into<String>,
        arguments: &Value,
        actor: impl Into<String>,
        expires_at: Duration,
    ) -> Self {
        let approval = CallScopedApproval::new(tool_name, call_id, arguments, actor, expires_at);
        self.records.insert(
            (
                approval.tool_name.clone(),
                approval.call_id.clone(),
                approval.actor.clone(),
            ),
            approval,
        );
        self
    }

    /// Authorizes only the exact call represented by a recorded grant.
    pub fn authorize(
        &self,
        tool_name: &str,
        call_id: &str,
        arguments: &Value,
        actor: &str,
        now: Duration,
    ) -> Result<ApprovalGranted, CallApprovalError> {
        let Some(record) =
            self.records
                .get(&(tool_name.to_owned(), call_id.to_owned(), actor.to_owned()))
        else {
            return Err(CallApprovalError::Missing);
        };
        if record.argument_fingerprint != argument_fingerprint(arguments) {
            return Err(CallApprovalError::ArgumentMismatch);
        }
        if now.as_millis() >= u128::from(record.expires_at_ms) {
            return Err(CallApprovalError::Expired);
        }
        Ok(ApprovalGranted)
    }
}

/// A closed reason why a call-scoped grant cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallApprovalError {
    /// No grant matches the tool, call ID, and actor.
    Missing,
    /// The arguments differ from the approved arguments.
    ArgumentMismatch,
    /// The grant's expiry has elapsed.
    Expired,
}

impl fmt::Display for CallApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "call approval is missing",
            Self::ArgumentMismatch => "call approval arguments do not match",
            Self::Expired => "call approval has expired",
        })
    }
}

impl std::error::Error for CallApprovalError {}

/// Computes a stable SHA-256 fingerprint for JSON arguments.
pub fn argument_fingerprint(arguments: &Value) -> String {
    let mut canonical = String::new();
    write_canonical_json(arguments, &mut canonical);
    let digest = Sha256::digest(canonical.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Object(object) => {
            output.push('{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("JSON string serialization cannot fail"),
                );
                output.push(':');
                write_canonical_json(&object[key], output);
            }
            output.push('}');
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output);
            }
            output.push(']');
        }
        _ => {
            output.push_str(&serde_json::to_string(value).expect("JSON serialization cannot fail"))
        }
    }
}

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

    use super::{ApprovalDecision, ApprovalGranted, evaluate_approval};

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
