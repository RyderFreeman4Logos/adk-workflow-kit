//! Deterministic local dependency/security audit.
//!
//! Fixture payloads and advisory bodies never appear in `Debug`/`Display`/serde
//! snapshots. Clean, critical, and boundary-miss stay distinct typed paths.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

/// Distinct typed audit dispositions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDisposition {
    /// No unresolved critical findings.
    Clean,
    /// A planted or policy-denied critical finding.
    Critical,
    /// Missing or invalid policy/lock fixture.
    BoundaryMiss,
}

/// Redacted audit result. Lock bytes and advisory bodies stay off this surface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditReport {
    disposition: AuditDisposition,
    critical_count: usize,
    package_count: usize,
    policy_len: usize,
    lock_len: usize,
}

impl AuditReport {
    /// Returns the typed audit disposition.
    pub const fn disposition(&self) -> AuditDisposition {
        self.disposition
    }

    /// Returns the number of critical findings.
    pub const fn critical_count(&self) -> usize {
        self.critical_count
    }

    /// Returns the number of scanned lock packages.
    pub const fn package_count(&self) -> usize {
        self.package_count
    }
}

impl fmt::Display for AuditReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.disposition {
            AuditDisposition::Clean => formatter.write_str("no unresolved critical findings"),
            AuditDisposition::Critical => {
                write!(
                    formatter,
                    "critical dependency findings: {}",
                    self.critical_count
                )
            }
            AuditDisposition::BoundaryMiss => {
                formatter.write_str("audit policy or lock fixture missed a typed boundary")
            }
        }
    }
}

/// Typed, payload-free audit boundary failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AuditError {
    kind: AuditDisposition,
    code: &'static str,
    policy_len: usize,
    lock_len: usize,
}

impl AuditError {
    fn boundary(policy_len: usize, lock_len: usize) -> Self {
        Self {
            kind: AuditDisposition::BoundaryMiss,
            code: "workflow.audit.boundary_miss",
            policy_len,
            lock_len,
        }
    }

    /// Returns the typed failure disposition.
    pub const fn kind(self) -> AuditDisposition {
        self.kind
    }

    /// Returns the stable machine-readable diagnostic code.
    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "audit policy or lock fixture missed a typed boundary (policy_len={}, lock_len={})",
            self.policy_len, self.lock_len
        )
    }
}

impl std::error::Error for AuditError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditPolicyWire {
    schema_version: Option<u32>,
    #[serde(default)]
    denied_crates: Vec<String>,
    #[serde(default)]
    licenses: Option<LicensePolicyWire>,
    #[serde(default)]
    bans: Option<BanPolicyWire>,
    #[serde(default)]
    advisories: Option<AdvisoryPolicyWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LicensePolicyWire {
    #[serde(default)]
    allow: Option<Vec<String>>,
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BanPolicyWire {
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvisoryPolicyWire {
    #[serde(default)]
    unmaintained: Option<UnmaintainedAction>,
    #[serde(default)]
    yanked: Option<DenyAction>,
}

#[derive(Deserialize)]
enum UnmaintainedAction {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "deny")]
    Deny,
}

#[derive(Deserialize)]
enum DenyAction {
    #[serde(rename = "deny")]
    Deny,
}

#[derive(Deserialize)]
struct CargoLockWire {
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    advisory_severity: Option<String>,
    #[serde(default)]
    unmaintained: bool,
    #[serde(default)]
    yanked: bool,
}

/// Audits one policy fixture against one lock fixture.
///
/// Binding is deterministic and typed. A critical finding never reports a clean
/// pass. A boundary miss never reports that the audit ran clean.
pub fn audit_dependencies(policy: &str, lock: &str) -> Result<AuditReport, AuditError> {
    let policy_len = policy.len();
    let lock_len = lock.len();
    if policy.is_empty() || lock.is_empty() {
        return Err(AuditError::boundary(policy_len, lock_len));
    }

    let parsed_policy: AuditPolicyWire =
        toml::from_str(policy).map_err(|_| AuditError::boundary(policy_len, lock_len))?;
    if parsed_policy
        .schema_version
        .is_some_and(|version| version != 1)
        || (parsed_policy.schema_version.is_none()
            && parsed_policy.licenses.is_none()
            && parsed_policy.bans.is_none()
            && parsed_policy.advisories.is_none())
    {
        return Err(AuditError::boundary(policy_len, lock_len));
    }

    let parsed_lock: CargoLockWire =
        toml::from_str(lock).map_err(|_| AuditError::boundary(policy_len, lock_len))?;
    let mut denied = parsed_policy
        .denied_crates
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if let Some(bans) = &parsed_policy.bans {
        denied.extend(bans.deny.iter().map(String::as_str));
    }
    let denied_licenses = parsed_policy
        .licenses
        .as_ref()
        .map(|licenses| {
            licenses
                .deny
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let allowed_licenses = parsed_policy
        .licenses
        .as_ref()
        .and_then(|licenses| licenses.allow.as_ref())
        .map(|licenses| licenses.iter().map(String::as_str).collect::<BTreeSet<_>>());
    let advisories_enabled = true;
    let unmaintained_enabled = parsed_policy
        .advisories
        .as_ref()
        .is_some_and(|advisories| advisories.unmaintained.is_some());
    let yanked_enabled = parsed_policy
        .advisories
        .as_ref()
        .is_some_and(|advisories| advisories.yanked.is_some());
    let package_count = parsed_lock.package.len();
    let critical_count = parsed_lock
        .package
        .iter()
        .map(|package| {
            usize::from(denied.contains(package.name.as_str()))
                + usize::from(
                    package
                        .license
                        .as_deref()
                        .is_some_and(|license| denied_licenses.contains(license)),
                )
                + usize::from(allowed_licenses.as_ref().is_some_and(|allowed| {
                    package.license.as_deref().is_none_or(|license| {
                        !allowed.contains(license)
                            || license.contains(" OR ")
                            || license.contains(" AND ")
                            || license.contains(" WITH ")
                    })
                }))
                + usize::from(advisories_enabled && package.advisory_severity.as_deref().is_some())
                + usize::from(unmaintained_enabled && package.unmaintained)
                + usize::from(yanked_enabled && package.yanked)
        })
        .sum();
    let disposition = if critical_count == 0 {
        AuditDisposition::Clean
    } else {
        AuditDisposition::Critical
    };

    Ok(AuditReport {
        disposition,
        critical_count,
        package_count,
        policy_len,
        lock_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY_AUDIT_CLEAN_70: &str = "CANARY_AUDIT_CLEAN_70";
    const CANARY_AUDIT_CRITICAL_70: &str = "CANARY_AUDIT_CRITICAL_70";
    const CANARY_AUDIT_BOUNDARY_70: &str = "CANARY_AUDIT_BOUNDARY_70";

    const CLEAN_POLICY: &str = "schema_version = 1\ndenied_crates = []\n";
    const CLEAN_LOCK: &str = "[[package]]\nname = \"workflow-spec\"\nversion = \"0.2.2\"\nadvisory_body = \"CANARY_AUDIT_CLEAN_70\"\n";
    const CRITICAL_POLICY: &str = "schema_version = 1\ndenied_crates = [\"evil-crate\"]\n";
    const CRITICAL_LOCK: &str = "[[package]]\nname = \"evil-crate\"\nversion = \"0.0.1\"\nadvisory_body = \"CANARY_AUDIT_CRITICAL_70\"\n";

    fn assert_redacted(serialized: &str, canary: &str) {
        assert!(!serialized.contains(canary));
        assert!(!serialized.contains("advisory_body"));
    }

    #[test]
    fn canary_audit_clean_70_reports_no_critical_findings() {
        let result = audit_dependencies(CLEAN_POLICY, CLEAN_LOCK)
            .expect("clean fixture must report no critical findings");
        assert_eq!(result.disposition(), AuditDisposition::Clean);
        assert_ne!(result.disposition(), AuditDisposition::Critical);
        assert_ne!(result.disposition(), AuditDisposition::BoundaryMiss);
        assert_eq!(result.critical_count(), 0);
        assert_eq!(result.package_count(), 1);
        assert_eq!(result.to_string(), "no unresolved critical findings");
        assert_redacted(&format!("{result:?}"), CANARY_AUDIT_CLEAN_70);
        assert_redacted(&result.to_string(), CANARY_AUDIT_CLEAN_70);
        assert_redacted(
            &serde_json::to_string(&result).expect("serialize clean report"),
            CANARY_AUDIT_CLEAN_70,
        );
    }

    #[test]
    fn canary_audit_critical_70_fails_closed_and_cannot_report_clean() {
        let result = audit_dependencies(CRITICAL_POLICY, CRITICAL_LOCK)
            .expect("critical fixture must produce a typed report");
        assert_eq!(result.disposition(), AuditDisposition::Critical);
        assert_ne!(result.disposition(), AuditDisposition::Clean);
        assert_ne!(result.disposition(), AuditDisposition::BoundaryMiss);
        assert!(result.critical_count() > 0);
        assert_ne!(result.to_string(), "no unresolved critical findings");
        assert!(!result
            .to_string()
            .contains("no unresolved critical findings"));
        assert_redacted(&format!("{result:?}"), CANARY_AUDIT_CRITICAL_70);
        assert_redacted(&result.to_string(), CANARY_AUDIT_CRITICAL_70);
        assert_redacted(
            &serde_json::to_string(&result).expect("serialize critical report"),
            CANARY_AUDIT_CRITICAL_70,
        );
    }

    #[test]
    fn canary_audit_boundary_70_is_typed_miss_and_cannot_report_clean() {
        let error = audit_dependencies("", CANARY_AUDIT_BOUNDARY_70)
            .expect_err("missing policy must miss the boundary");
        assert_eq!(error.kind(), AuditDisposition::BoundaryMiss);
        assert_eq!(error.code(), "workflow.audit.boundary_miss");
        assert_ne!(error.kind(), AuditDisposition::Clean);
        assert_ne!(error.kind(), AuditDisposition::Critical);
        assert!(!error
            .to_string()
            .contains("no unresolved critical findings"));
        assert_redacted(&format!("{error:?}"), CANARY_AUDIT_BOUNDARY_70);
        assert_redacted(&error.to_string(), CANARY_AUDIT_BOUNDARY_70);
        assert_redacted(
            &serde_json::to_string(&error).expect("serialize boundary error"),
            CANARY_AUDIT_BOUNDARY_70,
        );
    }

    #[test]
    fn cargo_deny_license_and_advisory_findings_are_critical() {
        let policy = "[licenses]\ndeny = [\"GPL-3.0-only\"]\n[bans]\ndeny = []\n[advisories]\nunmaintained = \"all\"\nyanked = \"deny\"\n";
        let lock = "[[package]]\nname = \"licensed-crate\"\nlicense = \"GPL-3.0-only\"\nadvisory_severity = \"high\"\n";

        let result = audit_dependencies(policy, lock).expect("valid cargo-deny fixture");
        assert_eq!(result.disposition(), AuditDisposition::Critical);
        assert_eq!(result.critical_count(), 2);
    }

    #[test]
    fn allow_list_rejects_package_without_license() {
        let policy = "[licenses]\nallow = [\"MIT\"]\n";
        let lock = "[[package]]\nname = \"unlicensed-crate\"\n";

        let result = audit_dependencies(policy, lock).expect("valid policy and lock fixture");
        assert_eq!(result.disposition(), AuditDisposition::Critical);
    }

    #[test]
    fn vulnerability_default_rejects_every_advisory_severity() {
        let policy = "[advisories]\nunmaintained = \"all\"\nyanked = \"deny\"\n";
        let lock = "[[package]]\nname = \"low-risk-crate\"\nadvisory_severity = \"low\"\n";

        let result = audit_dependencies(policy, lock).expect("cargo-deny 0.19 policy is valid");
        assert_eq!(result.disposition(), AuditDisposition::Critical);
    }

    #[test]
    fn compound_license_is_not_clean() {
        let policy = "[licenses]\nallow = [\"MIT\", \"Apache-2.0\"]\n";
        let lock =
            "[[package]]\nname = \"compound-license-crate\"\nlicense = \"MIT OR Apache-2.0\"\n";

        let result = audit_dependencies(policy, lock).expect("valid policy and lock fixture");
        assert_ne!(result.disposition(), AuditDisposition::Clean);
    }

    #[test]
    fn diagnostics_remain_payload_free_for_advisory_fixture() {
        let policy = "[advisories]\nunmaintained = \"all\"\nyanked = \"deny\"\n";
        let lock = "[[package]]\nname = \"payload-crate\"\nadvisory_severity = \"critical\"\nadvisory_body = \"SECRET_ADVISORY_BODY_R3B\"\n";

        let result = audit_dependencies(policy, lock).expect("valid policy and lock fixture");
        let serialized = serde_json::to_string(&result).expect("serialize redacted report");
        assert!(!serialized.contains("SECRET_ADVISORY_BODY_R3B"));
        assert!(!result.to_string().contains("SECRET_ADVISORY_BODY_R3B"));
    }

    #[test]
    fn committed_cargo_deny_shape_rejects_disallowed_license() {
        let policy = "[licenses]\nallow = [\"MIT\"]\n[advisories]\nunmaintained = \"all\"\nyanked = \"deny\"\n";
        let lock = "[[package]]\nname = \"gpl-crate\"\nlicense = \"GPL-3.0-only\"\n";

        let result = audit_dependencies(policy, lock).expect("valid committed policy shape");
        assert_eq!(result.disposition(), AuditDisposition::Critical);
    }

    #[test]
    fn committed_advisory_shapes_reject_matching_findings() {
        let policy = "[licenses]\nallow = [\"MIT\"]\n[advisories]\nunmaintained = \"all\"\nyanked = \"deny\"\n";
        let lock = "[[package]]\nname = \"flagged-crate\"\nlicense = \"MIT\"\nunmaintained = true\nyanked = true\n";

        let result = audit_dependencies(policy, lock).expect("valid committed policy shape");
        assert_eq!(result.disposition(), AuditDisposition::Critical);
        assert_eq!(result.critical_count(), 2);
    }

    #[test]
    fn removed_advisory_action_is_a_boundary_miss() {
        let policy = "[advisories]\nremoved_action = \"warn\"\n";
        let lock = "[[package]]\nname = \"vulnerable-crate\"\nadvisory_severity = \"high\"\n";

        let error = audit_dependencies(policy, lock).expect_err("warn must fail closed");
        assert_eq!(error.kind(), AuditDisposition::BoundaryMiss);
    }

    #[test]
    fn warn_yanked_action_is_a_boundary_miss() {
        let policy = "[advisories]\nyanked = \"warn\"\n";
        let lock = "[[package]]\nname = \"yanked-crate\"\nyanked = true\n";

        let error = audit_dependencies(policy, lock).expect_err("warn must fail closed");
        assert_eq!(error.kind(), AuditDisposition::BoundaryMiss);
    }

    #[test]
    fn unknown_advisory_action_is_a_boundary_miss() {
        let policy = "[advisories]\nunmaintained = \"review\"\n";
        let lock = "[[package]]\nname = \"ordinary-crate\"\n";

        let error = audit_dependencies(policy, lock).expect_err("unknown action must fail closed");
        assert_eq!(error.kind(), AuditDisposition::BoundaryMiss);
    }

    #[test]
    fn committed_advisory_actions_still_report_matching_critical_findings() {
        let policy = "[advisories]\nunmaintained = \"all\"\nyanked = \"deny\"\n";
        let lock = "[[package]]\nname = \"flagged-crate\"\nunmaintained = true\nyanked = true\n";

        let result = audit_dependencies(policy, lock).expect("committed actions are valid");
        assert_eq!(result.disposition(), AuditDisposition::Critical);
        assert_eq!(result.critical_count(), 2);
    }

    #[test]
    fn unknown_policy_fields_are_boundary_misses() {
        let policy = "[licenses]\nallow = [\"MIT\"]\nunsupported = true\n";
        let lock = "[[package]]\nname = \"ordinary-crate\"\nlicense = \"MIT\"\n";

        let error = audit_dependencies(policy, lock).expect_err("unknown policy must fail closed");
        assert_eq!(error.kind(), AuditDisposition::BoundaryMiss);
    }
}
