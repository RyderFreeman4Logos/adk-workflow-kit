use workflow_compiler::{audit_dependencies, AuditDisposition};

const CANARY_AUDIT_CLEAN_70: &str = "CANARY_AUDIT_CLEAN_70";
const CANARY_AUDIT_CRITICAL_70: &str = "CANARY_AUDIT_CRITICAL_70";
const CANARY_AUDIT_BOUNDARY_70: &str = "CANARY_AUDIT_BOUNDARY_70";

const CLEAN_POLICY: &str = "schema_version = 1\ndenied_crates = []\n";
const CLEAN_LOCK: &str = "[[package]]\nname = \"workflow-spec\"\nversion = \"0.2.2\"\nadvisory_body = \"CANARY_AUDIT_CLEAN_70\"\n";
const CRITICAL_POLICY: &str = "schema_version = 1\ndenied_crates = [\"evil-crate\"]\n";
const CRITICAL_LOCK: &str = "[[package]]\nname = \"evil-crate\"\nversion = \"0.0.1\"\nadvisory_body = \"CANARY_AUDIT_CRITICAL_70\"\n";

#[test]
fn integration_clean_fixture_is_not_dropped_or_marked_critical() {
    let result = audit_dependencies(CLEAN_POLICY, CLEAN_LOCK)
        .expect("clean fixture must remain a typed clean report");
    assert_eq!(result.disposition(), AuditDisposition::Clean);
    assert_eq!(result.critical_count(), 0);
    assert_eq!(result.package_count(), 1);
    assert!(!format!("{result:?}").contains(CANARY_AUDIT_CLEAN_70));
}

#[test]
fn integration_critical_fixture_cannot_report_clean() {
    let result = audit_dependencies(CRITICAL_POLICY, CRITICAL_LOCK)
        .expect("critical fixture must remain a typed critical report");
    assert_eq!(result.disposition(), AuditDisposition::Critical);
    assert_ne!(result.disposition(), AuditDisposition::Clean);
    assert!(result.critical_count() > 0);
    assert!(!result
        .to_string()
        .contains("no unresolved critical findings"));
    assert!(!format!("{result:?}").contains(CANARY_AUDIT_CRITICAL_70));
}

#[test]
fn integration_boundary_fixture_cannot_report_clean() {
    let error = audit_dependencies("not-toml", CANARY_AUDIT_BOUNDARY_70)
        .expect_err("invalid policy must miss the boundary");
    assert_eq!(error.kind(), AuditDisposition::BoundaryMiss);
    assert_ne!(error.kind(), AuditDisposition::Clean);
    assert!(!format!("{error:?}").contains(CANARY_AUDIT_BOUNDARY_70));
}
