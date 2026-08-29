use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use workflow_testkit::conformance::{
    ConformanceStatus, documented_failure_matrix, write_conformance_report,
};

static NEXT_REPORT: AtomicU64 = AtomicU64::new(0);

fn report_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "workflow-m1-15-conformance-{}-{}.md",
        std::process::id(),
        NEXT_REPORT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn documented_failure_matrix_covers_all_required_fail_closed_classes() {
    let matrix = documented_failure_matrix();
    let classes = matrix.iter().map(|entry| entry.class()).collect::<Vec<_>>();
    assert_eq!(
        classes,
        [
            "model",
            "tool",
            "checkpoint",
            "artifact",
            "sandbox",
            "graph"
        ]
    );

    for required in [
        "unknown route",
        "denial",
        "corruption",
        "compatibility mismatch",
        "semantic ID binding",
        "illegal stage jump",
        "digest/hash mismatch",
        "closed diagnostics",
    ] {
        assert!(
            matrix
                .iter()
                .any(|entry| entry.probes().contains(&required)),
            "{required} must be covered by a documented deterministic probe"
        );
    }
}

#[test]
fn conformance_report_binds_exact_checkout_identity_and_status() {
    let path = report_path();
    let receipt = write_conformance_report(
        &path,
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
    )
    .expect("report must be written");

    assert_eq!(receipt.path(), path.as_path());
    assert_eq!(receipt.status(), ConformanceStatus::Pass);
    let report = fs::read_to_string(&path).expect("report must be readable");
    assert!(report.contains("status: PASS"));
    assert!(report.contains("head: e9f6c6334491432c2b544209e3d303128239290b"));
    assert!(report.contains("tree: 8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3"));

    fs::remove_file(path).expect("report cleanup");
}
