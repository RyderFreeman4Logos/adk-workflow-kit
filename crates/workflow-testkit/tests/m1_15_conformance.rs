use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use workflow_adk::TerminalOutcome;
use workflow_testkit::conformance::{
    ConformanceStatus, ConformanceSubgate, documented_failure_matrix, write_conformance_report,
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
fn documented_failure_matrix_covers_every_contract_probe_with_aggregate_target() {
    let matrix = documented_failure_matrix();
    let classes = matrix.iter().map(|entry| entry.class()).collect::<Vec<_>>();
    assert_eq!(
        classes,
        [
            "model",
            "tool",
            "graph",
            "authorization",
            "checkpoint",
            "sandbox",
        ]
    );

    let required = [
        ("model", "connection failure"),
        ("model", "HTTP error"),
        ("model", "invalid response"),
        ("model", "malformed tool arguments"),
        ("model", "empty response"),
        ("model", "timeout"),
        ("model", "context limit"),
        ("model", "rate limit"),
        ("model", "transient retry then success"),
        ("model", "retry exhaustion"),
        ("tool", "unknown tool"),
        ("tool", "invalid arguments"),
        ("tool", "typed empty result"),
        ("tool", "timeout"),
        ("tool", "output too large"),
        ("tool", "sandbox denial"),
        ("tool", "path denial"),
        ("tool", "transient failure"),
        ("tool", "side effect already committed"),
        ("tool", "artifact store failure"),
        ("graph", "undeclared route"),
        ("graph", "missing node"),
        ("graph", "unbounded cycle rejected before run"),
        ("graph", "recursion/visit limit"),
        ("graph", "fan-in state conflict"),
        ("graph", "validator route mismatch"),
        ("graph", "terminal node reached with invalid output"),
        ("authorization", "capability absent"),
        ("authorization", "caller scope absent"),
        ("authorization", "skill requests forbidden tool"),
        ("authorization", "approval denied"),
        ("authorization", "approval call ID mismatch"),
        ("authorization", "approval argument fingerprint mismatch"),
        ("authorization", "approval expired"),
        ("checkpoint", "checkpoint write failure"),
        ("checkpoint", "malformed SQLite"),
        ("checkpoint", "unknown manifest version"),
        ("checkpoint", "workflow hash mismatch"),
        ("checkpoint", "missing artifact"),
        ("checkpoint", "tool implementation drift"),
        ("checkpoint", "resume node no longer exists"),
        ("checkpoint", "effect journal unavailable"),
        ("checkpoint", "crash at each transaction boundary"),
        ("sandbox", "backend unavailable"),
        ("sandbox", "requested capability unsupported"),
        ("sandbox", "filesystem escape attempt"),
        ("sandbox", "network attempt"),
        ("sandbox", "process spawn denied"),
        ("sandbox", "memory/time/output limit"),
        ("sandbox", "child skill script asks for wider authority"),
    ];

    for (class, probe) in required {
        let entry = matrix
            .iter()
            .find(|entry| entry.class() == class)
            .unwrap_or_else(|| panic!("missing documented class {class}"));
        assert!(
            entry.probes().contains(&probe),
            "{class} probe {probe:?} is name-only or missing"
        );
        assert!(
            !entry.aggregate_targets().is_empty(),
            "{class} has no executable aggregate target"
        );
    }
}

#[test]
fn fan_in_state_conflict_requires_a_dedicated_executable_target() {
    let graph = documented_failure_matrix()
        .iter()
        .find(|entry| entry.class() == "graph")
        .expect("graph failure class is documented");

    assert_eq!(
        graph.aggregate_targets(),
        &["workflow-adk --test translation fan_in_state_conflict_is_executable"],
        "fan-in state conflict must reach its dedicated test body, not only a name-only target"
    );
}

#[test]
fn failure_matrix_uses_production_boundary_selectors() {
    let matrix = documented_failure_matrix();
    let authorization = matrix
        .iter()
        .find(|entry| entry.class() == "authorization")
        .expect("authorization failure class is documented");
    assert_eq!(
        authorization.aggregate_targets(),
        &[
            "workflow-runtime --test m1_07_tool_bridge caller_scope_and_approval_denial_stop_handler",
        ],
        "authorization must name the production denial selector, not its whole test binary"
    );

    let checkpoint = matrix
        .iter()
        .find(|entry| entry.class() == "checkpoint")
        .expect("checkpoint failure class is documented");
    assert!(
        checkpoint
            .aggregate_targets()
            .contains(&"workflow-adk --test m1_11_execution_checkpoints resume_failures_map_to_incompatible_terminal_outcome"),
        "resume compatibility requires an executable terminal-outcome selector"
    );
}

#[test]
fn terminal_categories_are_closed_and_executable() {
    assert_eq!(
        TerminalOutcome::ALL.map(TerminalOutcome::as_str),
        [
            "completed",
            "abstained",
            "incomplete",
            "failed",
            "timed_out",
            "cancelled",
            "limit_exceeded",
            "authorization_denied",
            "incompatible_resume",
        ]
    );
}

#[test]
fn conformance_report_binds_exact_checkout_identity_and_status() {
    let path = report_path();
    let receipt = write_conformance_report(
        &path,
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
        &[ConformanceSubgate::new(
            "just m1-15-test",
            ConformanceStatus::Pass,
        )],
    )
    .expect("report must be written");

    assert_eq!(receipt.path(), path.as_path());
    assert_eq!(receipt.status(), ConformanceStatus::Pass);
    let report = fs::read_to_string(&path).expect("report must be readable");
    assert!(report.contains("status: PASS"));
    assert!(report.contains("head: e9f6c6334491432c2b544209e3d303128239290b"));
    assert!(report.contains("tree: 8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3"));
    assert!(
        report.contains("subgates:\n- command: just m1-15-test\n  result: PASS"),
        "reports must retain each subgate command and result"
    );

    fs::remove_file(path).expect("report cleanup");
}

#[test]
fn conformance_report_rejects_missing_subgate_evidence() {
    let error = write_conformance_report(
        report_path(),
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
        &[],
    )
    .expect_err("a conformance report without subgate evidence must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
