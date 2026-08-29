use std::{
    collections::BTreeSet,
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

fn complete_probe_evidence(status: ConformanceStatus) -> Vec<ConformanceSubgate> {
    documented_failure_matrix()
        .iter()
        .flat_map(|class| class.probes().iter())
        .map(|probe| ConformanceSubgate::executed(probe.selector(), status))
        .collect()
}

#[test]
fn documented_failure_matrix_binds_every_contract_probe_to_a_unique_selector_and_assertion() {
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

    for (class, name) in required {
        let entry = matrix
            .iter()
            .find(|entry| entry.class() == class)
            .unwrap_or_else(|| panic!("missing documented class {class}"));
        let probe = entry
            .probes()
            .iter()
            .find(|probe| probe.name() == name)
            .unwrap_or_else(|| panic!("{class} probe {name:?} is missing"));
        assert!(
            probe.selector().starts_with("workflow-")
                || probe.selector().starts_with("workflowctl"),
            "{class} probe {name:?} needs an exact package test selector"
        );
        assert!(
            !probe.expected_fail_closed_assertion().is_empty(),
            "{class} probe {name:?} needs its fail-closed assertion"
        );
    }

    let selectors = matrix
        .iter()
        .flat_map(|class| class.probes())
        .map(|probe| probe.selector())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        selectors.len(),
        matrix
            .iter()
            .map(|class| class.probes().len())
            .sum::<usize>(),
        "every documented probe must bind a unique test selector"
    );
}

#[test]
fn fan_in_state_conflict_requires_a_dedicated_executable_target() {
    let graph = documented_failure_matrix()
        .iter()
        .find(|entry| entry.class() == "graph")
        .expect("graph failure class is documented");
    let probe = graph
        .probes()
        .iter()
        .find(|probe| probe.name() == "fan-in state conflict")
        .expect("fan-in probe is documented");

    assert_eq!(
        probe.selector(),
        "workflow-adk --test translation fan_in_same_key_writes_fail_closed_before_merge",
        "fan-in state conflict must reach its dedicated test body"
    );
}

#[test]
fn failure_matrix_uses_production_boundary_selectors() {
    let matrix = documented_failure_matrix();
    let authorization = matrix
        .iter()
        .find(|entry| entry.class() == "authorization")
        .expect("authorization failure class is documented");
    let caller_scope = authorization
        .probes()
        .iter()
        .find(|probe| probe.name() == "caller scope absent")
        .expect("caller scope denial is documented");
    assert_eq!(
        caller_scope.selector(),
        "workflow-adk --test tool_bridge real_tool_bridge_policy_denial_projects_authorization_terminal_outcome",
        "authorization must name the production denial selector, not its whole test binary"
    );

    let checkpoint = matrix
        .iter()
        .find(|entry| entry.class() == "checkpoint")
        .expect("checkpoint failure class is documented");
    assert!(checkpoint.probes().iter().any(|probe| {
        probe.selector()
            == "workflow-adk --test m1_11_execution_checkpoints resume_rejects_missing_target_node_before_graph_invocation"
    }));
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
fn conformance_report_rejects_unexecuted_matrix_probes() {
    let path = report_path();
    let error = write_conformance_report(
        &path,
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
        &[ConformanceSubgate::new(
            "just m1-15-test",
            ConformanceStatus::Pass,
        )],
    )
    .expect_err("a static matrix cannot prove unexecuted probes");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!path.exists(), "rejected report must not be written");
}

#[test]
fn conformance_report_rejects_inconsistent_total_status() {
    let error = write_conformance_report(
        report_path(),
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
        &[ConformanceSubgate::new(
            "just m1-15-test",
            ConformanceStatus::Fail,
        )],
    )
    .expect_err("PASS must not contradict a failed subgate");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
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

#[test]
fn conformance_report_binds_every_executed_matrix_probe() {
    let path = report_path();
    let receipt = write_conformance_report(
        &path,
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
        &complete_probe_evidence(ConformanceStatus::Pass),
    )
    .expect("complete executed matrix must produce a report");

    assert_eq!(receipt.status(), ConformanceStatus::Pass);
    let report = fs::read_to_string(&path).expect("report must be readable");
    assert_eq!(report.matches("  result: PASS\n").count(), 50);
    fs::remove_file(path).expect("report cleanup");
}

#[test]
fn conformance_report_rejects_unknown_or_duplicate_probe_evidence() {
    let mut unknown = complete_probe_evidence(ConformanceStatus::Pass);
    unknown[0] =
        ConformanceSubgate::new("workflow-testkit --test unknown", ConformanceStatus::Pass);
    let unknown = write_conformance_report(
        report_path(),
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
        &unknown,
    )
    .expect_err("unknown selector must fail closed");
    assert_eq!(unknown.kind(), std::io::ErrorKind::InvalidInput);

    let mut duplicate = complete_probe_evidence(ConformanceStatus::Pass);
    duplicate.push(duplicate[0].clone());
    let duplicate = write_conformance_report(
        report_path(),
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
        &duplicate,
    )
    .expect_err("duplicate selector must fail closed");
    assert_eq!(duplicate.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn conformance_report_rejects_caller_forged_selector_only_passes() {
    let error = write_conformance_report(
        report_path(),
        "e9f6c6334491432c2b544209e3d303128239290b",
        "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3",
        ConformanceStatus::Pass,
        &documented_failure_matrix()
            .iter()
            .flat_map(|class| class.probes().iter())
            .map(|probe| ConformanceSubgate::new(probe.selector(), ConformanceStatus::Pass))
            .collect::<Vec<_>>(),
    )
    .expect_err("selector/status strings are not execution receipts");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
