use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::json;
use workflow_adk::TerminalOutcome;
use workflow_runtime::{
    CapabilityIntersection, RunContext, RunId, RunLimits, RunSandbox, SandboxCapability,
    ToolBridge, ToolBridgeErrorKind, WorkdirManager,
};
use workflow_testkit::conformance::documented_failure_matrix;

static NEXT_REPORT: AtomicU64 = AtomicU64::new(0);

fn report_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "workflow-m1-15-conformance-{}-{}.md",
        std::process::id(),
        NEXT_REPORT.fetch_add(1, Ordering::Relaxed)
    ))
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
        ("model", "rate limit"),
        ("model", "transient retry then success"),
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
        ("graph", "route fan-in same-key state conflict"),
        ("graph", "route fan-in disjoint-key state success"),
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
        "workflow-adk --test tool_bridge registered_tool_policy_denial_preserves_authorization_terminal_outcome",
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
fn report_binary_rejects_caller_supplied_selector_only_passes() {
    let path = report_path();
    let evidence = path.with_extension("evidence");
    let rows = documented_failure_matrix()
        .iter()
        .flat_map(|class| class.probes().iter())
        .map(|probe| format!("PASS\t{}\n", probe.selector()))
        .collect::<String>();
    fs::write(&evidence, rows).expect("forged evidence fixture is writable");

    let output = Command::new(env!("CARGO_BIN_EXE_m1-15-report"))
        .args([
            path.as_os_str(),
            "e9f6c6334491432c2b544209e3d303128239290b".as_ref(),
            "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3".as_ref(),
            "PASS".as_ref(),
            evidence.as_os_str(),
        ])
        .output()
        .expect("report binary starts");

    assert!(
        !output.status.success(),
        "caller-provided selector/PASS rows must not produce a report"
    );
    assert!(!path.exists(), "rejected report must not be written");
    fs::remove_file(evidence).expect("forged evidence fixture cleanup");
}

#[test]
fn conformance_probe_requires_a_test_owned_structured_receipt() {
    let output = Command::new("just")
        .args([
            "conformance-probe",
            "workflow-runtime --test tool_contracts malformed_and_hostile_failure_data_fail_closed",
        ])
        .output()
        .expect("conformance probe starts");
    assert!(output.status.success(), "fixture contract test passes");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("M1_15_RECEIPT="),
        "a PASS row requires a test-owned machine-readable receipt"
    );
}

#[test]
fn conformance_probe_emits_structured_receipt() {
    let Ok(selector) = std::env::var("M1_15_PROBE_SELECTOR") else {
        return;
    };
    let (class, probe) = documented_failure_matrix()
        .iter()
        .find_map(|class| {
            class
                .probes()
                .iter()
                .find(|probe| probe.selector() == selector)
                .map(|probe| (class.class(), probe))
        })
        .expect("probe selector is documented");
    let output = Command::new("just")
        .args(["conformance-contract", &selector])
        .output()
        .expect("selected contract test starts");
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let test_name = selector
        .split_ascii_whitespace()
        .nth(3)
        .expect("documented selector names one exact test");
    let test_count = output_text.matches("running 1 test").count();
    assert!(output.status.success(), "selected contract test must pass");
    assert_eq!(
        test_count, 1,
        "selected contract test must run exactly once"
    );
    assert!(
        output_text
            .lines()
            .any(|line| line.starts_with(&format!("test {test_name} ... ok"))),
        "selected contract test must report its exact name"
    );
    println!(
        "M1_15_RECEIPT={}",
        serde_json::to_string(&json!({
            "probe": probe.name(),
            "failure_class": class,
            "asserted_fail_closed_outcome": probe.expected_fail_closed_assertion(),
            "selector": selector,
            "test_count": test_count,
            "exit_code": output.status.code().unwrap_or(-1),
            "result": "PASS",
        }))
        .expect("receipt serializes")
    );
}

fn unknown_tool_sandbox() -> RunSandbox {
    let root = std::env::temp_dir().join(format!(
        "workflow-m1-15-unknown-tool-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("fixture root exists");
    let context = RunContext::new(
        RunId::new("m1-15-unknown-tool".to_owned()).expect("fixture run ID"),
        RunLimits::new(
            std::num::NonZeroU64::new(1).unwrap(),
            std::num::NonZeroU64::new(1).unwrap(),
            std::num::NonZeroU64::new(1).unwrap(),
            std::num::NonZeroU64::new(1_000).unwrap(),
            std::num::NonZeroU64::new(1_000).unwrap(),
            std::num::NonZeroU64::new(1_000).unwrap(),
            std::num::NonZeroU64::new(1_000).unwrap(),
        ),
    );
    let workdir = WorkdirManager::new(root)
        .expect("fixture base is trusted")
        .allocate(context.run_id())
        .expect("fixture workdir allocates");
    RunSandbox::new(context, workdir, [SandboxCapability::FilesystemRead])
        .expect("fixture sandbox binds")
}

#[test]
fn unknown_tool_fails_closed_before_dispatch() {
    let bridge = ToolBridge::new(unknown_tool_sandbox());
    let authority = CapabilityIntersection::new(
        std::iter::empty::<SandboxCapability>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<SandboxCapability>(),
    );
    assert_eq!(
        bridge
            .preflight("not-registered", &json!({}), &authority)
            .expect_err("unknown tool must fail before dispatch")
            .kind(),
        ToolBridgeErrorKind::UnknownTool
    );
}
