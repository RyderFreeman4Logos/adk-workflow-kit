//! The production backend's explicit host-only route, not a translator shortcut.
use super::{
    BEHAVIORAL, RAW, WORKFLOW, approval, behavioral_oracles, deadline, store, uncancelled,
};
use serde_json::json;
use workflow_adk::execution::ExecutionBackend;
use workflow_runtime::{
    ArtifactId, ArtifactStore, PageRequest, WorkflowRuntimeEventKindV1 as Kind,
    behavioral::ProbeStop,
};

// Every host-storage entrance is forbidden until admission succeeds.
struct NoStore;
impl ArtifactStore for NoStore {
    fn stage(
        &mut self,
        _: &[u8],
    ) -> Result<workflow_runtime::StagedArtifact, workflow_runtime::ArtifactError> {
        panic!("storage before admission")
    }
    fn commit(
        &mut self,
        _: workflow_runtime::StagedArtifact,
    ) -> Result<ArtifactId, workflow_runtime::ArtifactError> {
        panic!("commit before admission")
    }
    fn read_page(
        &self,
        _: &ArtifactId,
        _: PageRequest,
    ) -> Result<workflow_runtime::ArtifactPage, workflow_runtime::ArtifactError> {
        panic!("read before admission")
    }
    fn set_retention(
        &mut self,
        _: &ArtifactId,
        _: workflow_runtime::RetentionPolicy,
    ) -> Result<(), workflow_runtime::ArtifactError> {
        panic!("retention before admission")
    }
    fn retention(
        &self,
        _: &ArtifactId,
    ) -> Result<workflow_runtime::RetentionPolicy, workflow_runtime::ArtifactError> {
        panic!("retention read before admission")
    }
}

struct Root(std::path::PathBuf);
impl Root {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "behavioral-backend-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("runs")).unwrap();
        Self(root)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn backend_default_profile_and_implementation_entries_still_deny_before_adapters() {
    use workflow_adk::execution::{ExecutionErrorKind, ExecutionProfileV1};
    let root = Root::new();
    let path = root.0.join("workflow.toml");
    std::fs::write(&path, format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    let profile = json!({"schema_version":1,"model":{"provider":"fake","name":"fake","version":"1","model":"fake","responses":["unused"]},"sandbox":{"capabilities":[]}});
    for key in ["trusted_script", "behavioral", "approval", "credential"] {
        let mut forged = profile.clone();
        forged[key] = json!({"authorized":true});
        assert!(ExecutionProfileV1::parse(&serde_json::to_vec(&forged).unwrap()).is_err());
    }
    for entry in ["run", "cancellable", "implementations"] {
        let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&profile).unwrap()).unwrap();
        ExecutionBackend::take_adapter_counts_for_tests();
        let input = json!({"schema_version":1,"bytes":RAW});
        let result = match entry {
            "run" => ExecutionBackend::run(&path, profile, input, root.0.join("runs")),
            "cancellable" => ExecutionBackend::run_cancellable(
                &path,
                profile,
                input,
                root.0.join("runs"),
                uncancelled(),
            ),
            _ => ExecutionBackend::run_with_implementations(
                &path,
                profile,
                input,
                root.0.join("runs"),
                &workflow_runtime::ToolImplementationRegistry::new(),
            ),
        };
        assert_eq!(
            result.unwrap_err().kind(),
            ExecutionErrorKind::Compile,
            "{entry}"
        );
        assert_eq!(
            ExecutionBackend::take_adapter_counts_for_tests(),
            (0, 0),
            "{entry}"
        );
        assert_eq!(std::fs::read_dir(root.0.join("runs")).unwrap().count(), 0);
    }
    // A real ordinary-preparation run proves both adapter-entry counters are live.
    std::fs::write(&path, WORKFLOW).unwrap();
    let profile = ExecutionProfileV1::parse(&serde_json::to_vec(&profile).unwrap()).unwrap();
    ExecutionBackend::run(
        &path,
        profile,
        json!({"schema_version":1,"bytes":RAW}),
        root.0.join("runs"),
    )
    .unwrap();
    let (models, tools) = ExecutionBackend::take_adapter_counts_for_tests();
    assert!(
        models > 0 && tools > 0,
        "ordinary backend constructs both adapter kinds"
    );
}

#[test]
fn backend_admission_rejects_wrong_source_ir_and_forged_controls_without_storage() {
    for case in [
        "source",
        "ir",
        "not-opted",
        "limits",
        "resume_from",
        "checkpoint",
        "profile",
        "credential",
        "trusted_script",
        "cancelled",
        "expired",
    ] {
        let text = format!("{WORKFLOW}{BEHAVIORAL}");
        let approved = workflow_spec::parse_str("host.toml", &text).unwrap();
        let changed = match case {
            "ir" => text.replace("sentinel-preparation", "other-workflow"),
            "not-opted" => WORKFLOW.to_owned(),
            "limits" => text.replace("max_steps = 8", "max_steps = 7"),
            _ => text,
        };
        let spec = workflow_spec::parse_str("host.toml", &changed).unwrap();
        let script = approval(
            &approved,
            RAW,
            "revision-1",
            json!([{"kind":"call","tool":"complete","arguments":{}}]),
        );
        let supplied = if case == "source" {
            b"wrong".as_slice()
        } else {
            RAW
        };
        let mut input = json!({"schema_version":1,"bytes":supplied});
        if matches!(
            case,
            "resume_from" | "checkpoint" | "profile" | "credential" | "trusted_script"
        ) {
            input[case] = json!({"authorized":true});
        }
        let cancel = uncancelled();
        if case == "cancelled" {
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let end = if case == "expired" {
            std::time::Instant::now()
        } else {
            deadline()
        };
        let mut artifacts = NoStore;
        ExecutionBackend::take_adapter_counts_for_tests();
        let result = ExecutionBackend::run_with_sentinel_script(
            &spec,
            script,
            input,
            &mut artifacts,
            cancel,
            end,
        );
        assert!(result.is_err(), "{case}");
        assert_eq!(
            ExecutionBackend::take_adapter_counts_for_tests(),
            (0, 0),
            "{case}"
        );
    }
}

#[test]
fn backend_report_failure_and_cooperative_stops_never_return_stale_success() {
    let spec = workflow_spec::parse_str("host.toml", &format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    for case in [
        "retention",
        "cancel-in-preparation",
        "expire-in-preparation",
        "crash",
        "tripwire",
        "fresh",
    ] {
        let cancelled = uncancelled();
        let mut artifacts = super::ControlledStore {
            inner: store(),
            cancel: (case == "cancel-in-preparation").then(|| cancelled.clone()),
            fail_report: case == "retention",
            fail_trajectory: false,
            expire: case == "expire-in-preparation",
            report_attempts: 0,
        };
        let steps = match case {
            "crash" => json!([{"kind":"crash"}, {"kind":"call","tool":"complete","arguments":{}}]),
            "tripwire" => {
                json!([{"kind":"call","tool":"host_command","arguments":{"command":"never execute"}}])
            }
            _ => json!([{"kind":"call","tool":"complete","arguments":{}}]),
        };
        let result = ExecutionBackend::run_with_sentinel_script(
            &spec,
            approval(&spec, RAW, "revision-1", steps.clone()),
            json!({"schema_version":1,"bytes":RAW}),
            &mut artifacts,
            cancelled,
            deadline(),
        );
        if case == "retention" {
            assert!(result.is_err(), "{case}");
            assert_eq!(artifacts.report_attempts, 1);
        } else {
            let result = result.unwrap();
            if matches!(case, "cancel-in-preparation" | "expire-in-preparation") {
                assert!(result.report.events().is_empty());
                assert!(result.report.evidence().unwrap().is_none());
            } else {
                let expected = behavioral_oracles::expected_report(steps, result.run_id.as_str());
                behavioral_oracles::owned_report(
                    &expected,
                    &result.report,
                    &result.observer,
                    &artifacts,
                );
            }
            behavioral_oracles::no_model(&result.observer);
            assert_eq!(artifacts.report_attempts, 1);
            assert_eq!(
                result.report.stop(),
                match case {
                    "cancel-in-preparation" => ProbeStop::Cancelled,
                    "expire-in-preparation" => ProbeStop::TimedOut,
                    "crash" => ProbeStop::ScriptedCrash,
                    "tripwire" =>
                        ProbeStop::Tripwire(workflow_runtime::behavioral::ProbeSignal::HostCommand),
                    _ => ProbeStop::NoCompromiseObserved,
                }
            );
        }
    }
}

#[test]
fn backend_executes_and_retains_the_exact_host_bound_report() {
    let spec = workflow_spec::parse_str("host.toml", &format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    let steps = json!([
        {"kind":"call","tool":"read_document","arguments":{"path":"workspace/report.txt"}},
        {"kind":"call","tool":"complete","arguments":{}},
        {"kind":"crash"}
    ]);
    let mut artifacts = store();
    ExecutionBackend::take_adapter_counts_for_tests();
    let result = ExecutionBackend::run_with_sentinel_script(
        &spec,
        approval(&spec, RAW, "revision-1", steps.clone()),
        json!({"schema_version":1,"bytes":RAW}),
        &mut artifacts,
        uncancelled(),
        deadline(),
    )
    .expect("public production backend executes host-authorized inert trajectory");
    assert_eq!(ExecutionBackend::take_adapter_counts_for_tests(), (0, 0));
    let root = Root::new();
    assert!(ExecutionBackend::resume(root.0.join("runs"), result.run_id.as_str()).is_err());
    assert_eq!(std::fs::read_dir(root.0.join("runs")).unwrap().count(), 0);
    let expected = behavioral_oracles::expected_report(steps, result.run_id.as_str());
    behavioral_oracles::owned_report(&expected, &result.report, &result.observer, &artifacts);
    behavioral_oracles::no_model(&result.observer);
    assert_eq!(result.report.stop(), ProbeStop::NoCompromiseObserved);
    assert_eq!(result.report.events().len(), 2);
    assert!(result.report.evidence().unwrap().is_none());
    assert!(
        result
            .observer
            .events()
            .iter()
            .all(|event| event.run_id() == result.run_id.as_str())
    );
    assert_eq!(
        result
            .observer
            .events()
            .iter()
            .filter(|event| event.kind() == Kind::WorkflowCompleted)
            .count(),
        1
    );
    use sha2::{Digest, Sha256};
    let id = ArtifactId::parse(format!("{:x}", Sha256::digest(RAW))).unwrap();
    assert_eq!(
        artifacts
            .read_page(&id, PageRequest::new(0, 100_000.try_into().unwrap()))
            .unwrap()
            .bytes(),
        RAW
    );
}
