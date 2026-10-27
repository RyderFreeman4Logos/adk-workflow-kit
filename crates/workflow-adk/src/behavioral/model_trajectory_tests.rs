//! Exact post-verification ownership control; no production timing hook.
use super::*;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::DirBuilderExt, path::Path};
use workflow_runtime::behavioral::{ProbeLimits, TrustedModelProbe, worker::SealedProbeWorker};
use workflow_runtime::{ContentObject, Materialization, RunId, TrustPolicy, WorkdirManager};

fn verified_fixture(label: &str) -> VerifiedTrajectoryBundle {
    let base =
        std::env::temp_dir().join(format!("trajectory-settle-{}-{label}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let _cleanup = Cleanup(base.clone());
    let workdir = WorkdirManager::new(&base)
        .unwrap()
        .materialize(
            &RunId::new("settlement".into()).unwrap(),
            &Materialization::default(),
        )
        .unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let bytes = fs::read(root.join("target/debug/sentinel-probe-worker.fixture")).unwrap();
    let stamp =
        fs::read_to_string(root.join("target/debug/sentinel-probe-worker.fixture.sha256")).unwrap();
    let expected = format!("sha256:{}", stamp.split_whitespace().next().unwrap());
    assert_eq!(expected, format!("sha256:{:x}", Sha256::digest(&bytes)));
    let worker = SealedProbeWorker::authorize(&bytes, &expected).unwrap();
    let provenance = TrustPolicy::new("settlement", ["trusted"])
        .unwrap()
        .classify(ContentObject::Comment {
            object_id: "fixture",
            author: "untrusted",
        })
        .unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let approval = TrustedModelProbe::authorize(
        &digest,
        workflow_runtime::ArtifactId::parse("a".repeat(64)).unwrap(),
        provenance,
        "fixture",
        &digest,
        ProbeLimits {
            max_steps: 8,
            timeout_ms: 1000,
        },
    )
    .unwrap();
    let observed=worker.observe_batch_with_trajectory(&approval,&workdir,br#"{"schema_version":1,"steps":[{"kind":"call","tool":"host_command","arguments":{}}]}"#).unwrap();
    let facts = observed
        .report
        .bind_trajectory(
            &approval,
            &workdir,
            &observed.projection,
            workflow_runtime::behavioral::worker::trajectory::ModelTrajectoryBinding {
                source: &workflow_runtime::ArtifactId::parse("a".repeat(64)).unwrap(),
                worker_digest: &expected,
                ir_hash: &digest,
                declaration_digest: &digest,
            },
        )
        .unwrap();
    let mut bundle = VerifiedTrajectoryBundle {
        reduction: None,
        reduction_facts: Some(facts),
        producer_identity: digest,
        report: observed.report,
        projection: observed.projection,
        identity: "sealed-identity".into(),
        raw_visibility: ReasoningStatus::Present,
        claims_status: ReasoningStatus::Unavailable,
        claims: None,
        deterministic_weak_signals: vec![],
    };
    bundle.reduction = Some(bundle.reduce(&[], None).unwrap());
    bundle
}

#[test]
fn owned_bundle_survives_post_verification_cancel_and_expiry() {
    for expired in [false, true] {
        let mut verified = verified_fixture(&format!("settlement-{expired}"));
        let report = verified.report.to_json().unwrap();
        let feature = serde_json::to_string(&verified.projection).unwrap();
        verified.claims_status = ReasoningStatus::Malformed;
        verified.deterministic_weak_signals = vec![WeakSignal::ToolManipulation];
        // Equality completes before either cancellation or expiry is introduced.
        let cancellation = crate::ModelRouteCancellation::new();
        let deadline = if expired {
            Instant::now()
        } else {
            cancellation.cancel();
            Instant::now() + std::time::Duration::from_secs(1)
        };
        let failure = match settle_verified(
            verified,
            RoleMetadata::not_started(),
            deadline,
            &cancellation,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("settlement must preserve failure"),
        };
        assert_eq!(
            failure.kind,
            if expired {
                TrajectoryMonitorErrorKind::Deadline
            } else {
                TrajectoryMonitorErrorKind::Cancelled
            }
        );
        assert_eq!(failure.observer.phase, RolePhase::NotStarted);
        let bundle = failure.verified.unwrap();
        assert_eq!(bundle.report.to_json().unwrap(), report);
        assert_eq!(serde_json::to_string(&bundle.projection).unwrap(), feature);
        assert_eq!(bundle.identity, "sealed-identity");
        assert_eq!(bundle.claims_status, ReasoningStatus::Malformed);
        assert_eq!(
            bundle.deterministic_weak_signals,
            [WeakSignal::ToolManipulation]
        );
    }
}

#[test]
fn actual_claims_adapter_preserves_completed_facts_on_late_cancel_and_expiry() {
    let valid = br#"{"schema_version":1,"goal_override":true,"secret_seeking":false,"tool_manipulation":false,"claims_no_tools":true}"#;
    let mut observations = Vec::new();
    for malformed in [false, true] {
        for expired in [false, true] {
            let verified = verified_fixture(&format!("parse-{malformed}-{expired}"));
            let report = verified.report.to_json().unwrap();
            let feature = serde_json::to_string(&verified.projection).unwrap();
            let cancellation = crate::ModelRouteCancellation::new();
            let deadline = Instant::now() + std::time::Duration::from_millis(100);
            let mut parsed = false;
            let read = crate::behavioral::reasoning_capture::read_closed_claims_after_parse(
                if malformed {
                    b"[1,true]".to_vec()
                } else {
                    valid.to_vec()
                },
                verified.identity.clone(),
                deadline,
                &cancellation,
                || {
                    parsed = true;
                    if expired {
                        std::thread::sleep(
                            deadline.saturating_duration_since(Instant::now())
                                + std::time::Duration::from_millis(1),
                        );
                    } else {
                        cancellation.cancel();
                    }
                },
            );
            assert!(parsed, "control must occur after actual parsing");
            assert!(read.disposition.is_err(), "late denial must still fail");
            // Synthetic role metadata tests exact carrier preservation; public
            // ADK fake tests separately establish the actual completed-role facts.
            let usage = crate::ProviderTokenUsage::from_provider_usage(&serde_json::json!({"prompt_tokens":0,"completion_tokens":7,"completion_tokens_details":{"reasoning_tokens":0}})).unwrap();
            let probe = RoleMetadata {
                phase: RolePhase::Completed,
                provenance: None,
                usage: Some(usage.clone()),
                elapsed_ns: Some(19),
            };
            let failure = match settle_claims_read(verified, probe, read, deadline, &cancellation) {
                Err(failure) => failure,
                Ok(_) => panic!("late claims denial must remain failure"),
            };
            assert_eq!(
                failure.kind,
                if expired {
                    TrajectoryMonitorErrorKind::Deadline
                } else {
                    TrajectoryMonitorErrorKind::Cancelled
                }
            );
            assert_eq!(failure.probe.phase, RolePhase::Completed);
            assert_eq!(failure.probe.usage, Some(usage));
            assert_eq!(failure.probe.elapsed_ns, Some(19));
            assert!(failure.probe.provenance.is_none());
            assert_eq!(failure.observer.phase, RolePhase::NotStarted);
            assert!(failure.observer.usage.is_none());
            let bundle = failure.verified.unwrap();
            assert_eq!(bundle.report.to_json().unwrap(), report);
            assert_eq!(serde_json::to_string(&bundle.projection).unwrap(), feature);
            assert_eq!(bundle.raw_visibility, ReasoningStatus::Present);
            observations.push((
                malformed,
                bundle.claims_status,
                bundle.claims.is_some(),
                bundle.deterministic_weak_signals,
            ));
        }
    }
    assert_eq!(
        observations,
        [
            (
                false,
                ReasoningStatus::Present,
                true,
                vec![
                    WeakSignal::GoalOverride,
                    WeakSignal::ReasoningActionInconsistency
                ]
            ),
            (
                false,
                ReasoningStatus::Present,
                true,
                vec![
                    WeakSignal::GoalOverride,
                    WeakSignal::ReasoningActionInconsistency
                ]
            ),
            (true, ReasoningStatus::Malformed, false, vec![]),
            (true, ReasoningStatus::Malformed, false, vec![]),
        ]
    );
}

#[test]
fn claims_adapter_before_read_denial_has_no_completed_facts() {
    for expired in [false, true] {
        let verified = verified_fixture(&format!("before-read-{expired}"));
        let cancellation = crate::ModelRouteCancellation::new();
        let deadline = if expired {
            Instant::now()
        } else {
            cancellation.cancel();
            Instant::now() + std::time::Duration::from_secs(1)
        };
        let mut called = false;
        let read = crate::behavioral::reasoning_capture::read_closed_claims_after_parse(
            b"{}".to_vec(),
            verified.identity.clone(),
            deadline,
            &cancellation,
            || {
                called = true;
            },
        );
        assert!(!called);
        assert!(read.parsed.is_none());
        let failure = match settle_claims_read(
            verified,
            RoleMetadata::not_started(),
            read,
            deadline,
            &cancellation,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("before-read denial"),
        };
        let bundle = failure.verified.unwrap();
        assert_eq!(bundle.claims_status, ReasoningStatus::Unavailable);
        assert!(bundle.claims.is_none());
        assert!(bundle.deterministic_weak_signals.is_empty());
        assert_eq!(bundle.identity, "sealed-identity");
    }
}
