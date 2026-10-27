//! Public fake SDK and real sealed worker exercise the production reduction.
use super::*;
use workflow_runtime::{SentinelVerdict, TypedPayload};

pub(super) fn evidence(
    bundle: &workflow_adk::behavioral::VerifiedTrajectoryBundle,
) -> &workflow_runtime::SentinelEvidence {
    let reduced = bundle
        .reduction()
        .expect("successful actual model monitor must establish a source-bound reduction");
    assert!(reduced.output().to_json().unwrap().len() <= 512);
    let TypedPayload::Sentinel(value) = reduced.output().payload() else {
        panic!("Sentinel output required")
    };
    assert_eq!(value.verdict(), SentinelVerdict::Suspicious);
    assert!(value.spans().is_empty());
    value
}

#[tokio::test]
async fn actual_model_hard_and_weak_reach_shared_reducer() {
    for (hard, weak) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut fixture =
            CaptureFixture::new(vec![response(vec![text(if hard { HARD } else { PREFIX })])]);
        let flags = if weak {
            SIGNALS.to_owned()
        } else {
            SIGNALS.replace("true", "false")
        };
        let inner = observer(vec![response(vec![text(&flags)])]);
        let route = observer_route(inner.clone(), fixture.route.deadline());
        attach(&mut fixture, &route);
        let mut result = fixture
            .host()
            .observe_trajectory(Some(&route))
            .await
            .unwrap();
        assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 1);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        let refs = evidence(&result.verified).artifacts();
        if hard {
            assert_eq!(refs.len(), 1);
            assert_eq!(refs[0].sha256(), result.verified.projection.report_digest());
        } else if weak {
            assert_eq!(refs.len(), 1);
            assert_ne!(refs[0].sha256(), result.verified.projection.report_digest());
        } else {
            assert!(
                refs.is_empty(),
                "all-false is abstention, never negative evidence"
            );
        }
        let before = result
            .verified
            .reduction()
            .unwrap()
            .output()
            .to_json()
            .unwrap();
        let identity = result.verified.reduction().unwrap().identity().to_owned();
        result.verified.identity = "public-mutation-is-not-authority".into();
        result.verified.claims = None;
        result.verified.deterministic_weak_signals.clear();
        result.weak_signals.clear();
        assert_eq!(
            result
                .verified
                .reduction()
                .unwrap()
                .output()
                .to_json()
                .unwrap(),
            before
        );
        assert_eq!(result.verified.reduction().unwrap().identity(), identity);
    }
}

#[tokio::test]
async fn genuine_worker_binding_rejects_foreign_context_and_projection() {
    use workflow_runtime::behavioral::worker::trajectory::ModelTrajectoryBinding;
    let mut fixture = CaptureFixture::new(vec![response(vec![text(HARD)])]);
    let inner = observer(vec![response(vec![text(SIGNALS)])]);
    let route = observer_route(inner, fixture.route.deadline());
    attach(&mut fixture, &route);
    let mut result = fixture
        .host()
        .observe_trajectory(Some(&route))
        .await
        .unwrap();
    let mut other = CaptureFixture::new(vec![response(vec![text(PREFIX)])]);
    attach(&mut other, &route);
    let mut foreign = other.host().observe_trajectory(Some(&route)).await.unwrap();
    let worker_digest = worker().deployment_digest().to_owned();
    let ir_hash = format!(
        "sha256:{}",
        fixture
            .plan
            .ir()
            .canonical_hash()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let declaration = fixture
        .route
        .snapshot()
        .probe_reasoning_capture_declaration_digest()
        .unwrap();
    let different = format!("sha256:{}", "0".repeat(64));
    let wrong_source = workflow_runtime::ArtifactId::parse("0".repeat(64)).unwrap();
    let wrong_run = WorkdirManager::new(&other.fixture.base)
        .unwrap()
        .materialize(
            &RunId::new("different-reduction-run".to_owned()).unwrap(),
            &Materialization::default(),
        )
        .unwrap();
    assert_ne!(
        wrong_run.run_id(),
        fixture.fixture.workdir.run_id(),
        "negative run fixture must be genuinely foreign"
    );
    let (_, wrong_approval) = semantic_approval(
        &declaration,
        &route
            .snapshot()
            .trajectory_observer_declaration_digest()
            .unwrap(),
        "Different authenticated task",
    )
    .unwrap();
    for mismatch in 0..8 {
        let binding = ModelTrajectoryBinding {
            source: if mismatch == 0 {
                &wrong_source
            } else {
                fixture.source.original_id()
            },
            worker_digest: if mismatch == 1 {
                &different
            } else {
                &worker_digest
            },
            ir_hash: if mismatch == 2 { &different } else { &ir_hash },
            declaration_digest: if mismatch == 3 {
                &different
            } else {
                &declaration
            },
        };
        let report = if mismatch == 7 {
            &foreign.verified.report
        } else {
            &result.verified.report
        };
        let bound = report.bind_trajectory(
            if mismatch == 4 {
                &wrong_approval
            } else {
                &fixture.approval
            },
            if mismatch == 5 {
                &wrong_run
            } else {
                &fixture.fixture.workdir
            },
            if mismatch == 6 {
                &foreign.verified.projection
            } else {
                &result.verified.projection
            },
            binding,
        );
        assert!(
            bound.is_err(),
            "foreign binding {mismatch} cannot become model evidence"
        );
    }
    let facts = result
        .verified
        .report
        .bind_trajectory(
            &fixture.approval,
            &fixture.fixture.workdir,
            &result.verified.projection,
            ModelTrajectoryBinding {
                source: fixture.source.original_id(),
                worker_digest: &worker_digest,
                ir_hash: &ir_hash,
                declaration_digest: &declaration,
            },
        )
        .unwrap();
    assert!(workflow_runtime::reduce_model_trajectory(&facts, &[], "forged-observer").is_err());
    let original = workflow_runtime::reduce_model_trajectory(&facts, &[], &declaration).unwrap();
    let drift = workflow_runtime::reduce_model_trajectory(&facts, &[], &different).unwrap();
    assert_ne!(
        original.identity(),
        drift.identity(),
        "ordinary observer provenance changes evidence identity, never authority"
    );
    assert_eq!(
        original.output().to_json().unwrap(),
        drift.output().to_json().unwrap(),
        "observer cannot erase hard facts"
    );
    assert_eq!(
        original.policy_version(),
        workflow_runtime::SENTINEL_REDUCTION_POLICY_VERSION
    );
    assert_ne!(
        result.verified.reduction().unwrap().identity(),
        foreign.verified.reduction().unwrap().identity()
    );
    let computed_identity = result.verified.reduction().unwrap().identity().to_owned();
    let computed_output = result
        .verified
        .reduction()
        .unwrap()
        .output()
        .to_json()
        .unwrap();
    std::mem::swap(&mut result.verified.report, &mut foreign.verified.report);
    std::mem::swap(
        &mut result.verified.projection,
        &mut foreign.verified.projection,
    );
    assert_ne!(
        result.verified.projection.report_digest(),
        evidence(&result.verified).artifacts()[0].sha256(),
        "replacing public report/projection cannot re-admit a foreign producer"
    );
    assert_eq!(
        result.verified.reduction().unwrap().identity(),
        computed_identity
    );
    assert_eq!(
        result
            .verified
            .reduction()
            .unwrap()
            .output()
            .to_json()
            .unwrap(),
        computed_output
    );
}
