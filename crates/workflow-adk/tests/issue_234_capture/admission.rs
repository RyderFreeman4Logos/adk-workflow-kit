use super::*;

#[tokio::test]
async fn strict_default_and_ordinary_entry_do_not_enable_capture() {
    let mut fixture = CaptureFixture::new(vec![response(vec![thinking(REASONING), text(BATCH)])]);
    assert!(fixture.host().observe().await.is_err());
    assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 0);
    (fixture.plan, fixture.approval) =
        approved(&fixture.route.snapshot().probe_declaration_digest().unwrap());
    let mut called = false;
    assert!(
        fixture
            .host()
            .observe_with_reasoning_capture(|_| {
                called = true;
                ReasoningCaptureCompletion::Complete
            })
            .await
            .is_err()
    );
    assert!(!called);
    assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 0);
    assert!(fixture.host().observe().await.is_err());
    assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn live_source_route_approval_cancellation_mismatch_denies_before_model() {
    for mismatch in 0..4 {
        let mut fixture =
            CaptureFixture::new(vec![response(vec![thinking(REASONING), text(BATCH)])]);
        match mismatch {
            0 => fixture.source = prepared(b"different source", Instant::now()),
            1 => {
                fixture.approval =
                    approved(&fixture.route.snapshot().probe_declaration_digest().unwrap()).1;
            }
            2 => {
                fixture.route = ModelRoutePublisher::new(snapshot(
                    profile().with_provider("different-provider"),
                ))
                .policy(Instant::now() + Duration::from_secs(5))
            }
            _ => fixture.cancel.cancel(),
        }
        let mut called = false;
        assert!(
            fixture
                .host()
                .observe_with_reasoning_capture(|_| {
                    called = true;
                    ReasoningCaptureCompletion::Complete
                })
                .await
                .is_err()
        );
        assert!(!called);
        assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn mismatched_capture_declaration_denies_before_secret_resolution() {
    let mut fixture = CaptureFixture::new(vec![response(vec![thinking(REASONING), text(BATCH)])]);
    let secrets = Arc::new(Secrets(AtomicUsize::new(0)));
    fixture.broker = CredentialBroker::new().with_secret_provider(secrets.clone());
    let mut registry = ModelProfileRegistry::new();
    registry
        .register(OpenAiCompatibleProfile::new(
            "probe",
            "1",
            "model",
            "http://127.0.0.1:9/v1",
            CredentialHandle::secret_provider("capture-test"),
        ))
        .unwrap();
    let candidate = ModelRouteCandidate::new(ModelRole::Worker, "probe", "1");
    fixture.route = ModelRoutePublisher::new(
        ModelRouteSnapshot::new(
            registry,
            [candidate.clone()],
            ModelRouteAuthorization::new([candidate]),
        )
        .unwrap(),
    )
    .policy(Instant::now() + Duration::from_secs(5));
    assert!(
        fixture
            .host()
            .observe_with_reasoning_capture(|_| panic!("unauthorized reader"))
            .await
            .is_err()
    );
    assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 0);
    assert_eq!(secrets.0.load(Ordering::SeqCst), 0);
}
