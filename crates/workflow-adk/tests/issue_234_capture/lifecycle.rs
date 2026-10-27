use super::*;

#[tokio::test]
async fn trusted_reader_rejection_and_cancel_after_read_fail_closed() {
    for cancel_after in [false, true] {
        let fixture = CaptureFixture::new(vec![response(vec![thinking(REASONING), text(BATCH)])]);
        let mut reads = 0;
        assert!(
            fixture
                .host()
                .observe_with_reasoning_capture(|reader| {
                    assert_eq!(
                        reader.read(0, 4096.try_into().unwrap()).unwrap(),
                        REASONING.as_bytes()
                    );
                    reads += 1;
                    if cancel_after {
                        fixture.cancel.cancel();
                        ReasoningCaptureCompletion::Complete
                    } else {
                        ReasoningCaptureCompletion::Rejected
                    }
                })
                .await
                .is_err()
        );
        assert_eq!(reads, 1);
    }
}

struct StreamReleased(Arc<std::sync::atomic::AtomicBool>);
impl Drop for StreamReleased {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
struct PendingReasoning {
    admitted: Arc<tokio::sync::Notify>,
    released: Arc<std::sync::atomic::AtomicBool>,
    calls: AtomicUsize,
}
#[adk_rust::async_trait]
impl adk_rust::Llm for PendingReasoning {
    fn name(&self) -> &str {
        "pending-reasoning"
    }
    async fn generate_content(
        &self,
        _: adk_rust::LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let admitted = Arc::clone(&self.admitted);
        let owner = StreamReleased(Arc::clone(&self.released));
        Ok(Box::pin(adk_rust::futures::stream::unfold(
            (true, owner),
            move |(first, owner)| {
                let admitted = Arc::clone(&admitted);
                async move {
                    if first {
                        let mut chunk = response(vec![thinking(REASONING)]);
                        chunk.partial = true;
                        chunk.turn_complete = false;
                        chunk.finish_reason = None;
                        admitted.notify_one();
                        Some((Ok(chunk), (false, owner)))
                    } else {
                        let _owner = owner;
                        std::future::pending().await
                    }
                }
            },
        )))
    }
}

#[tokio::test]
async fn cancellation_during_partial_reasoning_drops_stream_without_reader() {
    let mut fixture = CaptureFixture::new(Vec::new());
    let model = Arc::new(PendingReasoning {
        admitted: Arc::new(tokio::sync::Notify::new()),
        released: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        calls: AtomicUsize::new(0),
    });
    let snapshot = snapshot(profile())
        .with_test_llm(
            ModelRouteCandidate::new(ModelRole::Worker, "probe", "1"),
            model.clone(),
        )
        .unwrap();
    fixture.route =
        ModelRoutePublisher::new(snapshot).policy(Instant::now() + Duration::from_secs(5));
    let mut called = false;
    {
        let mut operation = Box::pin(fixture.host().observe_with_reasoning_capture(|_| {
            called = true;
            ReasoningCaptureCompletion::Complete
        }));
        tokio::select! {
            admitted=timeout(Duration::from_secs(2),model.admitted.notified())=>{ admitted.expect("Thinking must be delivered before cancellation"); fixture.cancel.cancel(); },
            _=&mut operation=>panic!("partial reasoning must not complete the observation"),
        }
        assert!(operation.await.is_err());
    }
    assert!(!called);
    assert_eq!(model.calls.load(Ordering::SeqCst), 1);
    assert!(model.released.load(Ordering::SeqCst));
}
