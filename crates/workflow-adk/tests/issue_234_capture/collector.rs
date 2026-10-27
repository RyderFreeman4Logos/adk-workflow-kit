use super::*;

#[tokio::test]
async fn capture_failure_matrix_never_calls_reader_or_retries() {
    let mut partial = response(vec![thinking(REASONING), text(BATCH)]);
    partial.partial = true;
    let mut unfinished = partial.clone();
    unfinished.partial = false;
    unfinished.turn_complete = false;
    unfinished.finish_reason = None;
    let mut interrupted = response(vec![thinking(REASONING), text(BATCH)]);
    interrupted.interrupted = true;
    let mut first = response(vec![thinking(&"a".repeat(8192))]);
    first.partial = true;
    first.turn_complete = false;
    first.finish_reason = None;
    for responses in [
        vec![partial],
        vec![unfinished],
        vec![interrupted],
        vec![response(vec![thinking(REASONING), text("{")])],
        vec![response(vec![
            thinking(REASONING),
            text(
                r#"{"schema_version":1,"steps":[{"kind":"call","tool":"complete","arguments":{"invalid":7}}]}"#,
            ),
        ])],
        vec![response(vec![
            thinking(&"a".repeat(8192)),
            thinking(&"b".repeat(8193)),
            text(BATCH),
        ])],
        vec![
            first,
            response(vec![thinking(&"b".repeat(8193)), text(BATCH)]),
        ],
    ] {
        let fixture = CaptureFixture::new(responses);
        let mut called = false;
        let result = fixture
            .host()
            .observe_with_reasoning_capture(|_| {
                called = true;
                ReasoningCaptureCompletion::Complete
            })
            .await;
        assert!(result.is_err());
        assert!(!called);
        assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 1);
        let error = result.err().unwrap();
        assert!(!format!("{error:?}:{error}").contains(REASONING));
    }
}

#[tokio::test]
async fn every_other_nontext_part_is_rejected_even_with_capture() {
    use adk_rust::Part;
    let parts = vec![
        Part::InlineData {
            mime_type: "text/plain".into(),
            data: REASONING.as_bytes().to_vec(),
            uri: None,
            annotations: None,
        },
        Part::FileData {
            mime_type: "text/plain".into(),
            file_uri: "file:///private".into(),
            annotations: None,
        },
        Part::FunctionCall {
            name: "complete".into(),
            args: json!({}),
            id: None,
            thought_signature: None,
        },
        serde_json::from_value(json!({"functionResponse":{"name":"complete","response":{}}}))
            .unwrap(),
        Part::ServerToolCall {
            server_tool_call: json!({"private": REASONING}),
        },
        Part::ServerToolResponse {
            server_tool_response: json!({"private": REASONING}),
        },
        serde_json::from_value(json!({"resource":{"uri":"file:///private","text":REASONING}}))
            .unwrap(),
    ];
    for part in parts {
        let fixture =
            CaptureFixture::new(vec![response(vec![thinking(REASONING), part, text(BATCH)])]);
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
        assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn absent_reasoning_and_signature_only_remain_unavailable() {
    for parts in [vec![text(BATCH)], vec![thinking(""), text(BATCH)]] {
        let fixture = CaptureFixture::new(vec![response(parts)]);
        let mut reads = 0;
        let observation = fixture
            .host()
            .observe_with_reasoning_capture(|reader| {
                assert_eq!(
                    reader.status(),
                    workflow_runtime::behavioral::trajectory::ReasoningStatus::Unavailable
                );
                assert_eq!(
                    reader.read(0, 1.try_into().unwrap()),
                    Err(workflow_adk::behavioral::ReasoningReadError::Unavailable)
                );
                reads += 1;
                ReasoningCaptureCompletion::Complete
            })
            .await
            .unwrap();
        assert_eq!(reads, 1);
        assert_eq!(observation.report.event_count(), 1);
        assert!(observation.usage.is_none());
        assert!(!observation.report.to_json().unwrap().contains(REASONING));
    }
}

#[tokio::test]
async fn aggregate_exact_cap_across_chunks_is_available_in_bounded_pages() {
    let mut first = response(vec![thinking(&"a".repeat(8192))]);
    first.partial = true;
    first.turn_complete = false;
    first.finish_reason = None;
    let fixture = CaptureFixture::new(vec![
        first,
        response(vec![thinking(&"b".repeat(8192)), text(BATCH)]),
    ]);
    fixture
        .host()
        .observe_with_reasoning_capture(|reader| {
            for (offset, byte) in [(0, b'a'), (4096, b'a'), (8192, b'b'), (12288, b'b')] {
                assert_eq!(
                    reader.read(offset, 4096.try_into().unwrap()).unwrap(),
                    vec![byte; 4096]
                );
            }
            assert_eq!(reader.read(16384, 4096.try_into().unwrap()).unwrap(), b"");
            ReasoningCaptureCompletion::Complete
        })
        .await
        .unwrap();
    assert_eq!(fixture.llm.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn capture_preserves_latest_usage_and_unknown_versus_zero() {
    for known_zero in [true, false] {
        let mut completed = response(vec![thinking(REASONING), text(BATCH)]);
        completed.usage_metadata = Some(Default::default());
        completed.usage_metadata.as_mut().unwrap().provider_usage =
            Some(json!({"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}));
        let mut latest = adk_rust::LlmResponse {
            usage_metadata: Some(Default::default()),
            ..Default::default()
        };
        latest.usage_metadata.as_mut().unwrap().provider_usage = Some(if known_zero {
            json!({"prompt_tokens":0,"completion_tokens":0,"total_tokens":0,"completion_tokens_details":{"reasoning_tokens":0}})
        } else {
            json!({"completion_tokens":9})
        });
        let empty = adk_rust::LlmResponse::default();
        let fixture = CaptureFixture::new(vec![completed, latest, empty]);
        let observation = fixture
            .host()
            .observe_with_reasoning_capture(|reader| {
                assert_eq!(
                    reader.read(0, 4096.try_into().unwrap()).unwrap(),
                    REASONING.as_bytes()
                );
                ReasoningCaptureCompletion::Complete
            })
            .await
            .unwrap();
        let usage = observation.usage.unwrap();
        assert_eq!(
            usage.input_tokens(),
            if known_zero { Some(0) } else { None }
        );
        assert_eq!(usage.output_tokens(), Some(if known_zero { 0 } else { 9 }));
        assert_eq!(
            usage.reasoning_tokens(),
            if known_zero { Some(0) } else { None }
        );
        assert!(!observation.report.to_json().unwrap().contains(REASONING));
        assert!(!format!("{:?}", observation.provenance).contains(REASONING));
    }
}

#[tokio::test]
async fn unknown_tool_stays_a_hard_observation_even_when_reasoning_is_present() {
    let fixture = CaptureFixture::new(vec![response(vec![
        thinking(REASONING),
        text(
            r#"{"schema_version":1,"steps":[{"kind":"call","tool":"not-in-catalog","arguments":{}}]}"#,
        ),
    ])]);
    let observation = fixture
        .host()
        .observe_with_reasoning_capture(|reader| {
            assert_eq!(
                reader.read(0, 4096.try_into().unwrap()).unwrap(),
                REASONING.as_bytes()
            );
            ReasoningCaptureCompletion::Complete
        })
        .await
        .unwrap();
    assert_eq!(
        observation.report.stop(),
        workflow_runtime::behavioral::ProbeStop::Tripwire(
            workflow_runtime::behavioral::ProbeSignal::UnknownTool
        )
    );
    assert!(!observation.report.to_json().unwrap().contains(REASONING));
}
