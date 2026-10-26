//! First observed private failure is diagnostic evidence, never aggregate accounting.
use super::*;

#[tokio::test]
async fn private_failure_preserves_closed_classes_without_payloads_or_retry() {
    for (mode, count, kind, model_error, output_error, status) in [
        (Mode::Fail, 2, "model_profile", Some("provider"), None, None),
        (
            Mode::FailStatus,
            2,
            "model_profile",
            Some("retryable_provider"),
            None,
            Some(429),
        ),
        (
            Mode::Oversize,
            2,
            "structured_output",
            None,
            Some("output_too_large"),
            None,
        ),
        (
            Mode::TaskMalformed,
            3,
            "structured_output",
            None,
            Some("invalid_json"),
            None,
        ),
        (
            Mode::TaskForeign,
            3,
            "structured_output",
            None,
            Some("schema_violation"),
            None,
        ),
    ] {
        let (graph, probe, mut store, mut mapper) = setup(mode, count);
        let graph = if count == 3 {
            graph
                .with_sentinel_trusted_goal("Summarize the note. private-goal-canary", "v1")
                .unwrap()
        } else {
            graph
        };
        tokio::time::timeout(
            Duration::from_secs(2),
            graph.invoke_observed(
                state(RAW),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            ),
        )
        .await
        .expect("failure must cancel pending siblings")
        .unwrap();
        assert_eq!(probe.requests.lock().unwrap().len(), count);
        assert_eq!(probe.active.load(Ordering::SeqCst), 0);
        let report = report(&store, &mapper);
        assert_eq!(report["reason"], "invalid_or_failed");
        assert!(report["decision"].is_null());
        assert_eq!(report["findings"], json!([]));
        assert_eq!(report["observations"], Value::Null);
        let failure = &report["failure"];
        assert_eq!(failure["stage"], "invocation");
        assert!(failure["probe"].as_u64().unwrap() < count as u64);
        if count == 3 {
            assert_eq!(failure["probe"], 2);
        }
        assert_eq!(failure["kind"], kind);
        assert_eq!(failure["model_error"], json!(model_error));
        assert_eq!(failure["output_error"], json!(output_error));
        assert_eq!(failure["upstream_status_code"], json!(status));
        assert_eq!(failure["attempts"], 1);
        assert_eq!(failure.as_object().unwrap().len(), 7);
        assert!(report.to_string().len() < 1024);
        for serialized in [
            report.to_string(),
            serde_json::to_string(mapper.events()).unwrap(),
        ] {
            for private in [
                "raw-secret-do-not-echo",
                "private-goal-canary",
                "must-not-reach-probes",
                std::str::from_utf8(RAW).unwrap(),
            ] {
                assert!(!serialized.contains(private));
            }
        }
    }
}

#[tokio::test]
async fn private_failure_is_absent_after_complete_or_denied_execution() {
    for (mode, raw, reason) in [
        (Mode::Agree, RAW, "agreement"),
        (Mode::Agree, "中文資料".as_bytes(), "language_gate"),
    ] {
        let (graph, probe, mut store, mut mapper) = setup(mode, 2);
        graph
            .invoke_observed(
                state(raw),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await
            .unwrap();
        let report = report(&store, &mapper);
        assert_eq!(report["schema_version"], 5);
        assert_eq!(report["reason"], reason);
        assert_eq!(report.get("failure"), Some(&Value::Null));
        assert_eq!(probe.active.load(Ordering::SeqCst), 0);
        assert_eq!(
            probe.requests.lock().unwrap().len(),
            if reason == "agreement" { 2 } else { 0 }
        );
    }
}
