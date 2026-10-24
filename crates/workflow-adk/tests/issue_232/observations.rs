//! Private call observations remain independent of non-authorizing findings.
use super::*;

const GOAL: &str = "Summarize the public security training note. private-goal-canary";

#[tokio::test]
async fn private_probe_usage_survives_clean_and_conflict_without_partial_findings() {
    for (mode, reason, finding_count) in [
        (Mode::Agree, "agreement", 3),
        (Mode::TaskBenign, "clean_not_authoritative", 0),
        (Mode::TaskConflict, "conflict", 0),
    ] {
        let (graph, probe, mut store, mut mapper) = setup(mode, 3);
        let output = graph
            .with_sentinel_trusted_goal(GOAL, "private-usage-v1")
            .unwrap()
            .invoke_observed(
                state(RAW),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await
            .unwrap();
        assert!(output["terminal"]["decision"].is_null());
        let report = report(&store, &mapper);
        assert_eq!(report["reason"], reason);
        assert_eq!(report["findings"].as_array().unwrap().len(), finding_count);
        if finding_count == 0 {
            assert!(report["decision"].is_null());
        }
        let observations = report["observations"].as_array().unwrap();
        assert_eq!(observations.len(), 3);
        for (observation, (branch, rank)) in
            observations
                .iter()
                .zip([("ordered", 1_u64), ("shuffled", 2), ("task_alignment", 4)])
        {
            assert_eq!(observation["branch"], branch);
            assert_eq!(observation["view"]["source"]["start"], 0);
            assert_eq!(observation["view"]["source"]["end"], RAW.len());
            let identity = observation["invocation_identity"].as_str().unwrap();
            assert_eq!(identity.len(), 64);
            assert!(identity.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(
                observation["schema_hash"]
                    .as_str()
                    .unwrap()
                    .starts_with("sha256:")
            );
            assert_eq!(
                observation["usage"],
                json!({
                    "input_tokens":100 * rank,"output_tokens":10 * rank,
                    "total_tokens":999 + rank,"cache_read_tokens":0,
                    "cache_write_tokens":2 * rank,"reasoning_tokens":3 * rank,
                })
            );
            assert!(observation.get("output").is_none());
        }
        assert_eq!(probe.active.load(Ordering::SeqCst), 0);
        assert!(!report.to_string().contains("private-goal-canary"));
    }
}

#[tokio::test]
async fn private_probe_usage_distinguishes_missing_zero_and_latest_snapshot() {
    for (mode, expected) in [
        (Mode::UsageMissing, Value::Null),
        (Mode::UsageInvalid, Value::Null),
        (
            Mode::UsageZero,
            json!({"input_tokens":0,"output_tokens":null,
            "total_tokens":null,"cache_read_tokens":null,"cache_write_tokens":null,
            "reasoning_tokens":null}),
        ),
        (
            Mode::UsageSnapshots,
            json!({"input_tokens":7,"output_tokens":null,
            "total_tokens":null,"cache_read_tokens":null,"cache_write_tokens":null,
            "reasoning_tokens":null}),
        ),
    ] {
        let (graph, probe, mut store, mut mapper) = setup(mode, 2);
        graph
            .invoke_observed(
                state(RAW),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await
            .unwrap();
        let report = report(&store, &mapper);
        assert_eq!(report["reason"], "agreement");
        let observations = report["observations"].as_array().unwrap();
        assert_eq!(observations.len(), 2);
        for observation in observations {
            assert_eq!(observation["usage"], expected);
        }
        assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn private_probe_same_view_prefix_preserves_branch_and_goal_isolation() {
    let (graph, probe, mut store, mut mapper) = setup(Mode::Agree, 3);
    graph
        .with_sentinel_trusted_goal(GOAL, "private-prefix-v1")
        .unwrap()
        .invoke_observed(
            state(RAW),
            ExecutionConfig::new("probe-run"),
            &mut mapper,
            &mut store,
        )
        .await
        .unwrap();
    let requests = probe.requests.lock().unwrap();
    let mut source = Vec::new();
    for request in requests.iter() {
        assert_eq!(request.contents.len(), 2);
        assert!(request.tools.is_empty());
        let system = text(&request.contents[0]);
        let user = text(&request.contents[1]);
        let suffix = frame(&user, "TASK_SUFFIX");
        if suffix.contains("/task_alignment;") {
            assert!(system.contains(GOAL));
        } else {
            assert!(!system.contains(GOAL));
            assert!(!user.contains(GOAL));
            let prefix = user
                .strip_suffix(&format!("TASK_SUFFIX_BYTES:{}\n{}", suffix.len(), suffix))
                .unwrap();
            source.push((system, prefix.to_owned(), suffix.to_owned()));
        }
    }
    assert_eq!(source.len(), 2);
    assert_eq!(source[0].0, source[1].0);
    assert_eq!(source[0].1, source[1].1);
    assert_ne!(source[0].2, source[1].2);
    let report = report(&store, &mapper);
    let observations = report["observations"].as_array().unwrap();
    assert_eq!(
        observations[0]["schema_hash"],
        observations[1]["schema_hash"]
    );
    assert_ne!(
        observations[0]["invocation_identity"],
        observations[1]["invocation_identity"]
    );
    assert_ne!(
        observations[0]["schema_hash"],
        observations[2]["schema_hash"]
    );
}
