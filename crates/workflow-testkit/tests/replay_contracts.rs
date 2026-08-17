use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{json, Value};
use workflow_runtime::{BackendCapabilities, RunStatus, SandboxCapability};
use workflow_testkit::{
    FakeSandboxBackend, FakeTool, ReplayBundle, ReplayError, ReplayErrorKind, ReplayEvent,
};

const DIGEST: &str = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn bundle() -> Value {
    json!({
        "schema_version": 1,
        "workflow_lock": { "toml": "test", "sha256": DIGEST },
        "input_sha256": DIGEST,
        "events": [
            { "type": "node_started", "node_id": "node-a" },
            {
                "type": "model_exchange",
                "node_id": "node-a",
                "model_id": "model-a",
                "request_sha256": DIGEST,
                "response_sha256": DIGEST,
                "input_tokens": 3,
                "output_tokens": 5,
                "cached_input_tokens": 2
            },
            {
                "type": "policy_decision",
                "node_id": "node-a",
                "requested": ["network"],
                "effective": ["network"],
                "allowed": true
            },
            { "type": "terminal", "status": "completed", "outcome_sha256": DIGEST }
        ],
        "fixtures": [{ "sha256": DIGEST }],
        "artifacts": []
    })
}

fn parse(value: &Value) -> Result<ReplayBundle, ReplayError> {
    let bytes = serde_json::to_vec(value).expect("test replay bundle must serialize");
    ReplayBundle::from_json(&bytes)
}

#[test]
fn empty_or_missing_required_fields_fail_closed_without_panicking() {
    let mut empty_input_digest = bundle();
    empty_input_digest["input_sha256"] = json!("");

    for (value, expected_kind) in [
        (json!({}), ReplayErrorKind::InvalidDocument),
        (
            json!({ "schema_version": 1 }),
            ReplayErrorKind::InvalidDocument,
        ),
        (empty_input_digest, ReplayErrorKind::MissingRequiredData),
    ] {
        let result = catch_unwind(AssertUnwindSafe(|| parse(&value)));
        match result {
            Ok(Err(error)) => assert_eq!(error.kind(), expected_kind),
            Ok(Ok(_)) => panic!("incomplete replay bundle unexpectedly parsed"),
            Err(_) => panic!("incomplete replay bundle panicked"),
        }
    }
}

#[test]
fn unknown_or_secret_bearing_fields_fail_without_echoing_input() {
    let secret = "secret-never-echo";
    let mut unknown_field = bundle();
    unknown_field["api_key"] = Value::String(secret.to_owned());
    let mut hidden_reasoning = bundle();
    hidden_reasoning["events"][0]["reasoning"] = Value::String(secret.to_owned());

    for value in [unknown_field, hidden_reasoning] {
        let error = match parse(&value) {
            Ok(_) => panic!("secret-bearing replay bundle unexpectedly parsed"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ReplayErrorKind::InvalidDocument);
        let message = error.to_string();
        assert!(!message.contains(secret));
        assert!(!message.contains("api_key"));
        assert!(!message.contains("reasoning"));
    }
}

#[test]
fn oversized_bundle_or_payload_fails_before_replay() {
    let oversized_bundle = vec![b' '; ReplayBundle::MAX_BUNDLE_BYTES + 1];
    let error = ReplayBundle::from_json(&oversized_bundle)
        .expect_err("oversized bundle must fail before replay");
    assert_eq!(error.kind(), ReplayErrorKind::BundleTooLarge);

    let mut oversized_payload = bundle();
    oversized_payload["fixtures"][0]["bytes"] = Value::Array(
        (0..=ReplayBundle::MAX_INLINE_PAYLOAD_BYTES)
            .map(|_| Value::from(0_u8))
            .collect(),
    );
    let error = parse(&oversized_payload).expect_err("oversized payload must fail before replay");
    assert_eq!(error.kind(), ReplayErrorKind::PayloadTooLarge);
}

#[test]
fn replay_twice_reproduces_exact_structural_trace_without_dispatch() {
    let bundle = match parse(&bundle()) {
        Ok(bundle) => bundle,
        Err(error) => panic!("valid replay bundle must parse: {error}"),
    };
    let tool = FakeTool::new("lookup", "test tool", json!({"result": "unused"}));
    let sandbox = FakeSandboxBackend::new(BackendCapabilities::new([]));

    let first = bundle.replay();
    let second = bundle.replay();

    assert_eq!(first, second);
    assert_eq!(first.workflow_lock_sha256(), DIGEST);
    assert_eq!(first.input_sha256(), DIGEST);
    assert_eq!(
        first.events(),
        [
            ReplayEvent::NodeStarted {
                node_id: "node-a".to_owned(),
            },
            ReplayEvent::ModelExchange {
                node_id: "node-a".to_owned(),
                model_id: "model-a".to_owned(),
                request_sha256: DIGEST.to_owned(),
                response_sha256: DIGEST.to_owned(),
                input_tokens: 3,
                output_tokens: 5,
                cached_input_tokens: 2,
            },
            ReplayEvent::PolicyDecision {
                node_id: "node-a".to_owned(),
                requested: vec![SandboxCapability::Network],
                effective: vec![SandboxCapability::Network],
                allowed: true,
            },
            ReplayEvent::Terminal {
                status: RunStatus::Completed,
                outcome_sha256: DIGEST.to_owned(),
            },
        ]
        .as_slice(),
    );
    assert_eq!(tool.calls().expect("fake tool ledger must be readable"), []);
    assert_eq!(sandbox.call_count(), 0);
}

#[test]
fn recorded_capability_expansion_is_rejected() {
    let mut expanded = bundle();
    expanded["events"][2]["effective"] = json!(["network", "process.spawn"]);

    let error = parse(&expanded).expect_err("capability expansion must be rejected");
    assert_eq!(error.kind(), ReplayErrorKind::CapabilityExpansion);
}
