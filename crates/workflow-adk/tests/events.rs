use serde_json::{Value, json};
use workflow_adk::events::{
    AdkEventMapper, AdkEventMappingErrorKind, AdkRuntimeObservationKindV1, AdkRuntimeObservationV1,
};
use workflow_runtime::{ProtectedArtifactReferenceV1, SensitiveSnapshot, WorkflowRuntimeEventV1};

const OCCURRED_AT: &str = "2026-08-27T20:00:00Z";

fn observation(event_id: &str, kind: AdkRuntimeObservationKindV1) -> AdkRuntimeObservationV1 {
    AdkRuntimeObservationV1::new(event_id, OCCURRED_AT, kind)
}

#[test]
fn maps_every_required_observation_kind_in_total_order() {
    use AdkRuntimeObservationKindV1 as Kind;

    let cases = [
        (Kind::WorkflowStarted, "workflow_started"),
        (Kind::WorkflowResumed, "workflow_resumed"),
        (Kind::WorkflowCancelled, "workflow_cancelled"),
        (Kind::NodeScheduled, "node_scheduled"),
        (Kind::NodeStarted, "node_started"),
        (Kind::NodeCompleted, "node_completed"),
        (Kind::NodeFailed, "node_failed"),
        (Kind::ModelRequestStarted, "model_request_started"),
        (Kind::ModelRequestCompleted, "model_request_completed"),
        (Kind::ToolRequested, "tool_requested"),
        (Kind::ToolAuthorized, "tool_authorized"),
        (Kind::ToolDenied, "tool_denied"),
        (Kind::ToolStarted, "tool_started"),
        (Kind::ToolCompleted, "tool_completed"),
        (Kind::RetryScheduled, "retry_scheduled"),
        (Kind::ApprovalRequested, "approval_requested"),
        (Kind::ApprovalResolved, "approval_resolved"),
        (Kind::CheckpointCommitStarted, "checkpoint_commit_started"),
        (Kind::CheckpointCommitted, "checkpoint_committed"),
        (Kind::CheckpointFailed, "checkpoint_failed"),
        (Kind::ArtifactCommitted, "artifact_committed"),
        (Kind::ReviewCompleted, "review_completed"),
        (Kind::RevisionRequested, "revision_requested"),
        (Kind::WorkflowCompleted, "workflow_completed"),
        (Kind::WorkflowAbstained, "workflow_abstained"),
        (Kind::WorkflowIncomplete, "workflow_incomplete"),
        (Kind::WorkflowFailed, "workflow_failed"),
    ];
    let mut mapper = AdkEventMapper::new("run-kinds", "workflow-kinds").unwrap();

    for (index, (kind, expected)) in cases.into_iter().enumerate() {
        let event = mapper
            .map(observation(&format!("event-{index}"), kind))
            .unwrap();
        assert_eq!(event.kind().as_str(), expected);
        assert_eq!(event.sequence(), index as u64 + 1);
    }
}

#[test]
fn model_mapping_json_snapshot_is_stable_and_project_owned() {
    let mut mapper = AdkEventMapper::new("run-1", "workflow-1").unwrap();
    let event = mapper
        .map(
            observation(
                "evt-model",
                AdkRuntimeObservationKindV1::ModelRequestCompleted,
            )
            .with_node_id("agent")
            .with_request(json!({"prompt": "hello"}))
            .with_response(json!({"answer": 42}))
            .with_tokens(11, 7)
            .with_latency_ms(42)
            .with_structured_output(json!({"answer": 42}))
            .with_finish_reason("stop"),
        )
        .unwrap();
    let snapshot = serde_json::to_string(&event).unwrap();

    assert_eq!(
        snapshot,
        r#"{"schema_version":1,"event_id":"evt-model","run_id":"run-1","workflow_id":"workflow-1","node_id":"agent","sequence":1,"occurred_at":"2026-08-27T20:00:00Z","kind":"model_request_completed","payload":{"finish_reason":"stop","input_tokens":11,"latency_ms":42,"output_tokens":7,"request_digest":"sha256:8a44725210b9dcd4fefd9f0eca07b70ae45e69274a3105fb25eb426a2cf8bbf4","response_digest":"sha256:ecf59a2696ca44a417e20e2a7eabb1b26e82c779f8546bea354a2cc80e8e1eed","structured_output":{"answer":42},"tool_call_occurred":false},"integrity":{"payload_sha256":"sha256:57fd2448c6d9dd8d5d6a17c8cc2b45ccd37f174e079b4f9c375fd576d16605d7"}}"#
    );
    assert!(!snapshot.contains("adk_rust"));
    assert!(!snapshot.contains("Event {"));
}

#[test]
fn persisted_digests_use_the_recursive_redacted_copy() {
    let map = |event_id, public, secret| {
        let mut mapper = AdkEventMapper::new(format!("run-{event_id}"), "workflow-digest").unwrap();
        mapper
            .map(
                observation(event_id, AdkRuntimeObservationKindV1::ModelRequestCompleted)
                    .with_request(json!({"public": public, "nested": {"api_key": secret}}))
                    .with_response(json!({"public": public, "nested": [{"password": secret}]})),
            )
            .unwrap()
    };
    let first = map("first", "same", "first-secret");
    let changed_secret = map("second", "same", "second-secret");
    let changed_public = map("third", "changed", "first-secret");

    for key in ["request_digest", "response_digest"] {
        assert_eq!(first.payload()[key], changed_secret.payload()[key]);
        assert_ne!(first.payload()[key], changed_public.payload()[key]);
    }
}

#[test]
fn redacts_sensitive_fields_and_keeps_raw_observations_out_of_events() {
    let mut mapper = AdkEventMapper::new("run-private", "workflow-private").unwrap();
    let event = mapper
        .map(
            observation(
                "evt-private",
                AdkRuntimeObservationKindV1::ModelRequestCompleted,
            )
            .with_request(json!({"authorization": "Bearer REQUEST_SECRET"}))
            .with_response(json!({"token": "RESPONSE_SECRET"}))
            .with_structured_output(json!({
                "answer": "visible",
                "password": "PASSWORD_SECRET",
                "client_secret": "CLIENT_SECRET",
                "auth_token": "AUTH_TOKEN",
                "apiKey": "API_KEY",
                "nested": {"chain_of_thought": "HIDDEN_REASONING"}
            }))
            .with_sensitive_snapshot(SensitiveSnapshot::chain_of_thought("RAW_REASONING")),
        )
        .unwrap();
    let encoded = serde_json::to_string(&event).unwrap();
    let value = serde_json::to_value(&event).unwrap();

    for forbidden in [
        "REQUEST_SECRET",
        "RESPONSE_SECRET",
        "PASSWORD_SECRET",
        "CLIENT_SECRET",
        "AUTH_TOKEN",
        "API_KEY",
        "HIDDEN_REASONING",
        "RAW_REASONING",
    ] {
        assert!(!encoded.contains(forbidden), "event leaked {forbidden}");
    }
    assert_eq!(
        value["payload"]["structured_output"]["password"],
        json!("<redacted>")
    );
    for key in ["client_secret", "auth_token", "apiKey"] {
        assert_eq!(
            value["payload"]["structured_output"][key],
            json!("<redacted>"),
            "structured output did not redact {key}"
        );
    }
    assert_eq!(
        value["payload"]["structured_output"]["nested"]["chain_of_thought"],
        json!("<redacted>")
    );
    assert_eq!(value["payload"]["sensitive_snapshot"], json!("<redacted>"));
}

#[test]
fn large_structured_outputs_require_and_use_protected_artifacts() {
    let large = json!({"blob": "x".repeat(5_000)});
    let mut mapper = AdkEventMapper::new("run-large", "workflow-large").unwrap();
    let error = mapper
        .map(
            observation(
                "evt-large-rejected",
                AdkRuntimeObservationKindV1::ToolCompleted,
            )
            .with_structured_output(large.clone()),
        )
        .unwrap_err();
    assert_eq!(
        error.kind(),
        AdkEventMappingErrorKind::LargePayloadMissingArtifact
    );

    let artifact = ProtectedArtifactReferenceV1::new(
        "artifact-42",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        5_011,
    )
    .unwrap();
    let event = mapper
        .map(
            observation("evt-large", AdkRuntimeObservationKindV1::ToolCompleted)
                .with_structured_output(large)
                .with_artifact_reference(artifact),
        )
        .unwrap();
    let payload = event.payload();

    assert!(payload.get("structured_output").is_none());
    assert!(payload.get("structured_output_digest").is_some());
    assert_eq!(payload["artifact_reference"]["artifact_id"], "artifact-42");
}

#[test]
fn duplicate_event_ids_fail_closed_without_advancing_sequence() {
    let mut mapper = AdkEventMapper::new("run-duplicate", "workflow-duplicate").unwrap();
    mapper
        .map(observation(
            "same-id",
            AdkRuntimeObservationKindV1::WorkflowStarted,
        ))
        .unwrap();
    let error = mapper
        .map(observation(
            "same-id",
            AdkRuntimeObservationKindV1::NodeStarted,
        ))
        .unwrap_err();

    assert_eq!(error.kind(), AdkEventMappingErrorKind::DuplicateEventId);
    assert_eq!(mapper.events().len(), 1);
    assert_eq!(mapper.events()[0].sequence(), 1);
}

#[test]
fn resume_continues_sequence_without_rewriting_prior_events() {
    let mut initial = AdkEventMapper::new("run-resume", "workflow-resume").unwrap();
    initial
        .map(observation(
            "evt-start",
            AdkRuntimeObservationKindV1::WorkflowStarted,
        ))
        .unwrap();
    let prior = initial.into_events();
    let prior_snapshot = serde_json::to_vec(&prior).unwrap();

    let mut resumed = AdkEventMapper::resume("run-resume", "workflow-resume", prior).unwrap();
    let event = resumed
        .map(observation(
            "evt-resume",
            AdkRuntimeObservationKindV1::WorkflowResumed,
        ))
        .unwrap();

    assert_eq!(event.sequence(), 2);
    assert_eq!(
        serde_json::to_vec(&resumed.events()[..1]).unwrap(),
        prior_snapshot
    );
}

#[test]
fn missing_old_unknown_and_modified_event_schemas_fail_closed() {
    let mut mapper = AdkEventMapper::new("run-schema", "workflow-schema").unwrap();
    let event = mapper
        .map(observation(
            "evt-schema",
            AdkRuntimeObservationKindV1::WorkflowStarted,
        ))
        .unwrap();
    let valid = serde_json::to_value(event).unwrap();

    let mut malformed = Vec::<Value>::new();
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("schema_version");
    malformed.push(missing);
    for version in [0, 2] {
        let mut incompatible = valid.clone();
        incompatible["schema_version"] = json!(version);
        malformed.push(incompatible);
    }
    let mut modified = valid;
    modified["payload"]["unexpected"] = json!(true);
    malformed.push(modified);

    for candidate in malformed {
        assert!(
            serde_json::from_value::<WorkflowRuntimeEventV1>(candidate).is_err(),
            "incompatible or modified event decoded"
        );
    }
}
