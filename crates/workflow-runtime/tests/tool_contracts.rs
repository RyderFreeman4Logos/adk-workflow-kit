use std::{error::Error, num::NonZeroU64, time::Duration};

use workflow_runtime::{
    ArtifactStore, InMemoryArtifactStore, PageRequest, RunContext, RunController, RunId,
    RunLimitKind, RunLimits, RunTerminalCause, RunTermination, ToolEnvelope, ToolFailure,
    ToolProvenance,
};

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("test limits must be positive")
}

fn provenance() -> ToolProvenance {
    ToolProvenance::new("registry.tool", "1.2.3")
}

fn context(max_tool_output_bytes: u64) -> RunContext {
    RunContext::new(
        RunId::new(String::from("tool-contracts")).expect("fixture run ID must be valid"),
        RunLimits::new(
            nonzero(1),
            nonzero(1),
            nonzero(1),
            nonzero(100),
            nonzero(100),
            nonzero(100),
            nonzero(max_tool_output_bytes),
        ),
    )
}

fn pass(result: Result<(), RunTermination>) {
    result.expect("runtime boundary must proceed");
}

#[test]
fn success_empty_and_failure_round_trip_with_exact_provenance() {
    let cases = [
        (
            ToolEnvelope::Success {
                payload: String::from("payload"),
                provenance: provenance(),
                next_offset: Some(12),
                artifact_id: Some(String::from("artifact-1")),
            },
            r#"{"status":"success","payload":"payload","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"},"next_offset":12,"artifact_id":"artifact-1"}"#,
        ),
        (
            ToolEnvelope::Empty {
                provenance: provenance(),
            },
            r#"{"status":"empty","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#,
        ),
        (
            ToolEnvelope::Failure {
                failure: ToolFailure::InvalidInput,
                provenance: provenance(),
            },
            r#"{"status":"failure","failure":"invalid_input","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#,
        ),
    ];

    for (envelope, expected_json) in cases {
        assert_eq!(
            serde_json::to_string(&envelope).expect("envelope serialization must succeed"),
            expected_json
        );
        let decoded: ToolEnvelope<String> =
            serde_json::from_str(expected_json).expect("known envelope must decode");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.provenance().tool_id(), "registry.tool");
        assert_eq!(decoded.provenance().tool_version(), "1.2.3");
    }
}

#[test]
fn empty_success_is_distinct_from_success_with_empty_payload() {
    let empty = ToolEnvelope::<String>::Empty {
        provenance: provenance(),
    };
    let empty_string = ToolEnvelope::Success {
        payload: String::new(),
        provenance: provenance(),
        next_offset: None,
        artifact_id: None,
    };
    assert_ne!(empty, empty_string);
    assert!(matches!(empty_string, ToolEnvelope::Success { .. }));

    let empty_collection = ToolEnvelope::Success {
        payload: Vec::<String>::new(),
        provenance: provenance(),
        next_offset: None,
        artifact_id: None,
    };
    assert!(matches!(empty_collection, ToolEnvelope::Success { .. }));

    let optional_payload = ToolEnvelope::Success {
        payload: None::<String>,
        provenance: provenance(),
        next_offset: None,
        artifact_id: None,
    };
    assert!(matches!(optional_payload, ToolEnvelope::Success { .. }));
    assert_eq!(
        serde_json::to_string(&optional_payload).expect("optional payload must serialize"),
        r#"{"status":"success","payload":null,"provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#
    );

    let empty_page = ToolEnvelope::Success {
        payload: Vec::<u8>::new(),
        provenance: provenance(),
        next_offset: Some(8),
        artifact_id: None,
    };
    assert!(matches!(
        empty_page,
        ToolEnvelope::Success {
            payload,
            next_offset: Some(8),
            ..
        } if payload.is_empty()
    ));
}

#[test]
fn malformed_and_hostile_failure_data_fail_closed() {
    for document in [
        r#"{"status":"success","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#,
        r#"{"status":"empty"}"#,
        r#"{"status":"failure","failure":"invalid_input"}"#,
        r#"{"status":"unknown","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#,
        r#"{"status":"failure","failure":"unknown","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#,
        r#"{"status":"failure","failure":"invalid_input","payload":"hostile","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#,
        r#"{"status":"failure","failure":"invalid_input","next_offset":0,"provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#,
        r#"{"status":"failure","failure":"invalid_input","artifact_id":"hostile","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#,
        r#"{"status":"failure","failure":"invalid_input","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3","detail":"hostile"}}"#,
    ] {
        let decoded = serde_json::from_str::<ToolEnvelope<serde_json::Value>>(document);
        assert!(decoded.is_err(), "must reject {document}");
    }

    for (failure, message) in [
        (ToolFailure::InvalidInput, "tool input was invalid"),
        (ToolFailure::NotFound, "tool result was not found"),
        (ToolFailure::Unavailable, "tool was unavailable"),
        (ToolFailure::Internal, "tool failed internally"),
    ] {
        let error: &dyn Error = &failure;
        assert_eq!(error.to_string(), message);
        assert!(!error.to_string().contains("hostile"));
    }
}

#[test]
fn artifact_handle_and_pagination_preserve_wire_metadata() {
    let mut store = InMemoryArtifactStore::new(nonzero(16), nonzero(2));
    let artifact_id = store.put(b"abc").expect("fixture artifact must store");
    let page = store
        .read_page(&artifact_id, PageRequest::new(0, nonzero(8)))
        .expect("fixture artifact page must read");

    let envelope = ToolEnvelope::Success {
        payload: page.bytes().to_vec(),
        provenance: provenance(),
        next_offset: page.next_offset(),
        artifact_id: Some(String::from(artifact_id.as_str())),
    };
    let encoded = serde_json::to_string(&envelope).expect("envelope serialization must succeed");
    let decoded: ToolEnvelope<Vec<u8>> =
        serde_json::from_str(&encoded).expect("serialized envelope must decode");

    assert_eq!(decoded, envelope);
    match decoded {
        ToolEnvelope::Success {
            payload,
            next_offset,
            artifact_id: handle,
            ..
        } => {
            assert_eq!(payload, b"ab");
            assert_eq!(next_offset, Some(2));
            assert_eq!(handle.as_deref(), Some(artifact_id.as_str()));
        }
        ToolEnvelope::Empty { .. } | ToolEnvelope::Failure { .. } => {
            panic!("artifact page must remain a success envelope")
        }
    }
}

#[test]
fn serialized_inline_output_obeys_existing_runtime_byte_limit() {
    let envelope = ToolEnvelope::Success {
        payload: String::from("inline output"),
        provenance: provenance(),
        next_offset: None,
        artifact_id: None,
    };
    let serialized = serde_json::to_vec(&envelope).expect("envelope serialization must succeed");
    let byte_count = u64::try_from(serialized.len()).expect("serialized output must fit u64");
    let one_byte_less = byte_count
        .checked_sub(1)
        .expect("fixture output must be non-empty");

    let accepted_context = context(byte_count);
    let mut accepted = RunController::new(&accepted_context);
    pass(accepted.begin_tool_call(Duration::ZERO, "registry.tool", "1.2.3"));
    pass(accepted.accept_tool_output(Duration::ZERO, byte_count));
    pass(accepted.finish_tool_call(Duration::ZERO));

    let rejected_context = context(one_byte_less);
    let mut rejected = RunController::new(&rejected_context);
    pass(rejected.begin_tool_call(Duration::ZERO, "registry.tool", "1.2.3"));
    let termination = rejected
        .accept_tool_output(Duration::ZERO, byte_count)
        .expect_err("one byte below the serialized output must terminate");
    assert_eq!(
        termination.cause(),
        RunTerminalCause::LimitExceeded(RunLimitKind::ToolOutputBytes)
    );
}
