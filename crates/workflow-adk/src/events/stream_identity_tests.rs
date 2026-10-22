use super::*;
use adk_rust::{Content, Event, FinishReason, FunctionResponseData, Part};
use serde_json::json;
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    sync::{Arc, Mutex},
};
use workflow_runtime::InMemoryArtifactStore;

fn artifacts() -> InMemoryArtifactStore {
    InMemoryArtifactStore::new(
        NonZeroU64::new(64 * 1024).unwrap(),
        NonZeroU64::new(64 * 1024).unwrap(),
    )
}

fn chunk(id: &str, partial: bool) -> Event {
    let mut event = Event::new("invocation");
    event.id = id.to_owned();
    event.author = "agent".into();
    event.llm_response.content = Some(Content::new("model").with_text("chunk"));
    event.llm_response.partial = partial;
    event.llm_response.turn_complete = !partial;
    event
}

fn map(
    mapper: &mut AdkEventMapper,
    node: &str,
    event: Event,
) -> Result<WorkflowRuntimeEventV1, AdkEventMappingError> {
    mapper.map_adk_event(node.into(), event, &mut artifacts())
}

fn distinct_responses_and_nodes_keep_each_callback_and_first_source_identity() {
    let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
    for (node, id) in [
        ("a", "response-1"),
        ("a", "response-2"),
        ("b", "response-3"),
    ] {
        let first = map(&mut mapper, node, chunk(id, true)).unwrap();
        assert_eq!(first.event_id(), id);
        let second = map(&mut mapper, node, chunk(id, true)).unwrap();
        let mut final_event = chunk(id, false);
        final_event.llm_response.finish_reason = Some(FinishReason::Stop);
        let final_audit = map(&mut mapper, node, final_event.clone()).unwrap();
        assert_eq!(final_event.id, id, "SDK source IDs are never rewritten");
        assert_ne!(first.event_id(), second.event_id());
        assert_ne!(second.event_id(), final_audit.event_id());
        assert_eq!(final_audit.payload()["finish_reason"], "stop");
    }
    assert_eq!(mapper.events().len(), 9);
}

fn nonstream_duplicates_and_every_terminal_form_close_the_source() {
    for terminal in 0..5 {
        let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
        let mut event = chunk("response", terminal != 0);
        match terminal {
            0 => {}
            1 => event.llm_response.turn_complete = true,
            2 => event.llm_response.interrupted = true,
            3 => event.llm_response.error_code = Some("failed".into()),
            4 => event.llm_response.error_message = Some("failed".into()),
            _ => unreachable!(),
        }
        map(&mut mapper, "a", event.clone()).unwrap();
        for duplicate in [event, chunk("response", true), chunk("response", false)] {
            assert_eq!(
                map(&mut mapper, "a", duplicate).unwrap_err().kind(),
                AdkEventMappingErrorKind::DuplicateEventId,
                "terminal {terminal}"
            );
            assert_eq!(mapper.events().len(), 1);
        }
    }
    let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
    map(&mut mapper, "a", chunk("response", true)).unwrap();
    map(&mut mapper, "a", chunk("response", false)).unwrap();
    assert_eq!(
        map(&mut mapper, "a", chunk("response", false))
            .unwrap_err()
            .kind(),
        AdkEventMappingErrorKind::DuplicateEventId
    );
    assert_eq!(mapper.events().len(), 2);
}

fn a_stream_source_cannot_move_between_owners() {
    for owner in 0..4 {
        let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
        map(&mut mapper, "a", chunk("response", true)).unwrap();
        let mut next = chunk("response", true);
        let node = match owner {
            0 => "b",
            1 => {
                next.invocation_id = "other".into();
                "a"
            }
            2 => {
                next.author = "other".into();
                "a"
            }
            3 => {
                next.branch = "other".into();
                "a"
            }
            _ => unreachable!(),
        };
        assert_eq!(
            map(&mut mapper, node, next).unwrap_err().kind(),
            AdkEventMappingErrorKind::DuplicateEventId
        );
        assert_eq!(mapper.events().len(), 1);
    }
}

fn generated_and_sdk_identity_namespace_collisions_fail_in_both_orders() {
    let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
    map(&mut mapper, "a", chunk("adk-stream-3", false)).unwrap();
    map(&mut mapper, "b", chunk("response", true)).unwrap();
    assert_eq!(
        map(&mut mapper, "b", chunk("response", false))
            .unwrap_err()
            .kind(),
        AdkEventMappingErrorKind::DuplicateEventId
    );
    assert_eq!(mapper.events().len(), 2);

    let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
    map(&mut mapper, "a", chunk("response", true)).unwrap();
    assert_eq!(
        map(&mut mapper, "a", chunk("response", true))
            .unwrap()
            .event_id(),
        "adk-stream-2"
    );
    assert_eq!(
        map(&mut mapper, "b", chunk("adk-stream-2", true))
            .unwrap_err()
            .kind(),
        AdkEventMappingErrorKind::DuplicateEventId
    );
    assert_eq!(mapper.events().len(), 2);
}

fn failed_projection_does_not_admit_or_close_a_source() {
    let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
    for partial in [true, false] {
        let mut invalid = chunk("response", partial);
        invalid
            .provider_metadata
            .insert("latency_ms".into(), "invalid".into());
        let before = mapper.events().len();
        assert_eq!(
            map(&mut mapper, "a", invalid).unwrap_err().kind(),
            AdkEventMappingErrorKind::InvalidObservation
        );
        assert_eq!(mapper.events().len(), before);
        map(&mut mapper, "a", chunk("response", partial)).unwrap();
    }
    assert_eq!(mapper.events().len(), 2);
}

fn failed_append_does_not_close_a_source() {
    let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
    map(&mut mapper, "a", chunk("response", true)).unwrap();
    mapper
        .map(AdkRuntimeObservationV1::new(
            "adk-stream-3",
            "time",
            AdkRuntimeObservationKindV1::NodeStarted,
        ))
        .unwrap();
    assert_eq!(
        map(&mut mapper, "a", chunk("response", false))
            .unwrap_err()
            .kind(),
        AdkEventMappingErrorKind::DuplicateEventId
    );
    assert_eq!(mapper.events().len(), 2);
    mapper
        .map(AdkRuntimeObservationV1::new(
            "other",
            "time",
            AdkRuntimeObservationKindV1::NodeStarted,
        ))
        .unwrap();
    assert_eq!(
        map(&mut mapper, "a", chunk("response", false))
            .unwrap()
            .event_id(),
        "adk-stream-4"
    );
}

fn resume_keeps_prior_bytes_and_rejects_source_replay_including_inflight_partial() {
    for final_seen in [false, true] {
        let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
        map(&mut mapper, "a", chunk("response", true)).unwrap();
        if final_seen {
            map(&mut mapper, "a", chunk("response", false)).unwrap();
        }
        let prior = mapper.events().to_vec();
        let mut resumed = AdkEventMapper::resume("run", "workflow", prior.clone()).unwrap();
        assert_eq!(
            map(&mut resumed, "a", chunk("response", false))
                .unwrap_err()
                .kind(),
            AdkEventMappingErrorKind::DuplicateEventId
        );
        map(&mut resumed, "a", chunk("new-response", true)).unwrap();
        map(&mut resumed, "a", chunk("new-response", false)).unwrap();
        assert_eq!(&resumed.events()[..prior.len()], prior.as_slice());
    }
}

fn tool_result(id: &str) -> Event {
    let mut event = chunk(id, true);
    event.llm_response.content = Some(Content {
        role: "tool".into(),
        parts: vec![Part::FunctionResponse {
            function_response: FunctionResponseData::new("search", json!({"answer":"ok"})),
            id: Some("provider-call".into()),
            annotations: None,
        }],
    });
    event
}

fn durable_tool_tokens_are_not_replaced_by_stream_audit_ids() {
    for id in ["response", "tool-completed-v1-private-token"] {
        let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
        mapper.bind_tool_audit(Arc::new(Mutex::new(BTreeMap::from([(
            ("a".into(), "provider-call".into()),
            ("search".into(), "private-token".into()),
        )]))));
        let event = tool_result(id);
        let mapped = map(&mut mapper, "a", event.clone()).unwrap();
        assert_eq!(mapped.event_id(), "tool-completed-v1-private-token");
        assert!(
            !serde_json::to_string(&mapped)
                .unwrap()
                .contains("provider-call")
        );
        assert_eq!(
            map(&mut mapper, "a", event).unwrap_err().kind(),
            AdkEventMappingErrorKind::DuplicateEventId
        );
        assert_eq!(mapper.events().len(), 1);
    }
}

fn transformed_tool_source_names_cannot_collide_with_generated_audit_ids() {
    for generated_first in [false, true] {
        let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
        mapper.bind_tool_audit(Arc::new(Mutex::new(BTreeMap::from([(
            ("a".into(), "provider-call".into()),
            ("search".into(), "private-token".into()),
        )]))));
        let result = if generated_first {
            mapper
                .map_stream_observation(
                    None,
                    AdkRuntimeObservationKindV1::NodeStarted,
                    None,
                    None,
                    &mut artifacts(),
                )
                .unwrap();
            map(&mut mapper, "a", tool_result("adk-stream-1"))
        } else {
            map(&mut mapper, "a", tool_result("adk-stream-2")).unwrap();
            mapper.map_stream_observation(
                None,
                AdkRuntimeObservationKindV1::NodeStarted,
                None,
                None,
                &mut artifacts(),
            )
        };
        assert_eq!(
            result.unwrap_err().kind(),
            AdkEventMappingErrorKind::DuplicateEventId
        );
        assert_eq!(mapper.events().len(), 1);
    }
}

fn long_running_tool_llm_partials_keep_their_shared_response_identity() {
    let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
    let mut partial = chunk("response", true);
    partial.llm_response.content = Some(Content {
        role: "model".into(),
        parts: vec![Part::FunctionCall {
            name: "search".into(),
            args: json!({}),
            id: Some("provider-call".into()),
            thought_signature: None,
        }],
    });
    partial.long_running_tool_ids = vec!["search".into()];
    assert!(
        partial.is_final_response(),
        "agent finality does not end an LLM partial response"
    );
    map(&mut mapper, "a", partial.clone()).unwrap();
    map(&mut mapper, "a", partial.clone()).unwrap();
    partial.llm_response.partial = false;
    partial.llm_response.turn_complete = true;
    map(&mut mapper, "a", partial).unwrap();
    assert_eq!(mapper.events().len(), 3);
    assert!(
        mapper
            .events()
            .iter()
            .all(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolRequested)
    );
}

#[test]
fn sdk_identity_lifecycle_contract() {
    for reason in [FinishReason::Stop, FinishReason::MaxTokens] {
        let mut mapper = AdkEventMapper::new("run", "workflow").unwrap();
        let mut partial = chunk("response", true);
        partial.llm_response.finish_reason = Some(reason);
        map(&mut mapper, "a", partial).unwrap();
        map(&mut mapper, "a", chunk("response", false)).unwrap();
        assert_eq!(mapper.events().len(), 2);
    }
    distinct_responses_and_nodes_keep_each_callback_and_first_source_identity();
    nonstream_duplicates_and_every_terminal_form_close_the_source();
    a_stream_source_cannot_move_between_owners();
    generated_and_sdk_identity_namespace_collisions_fail_in_both_orders();
    failed_projection_does_not_admit_or_close_a_source();
    failed_append_does_not_close_a_source();
    resume_keeps_prior_bytes_and_rejects_source_replay_including_inflight_partial();
    long_running_tool_llm_partials_keep_their_shared_response_identity();
    transformed_tool_source_names_cannot_collide_with_generated_audit_ids();
    durable_tool_tokens_are_not_replaced_by_stream_audit_ids();
}
