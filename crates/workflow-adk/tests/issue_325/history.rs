use super::*;
use adk_rust::session::AppendEventRequest;
use adk_rust::{Event, EventCompaction, Session as _};

#[tokio::test]
async fn history_and_full_identity_change_provenance_without_changing_stateless_identity() {
    let probe = Probe::new(vec![Reply::Answer; 4]);
    let binding = binding(probe);
    let spec = spec(
        ProviderRouteIdentity::from_binding(&binding),
        "same request",
        0,
    );
    let stateless = spec.provenance();
    let first = InMemorySessionService::new();
    let copy = InMemorySessionService::new();
    let id = identity("identity-app", "user-a");
    let other = identity("identity-app", "user-b");
    create(&first, &id).await;
    create(&first, &other).await;
    create(&copy, &id).await;
    let mut results = vec![];
    for (store, identity) in [(&first, &id), (&copy, &id), (&first, &other), (&first, &id)] {
        results.push(
            spec.clone()
                .invoke_in_session(
                    &binding,
                    store,
                    identity,
                    Instant::now() + Duration::from_secs(2),
                    &ModelRouteCancellation::new(),
                )
                .await
                .unwrap(),
        );
    }
    let provenance: Vec<_> = results.iter().map(|result| result.provenance()).collect();
    assert_eq!(
        provenance[0], provenance[1],
        "same identity/history/request are stable across invocation objects and stores"
    );
    for index in [2, 3] {
        assert_ne!(
            provenance[0].session_history_digest(),
            provenance[index].session_history_digest()
        );
        assert_ne!(
            provenance[0].invocation_identity(),
            provenance[index].invocation_identity()
        );
        assert_ne!(provenance[0].seed(), provenance[index].seed());
    }
    assert!(provenance[0].session_history_digest().is_some());
    assert_eq!(spec.provenance(), stateless);
    assert_eq!(stateless.session_history_digest(), None);
    let diagnostic = format!("{:?}", provenance[3]);
    for private in ["identity-app", "user-a", "same request"] {
        assert!(!diagnostic.contains(private));
    }
    let events = first.get_for_identity(&id).await.unwrap().events().all();
    assert!(
        events
            .iter()
            .all(|event| event.llm_response.usage_metadata.is_none()),
        "raw provider metadata is not session history"
    );
}

#[tokio::test]
async fn official_adk_projection_preserves_compaction_partial_and_unscoped_branch_semantics() {
    let store = InMemorySessionService::new();
    let id = identity("projected-app", "user");
    create(&store, &id).await;
    let mut old = Event::new("old");
    old.author = "user".into();
    old.llm_response = LlmResponse::new(Content::new("user").with_text("obsolete private history"));
    let boundary = old.timestamp;
    let mut compacted = Event::new("compacted");
    compacted.actions.compaction = Some(EventCompaction {
        start_timestamp: boundary,
        end_timestamp: boundary,
        compacted_content: Content::new("model").with_text("official summary"),
    });
    let mut partial = Event::new("partial");
    partial.author = "model".into();
    partial.llm_response = LlmResponse::new(Content::new("model").with_text("private partial"));
    partial.llm_response.partial = true;
    let mut sibling = Event::new("sibling");
    sibling.author = "model".into();
    sibling.branch = "sibling".into();
    sibling.llm_response = LlmResponse::new(Content::new("model").with_text("private sibling"));
    for event in [old, compacted, partial, sibling] {
        store
            .append_event_for_identity(AppendEventRequest {
                identity: id.clone(),
                event,
            })
            .await
            .unwrap();
    }
    let snapshot = store.get_for_identity(&id).await.unwrap();
    let projected =
        adk_rust::runner::MutableSession::new(Arc::from(snapshot)).conversation_history();
    assert_eq!(projected.len(), 2);
    assert_eq!(projected[0].parts[0].text(), Some("official summary"));
    assert_eq!(projected[1].parts[0].text(), Some("private sibling"));
    let probe = Probe::new(vec![Reply::Answer]);
    let binding = binding(probe.clone());
    spec(ProviderRouteIdentity::from_binding(&binding), "current", 0)
        .invoke_in_session(
            &binding,
            &store,
            &id,
            Instant::now() + Duration::from_secs(2),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();
    let requests = probe.requests.lock().unwrap();
    assert_eq!(requests[0].as_array().unwrap().len(), 4);
    for (index, content) in projected.iter().enumerate() {
        assert_eq!(
            requests[0][index + 1],
            serde_json::to_value(content).unwrap()
        );
    }
    for private in ["obsolete private history", "private partial"] {
        assert!(!requests[0].to_string().contains(private));
    }
}
