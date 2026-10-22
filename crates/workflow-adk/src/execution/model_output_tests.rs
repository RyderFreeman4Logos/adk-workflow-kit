use super::*;
use adk_rust::Part;

struct Fixture(PathBuf, Arc<LoopLedgerStore>);
impl Fixture {
    fn new() -> Self {
        let (root, ledger) = execution_registry_tests::fanout_ledger();
        Self(root, ledger)
    }
    fn controller(&self) -> LoopController {
        let limit = NonZeroU64::new(5000).unwrap();
        LoopController::new(
            "left",
            RunLimits::new(limit, limit, limit, limit, limit, limit, limit),
            self.1.clone(),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Instant::now())),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn text(value: &str) -> Part {
    Part::Text { text: value.into() }
}
fn thinking() -> Part {
    Part::Thinking {
        thinking: "not output".into(),
        signature: None,
    }
}
fn content(parts: Vec<Part>) -> Content {
    Content {
        role: "model".into(),
        parts,
    }
}

#[test]
fn split_finish_admission_persists_and_restores_exact_successor() {
    let fixture = Fixture::new();
    let controller = fixture.controller();
    controller
        .before_model(LlmRequest::new(
            "synthetic",
            vec![Content::new("user").with_text("synthetic request")],
        ))
        .unwrap();
    let response = LlmResponse::new(content(vec![
        thinking(),
        text(r#"{"status":"finished","output":{"answer":"#),
        thinking(),
        text(r#""ok"}}"#),
    ]));
    controller
        .observe_model(&response, &BTreeSet::new())
        .expect("one finish spans Text parts");
    let expected = json!({"answer":"ok"});
    let state = fixture.1.snapshot("left").unwrap();
    assert_eq!(state.finished_output, Some(expected.clone()));
    assert_eq!(state.finish_successor, Some(expected.clone()));
    assert!(state.finish_admitted && valid_loop_state(&state));
    assert_eq!(state.model_iterations, 1);
    assert_eq!(state.total_tool_calls, 0);
    assert!(state.pending_calls.is_empty() && state.completed_calls.is_empty());
    let nodes = fixture.1.nodes.lock().unwrap().clone();
    let restored = LoopLedgerStore::open(
        fixture.1.path.clone(),
        fixture.1.checkpoint_path.clone(),
        fixture.1.checkpoint_identity.clone(),
        fixture.1.checkpoint_manifest.clone(),
        fixture.1.run_id.clone(),
        &loop_ledger_digest(&nodes).unwrap(),
        true,
    )
    .expect("the durable finish can be resumed");
    let mut restored = restored.snapshot("left").unwrap();
    assert!(valid_loop_state(&restored));
    assert_eq!(restored.finished_output, state.finished_output);
    restored.finish_successor = Some(json!({"answer":"forged"}));
    assert!(!valid_loop_state(&restored));
    let identity = NodeCacheIdentity {
        workflow_id: "multipart".into(),
        workflow_version: "1".into(),
        node_id: "left".into(),
        node_version: "1".into(),
        invocation_identity: "synthetic".into(),
        policy_digest: "policy".into(),
    };
    let key = identity
        .bind(&LlmRequest::new("synthetic", vec![]))
        .unwrap();
    let cache = NodeResultCache::open(fixture.0.join("cache")).unwrap();
    let pending = Mutex::new(Some((key.clone(), expected.clone())));
    let dispositions = Mutex::new(BTreeMap::new());
    persist_accepted_node_result(
        &Some((cache.clone(), identity)),
        &pending,
        &dispositions,
        "left".into(),
        &response,
    );
    let NodeCacheLookup::Hit(entry) = cache.lookup(&key).unwrap() else {
        panic!("accepted assembled finish is cached");
    };
    assert_eq!(entry.payload(), &expected);
    assert_eq!(
        dispositions.lock().unwrap().get("left"),
        Some(&CacheDisposition::Recorded)
    );
    assert_eq!(
        admitted_finish(
            cached_finish_response(expected.clone())
                .content
                .as_ref()
                .unwrap()
        ),
        Ok(Some(expected))
    );
}

#[test]
fn finish_assembly_rejects_multiple_objects_mixed_calls_and_missing_text() {
    let finish = r#"{"status":"finished","output":{"answer":"ok"}}"#;
    let call = Part::FunctionCall {
        name: "search_code".into(),
        args: json!({"query":"needle"}),
        id: Some("must-not-run".into()),
        thought_signature: None,
    };
    let cases = vec![
        vec![],
        vec![thinking()],
        vec![text(" ")],
        vec![text(finish), text(finish)],
        vec![text(finish), call.clone()],
        vec![text(r#"{"status":"finished","output":{},"extra":true}"#)],
        vec![text(r#"{"status":"finished"}"#)],
    ];
    for parts in cases {
        let fixture = Fixture::new();
        let controller = fixture.controller();
        let before = fs::read(&fixture.1.path).unwrap();
        let content = content(parts);
        assert!(admitted_finish(&content).is_err());
        assert!(
            controller
                .observe_model(
                    &LlmResponse::new(content),
                    &BTreeSet::from(["search_code".into()])
                )
                .is_err()
        );
        assert_eq!(
            *controller.terminal.lock().unwrap(),
            Some(ExecutionErrorKind::InvalidOutput)
        );
        assert!(controller.cancellation.load(Ordering::Acquire));
        assert_eq!(fs::read(&fixture.1.path).unwrap(), before);
        let state = fixture.1.snapshot("left").unwrap();
        assert_eq!(state.model_iterations, 0);
        assert!(state.pending_calls.is_empty() && state.completed_calls.is_empty());
        assert!(state.finished_output.is_none() && state.finish_successor.is_none());
    }
    assert_eq!(admitted_finish(&content(vec![thinking(), call])), Ok(None));
    let fixture = Fixture::new();
    let controller = fixture.controller();
    let before = fs::read(&fixture.1.path).unwrap();
    let mut response = LlmResponse::new(Content::new("model"));
    response.content = None;
    assert!(
        controller
            .observe_model(&response, &BTreeSet::new())
            .is_err()
    );
    assert_eq!(
        *controller.terminal.lock().unwrap(),
        Some(ExecutionErrorKind::InvalidOutput)
    );
    assert_eq!(fs::read(&fixture.1.path).unwrap(), before);
}
