use super::*;

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Capture {
    requests: Arc<Mutex<Vec<LlmRequest>>>,
}
#[async_trait]
impl Llm for Capture {
    fn name(&self) -> &str {
        "shared-history-probe"
    }
    async fn generate_content(
        &self,
        request: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        let mut requests = self.requests.lock().unwrap();
        let output = ["insufficient", "new mapped evidence", "sufficient"][requests.len()];
        requests.push(request);
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(
            LlmResponse::new(
                Content::new("assistant")
                    .with_text(json!({"status":"finished","output":output}).to_string()),
            ),
        )])))
    }
}

#[tokio::test]
async fn production_loop_reentry_keeps_shared_request_history_and_current_input() {
    let (root, ledger) = super::super::execution_registry_tests::fanout_ledger();
    let fixture = Fixture(root);
    fs::write(
        fixture.0.join("prompt.md"),
        b"Return only the routing decision from current mapped input.",
    )
    .unwrap();
    fs::write(fixture.0.join("output.json"), br#"{"type":"string"}"#).unwrap();
    let source = include_str!("../../tests/fixtures/issue_361_shared_cycle.toml");
    let workflow = fixture.0.join("shared.toml");
    fs::write(&workflow, source).unwrap();
    let plan = compile_file(workflow.to_str().unwrap()).unwrap();
    let contracts = resolve_agent_contracts(&fixture.0.join("shared.toml"), plan.ir()).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut registry = crate::ModelProfileRegistry::new();
    registry
        .register_worker(crate::FakeModelProfile::new(
            "worker",
            "1",
            "worker",
            ["unused"],
        ))
        .unwrap();
    let model = Arc::new(
        registry
            .bind_worker(&crate::CredentialBroker::new())
            .unwrap()
            .with_test_llm(Arc::new(Capture {
                requests: Arc::clone(&requests),
            })),
    );
    let fence = Arc::new(EffectFence {
        cancellation: Arc::new(AtomicBool::new(false)),
        wall_deadline: Instant::now() + Duration::from_secs(30),
        idle_timeout: Duration::from_secs(30),
        tool_timeout: Duration::from_secs(30),
        terminal: Arc::new(Mutex::new(None)),
        last_progress: Arc::new(Mutex::new(Instant::now())),
    });
    let agents = ["work", "revise"]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                build_profile_agent(
                    name,
                    Arc::clone(&model),
                    None,
                    contracts.get(name),
                    RunLimits::new(
                        NonZeroU64::new(100).unwrap(),
                        NonZeroU64::new(100).unwrap(),
                        NonZeroU64::new(100).unwrap(),
                        NonZeroU64::new(30000).unwrap(),
                        NonZeroU64::new(30000).unwrap(),
                        NonZeroU64::new(30000).unwrap(),
                        NonZeroU64::new(65536).unwrap(),
                    ),
                    Arc::clone(&ledger),
                    (Arc::clone(&fence), None, Arc::default(), Arc::default()),
                )
                .unwrap(),
            )
        })
        .collect();
    let continuation = Arc::new(GraphCheckpointMemory::default());
    let mut graph = AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &plan,
            &agents,
            None,
            &Value::Null,
            Some(continuation.clone()),
        )
        .unwrap();
    graph.shared_ledger = Some(Arc::clone(&ledger));
    let state = State::from([
        ("input".into(), json!("public-request")),
        ("undeclared".into(), json!("private-canary")),
    ]);
    let initial = Checkpoint::new(
        ledger.run_id.as_str(),
        state.clone(),
        0,
        vec!["work".into()],
    );
    let owned = isolated::nodes(&contracts);
    let mut observer = isolated::frontier_observer(
        &continuation,
        Some(initial),
        &ledger,
        &owned,
        &fence.terminal,
    );
    let mut mapper = AdkEventMapper::new(ledger.run_id.as_str(), "shared").unwrap();
    let mut artifacts = LoopLedgerStore::artifact_store(&ledger.path).unwrap();
    graph
        .invoke_observed_with_frontier(
            state,
            ExecutionConfig::new(ledger.run_id.as_str()),
            &mut mapper,
            &mut artifacts,
            &mut observer,
        )
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3, "A-B-A must make a fresh third request");
    assert_eq!(requests[0].contents.len(), 3);
    assert_eq!(requests[1].contents.len(), 5);
    assert_eq!(requests[2].contents.len(), 7);
    let last = serde_json::to_string(&requests[2].contents).unwrap();
    assert_eq!(last.matches("insufficient").count(), 1);
    assert_eq!(last.matches("new mapped evidence").count(), 2);
    assert!(!last.contains("private-canary"));
    assert_eq!(
        last.matches("Return only").count(),
        1,
        "instruction stays invocation-local"
    );
    assert_eq!(ledger.shared_history().unwrap().turns.len(), 3);
    assert!(valid_loop_state(&ledger.snapshot("work").unwrap()));
    validate(&ledger, &contracts).unwrap();
}
