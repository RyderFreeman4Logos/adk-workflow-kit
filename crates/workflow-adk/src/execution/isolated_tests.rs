use super::*;

struct Fixture {
    root: PathBuf,
    ledger: Arc<LoopLedgerStore>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct CountAgent(Arc<AtomicU64>);

struct ParallelAgent {
    node: &'static str,
    ledger: Arc<LoopLedgerStore>,
    calls: Arc<AtomicU64>,
}

#[async_trait]
impl Agent for ParallelAgent {
    fn name(&self) -> &str {
        self.node
    }
    fn description(&self) -> &str {
        "whole-frontier admission control"
    }
    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }
    fn capabilities(&self) -> adk_rust::AgentCapabilities {
        adk_rust::AgentCapabilities {
            shared_state: true,
            ..Default::default()
        }
    }
    async fn run(
        &self,
        _: Arc<dyn adk_rust::InvocationContext>,
    ) -> adk_rust::Result<adk_rust::EventStream> {
        if self.node != "start" {
            for node in ["left", "right"] {
                assert_eq!(
                    self.ledger.snapshot(node).unwrap().invocation.unwrap().step,
                    1,
                    "both distinct node owners must exist before either agent enters"
                );
            }
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Box::pin(adk_rust::futures::stream::iter([
            restored_finish_event(self.node, json!("accepted")),
        ])))
    }
}

#[tokio::test]
async fn parallel_frontier_is_owned_before_either_agent_enters() {
    let (root, ledger) = super::super::execution_registry_tests::fanout_ledger();
    let fixture = Fixture { root, ledger };
    let plan = workflow_compiler::compile_str(
        "parallel.toml",
        r#"
schema_version = 1
[workflow]
id = "isolated-parallel"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "agent"
[[nodes]]
id = "left"
kind = "agent"
[[nodes]]
id = "right"
kind = "agent"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "start"
to = "left"
[[edges]]
from = "start"
to = "right"
[[edges]]
from = "left"
to = "done"
[[edges]]
from = "right"
to = "done"
"#,
    )
    .unwrap();
    let continuation = Arc::new(GraphCheckpointMemory::default());
    let calls = Arc::new(AtomicU64::new(0));
    let agents = ["start", "left", "right"]
        .into_iter()
        .map(|node| {
            (
                node.to_owned(),
                Arc::new(ParallelAgent {
                    node,
                    ledger: fixture.ledger.clone(),
                    calls: calls.clone(),
                }) as Arc<dyn Agent>,
            )
        })
        .collect();
    let graph = AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &plan,
            &agents,
            None,
            &Value::Null,
            Some(continuation.clone()),
        )
        .unwrap();
    let terminal = Mutex::new(None);
    let isolated = BTreeSet::from(["left".into(), "right".into()]);
    let initial = Checkpoint::new(
        fixture.ledger.run_id.as_str(),
        State::new(),
        0,
        vec!["start".into()],
    );
    let mut observer = frontier_observer(
        &continuation,
        Some(initial),
        &fixture.ledger,
        &isolated,
        &terminal,
    );
    let mut mapper = AdkEventMapper::new(fixture.ledger.run_id.as_str(), "parallel").unwrap();
    let mut artifacts = LoopLedgerStore::artifact_store(&fixture.ledger.path).unwrap();
    graph
        .invoke_observed_with_frontier(
            State::new(),
            ExecutionConfig::new(fixture.ledger.run_id.as_str()),
            &mut mapper,
            &mut artifacts,
            &mut observer,
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 3);
}

#[async_trait]
impl Agent for CountAgent {
    fn name(&self) -> &str {
        "left"
    }
    fn description(&self) -> &str {
        "admission counter"
    }
    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }
    fn capabilities(&self) -> adk_rust::AgentCapabilities {
        adk_rust::AgentCapabilities {
            shared_state: true,
            ..Default::default()
        }
    }
    async fn run(
        &self,
        _: Arc<dyn adk_rust::InvocationContext>,
    ) -> adk_rust::Result<adk_rust::EventStream> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(Box::pin(adk_rust::futures::stream::iter([
            restored_finish_event("left", json!("accepted")),
        ])))
    }
}

#[tokio::test]
async fn frontier_save_failure_blocks_execution_and_preserves_matching_generation() {
    let (root, ledger) = super::super::execution_registry_tests::fanout_ledger();
    let fixture = Fixture { root, ledger };
    let ledger = &fixture.ledger;
    let store =
        SqliteCheckpointStore::open(&ledger.checkpoint_path, ledger.checkpoint_manifest.clone())
            .unwrap();
    let prior = store.load_latest(&ledger.run_id).unwrap().unwrap();
    let checkpoint = Arc::new(GraphCheckpointMemory::default());
    assert!(checkpoint.restore(Checkpoint::new(
        ledger.run_id.as_str(),
        State::new(),
        0,
        vec!["left".into()]
    )));
    let plan = workflow_compiler::compile_str(
        "isolated.toml",
        r#"
schema_version = 1
[workflow]
id = "isolated"
version = "1"
entry = "left"
[[nodes]]
id = "left"
kind = "agent"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "left"
to = "done"
"#,
    )
    .unwrap();
    let counter = Arc::new(AtomicU64::new(0));
    let graph = AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &plan,
            &BTreeMap::from([(
                "left".into(),
                Arc::new(CountAgent(Arc::clone(&counter))) as Arc<dyn Agent>,
            )]),
            None,
            &Value::Null,
            Some(checkpoint.clone()),
        )
        .unwrap();
    let isolated = BTreeSet::from(["left".into()]);
    let mut artifacts = FilesystemArtifactStore::try_new(
        fixture.root.join("artifacts"),
        NonZeroU64::new(65536).unwrap(),
        NonZeroU64::new(65536).unwrap(),
    )
    .unwrap();
    let connection = rusqlite::Connection::open(&ledger.checkpoint_path).unwrap();
    for fail in ["artifact", "event", "checkpoint", "none"] {
        let sink = fixture.root.join("events.jsonl").with_extension("tmp");
        let artifact_root = fixture.root.join("artifacts");
        let retained = fixture.root.join("retained-artifacts");
        if fail == "artifact" {
            fs::rename(&artifact_root, &retained).unwrap();
            fs::write(&artifact_root, b"not a directory").unwrap();
        }
        if fail == "event" {
            fs::create_dir(&sink).unwrap();
        }
        if fail == "checkpoint" {
            connection.execute_batch("CREATE TRIGGER reject_frontier BEFORE INSERT ON kit_checkpoints BEGIN SELECT RAISE(ABORT, 'test checkpoint refusal'); END;").unwrap();
        }
        let terminal = Mutex::new(None);
        let mut observer = frontier_observer(&checkpoint, None, ledger, &isolated, &terminal);
        let mut mapper = AdkEventMapper::new(ledger.run_id.as_str(), "isolated").unwrap();
        let result = graph
            .invoke_observed_with_frontier(
                State::new(),
                ExecutionConfig::new(ledger.run_id.as_str()),
                &mut mapper,
                &mut artifacts,
                &mut observer,
            )
            .await;
        if fail == "none" {
            assert!(
                result.is_ok(),
                "valid checkpoint permits execution: {result:?}"
            );
            assert_eq!(counter.load(Ordering::Relaxed), 1);
            assert_eq!(ledger.snapshot("left").unwrap().invocation.unwrap().step, 0);
        } else {
            assert!(result.is_err(), "{fail} refusal must stop graph");
            assert_eq!(
                *terminal.lock().unwrap(),
                Some(ExecutionErrorKind::Persistence)
            );
            assert_eq!(
                counter.load(Ordering::Relaxed),
                0,
                "no node/provider/tool entry after {fail} refusal"
            );
            assert!(ledger.snapshot("left").unwrap().invocation.is_none());
            assert!(
                ledger.durable_nodes.lock().unwrap()["left"]
                    .invocation
                    .is_none()
            );
            let saved = store.load_latest(&ledger.run_id).unwrap().unwrap();
            assert_eq!(
                saved.state(),
                prior.state(),
                "old checkpoint stays authoritative"
            );
            if fail == "artifact" {
                fs::remove_file(&artifact_root).unwrap();
                fs::rename(&retained, &artifact_root).unwrap();
            }
            let reopened = LoopLedgerStore::open(
                ledger.path.clone(),
                ledger.checkpoint_path.clone(),
                ledger.checkpoint_identity.clone(),
                ledger.checkpoint_manifest.clone(),
                ledger.run_id.clone(),
                &checkpoint_ledger_digest(saved.state()).unwrap(),
                true,
            )
            .unwrap();
            assert!(reopened.snapshot("left").unwrap().invocation.is_none());
        }
        if fail == "event" {
            fs::remove_dir(sink).unwrap();
        }
        if fail == "checkpoint" {
            connection
                .execute_batch("DROP TRIGGER reject_frontier;")
                .unwrap();
        }
    }
}

#[test]
fn whole_frontier_owns_parallel_nodes_and_rejects_unproved_resume_owner() {
    let (root, ledger) = super::super::execution_registry_tests::fanout_ledger();
    let fixture = Fixture { root, ledger };
    let ledger = &fixture.ledger;
    let checkpoint = Checkpoint::new(
        ledger.run_id.as_str(),
        State::new(),
        3,
        vec!["left".into(), "right".into()],
    );
    let mapper = AdkEventMapper::new(ledger.run_id.as_str(), "isolated").unwrap();
    let isolated = BTreeSet::from(["left".into(), "right".into()]);
    ledger
        .admit_frontier(&checkpoint, &isolated, &mapper, &ledger.artifacts)
        .unwrap();
    let saved =
        SqliteCheckpointStore::open(&ledger.checkpoint_path, ledger.checkpoint_manifest.clone())
            .unwrap()
            .load_latest(&ledger.run_id)
            .unwrap()
            .unwrap();
    for node in ["left", "right"] {
        let state = ledger.snapshot(node).unwrap();
        assert_eq!(state.invocation.unwrap().step, 3);
    }
    validate_checkpoint(ledger, &saved, &isolated).unwrap();
    for missing in [false, true] {
        let mut states = ledger.nodes.lock().unwrap();
        let state = states.get_mut("right").unwrap();
        if missing {
            state.invocation = None;
            state.model_iterations = 1;
        } else {
            state.invocation.as_mut().unwrap().step = 4;
        }
        drop(states);
        assert_eq!(
            validate_checkpoint(ledger, &saved, &isolated)
                .unwrap_err()
                .kind(),
            ExecutionErrorKind::InvalidRunState
        );
    }
}

#[test]
fn segment_preserves_cumulative_proof_and_only_reconstructs_current_skill_calls() {
    let old =
        Content::new("assistant").with_text(r#"{"status":"finished","output":"old-private"}"#);
    let mut state = LoopState {
        conversation: vec![Content::new("user").with_text("old input"), old],
        model_iterations: 1,
        invocation: Some(Invocation {
            step: 3,
            conversation_start: 2,
            model_iteration_start: 1,
        }),
        ..Default::default()
    };
    let mut request = LlmRequest::new(
        "fixture",
        vec![Content::new("user").with_text("current mapped input")],
    );
    prepare_request(&mut state, &mut request).unwrap();
    assert_eq!(request.contents.len(), 1);
    assert_eq!(state.conversation.len(), 3);
    assert!(valid_loop_state(&state));
    let mut invalid = state.clone();
    invalid.invocation.as_mut().unwrap().conversation_start = 1;
    assert!(
        !valid_loop_state(&invalid),
        "cursor cannot erase cumulative finish accounting"
    );
    let call = |iteration| PendingCall {
        id: format!("call-{iteration}"),
        name: "activate_skill".into(),
        args: json!({}),
        fingerprint: "fingerprint".into(),
        model_iteration: iteration,
        admission_ordinal: iteration,
        response: None,
        effect: None,
    };
    assert!(!current_call(&state, &call(1)));
    assert!(current_call(&state, &call(2)));
    state.conversation.clear();
    state.invocation.as_mut().unwrap().conversation_start = 0;
    state.conversation.push(tool_call_content(&call(2)));
    state.conversation_reconstructed = true;
    prepare_request(&mut state, &mut request).unwrap();
    assert_eq!(request.contents.len(), 2);
    assert_eq!(
        request.contents[0].parts,
        vec![adk_rust::Part::Text {
            text: "current mapped input".into()
        }]
    );
    assert!(
        matches!(&request.contents[1].parts[0], adk_rust::Part::FunctionCall { id: Some(id), .. } if id == "call-2")
    );
}
