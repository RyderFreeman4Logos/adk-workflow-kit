use super::*;
use workflow_runtime::InMemoryArtifactStore;

struct Fixture {
    root: PathBuf,
    ledger: Arc<LoopLedgerStore>,
}
impl Fixture {
    fn new() -> Self {
        let (root, ledger) = super::super::execution_registry_tests::fanout_ledger();
        Self { root, ledger }
    }
    fn mapper(&self) -> AdkEventMapper {
        let mut mapper = AdkEventMapper::new(self.ledger.run_id.as_str(), "audit").unwrap();
        mapper.bind_tool_audit(Arc::clone(&self.ledger.tool_audit_ids));
        mapper
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn artifacts() -> InMemoryArtifactStore {
    InMemoryArtifactStore::new(
        NonZeroU64::new(65536).unwrap(),
        NonZeroU64::new(65536).unwrap(),
    )
}
fn call(id: &str, query: &str, ordinal: u64) -> PendingCall {
    let args = json!({"query":query});
    PendingCall {
        id: id.into(),
        name: "search_code".into(),
        fingerprint: workflow_runtime::argument_fingerprint(&args),
        args,
        model_iteration: 1,
        admission_ordinal: ordinal,
        response: Some(json!({"found":true,"api_key":"PRIVATE-CANARY"})),
        effect: None,
    }
}
fn state(calls: &[PendingCall], pending: &[PendingCall]) -> LoopState {
    let all = calls.iter().chain(pending);
    let mut content = Content {
        role: "model".into(),
        parts: Vec::new(),
    };
    for call in all.clone() {
        content.parts.extend(tool_call_content(call).parts);
    }
    let mut conversation = vec![content];
    for call in calls {
        conversation.push(tool_response_content(call, call.response.clone().unwrap()));
    }
    let mut tool_calls = BTreeMap::new();
    for call in all.clone() {
        *tool_calls.entry(call.name.clone()).or_insert(0) += 1;
    }
    let state = LoopState {
        model_iterations: 1,
        total_tool_calls: all.clone().count() as u64,
        tool_calls,
        seen_ids: all.clone().map(|call| call.id.clone()).collect(),
        seen_calls: all
            .map(|call| (call.name.clone(), call.fingerprint.clone()))
            .collect(),
        tool_output_bytes: calls
            .iter()
            .map(|call| {
                serde_json::to_vec(call.response.as_ref().unwrap())
                    .unwrap()
                    .len() as u64
            })
            .sum(),
        completed_calls: calls
            .iter()
            .cloned()
            .map(|call| {
                if matches!(
                    call.name.as_str(),
                    "activate_skill" | "read_skill_resource" | "run_skill_script"
                ) {
                    CompletedCall::Skill(call)
                } else {
                    CompletedCall::Ordinary(call)
                }
            })
            .collect(),
        pending_calls: pending
            .iter()
            .cloned()
            .map(|mut call| {
                call.response = None;
                call
            })
            .collect(),
        conversation,
        ..LoopState::default()
    };
    assert!(valid_loop_state(&state), "valid seeded admission");
    state
}
fn complete(
    mapper: &mut AdkEventMapper,
    node: &str,
    calls: &[PendingCall],
    artifacts: &mut InMemoryArtifactStore,
) {
    let mut event = adk_rust::Event::new("audit");
    let parts = calls
        .iter()
        .flat_map(|call| tool_response_content(call, call.response.clone().unwrap()).parts)
        .collect();
    event.llm_response.content = Some(Content {
        role: "user".into(),
        parts,
    });
    mapper.map_adk_event(node.into(), event, artifacts).unwrap();
}
fn count(mapper: &AdkEventMapper, kind: WorkflowRuntimeEventKindV1) -> usize {
    mapper
        .events()
        .iter()
        .filter(|event| event.kind() == kind)
        .count()
}

#[test]
fn durable_completion_contract() {
    let a = call("predictable-a", "alpha", 1);
    let b = call("predictable-b", "beta", 2);
    let c = call("pending-c", "pending", 3);
    // Equal event count is not equal identity: B exists before A, same tool.
    let f = Fixture::new();
    f.ledger
        .replace(
            "left",
            state(&[a.clone(), b.clone()], std::slice::from_ref(&c)),
        )
        .unwrap();
    f.ledger
        .replace("right", state(std::slice::from_ref(&a), &[]))
        .unwrap();
    let mut mapper = f.mapper();
    let mut store = artifacts();
    complete(&mut mapper, "left", std::slice::from_ref(&b), &mut store);
    reconcile(&f.ledger, &mut mapper, &mut store).unwrap();
    assert_eq!(
        count(&mapper, WorkflowRuntimeEventKindV1::ToolCompleted),
        3,
        "exact per-node completed set"
    );
    assert_eq!(
        count(&mapper, WorkflowRuntimeEventKindV1::ToolRequested),
        3,
        "pending never projected"
    );
    let prior = mapper.events().to_vec();
    reconcile(&f.ledger, &mut mapper, &mut store).unwrap();
    assert_eq!(
        mapper.events(),
        prior,
        "repeated reconciliation has no effects"
    );
    // Identity allocation precedes publication: truncate the LOG, retain ledger,
    // reopen the verified generation and replace only the missing event subset.
    let committed = f.ledger.durable_nodes.lock().unwrap().clone();
    let opened = LoopLedgerStore::open(
        f.root.join(LOOP_LEDGER_FILE),
        f.ledger.checkpoint_path.clone(),
        f.ledger.checkpoint_identity.clone(),
        f.ledger.checkpoint_manifest.clone(),
        f.ledger.run_id.clone(),
        &loop_ledger_digest(&committed).unwrap(),
        true,
    )
    .unwrap();
    let mut resumed =
        AdkEventMapper::resume(opened.run_id.as_str(), "audit", prior[..1].to_vec()).unwrap();
    reconcile(&opened, &mut resumed, &mut store).unwrap();
    assert_eq!(
        count(&resumed, WorkflowRuntimeEventKindV1::ToolCompleted),
        3
    );
    let resumed_prior = resumed.events().to_vec();
    reconcile(&opened, &mut resumed, &mut store).unwrap();
    assert_eq!(resumed.events(), resumed_prior);
    let serialized = serde_json::to_string(resumed.events()).unwrap();
    assert!(!serialized.contains("PRIVATE-CANARY"));
    for event in resumed
        .events()
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolCompleted)
    {
        assert!(!event.event_id().contains("predictable"));
        assert!(!event.payload().to_string().contains("tool_call_id"));
        assert!(!event.payload().to_string().contains("argument_fingerprint"));
    }
    // A multi-result event stays ONE event; its complete membership prevents
    // either member being emitted again as a single-call compensation.
    let mut group = f.mapper();
    complete(&mut group, "left", &[b.clone(), a.clone()], &mut store);
    assert_eq!(count(&group, WorkflowRuntimeEventKindV1::ToolCompleted), 1);
    reconcile(&f.ledger, &mut group, &mut store).unwrap();
    assert_eq!(count(&group, WorkflowRuntimeEventKindV1::ToolCompleted), 2);
    let mut wrong_node = AdkEventMapper::new(f.ledger.run_id.as_str(), "audit").unwrap();
    wrong_node
        .map(
            AdkRuntimeObservationV1::new(
                group.events()[0].event_id(),
                "audit",
                AdkRuntimeObservationKindV1::ToolCompleted,
            )
            .with_node_id("right"),
        )
        .unwrap();
    assert_eq!(
        validate_existing(&f.ledger, &wrong_node, &store)
            .unwrap_err()
            .kind(),
        ExecutionErrorKind::InvalidRunState
    );
    // A bare historical completion is unprovable for unfinished work. Finished
    // legacy nodes, which cannot replay, retain their unchanged prior sequence.
    let mut legacy = AdkEventMapper::new(f.ledger.run_id.as_str(), "audit").unwrap();
    legacy
        .map(
            AdkRuntimeObservationV1::new(
                "old-sdk-event",
                "audit",
                AdkRuntimeObservationKindV1::ToolCompleted,
            )
            .with_node_id("left"),
        )
        .unwrap();
    assert_eq!(
        validate_existing(&f.ledger, &legacy, &store)
            .unwrap_err()
            .kind(),
        ExecutionErrorKind::InvalidRunState
    );
    {
        let mut nodes = f.ledger.durable_nodes.lock().unwrap();
        let left = nodes.get_mut("left").unwrap();
        left.finish_admitted = true;
        left.completion_event_ids.clear();
        left.completion_event_outputs.clear();
    }
    assert!(validate_existing(&f.ledger, &legacy, &store).is_ok());
}

#[test]
fn failed_persistence_never_publishes_completion() {
    let f = Fixture::new();
    let mut store = artifacts();
    let mut mapper = f.mapper();
    let a = call("a", "alpha", 1);
    f.ledger
        .replace("left", state(&[], std::slice::from_ref(&a)))
        .unwrap();
    // Fail the real atomic ledger replacement after the live node is mutated.
    fs::create_dir(f.ledger.path.with_extension("tmp")).unwrap();
    assert_eq!(
        f.ledger
            .replace("left", state(&[a], &[]))
            .unwrap_err()
            .kind(),
        ExecutionErrorKind::Persistence
    );
    assert_eq!(
        f.ledger.snapshot("left").unwrap().completed_calls.len(),
        1,
        "real live mutation witness"
    );
    reconcile(&f.ledger, &mut mapper, &mut store).unwrap();
    assert_eq!(
        count(&mapper, WorkflowRuntimeEventKindV1::ToolCompleted),
        0,
        "only last durable pending remains"
    );
    assert!(f.ledger.tool_audit_ids.lock().unwrap().is_empty());
    assert!(
        f.ledger.durable_nodes.lock().unwrap()["left"]
            .completion_event_outputs
            .is_empty()
    );
    // The ledger file can advance while checkpoint INSERT fails. Its unbound
    // generation still cannot become a completion proof in memory or on open.
    let g = Fixture::new();
    let a = call("checkpoint-failure", "alpha", 1);
    g.ledger
        .replace("left", state(&[], std::slice::from_ref(&a)))
        .unwrap();
    let generation = g.ledger.durable_nodes.lock().unwrap().clone();
    let db = rusqlite::Connection::open(&g.ledger.checkpoint_path).unwrap();
    db.execute_batch("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON kit_checkpoints BEGIN SELECT RAISE(FAIL, 'fixture checkpoint failure'); END;").unwrap();
    assert_eq!(
        g.ledger
            .replace("left", state(&[a], &[]))
            .unwrap_err()
            .kind(),
        ExecutionErrorKind::Persistence
    );
    let disk: LoopLedgerV1 = serde_json::from_slice(&fs::read(&g.ledger.path).unwrap()).unwrap();
    assert_eq!(
        disk.nodes["left"].completed_calls.len(),
        1,
        "ledger write really preceded checkpoint failure"
    );
    let reopened = LoopLedgerStore::open(
        g.ledger.path.clone(),
        g.ledger.checkpoint_path.clone(),
        g.ledger.checkpoint_identity.clone(),
        g.ledger.checkpoint_manifest.clone(),
        g.ledger.run_id.clone(),
        &loop_ledger_digest(&generation).unwrap(),
        true,
    )
    .unwrap();
    let mut mapper = g.mapper();
    reconcile(&g.ledger, &mut mapper, &mut store).unwrap();
    reconcile(&reopened, &mut mapper, &mut store).unwrap();
    assert_eq!(count(&mapper, WorkflowRuntimeEventKindV1::ToolCompleted), 0);
    assert!(g.ledger.tool_audit_ids.lock().unwrap().is_empty());
    assert!(
        !disk.nodes["left"].completion_event_outputs.is_empty(),
        "unconfirmed disk generation really has the projection"
    );
    for ledger in [g.ledger.as_ref(), &reopened] {
        let nodes = ledger.durable_nodes.lock().unwrap();
        assert!(nodes["left"].completion_event_ids.is_empty());
        assert!(
            nodes["left"].completion_event_outputs.is_empty(),
            "unconfirmed projection is never published"
        );
    }
}

#[test]
fn audit_binding_integrity_and_payload_limits() {
    let a = call("a", "alpha", 1);
    let b = call("b", "beta", 2);
    let mut nodes = BTreeMap::from([("left".into(), state(&[a.clone(), b], &[]))]);
    prepare(&mut nodes, &BTreeMap::new()).unwrap();
    assert!(unique_tokens(&nodes));
    let baseline = nodes.clone();
    let mut legacy = baseline.clone();
    legacy.get_mut("left").unwrap().completion_event_ids.clear();
    legacy
        .get_mut("left")
        .unwrap()
        .completion_event_outputs
        .clear();
    let prior_legacy = legacy.clone();
    prepare(&mut legacy, &prior_legacy).unwrap();
    assert!(
        legacy["left"].completion_event_ids.is_empty(),
        "unrelated saves preserve unlinked legacy facts"
    );
    prepare(&mut nodes, &baseline).unwrap();
    assert_eq!(
        nodes["left"].completion_event_ids,
        baseline["left"].completion_event_ids
    );
    nodes.get_mut("left").unwrap().completed_calls[0]
        .call_mut()
        .fingerprint = "different".into();
    prepare(&mut nodes, &baseline).unwrap();
    assert_ne!(
        nodes["left"].completion_event_ids["a"], baseline["left"].completion_event_ids["a"],
        "full admission identity"
    );
    let token = baseline["left"].completion_event_ids["a"].clone();
    nodes
        .get_mut("left")
        .unwrap()
        .completion_event_ids
        .insert("b".into(), token.clone());
    nodes
        .get_mut("left")
        .unwrap()
        .completion_event_ids
        .insert("a".into(), token);
    assert!(!valid_bindings(&nodes["left"]));
    let mut pending = state(&[], &[a]);
    pending.completion_event_ids = baseline["left"].completion_event_ids.clone();
    assert!(
        !valid_bindings(&pending),
        "pending/unknown identities rejected"
    );
    let f = Fixture::new();
    let mut large = call("large", "large", 1);
    large.response = Some(json!({"text":"x".repeat(10000),"api_key":"PRIVATE-CANARY"}));
    f.ledger.replace("left", state(&[large], &[])).unwrap();
    let mut mapper = f.mapper();
    let artifact_root = f.root.join("artifacts");
    let open = |cap| {
        workflow_runtime::FilesystemArtifactStore::new(
            &artifact_root,
            NonZeroU64::new(cap).unwrap(),
            NonZeroU64::new(cap).unwrap(),
        )
    };
    let mut store = open(65536);
    reconcile(&f.ledger, &mut mapper, &mut store).unwrap();
    let completion = mapper
        .events()
        .iter()
        .find(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolCompleted)
        .unwrap();
    assert!(completion.payload().get("artifact_reference").is_some());
    assert!(!completion.payload().to_string().contains("PRIVATE-CANARY"));
    assert!(serde_json::to_vec(completion.payload()).unwrap().len() < 4096);
    let length = completion.payload()["artifact_reference"]["byte_len"]
        .as_u64()
        .unwrap();
    let before = serde_json::to_vec(mapper.events()).unwrap();
    assert_eq!(
        validate_existing(&f.ledger, &mapper, &open(length - 1))
            .unwrap_err()
            .kind(),
        ExecutionErrorKind::InvalidRunState
    );
    assert_eq!(serde_json::to_vec(mapper.events()).unwrap(), before);
    let mut exact = open(length);
    validate_existing(&f.ledger, &mapper, &exact).unwrap();
    reconcile(&f.ledger, &mut mapper, &mut exact).unwrap();
    reconcile(&f.ledger, &mut mapper, &mut exact).unwrap();
    assert_eq!(serde_json::to_vec(mapper.events()).unwrap(), before);
}

#[test]
fn redacted_generation_keeps_original_identity_without_arguments() {
    let mut f = Fixture::new();
    Arc::get_mut(&mut f.ledger).unwrap().persist_raw_loop_state = false;
    let a = call("redacted-a", "PRIVATE-QUERY-CANARY", 1);
    f.ledger
        .replace("left", state(std::slice::from_ref(&a), &[]))
        .unwrap();
    let nodes = f.ledger.durable_nodes.lock().unwrap().clone();
    assert!(nodes["left"].conversation.is_empty());
    assert_eq!(
        nodes["left"].completed_calls[0].call().fingerprint,
        a.fingerprint
    );
    let reopened = LoopLedgerStore::open(
        f.ledger.path.clone(),
        f.ledger.checkpoint_path.clone(),
        f.ledger.checkpoint_identity.clone(),
        f.ledger.checkpoint_manifest.clone(),
        f.ledger.run_id.clone(),
        &loop_ledger_digest(&nodes).unwrap(),
        false,
    )
    .unwrap();
    let mut mapper = f.mapper();
    let mut store = artifacts();
    reconcile(&reopened, &mut mapper, &mut store).unwrap();
    assert_eq!(count(&mapper, WorkflowRuntimeEventKindV1::ToolCompleted), 1);
    assert_eq!(count(&mapper, WorkflowRuntimeEventKindV1::ToolRequested), 1);
    assert!(
        !serde_json::to_string(mapper.events())
            .unwrap()
            .contains("PRIVATE-QUERY-CANARY")
    );
    assert!(
        !serde_json::to_string(mapper.events())
            .unwrap()
            .contains("PRIVATE-CANARY")
    );
}

struct EntryCounter {
    entries: Arc<AtomicU64>,
    effect: PathBuf,
}
impl ToolHandler for EntryCounter {
    fn execute(
        &self,
        _sandbox: &workflow_runtime::ChildSandbox<'_>,
        _context: &ToolCallContext,
        _arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        self.entries.fetch_add(1, Ordering::SeqCst);
        fs::write(
            &self.effect,
            self.entries.load(Ordering::SeqCst).to_string(),
        )
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        Ok(ToolEnvelope::success(
            json!({"found":true}),
            ToolProvenance::new("search_code", "1"),
        ))
    }
    fn implementation_identity(&self) -> String {
        "audit-entry-counter-v1".into()
    }
    fn registration(&self) -> Option<ToolRegistration> {
        Some(
            ToolRegistration::for_types::<Value, Value>(
                "search_code",
                ToolProvenance::new("search_code", "1"),
                ToolFlags::new(true, true, true),
            )
            .unwrap(),
        )
    }
}
fn public_run(
    f: &Fixture,
    id: &str,
) -> (ExecutionReceipt, ToolImplementationRegistry, Arc<AtomicU64>) {
    let workflow = f.root.join("workflow.toml");
    fs::write(
        &workflow,
        r#"
schema_version=1
[workflow]
id="audit-public"
version="1"
entry="work"
[[nodes]]
id="work"
kind="agent"
model={role="worker",id="worker",version="1"}
tools=[{id="search_code",version="1"}]
[[nodes]]
id="done"
kind="terminal"
[[edges]]
from="work"
to="done"
"#,
    )
    .unwrap();
    let entries = Arc::new(AtomicU64::new(0));
    let mut implementations = ToolImplementationRegistry::new();
    implementations
        .register(
            "search_code",
            "1",
            Arc::new(EntryCounter {
                entries: entries.clone(),
                effect: f.root.join("handler-effect"),
            }),
        )
        .unwrap();
    let profile = ExecutionProfileV1::parse(
        &serde_json::to_vec(&json!({
            "schema_version":1,
            "model":{"provider":"fake","name":"worker","version":"1","model":"worker","responses":[
                {"calls":[{"id":id,"name":"search_code","args":{"query":"alpha"}}]},
                "{\"status\":\"finished\",\"output\":{\"answer\":\"done\"}}"
            ]},
            "tools":[{"name":"search_code","custom":true,"input_schema":{"type":"object"}}],
            "sandbox":{"capabilities":[]}
        }))
        .unwrap(),
    )
    .unwrap();
    let receipt = ExecutionBackend::run_with_implementations(
        &workflow,
        profile,
        json!({}),
        &f.root,
        &implementations,
    )
    .unwrap();
    assert_eq!(
        entries.load(Ordering::SeqCst),
        1,
        "real handler positive control"
    );
    (receipt, implementations, entries)
}
fn public_ledger(receipt: &ExecutionReceipt) -> LoopLedgerStore {
    let (_, manifest) = find_run(receipt.run_root().parent().unwrap(), receipt.run_id()).unwrap();
    let manifest = manifest.checkpoint_manifest.unwrap();
    let run = RunId::new(receipt.run_id().to_owned()).unwrap();
    let checkpoint = SqliteCheckpointStore::open(
        receipt.run_root().join("checkpoint.sqlite"),
        manifest.clone(),
    )
    .unwrap()
    .load_latest(&run)
    .unwrap()
    .unwrap();
    LoopLedgerStore::open(
        receipt.run_root().join(LOOP_LEDGER_FILE),
        receipt.run_root().join("checkpoint.sqlite"),
        ledger_checkpoint_identity(&manifest).unwrap(),
        manifest,
        run,
        &checkpoint_ledger_digest(checkpoint.state()).unwrap(),
        true,
    )
    .unwrap()
}

#[test]
fn r1_legacy_resume_rejects_before_replay_entry() {
    let f = Fixture::new();
    let (receipt, implementations, entries) = public_run(&f, "a");
    let ledger = public_ledger(&receipt);
    let nodes = BTreeMap::from([(
        "work".into(),
        state(&[call("a", "alpha", 1)], &[call("b", "beta", 2)]),
    )]);
    ledger
        .persist_ledger_with_checkpoint_generation(&nodes)
        .unwrap();
    let initial = Checkpoint::new(receipt.run_id(), State::new(), 0, vec!["work".into()]);
    let mut checkpoint = checkpoint_state(State::new(), &initial, None).unwrap();
    LoopLedgerStore::bind_digest(&mut checkpoint, &nodes).unwrap();
    SqliteCheckpointStore::open(&ledger.checkpoint_path, ledger.checkpoint_manifest.clone())
        .unwrap()
        .save_checkpoint(
            DurableCheckpointV1::new(
                ledger.run_id.clone(),
                "work",
                0,
                serde_json::to_vec(&checkpoint).unwrap(),
                BTreeSet::<String>::new(),
            )
            .unwrap(),
        )
        .unwrap();
    fs::write(receipt.run_root().join("events.jsonl"), b"").unwrap();
    let manifest_path = receipt.run_root().join("run-manifest.json");
    let mut manifest: RunManifestV2 =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest.status = "running".into();
    write_json(&manifest_path, &manifest).unwrap();
    let paths = [
        ledger.path.clone(),
        f.root.join("handler-effect"),
        receipt.run_root().join("effects.sqlite"),
        receipt.run_root().join("events.jsonl"),
    ];
    let before = paths.each_ref().map(|path| fs::read(path).unwrap());
    assert_eq!(
        public_ledger(&receipt)
            .snapshot("work")
            .unwrap()
            .pending_calls
            .len(),
        1,
        "real valid old checkpoint with pending replay"
    );
    let error =
        ExecutionBackend::resume_with_implementations(&f.root, receipt.run_id(), &implementations)
            .unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(
        entries.load(Ordering::SeqCst),
        1,
        "reject before pending B handler entry"
    );
    assert_eq!(
        paths.each_ref().map(|path| fs::read(path).unwrap()),
        before,
        "no ledger/effect/event mutation before refusal"
    );

    let g = Fixture::new();
    let (finished, implementations, entries) = public_run(&g, "finished");
    let ledger = public_ledger(&finished);
    let mut nodes = ledger.durable_nodes.lock().unwrap().clone();
    nodes.get_mut("work").unwrap().completion_event_ids.clear();
    nodes
        .get_mut("work")
        .unwrap()
        .completion_event_outputs
        .clear();
    ledger
        .persist_ledger_with_checkpoint_generation(&nodes)
        .unwrap();
    ledger.sync_checkpoint(&nodes).unwrap();
    let path = finished.run_root().join("events.jsonl");
    let mut events: Vec<workflow_runtime::WorkflowRuntimeEventV1> = read_events(&path).unwrap();
    for event in &mut events {
        if event.kind() == WorkflowRuntimeEventKindV1::ToolCompleted {
            let mut wire = serde_json::to_value(&*event).unwrap();
            wire["event_id"] = json!("legacy-finished-completion");
            *event = serde_json::from_value(wire).unwrap();
        }
    }
    write_events(&path, &events).unwrap();
    assert_eq!(
        ExecutionBackend::resume_with_implementations(&g.root, finished.run_id(), &implementations)
            .unwrap()
            .status(),
        "succeeded"
    );
    assert_eq!(
        entries.load(Ordering::SeqCst),
        1,
        "finished legacy never replays"
    );
}

#[test]
fn r2_artifact_requests_are_idempotent() {
    for (normal, grouped) in [(true, false), (true, true), (false, false)] {
        let f = Fixture::new();
        let calls = if grouped {
            (0..20)
                .map(|i| call(&format!("{i}-{}", "x".repeat(250)), &format!("q{i}"), i + 1))
                .collect::<Vec<_>>()
        } else {
            vec![call(&"x".repeat(5000), "alpha", 1)]
        };
        f.ledger.replace("left", state(&calls, &[])).unwrap();
        let mut mapper = f.mapper();
        let mut store = artifacts();
        if normal {
            let mut event = adk_rust::Event::new("audit");
            event.set_content(Content {
                role: "model".into(),
                parts: calls
                    .iter()
                    .flat_map(|call| tool_call_content(call).parts)
                    .collect(),
            });
            mapper
                .map_adk_event("left".into(), event, &mut store)
                .unwrap();
        }
        reconcile(&f.ledger, &mut mapper, &mut store).unwrap();
        let expected = if normal { 1 } else { calls.len() };
        assert_eq!(
            count(&mapper, WorkflowRuntimeEventKindV1::ToolRequested),
            expected,
            "do not duplicate artifact-backed request attribution"
        );
        let prior = mapper.events().to_vec();
        for _ in 0..2 {
            let mut resumed =
                AdkEventMapper::resume(f.ledger.run_id.as_str(), "audit", mapper.events().to_vec())
                    .unwrap();
            resumed.bind_tool_audit(Arc::clone(&f.ledger.tool_audit_ids));
            reconcile(&f.ledger, &mut resumed, &mut store).unwrap();
            assert_eq!(resumed.events(), prior);
            mapper = resumed;
        }
    }
    let f = Fixture::new();
    let (receipt, implementations, entries) = public_run(&f, &"x".repeat(5000));
    for _ in 0..2 {
        assert_eq!(
            ExecutionBackend::resume_with_implementations(
                &f.root,
                receipt.run_id(),
                &implementations
            )
            .unwrap()
            .status(),
            "succeeded"
        );
    }
    assert_eq!(entries.load(Ordering::SeqCst), 1);
    assert_eq!(
        read_events(&receipt.run_root().join("events.jsonl"))
            .unwrap()
            .iter()
            .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolRequested)
            .count(),
        1
    );
}

#[test]
fn r3_completion_members_match_actual_projection() {
    for large in [false, true] {
        let f = Fixture::new();
        let mut a = call("a", "alpha", 1);
        let mut b = call("b", "beta", 2);
        a.response = Some(json!({"value": if large { "a".repeat(5000) } else { "a".into() }}));
        b.response = Some(json!({"value": "b"}));
        f.ledger
            .replace("left", state(&[a.clone(), b.clone()], &[]))
            .unwrap();
        let mut mapper = f.mapper();
        let mut store = artifacts();
        complete(&mut mapper, "left", &[a], &mut store);
        let tokens = f.ledger.durable_nodes.lock().unwrap()["left"]
            .completion_event_ids
            .clone();
        for encoded in [
            format!("{}.{}", tokens["a"], tokens["b"]),
            tokens["b"].clone(),
        ] {
            let mut wire = serde_json::to_value(&mapper.events()[0]).unwrap();
            wire["event_id"] = json!(format!("{TOOL_AUDIT_PREFIX}{encoded}"));
            let event = serde_json::from_value(wire).unwrap();
            let tampered =
                AdkEventMapper::resume(f.ledger.run_id.as_str(), "audit", vec![event]).unwrap();
            assert_eq!(
                validate_existing(&f.ledger, &tampered, &store)
                    .unwrap_err()
                    .kind(),
                ExecutionErrorKind::InvalidRunState,
                "ID-only substitution must not forge delivered membership"
            );
        }
    }
}

#[test]
fn r3_redacted_skill_projection_binds_actual_members() {
    for (name, large) in [
        ("activate_skill", false),
        ("activate_skill", true),
        ("run_skill_script", false),
    ] {
        let mut f = Fixture::new();
        Arc::get_mut(&mut f.ledger).unwrap().persist_raw_loop_state = false;
        let calls = ["alpha", "beta"].into_iter().enumerate().map(|(index, skill)| {
            let mut call = call(skill, skill, index as u64 + 1);
            call.name = name.into();
            call.args = if name == "run_skill_script" {
                json!({"skill_id":skill,"script_id":"answer","input":{"value":"RAW-ARGUMENT-CANARY"}})
            } else {
                json!({"skill_id":skill})
            };
            call.fingerprint = workflow_runtime::argument_fingerprint(&call.args);
            call.response = Some(json!({
                "status":"success",
                "provenance":{"tool_id":"skill.runtime","tool_version":"1"},
                "payload":{
                    "skill_id":skill,"version":"1",
                    "instructions_ref": if large {format!("sha256:{}", skill.repeat(1000))} else {format!("sha256:{skill}")},
                    "instructions":"RAW-SKILL-CANARY","value":skill,
                    "resources":[{"id":"guide","sha256":"sha256:guide","content":"RAW-RESOURCE-CANARY"}],
                },
            }));
            call
        }).collect::<Vec<_>>();
        f.ledger.replace("left", state(&calls, &[])).unwrap();
        let committed = f.ledger.durable_nodes.lock().unwrap().clone();
        assert!(
            committed["left"]
                .completed_calls
                .iter()
                .all(|call| call.call().response.is_none())
        );
        let saved = fs::read_to_string(&f.ledger.path).unwrap();
        for canary in [
            "RAW-SKILL-CANARY",
            "RAW-RESOURCE-CANARY",
            "RAW-ARGUMENT-CANARY",
        ] {
            assert!(
                !saved.contains(canary),
                "only the normal safe projection may survive"
            );
        }
        let reopened = LoopLedgerStore::open(
            f.ledger.path.clone(),
            f.ledger.checkpoint_path.clone(),
            f.ledger.checkpoint_identity.clone(),
            f.ledger.checkpoint_manifest.clone(),
            f.ledger.run_id.clone(),
            &loop_ledger_digest(&committed).unwrap(),
            false,
        )
        .unwrap();
        let mut store = artifacts();
        let mut normal = f.mapper();
        complete(&mut normal, "left", &calls, &mut store);
        validate_existing(&reopened, &normal, &store).unwrap();
        let mut synthetic = f.mapper();
        reconcile(&reopened, &mut synthetic, &mut store).unwrap();
        let results = synthetic
            .events()
            .iter()
            .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolCompleted)
            .map(|event| event_output(event, &store).unwrap().unwrap()[0].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            Value::Array(results),
            event_output(&normal.events()[0], &store).unwrap().unwrap(),
            "normal and compensated safe members agree"
        );
        let prior = synthetic.events().to_vec();
        reconcile(&reopened, &mut synthetic, &mut store).unwrap();
        assert_eq!(synthetic.events(), prior);
        let tokens = &committed["left"].completion_event_ids;
        for encoded in [
            tokens["alpha"].clone(),
            format!("{}.{}", tokens["beta"], tokens["alpha"]),
        ] {
            let mut wire = serde_json::to_value(&normal.events()[0]).unwrap();
            wire["event_id"] = json!(format!("{TOOL_AUDIT_PREFIX}{encoded}"));
            let tampered = AdkEventMapper::resume(
                f.ledger.run_id.as_str(),
                "audit",
                vec![serde_json::from_value(wire).unwrap()],
            )
            .unwrap();
            assert_eq!(
                validate_existing(&reopened, &tampered, &store)
                    .unwrap_err()
                    .kind(),
                ExecutionErrorKind::InvalidRunState,
                "omitted or reordered real skill members must not match the retained payload"
            );
        }
        let mut reversed = f.mapper();
        complete(
            &mut reversed,
            "left",
            &[calls[1].clone(), calls[0].clone()],
            &mut store,
        );
        validate_existing(&reopened, &reversed, &store).unwrap();
    }
}
