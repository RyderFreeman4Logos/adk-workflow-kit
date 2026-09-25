//! Fake provider I/O at the public spec/compiler/ADK boundary; no network.
use super::{RAW, WORKFLOW};
use adk_rust::{
    Content, Llm, LlmRequest, LlmResponse, LlmResponseStream, Part, async_trait,
    futures::stream,
    graph::prelude::{ExecutionConfig, State},
};
use serde_json::{Value, json};
use std::{
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Barrier, Notify};
use workflow_adk::{
    AdkGraph, AdkGraphTranslator,
    events::AdkEventMapper,
    model_profiles::{CredentialBroker, FakeModelProfile, ModelProfileRegistry},
};
use workflow_runtime::{ArtifactId, ArtifactStore, InMemoryArtifactStore, PageRequest};

#[derive(Clone, Copy)]
enum Mode {
    Agree,
    Fail,
    Pending,
    ToolCall,
    Oversize,
    Truncated,
    ProviderError,
    Incomplete,
}
struct Probe {
    mode: Mode,
    barrier: Arc<Barrier>,
    ready: Arc<Notify>,
    active: Arc<AtomicUsize>,
    requests: Mutex<Vec<LlmRequest>>,
}
struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
fn text(content: &Content) -> String {
    content
        .parts
        .iter()
        .filter_map(|part| {
            if let Part::Text { text } = part {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect()
}
fn frame<'a>(text: &'a str, tag: &str) -> &'a str {
    let (_, remaining) = text.split_once(&format!("{tag}_BYTES:")).unwrap();
    let (length, remaining) = remaining.split_once('\n').unwrap();
    &remaining[..length.parse::<usize>().unwrap()]
}
#[async_trait]
impl Llm for Probe {
    fn name(&self) -> &str {
        "fake"
    }
    async fn generate_content(
        &self,
        request: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<LlmResponseStream> {
        let schema: Value =
            serde_json::from_str(frame(&text(&request.contents[0]), "OUTPUT_SCHEMA_JSON")).unwrap();
        let mut content = Content::new("assistant").with_text(schema["enum"][0].to_string());
        let ordinal = {
            let mut requests = self.requests.lock().unwrap();
            let ordinal = requests.len();
            requests.push(request);
            ordinal
        };
        if matches!(self.mode, Mode::ToolCall) {
            content.parts.push(Part::FunctionCall {
                name: "forbidden-tool".into(),
                args: json!({}),
                id: None,
                thought_signature: None,
            });
        }
        if matches!(self.mode, Mode::Oversize) {
            content = Content::new("assistant").with_text("x".repeat(513));
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        let live = Live(Arc::clone(&self.active));
        let (barrier, ready, mode) = (
            Arc::clone(&self.barrier),
            Arc::clone(&self.ready),
            self.mode,
        );
        Ok(Box::pin(stream::once(async move {
            let _live = live;
            let leader = barrier.wait().await.is_leader();
            if leader {
                ready.notify_one();
            }
            match mode {
                Mode::Pending => std::future::pending().await,
                Mode::Fail if ordinal != 0 => std::future::pending().await,
                Mode::Fail => Err(adk_rust::AdkError::agent("raw-secret-do-not-echo")),
                _ => {
                    let mut response = LlmResponse::new(content);
                    if matches!(mode, Mode::Truncated) {
                        response.finish_reason = Some(adk_rust::FinishReason::MaxTokens);
                    }
                    if matches!(mode, Mode::ProviderError) {
                        response.error_code = Some("raw-secret-do-not-echo".into());
                    }
                    if matches!(mode, Mode::Incomplete) {
                        response.finish_reason = None;
                        response.turn_complete = false;
                        response.partial = true;
                    }
                    Ok(response)
                }
            }
        })))
    }
}
fn setup(
    mode: Mode,
    count: usize,
) -> (AdkGraph, Arc<Probe>, InMemoryArtifactStore, AdkEventMapper) {
    let probe = Arc::new(Probe {
        mode,
        barrier: Arc::new(Barrier::new(count)),
        ready: Arc::new(Notify::new()),
        active: Arc::new(AtomicUsize::new(0)),
        requests: Mutex::new(vec![]),
    });
    let binding = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new("fake-model", "1", "fake", ["unused"]))
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap()
        .with_test_llm(probe.clone());
    let plan = workflow_compiler::compile_str("sentinel.toml", WORKFLOW).unwrap();
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .unwrap()
        .with_sentinel_model(Arc::new(binding));
    let limit = NonZeroU64::new(100_000).unwrap();
    (
        graph,
        probe,
        InMemoryArtifactStore::new(limit, limit),
        AdkEventMapper::new("probe-run", "sentinel-preparation").unwrap(),
    )
}
fn state(raw: &[u8]) -> State {
    let mut state = State::new();
    state.insert("input".into(), json!({"schema_version":1,"bytes":raw}));
    state.insert("outer-secret".into(), json!("must-not-reach-probes"));
    state
}
fn report(store: &InMemoryArtifactStore, mapper: &AdkEventMapper) -> Value {
    let events = serde_json::to_value(mapper.events()).unwrap();
    let completed = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "node_completed")
        .unwrap();
    let id = completed["payload"]["structured_output"]["preparation"]["semantics"]["artifact_id"]
        .as_str()
        .unwrap();
    let page = store
        .read_page(
            &ArtifactId::parse(id).unwrap(),
            PageRequest::new(0, NonZeroU64::new(32_768).unwrap()),
        )
        .unwrap();
    serde_json::from_slice(page.bytes()).unwrap()
}

#[tokio::test]
async fn concurrent_response_barrier_and_source_only_requests() {
    // Ordered + two overlapping shuffled windows + decoded candidate.
    let raw = format!("`{}` %61%62%63", "0123456789 ".repeat(30));
    let (graph, probe, mut store, mut mapper) = setup(Mode::Agree, 4);
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        graph.invoke_observed(
            state(raw.as_bytes()),
            ExecutionConfig::new("probe-run"),
            &mut mapper,
            &mut store,
        ),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "response barrier: {} requests entered",
            probe.requests.lock().unwrap().len()
        )
    })
    .unwrap();
    assert!(output["terminal"]["decision"].is_null());
    let report = report(&store, &mapper);
    assert_eq!(report["reason"], "agreement");
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    let requests = probe.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    let mut branches = vec![];
    for request in requests.iter() {
        assert_eq!(request.contents.len(), 2);
        assert!(request.tools.is_empty());
        assert_eq!(request.contents[0].role, "system");
        assert_eq!(request.contents[1].role, "user");
        let system = text(&request.contents[0]);
        let user = text(&request.contents[1]);
        assert!(!system.contains("0123456789"));
        assert!(!user.contains("must-not-reach-probes"));
        assert!(!user.contains("outer-secret"));
        assert_eq!(
            request.config.as_ref().unwrap().max_output_tokens,
            Some(128)
        );
        let data: Value = serde_json::from_str(frame(&user, "COMMON_DATA_JSON")).unwrap();
        assert_eq!(data["trust_domain"], "untrusted_content");
        assert!(
            data["preparation_identity"]
                .as_str()
                .is_some_and(|s| s.starts_with("sha256:"))
        );
        let schema: Value = serde_json::from_str(frame(&system, "OUTPUT_SCHEMA_JSON")).unwrap();
        let branch = schema["$id"].as_str().unwrap().rsplit(':').next().unwrap();
        branches.push(branch.to_owned());
        if branch == "decoded" {
            assert_eq!(data["text"], "abc");
            assert_eq!(data["view"]["candidate"], 0);
        }
        let source = &data["view"]["source"];
        assert_eq!(schema["enum"][0]["payload"]["spans"][0], *source);
    }
    branches.sort();
    assert_eq!(branches, ["decoded", "ordered", "shuffled", "shuffled"]);
    let findings = report["findings"].as_array().unwrap();
    let shuffled: Vec<_> = findings
        .iter()
        .filter(|f| f["branch"] == "shuffled")
        .collect();
    assert_ne!(shuffled[0]["view"]["start"], 0);
    assert!(
        shuffled[0]["view"]["start"].as_u64().unwrap()
            < shuffled[1]["view"]["end"].as_u64().unwrap()
    );
}

#[tokio::test]
async fn failure_drops_pending_sibling_without_partial_findings_or_echo() {
    let (graph, probe, mut store, mut mapper) = setup(Mode::Fail, 2);
    tokio::time::timeout(
        Duration::from_secs(2),
        graph.invoke_observed(
            state(RAW),
            ExecutionConfig::new("probe-run"),
            &mut mapper,
            &mut store,
        ),
    )
    .await
    .expect("first branch failure must cancel pending sibling")
    .unwrap();
    assert_eq!(probe.requests.lock().unwrap().len(), 2);
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    let report = report(&store, &mapper);
    assert_eq!(report["reason"], "invalid_or_failed");
    assert!(report["decision"].is_null());
    assert_eq!(report["findings"], json!([]));
    assert!(
        !serde_json::to_string(mapper.events())
            .unwrap()
            .contains("raw-secret-do-not-echo")
    );
}

#[tokio::test]
async fn cancellation_drops_all_live_streams_without_semantic_publication() {
    let (graph, probe, mut store, mut mapper) = setup(Mode::Pending, 2);
    let mut pending = Box::pin(graph.invoke_observed(
        state(RAW),
        ExecutionConfig::new("probe-run"),
        &mut mapper,
        &mut store,
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            _ = &mut pending => panic!("both streams must remain pending"),
            _ = probe.ready.notified() => {},
        }
    })
    .await
    .unwrap();
    assert_eq!(probe.active.load(Ordering::SeqCst), 2);
    drop(pending);
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    let events = serde_json::to_string(mapper.events()).unwrap();
    assert!(!events.contains("sentinel-semantics"));
    assert!(!events.contains("node_completed"));
}

#[tokio::test]
async fn language_and_view_budgets_deny_before_provider_entry() {
    for raw in ["中文資料".to_owned(), format!("`{}`", "0".repeat(1800))] {
        let (graph, probe, mut store, mut mapper) = setup(Mode::Agree, 1);
        graph
            .invoke_observed(
                state(raw.as_bytes()),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await
            .unwrap();
        assert!(probe.requests.lock().unwrap().is_empty());
        let report = report(&store, &mapper);
        assert!(report["decision"].is_null());
        assert_eq!(report["findings"], json!([]));
    }
}

#[tokio::test]
async fn deadline_drops_both_never_ending_streams() {
    let (graph, probe, mut store, mut mapper) = setup(Mode::Pending, 2);
    tokio::time::timeout(
        Duration::from_secs(35),
        graph.invoke_observed(
            state(RAW),
            ExecutionConfig::new("probe-run"),
            &mut mapper,
            &mut store,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(probe.requests.lock().unwrap().len(), 2);
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    let report = report(&store, &mapper);
    assert_eq!(report["reason"], "deadline");
    assert!(report["decision"].is_null());
    assert_eq!(report["findings"], json!([]));
}

#[tokio::test]
async fn nontext_and_overbudget_model_evidence_cannot_classify() {
    for mode in [
        Mode::ToolCall,
        Mode::Oversize,
        Mode::Truncated,
        Mode::ProviderError,
        Mode::Incomplete,
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
        assert!(
            report["decision"].is_null(),
            "nontext or overbudget evidence is not admissible"
        );
        assert_eq!(report["findings"], json!([]));
        assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    }
}
