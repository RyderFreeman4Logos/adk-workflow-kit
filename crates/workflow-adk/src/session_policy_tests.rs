use super::*;
use adk_rust::{Llm, LlmRequest, LlmResponse, agent::LlmAgentBuilder};
#[path = "shared_session_tests.rs"]
mod boundary;

struct Probe {
    requests: Arc<Mutex<Vec<LlmRequest>>>,
    answer: &'static str,
}

#[async_trait]
impl Llm for Probe {
    fn name(&self) -> &str {
        "session-policy-probe"
    }

    async fn generate_content(
        &self,
        request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.requests.lock().unwrap().push(request);
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(
            LlmResponse::new(Content::new("assistant").with_text(self.answer)),
        )])))
    }
}

fn graph(mode: &str, requests: Arc<Mutex<Vec<LlmRequest>>>) -> AdkGraph {
    graph_with_alpha(mode, requests, None, false, false)
}

fn graph_with_alpha(
    mode: &str,
    requests: Arc<Mutex<Vec<LlmRequest>>>,
    alpha: Option<Arc<dyn Agent>>,
    parallel: bool,
    checkpointed: bool,
) -> AdkGraph {
    let mut source = String::from(
        "schema_version = 1\n[workflow]\nid = \"session-policy\"\nversion = \"1\"\nentry = \"alpha\"\n",
    );
    let mut agents = BTreeMap::new();
    for (name, answer) in [
        (
            "alpha",
            r#"{"output":"accepted-alpha","state":{"hidden":"private-output-canary"}}"#,
        ),
        ("beta", r#"{"output":"accepted-beta"}"#),
    ] {
        source.push_str(&format!(
            r#"
[[nodes]]
id = "{name}"
kind = "agent"
model = {{ role = "worker", id = "worker", version = "1" }}
instruction = {{ path = "{name}.md", sha256 = "sha256:{}" }}
input = {{ state_keys = ["input"] }}
output = {{ state_key = "node:{name}", schema = "output.schema.json" }}
session = "{mode}"
"#,
            "0".repeat(64),
        ));
        let agent = LlmAgentBuilder::new(name)
            .model(Arc::new(Probe {
                requests: Arc::clone(&requests),
                answer,
            }))
            .instruction(format!("{name}-private-instruction"))
            .build()
            .unwrap();
        agents.insert(name.to_owned(), Arc::new(agent) as Arc<dyn Agent>);
    }
    source.push_str(
        r#"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "alpha"
to = "beta"
[[edges]]
from = "beta"
to = "done"
[state]
schema_id = "session-policy"
schema_version = "1"
required_keys = ["input"]
[state.keys.input]
schema_id = "json"
schema_version = "1"
[state.keys."node:alpha"]
schema_id = "json"
schema_version = "1"
[state.keys."node:beta"]
schema_id = "json"
schema_version = "1"
"#,
    );
    if let Some(alpha) = alpha {
        agents.insert("alpha".into(), alpha);
    }
    if parallel {
        source = source.replace("entry = \"alpha\"", "entry = \"starter\"")
            .replace("from = \"alpha\"\nto = \"beta\"", "from = \"starter\"\nto = \"alpha\"\n[[edges]]\nfrom = \"starter\"\nto = \"beta\"\n[[edges]]\nfrom = \"alpha\"\nto = \"done\"")
            .replace("[state]\n", "[[nodes]]\nid = \"starter\"\nkind = \"agent\"\nmodel = { role = \"worker\", id = \"worker\", version = \"1\" }\n[state]\n");
        agents.insert(
            "starter".into(),
            Arc::new(
                LlmAgentBuilder::new("starter")
                    .model(Arc::new(Probe {
                        requests: requests.clone(),
                        answer: r#"{"output":"started"}"#,
                    }))
                    .build()
                    .unwrap(),
            ),
        );
    }
    let plan = workflow_compiler::compile_str("session-policy.toml", &source).unwrap();
    AdkGraphTranslator::new()
        .translate_profile_with_checkpointer(
            &plan,
            &agents,
            None,
            &Value::Null,
            checkpointed.then(|| {
                Arc::new(adk_rust::graph::checkpoint::MemoryCheckpointer::new())
                    as Arc<dyn Checkpointer>
            }),
        )
        .unwrap()
}

async fn capture(mode: &str, observed: bool) -> Vec<LlmRequest> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let graph = graph(mode, Arc::clone(&requests));
    for _ in 0..2 {
        // Reusing the caller's run id must not retain a previous invocation.
        let state = State::from([
            ("input".into(), json!("mapped-public-input")),
            ("undeclared".into(), json!("private-state-canary")),
        ]);
        let config = ExecutionConfig::new("same-run-id");
        if observed {
            let mut mapper = events::AdkEventMapper::new("same-run-id", "session-policy").unwrap();
            let limit = std::num::NonZeroU64::new(65536).unwrap();
            let mut artifacts = workflow_runtime::InMemoryArtifactStore::new(limit, limit);
            graph
                .invoke_observed(state, config, &mut mapper, &mut artifacts)
                .await
                .unwrap();
        } else {
            graph.invoke(state, config).await.unwrap();
        }
    }
    drop(graph);
    Arc::try_unwrap(requests).unwrap().into_inner().unwrap()
}

#[adk_rust::tokio::test]
async fn shared_graph_history_reaches_normal_and_observed_model_requests() {
    for observed in [false, true] {
        let requests = capture("shared", observed).await;
        assert_eq!(requests.len(), 4);
        for pair in requests.as_chunks::<2>().0 {
            let first = serde_json::to_string(&pair[0].contents).unwrap();
            let second = serde_json::to_string(&pair[1].contents).unwrap();
            assert!(!first.contains("accepted-alpha"));
            assert_eq!(second.matches("accepted-alpha").count(), 1, "{second}");
            assert_eq!(second.matches("mapped-public-input").count(), 2, "{second}");
            assert!(!second.contains("alpha-private-instruction"));
            assert!(!second.contains("private-state-canary"));
            assert!(!second.contains("private-output-canary"));
        }
    }
}

#[adk_rust::tokio::test]
async fn isolated_graph_does_not_receive_prior_node_or_private_state() {
    for observed in [false, true] {
        let requests = capture("isolated", observed).await;
        assert_eq!(requests.len(), 4);
        for pair in requests.as_chunks::<2>().0 {
            let second = serde_json::to_string(&pair[1].contents).unwrap();
            assert!(!second.contains("accepted-alpha"));
            assert_eq!(second.matches("mapped-public-input").count(), 1);
            assert!(!second.contains("alpha-private-instruction"));
            assert!(!second.contains("private-state-canary"));
            assert!(!second.contains("private-output-canary"));
        }
    }
}
