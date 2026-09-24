use super::FirewallInvocation;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use workflow_runtime::{argument_fingerprint, firewall::*};

pub fn invocation(admission: &str, tool: &str) -> FirewallInvocation {
    let policy: FirewallPolicy = serde_json::from_value(json!({
        "schema_version":1,"version":"1","tools":{"noop":{
            "version":"1","capabilities":[],"scopes":["fake"],"destinations":["local"],
            "effect":"none","admission":admission,"arguments":{},
            "scope":{"kind":"literal","value":"fake"},
            "destination":{"kind":"literal","value":"local"},
            "resource":{"kind":"literal","value":"service"}}},
        "targets":[{"scope":"fake","destination":"local","resource":"service",
            "version":{"schema_version":1,"revision":"1"}}],"forbidden_markers":[]
    }))
    .unwrap();
    let goal: TrustedGoal =
        serde_json::from_value(json!({"schema_version":1,"id":"goal","version":"1",
        "capabilities":[],"scopes":["fake"],"destinations":["local"]}))
        .unwrap();
    let proposal: ToolProposal = serde_json::from_value(json!({"schema_version":1,
        "intent":{"schema_version":1,"goal_id":"goal","tool_id":tool,"tool_version":"1",
            "capabilities":[],"scope":"fake","destination":"local","resource":"service",
            "effect":{"schema_version":1,"class":"none"},"target_version":{"schema_version":1,"revision":"1"}},
        "arguments":{},"provenance":{"source_digest":"a".repeat(64),
            "arguments_digest":argument_fingerprint(&json!({})),"trust_domain":"untrusted_content"}
    })).unwrap();
    FirewallInvocation::new(policy, goal, proposal)
}
pub fn source(identity: &str) -> String {
    format!(
        r#"schema_version = 1
[workflow]
id = "firewall-test"
version = "1"
entry = "gate"
[[nodes]]
id = "gate"
kind = "validator"
firewall = {{ schema_version = 1, identity = "{identity}" }}
[[nodes]]
id = "judge"
kind = "agent"
model = {{ role = "worker", id = "synthetic", version = "1" }}
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "gate"
to = "judge"
[[edges]]
from = "judge"
to = "done"
"#
    )
}
pub struct CountingJudge(pub Arc<AtomicUsize>);
#[adk_rust::async_trait]
impl adk_rust::Agent for CountingJudge {
    fn name(&self) -> &str {
        "judge"
    }
    fn description(&self) -> &str {
        "count entry even when no model events escape"
    }
    fn sub_agents(&self) -> &[Arc<dyn adk_rust::Agent>] {
        &[]
    }
    async fn run(
        &self,
        _: Arc<dyn adk_rust::InvocationContext>,
    ) -> adk_rust::Result<adk_rust::EventStream> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let mut event = adk_rust::Event::new("judge");
        event.set_content(adk_rust::Content::new("assistant").with_text(r#"{"state":{}}"#));
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])))
    }
}
