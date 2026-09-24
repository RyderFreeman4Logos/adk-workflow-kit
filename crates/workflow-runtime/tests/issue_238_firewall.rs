use serde_json::json;
use workflow_runtime::{FirewallDecision, argument_fingerprint, firewall::*};

fn fixture() -> (FirewallPolicy, TrustedGoal, ToolProposal) {
    let goal = serde_json::from_value(json!({
        "schema_version":1,"id":"goal-1","version":"1","capabilities":[],
        "scopes":["fake"],"destinations":["local"]
    }))
    .unwrap();
    let policy = serde_json::from_value(json!({
        "schema_version":1,"version":"policy-1","tools":{
            "noop": {"version":"1","capabilities":[],"scopes":["fake"],
                "destinations":["local"],"effect":"none","admission":"low_risk",
                "arguments":{"count":{"kind":"integer","min":0,"max":4}},
                "scope":{"kind":"literal","value":"fake"},
                "destination":{"kind":"literal","value":"local"},
                "resource":{"kind":"literal","value":"service"}}
        },"targets":[{"scope":"fake","destination":"local","resource":"service",
            "version":{"schema_version":1,"revision":"r1"}}],"forbidden_markers":["synthetic-private-value"]
    })).unwrap();
    let args = json!({"count":1});
    let proposal = serde_json::from_value(json!({
        "schema_version":1,"intent":{"schema_version":1,"goal_id":"goal-1",
            "tool_id":"noop","tool_version":"1","capabilities":[],"scope":"fake",
            "destination":"local","resource":"service",
            "effect":{"schema_version":1,"class":"none"},
            "target_version":{"schema_version":1,"revision":"r1"}},
        "arguments":args,"provenance":{"source_digest":"a".repeat(64),
            "arguments_digest":argument_fingerprint(&args),"trust_domain":"untrusted_content"}
    }))
    .unwrap();
    (policy, goal, proposal)
}

fn decide(policy: &FirewallPolicy, goal: &TrustedGoal, proposal: &ToolProposal) -> ToolDecision {
    policy.evaluate(goal, proposal)
}

#[test]
fn explicit_low_risk_allow_and_default_approval_are_not_boolean_safety() {
    let (mut policy, goal, proposal) = fixture();
    let allow = decide(&policy, &goal, &proposal);
    assert_eq!(allow.decision(), FirewallDecision::Allow);
    assert_eq!(allow.reason(), FirewallReason::LowRisk);
    policy.tools.get_mut("noop").unwrap().admission = ToolAdmission::HumanApproval;
    let approval = decide(&policy, &goal, &proposal);
    assert_eq!(approval.decision(), FirewallDecision::RequireHumanApproval);
    assert_ne!(allow.identity(), approval.identity());
}

#[test]
fn synthetic_policy_matrix_is_fail_closed() {
    let (policy, goal, proposal) = fixture();
    let original = serde_json::to_value(&proposal).unwrap();
    let mutations = [
        ("/schema_version", json!(9), FirewallReason::Schema),
        ("/intent/schema_version", json!(9), FirewallReason::Schema),
        ("/intent/tool_id", json!("unknown"), FirewallReason::Tool),
        ("/intent/tool_version", json!("9"), FirewallReason::Tool),
        (
            "/intent/capabilities",
            json!(["network"]),
            FirewallReason::Capability,
        ),
        ("/intent/scope", json!("other"), FirewallReason::Scope),
        (
            "/intent/destination",
            json!("elsewhere"),
            FirewallReason::Destination,
        ),
        (
            "/intent/effect/class",
            json!("write"),
            FirewallReason::SideEffect,
        ),
        (
            "/intent/target_version/revision",
            json!("r0"),
            FirewallReason::StaleTarget,
        ),
        (
            "/provenance/arguments_digest",
            json!("b".repeat(64)),
            FirewallReason::Provenance,
        ),
    ];
    for (path, value, reason) in mutations {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = value;
        let changed: ToolProposal = serde_json::from_value(changed).unwrap();
        let result = decide(&policy, &goal, &changed);
        assert_eq!(result.decision(), FirewallDecision::Deny, "{path}");
        assert_eq!(result.reason(), reason, "{path}");
    }
    for args in [
        json!({"count":-1}),
        json!({"count":5}),
        json!({"count":"1"}),
        json!({}),
        json!({"count":1,"body":"raw document"}),
    ] {
        let mut changed = original.clone();
        changed["arguments"] = args.clone();
        changed["provenance"]["arguments_digest"] = json!(argument_fingerprint(&args));
        let changed: ToolProposal = serde_json::from_value(changed).unwrap();
        assert_eq!(
            decide(&policy, &goal, &changed).reason(),
            FirewallReason::Arguments
        );
    }
}

#[test]
fn secrets_and_raw_content_fail_closed_without_echoing_payloads() {
    let (policy, goal, proposal) = fixture();
    let original = serde_json::to_value(&proposal).unwrap();
    for args in [
        json!({"count":"synthetic-honeytoken-v1:trap"}),
        json!({"count":"synthetic-private-value"}),
        json!({"password":"fake-test-value"}),
    ] {
        let mut wire = original.clone();
        wire["arguments"] = args.clone();
        wire["provenance"]["arguments_digest"] = json!(argument_fingerprint(&args));
        let changed = serde_json::from_value(wire).unwrap();
        let result = decide(&policy, &goal, &changed);
        assert_eq!(result.reason(), FirewallReason::Secret);
        let output = result.render_json().unwrap();
        assert!(!output.contains("trap"));
        assert!(!output.contains("fake-test-value"));
    }
    for field in [
        "issue_body",
        "document",
        "reasoning",
        "rationale",
        "approved",
    ] {
        let mut wire = original.clone();
        wire[field] = json!("attacker text");
        assert!(ToolProposal::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
    }
    let mut wire = original;
    wire["intent"]["capabilities"] = json!(["unknown"]);
    assert!(ToolProposal::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
}

#[test]
fn proposal_canonicalization_binds_provenance_and_shared_output() {
    let (policy, goal, proposal) = fixture();
    assert_eq!(proposal.canonical_arguments(), r#"{"count":1}"#);
    assert_eq!(
        proposal.arguments_digest(),
        argument_fingerprint(&json!({"count":1}))
    );
    let result = decide(&policy, &goal, &proposal);
    let output = result.typed_output().unwrap();
    workflow_runtime::admit_for_reducer(&output).unwrap();
    assert_eq!(
        workflow_runtime::parse_typed_output(result.render_json().unwrap().as_bytes()).unwrap(),
        output
    );
    assert!(result.render_markdown().unwrap().contains("alw"));
    let restored: ToolProposal =
        serde_json::from_value(serde_json::to_value(&proposal).unwrap()).unwrap();
    assert_eq!(
        result.identity(),
        decide(&policy, &goal, &restored).identity()
    );
}
