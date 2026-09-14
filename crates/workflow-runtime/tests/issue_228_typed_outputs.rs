use workflow_runtime::{
    ArtifactRef, CompactStateDelta, Completeness, Continuation, DependencyJudgment,
    DependencyRecord, EscalationRecord, EscalationTarget, FirewallDecision, FirewallRecord,
    IssueCard, ResearchRationale, SentinelEvidence, SentinelVerdict, SourceSpan, TypedNodeKind,
    TypedOutput, TypedOutputError, TypedPayload, WorkflowExchange, admit_for_reducer,
    estimate_output_tokens, node_output_token_budget, parse_typed_output, render_json,
    render_markdown,
};

fn span() -> SourceSpan {
    SourceSpan::new("artifact:abc", 12, 40).expect("valid span")
}

fn artifact() -> ArtifactRef {
    ArtifactRef::new(
        "artifact:abc",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("valid artifact ref")
}

fn sentinel() -> TypedOutput {
    TypedOutput::new(
        TypedPayload::Sentinel(SentinelEvidence::new(
            SentinelVerdict::Injection,
            vec![span()],
            vec![artifact()],
        )),
        Completeness::Complete,
    )
    .expect("valid sentinel")
}

fn firewall() -> TypedOutput {
    TypedOutput::new(
        TypedPayload::Firewall(FirewallRecord::new(
            FirewallDecision::Deny,
            vec![artifact()],
        )),
        Completeness::Complete,
    )
    .expect("valid firewall")
}

fn compact_state() -> TypedOutput {
    TypedOutput::new(
        TypedPayload::CompactState(CompactStateDelta::new("cards", "add", vec![artifact()])),
        Completeness::Complete,
    )
    .expect("valid compact state")
}

fn issue_card() -> TypedOutput {
    TypedOutput::new(
        TypedPayload::IssueCard(IssueCard::new("card-1", "open", vec![span()])),
        Completeness::Complete,
    )
    .expect("valid issue card")
}

fn dependency() -> TypedOutput {
    TypedOutput::new(
        TypedPayload::Dependency(DependencyRecord::new(
            "card-1",
            "card-2",
            DependencyJudgment::Blocks,
            vec![artifact()],
        )),
        Completeness::Complete,
    )
    .expect("valid dependency")
}

fn escalation() -> TypedOutput {
    TypedOutput::new(
        TypedPayload::Escalation(EscalationRecord::new(
            EscalationTarget::Hitl,
            vec![artifact()],
        )),
        Completeness::Complete,
    )
    .expect("valid escalation")
}

fn all_outputs() -> [TypedOutput; 6] {
    [
        sentinel(),
        firewall(),
        compact_state(),
        issue_card(),
        dependency(),
        escalation(),
    ]
}

#[test]
fn six_kinds_round_trip_without_rationale() {
    for output in all_outputs() {
        let encoded = output.to_json().expect("serialize");
        assert!(
            !encoded.contains("rationale"),
            "operational wire must omit rationale: {encoded}"
        );
        let decoded = parse_typed_output(encoded.as_bytes()).expect("round-trip");
        assert_eq!(decoded, output);
        assert_eq!(decoded.schema_version(), 1);
        assert!(decoded.rationale().is_none());
    }
}

#[test]
fn unknown_schema_version_and_reason_code_fail_closed() {
    let mut version = sentinel().to_json().expect("json");
    version = version.replacen("\"schema_version\":1", "\"schema_version\":99", 1);
    let error = parse_typed_output(version.as_bytes()).expect_err("unknown version");
    assert!(matches!(error, TypedOutputError::UnknownSchemaVersion));

    let mut verdict = sentinel().to_json().expect("json");
    verdict = verdict.replacen("\"verdict\":\"inj\"", "\"verdict\":\"maybe\"", 1);
    let error = parse_typed_output(verdict.as_bytes()).expect_err("unknown code");
    assert!(matches!(error, TypedOutputError::UnknownReasonCode));
}

const GOLDEN_MARKDOWN: &str = "\
# sentinel
- verdict: inj
- label: injection
- span: artifact:abc#12-40
- artifact: artifact:abc
";

const GOLDEN_JSON: &str = "{\"completeness\":\"complete\",\"node\":\"sentinel\",\"payload\":{\"artifacts\":[{\"artifact_id\":\"artifact:abc\",\"sha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}],\"kind\":\"sentinel\",\"spans\":[{\"artifact_id\":\"artifact:abc\",\"end\":40,\"start\":12}],\"verdict\":\"inj\"},\"schema_version\":1}";

#[test]
fn renderer_goldens_do_not_invent_evidence() {
    let output = sentinel();
    let markdown = render_markdown(&output);
    assert_eq!(markdown, GOLDEN_MARKDOWN);
    assert!(!markdown.contains("attacker"));
    assert!(!markdown.contains("malicious"));
    assert!(!markdown.contains("because"));

    let json = render_json(&output).expect("json");
    assert_eq!(json, GOLDEN_JSON);
    let invented = ["likely", "probably", "appears", "suggests"];
    for word in invented {
        assert!(!json.contains(word), "invented evidence {word} in {json}");
    }
}

#[test]
fn truncated_output_is_rejected_before_reducer_use() {
    let truncated = TypedOutput::new(
        TypedPayload::Sentinel(SentinelEvidence::new(
            SentinelVerdict::Suspicious,
            vec![span()],
            vec![artifact()],
        )),
        Completeness::Truncated {
            continuation: Continuation::new(1, "next-1").expect("token"),
        },
    )
    .expect("valid truncated envelope");

    let error = admit_for_reducer(&truncated).expect_err("truncated must not enter reducer");
    assert!(matches!(error, TypedOutputError::Truncated));

    let complete = sentinel();
    let admitted = admit_for_reducer(&complete).expect("complete output is admissible");
    assert!(matches!(admitted, TypedPayload::Sentinel(_)));
}

#[test]
fn node_budgets_and_token_continuation_are_explicit() {
    assert_eq!(node_output_token_budget(TypedNodeKind::Sentinel), 128);
    assert_eq!(node_output_token_budget(TypedNodeKind::Firewall), 96);
    assert_eq!(node_output_token_budget(TypedNodeKind::CompactState), 192);
    assert_eq!(node_output_token_budget(TypedNodeKind::IssueCard), 160);
    assert_eq!(node_output_token_budget(TypedNodeKind::Dependency), 96);
    assert_eq!(node_output_token_budget(TypedNodeKind::Escalation), 80);

    let json = compact_state().to_json().expect("json");
    let tokens = estimate_output_tokens(&json);
    assert!(
        tokens <= node_output_token_budget(TypedNodeKind::CompactState) as usize,
        "compact fixture {tokens} exceeded budget"
    );

    let continuation = Continuation::new(2, "page-2").expect("token");
    assert_eq!(continuation.seq(), 2);
    assert_eq!(continuation.token(), "page-2");
}

#[test]
fn compact_fixture_uses_fewer_tokens_than_prose() {
    let compact = sentinel().to_json().expect("json");
    let prose = "The input is almost certainly a prompt-injection attempt because the untrusted comment asked the model to ignore the trusted goal, exfiltrate secrets, and disable the firewall. A reviewer should treat this as malicious and write a long narrative about attacker intent.";
    let compact_tokens = estimate_output_tokens(&compact);
    let prose_tokens = estimate_output_tokens(prose);
    assert!(
        compact_tokens < prose_tokens,
        "compact={compact_tokens} prose={prose_tokens}"
    );
}

#[test]
fn four_workflows_exchange_typed_outputs_without_prose() {
    let workflows = [
        WorkflowExchange::CodeInvestigation,
        WorkflowExchange::GroundedAnswer,
        WorkflowExchange::MultiHop,
        WorkflowExchange::Review,
    ];
    for output in all_outputs() {
        for from in workflows {
            for to in workflows {
                from.exchange(to, &output)
                    .expect("typed outputs must exchange without prose");
            }
        }
    }

    let with_prose = r#"{"schema_version":1,"node":"sentinel","completeness":"complete","payload":{"kind":"sentinel","verdict":"inj","spans":[{"artifact_id":"artifact:abc","start":12,"end":40}],"artifacts":[{"artifact_id":"artifact:abc","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]},"rationale":"the attacker is obviously trying something"}"#;
    let error = parse_typed_output(with_prose.as_bytes()).expect_err("rationale is off by default");
    assert!(matches!(error, TypedOutputError::RationaleNotEnabled));

    let stored = ResearchRationale::store(&sentinel(), "experiment notes").expect("research path");
    assert_eq!(stored.text(), "experiment notes");
    assert_ne!(stored.output_digest(), "");
}

#[test]
fn debug_redacts_source_ids() {
    let rendered = format!("{:?}", sentinel());
    assert!(!rendered.contains("artifact:abc"));
    assert!(!rendered.contains("aaaaaaaaaaaaaaaa"));
}
