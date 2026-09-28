use std::num::NonZeroU64;

use serde_json::Value;
use workflow_runtime::{
    Actionability, ComponentId, ExplicitIssueEdge, GitHubIssueMetadata, GitHubIssueState,
    ISSUE_PLAN_MAX_CARDS, ISSUE_PLAN_MAX_EDGES, InMemoryArtifactStore, IssueCardV1, IssuePlanError,
    IssuePlanTitle, OfflineComment, OfflineIssueContent, PriorityDependency, PriorityEffort,
    PriorityImpact, PriorityInputs, PriorityUrgency, TrustPolicy, build_canonical_issue_artifact,
    build_todo_plan,
};

fn issue(number: u64) -> GitHubIssueMetadata {
    GitHubIssueMetadata::new(
        number,
        "trusted-author",
        "MEMBER",
        GitHubIssueState::Open,
        "2026-09-26T00:00:00Z",
        false,
    )
    .expect("metadata")
}

fn artifact(number: u64) -> workflow_runtime::CanonicalIssueArtifact {
    let content = OfflineIssueContent::new(
        issue(number),
        "snapshot-252",
        b"trusted title".to_vec(),
        b"trusted body".to_vec(),
        vec![
            OfflineComment::new(
                "comment-1",
                "stranger",
                1,
                1,
                false,
                b"omitted comment".to_vec(),
            )
            .expect("comment"),
        ],
    )
    .expect("content");
    let policy = TrustPolicy::new("owner/repo", ["trusted-author"]).expect("policy");
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(65_536).expect("page size"),
        NonZeroU64::new(65_536).expect("artifact size"),
    );
    build_canonical_issue_artifact(&policy, &content, &mut store).expect("artifact")
}

fn card(id: &str, impact: PriorityImpact) -> IssueCardV1 {
    IssueCardV1::from_artifact(
        id,
        "card objective",
        Actionability::Actionable,
        PriorityInputs::new(
            impact,
            PriorityUrgency::Medium,
            PriorityEffort::Small,
            PriorityDependency::None,
        ),
        &artifact(252),
        "model:none",
        "prompt-v1",
    )
    .expect("card")
}

fn card_with_prerequisites(
    id: &str,
    impact: PriorityImpact,
    prerequisites: &[&str],
) -> IssueCardV1 {
    card(id, impact)
        .with_prerequisites(
            prerequisites
                .iter()
                .map(|value| ComponentId::new(*value).expect("prerequisite")),
        )
        .expect("prerequisites")
}

fn edge(predecessor_id: &str, dependent_id: &str) -> ExplicitIssueEdge {
    ExplicitIssueEdge::new(predecessor_id, dependent_id).expect("edge")
}

fn titles(ids: &[&str]) -> Vec<IssuePlanTitle> {
    ids.iter()
        .map(|id| IssuePlanTitle::new(*id, format!("title for {id}")))
        .collect::<Result<_, _>>()
        .expect("titles")
}

#[test]
fn explicit_dag_is_dependency_legal_reduced_and_priority_stable() {
    let cards = [
        card("c", PriorityImpact::Low),
        card("d", PriorityImpact::Low),
        card("b", PriorityImpact::Low),
        card("a", PriorityImpact::Low),
    ];
    let edges = [edge("a", "b"), edge("a", "c"), edge("b", "c")];
    let plan = build_todo_plan(&cards, &edges, &titles(&["a", "b", "c", "d"]))
        .expect("plan")
        .expect_resolved();

    assert_eq!(plan.item_ids(), ["d", "a", "b", "c"]);
    assert_eq!(plan.item("c").expect("c").prerequisites(), ["b"]);
    assert_eq!(plan.item("b").expect("b").prerequisites(), ["a"]);
}

#[test]
fn dependency_order_and_rendering_are_permutation_invariant() {
    let first_cards = [
        card("c", PriorityImpact::Medium),
        card("d", PriorityImpact::Medium),
        card("b", PriorityImpact::Medium),
        card("a", PriorityImpact::Medium),
    ];
    let second_cards = [
        first_cards[2].clone(),
        first_cards[0].clone(),
        first_cards[3].clone(),
        first_cards[1].clone(),
    ];
    let edges = [edge("a", "b"), edge("a", "c"), edge("b", "c")];
    let first =
        build_todo_plan(&first_cards, &edges, &titles(&["a", "b", "c", "d"])).expect("plan");
    let second =
        build_todo_plan(&second_cards, &edges, &titles(&["d", "c", "b", "a"])).expect("plan");

    assert_eq!(
        first.render_markdown().expect("markdown"),
        second.render_markdown().expect("markdown")
    );
    assert_eq!(
        first.render_json().expect("json"),
        second.render_json().expect("json")
    );
}

#[test]
fn self_and_multinode_cycles_are_unresolved_with_exact_sccs() {
    let cards = [
        card("downstream", PriorityImpact::Low),
        card("b", PriorityImpact::Low),
        card("a", PriorityImpact::Low),
        card("self", PriorityImpact::Low),
        card("disconnected", PriorityImpact::Low),
    ];
    let edges = [
        edge("b", "downstream"),
        edge("a", "b"),
        edge("b", "a"),
        edge("self", "self"),
    ];
    let plan = build_todo_plan(
        &cards,
        &edges,
        &titles(&["a", "b", "downstream", "self", "disconnected"]),
    )
    .expect("cycle result");

    assert_eq!(
        plan.cycles()
            .iter()
            .map(|cycle| cycle.as_slice())
            .collect::<Vec<_>>(),
        [vec!["a", "b"].as_slice(), vec!["self"].as_slice()]
    );
    assert!(!plan.cycles().iter().flatten().any(|id| id == "downstream"));
    let json = plan.render_json().expect("json");
    assert!(json.contains("\"status\":\"unresolved\""));
}

#[test]
fn duplicate_unknown_and_title_key_errors_are_fail_closed() {
    let duplicate = [
        card("a", PriorityImpact::Low),
        card("a", PriorityImpact::Low),
    ];
    assert_eq!(
        build_todo_plan(&duplicate, &[], &titles(&["a"])),
        Err(IssuePlanError::DuplicateCardId("a".to_owned()))
    );

    let generic_prerequisite = [card_with_prerequisites(
        "issue-42",
        PriorityImpact::Low,
        &["issue-42", "unmatched-capability"],
    )];
    let generic_plan = build_todo_plan(&generic_prerequisite, &[], &titles(&["issue-42"]))
        .expect("generic prerequisites are not issue edges")
        .expect_resolved();
    assert!(
        generic_plan
            .item("issue-42")
            .expect("issue-42")
            .prerequisites()
            .is_empty()
    );

    let unknown_edge = [edge("a", "missing")];
    let cards = [card("a", PriorityImpact::Low)];
    assert_eq!(
        build_todo_plan(&cards, &unknown_edge, &titles(&["a"])),
        Err(IssuePlanError::UnknownEdgeEndpoint("missing".to_owned()))
    );
    let unknown_predecessor = [edge("missing", "a")];
    assert_eq!(
        build_todo_plan(&cards, &unknown_predecessor, &titles(&["a"])),
        Err(IssuePlanError::UnknownEdgeEndpoint("missing".to_owned()))
    );
    let too_many_edges = (0..=ISSUE_PLAN_MAX_EDGES)
        .map(|_| edge("a", "a"))
        .collect::<Vec<_>>();
    assert_eq!(
        build_todo_plan(&cards, &too_many_edges, &titles(&["a"])),
        Err(IssuePlanError::TooManyEdges)
    );
    assert_eq!(
        build_todo_plan(&cards, &[], &[]),
        Err(IssuePlanError::MissingTitle("a".to_owned()))
    );
    assert_eq!(
        build_todo_plan(&cards, &[], &titles(&["a", "extra"])),
        Err(IssuePlanError::ExtraTitle("extra".to_owned()))
    );
    let duplicate_titles = [
        IssuePlanTitle::new("a", "one").expect("title"),
        IssuePlanTitle::new("a", "two").expect("title"),
    ];
    assert_eq!(
        build_todo_plan(&cards, &[], &duplicate_titles),
        Err(IssuePlanError::DuplicateTitle("a".to_owned()))
    );
}

#[test]
fn ready_selection_uses_highest_priority_without_crossing_edges() {
    let cards = [
        card("independent", PriorityImpact::Low),
        card("blocked-high", PriorityImpact::Critical),
        card("root", PriorityImpact::Low),
    ];
    let edges = [edge("root", "blocked-high")];
    let plan = build_todo_plan(
        &cards,
        &edges,
        &titles(&["blocked-high", "independent", "root"]),
    )
    .expect("plan")
    .expect_resolved();

    assert_eq!(plan.item_ids(), ["root", "blocked-high", "independent"]);
}

#[test]
fn priority_only_ready_choice_prefers_high_priority_over_lexical_order() {
    let cards = [
        card("a-low", PriorityImpact::Low),
        card("z-high", PriorityImpact::Critical),
    ];
    let plan = build_todo_plan(&cards, &[], &titles(&["a-low", "z-high"]))
        .expect("plan")
        .expect_resolved();

    assert!("a-low" < "z-high");
    assert_eq!(plan.item_ids(), ["z-high", "a-low"]);
}

#[test]
fn explicit_edge_endpoints_are_validated() {
    assert_eq!(
        ExplicitIssueEdge::new("", "a"),
        Err(IssuePlanError::InvalidEdgeEndpoint)
    );
    assert_eq!(
        ExplicitIssueEdge::new("a", "bad\nendpoint"),
        Err(IssuePlanError::InvalidEdgeEndpoint)
    );
}

#[test]
fn titles_are_escaped_in_markdown_but_preserved_in_canonical_json() {
    let cards = [card("a", PriorityImpact::Low)];
    let title = r#"![x](javascript:alert(1)) ~~drop~~ *raw* <img src=x>"#;
    let titles = [IssuePlanTitle::new("a", title).expect("title")];
    let plan = build_todo_plan(&cards, &[], &titles).expect("plan");
    let markdown = plan.render_markdown().expect("markdown");
    let json = plan.render_json().expect("json");

    assert!(!markdown.contains(title));
    assert!(markdown.contains(r"\!\[x\]\(javascript\:alert\(1\)\)"));
    let value: Value = serde_json::from_str(&json).expect("canonical json");
    assert_eq!(value["items"][0]["title"], title);
}

#[test]
fn input_bound_is_enforced_before_graph_work() {
    let cards = (0..=ISSUE_PLAN_MAX_CARDS)
        .map(|index| card(&format!("issue-{index}"), PriorityImpact::Low))
        .collect::<Vec<_>>();
    let title_ids = (0..=ISSUE_PLAN_MAX_CARDS)
        .map(|index| format!("issue-{index}"))
        .collect::<Vec<_>>();
    let title_refs = title_ids.iter().map(String::as_str).collect::<Vec<_>>();

    assert_eq!(
        build_todo_plan(&cards, &[], &titles(&title_refs)),
        Err(IssuePlanError::TooManyCards)
    );
}

#[test]
fn plan_output_is_bounded_and_contains_priority_order_keys() {
    let cards = [card("a", PriorityImpact::Critical)];
    let plan = build_todo_plan(&cards, &[], &titles(&["a"]))
        .expect("plan")
        .expect_resolved();
    let item = plan.item("a").expect("item");
    assert_eq!(item.priority_order_key(), cards[0].priority_order_key());
    assert!(plan.render_markdown().expect("markdown").len() < 32 * 1024);
    assert!(plan.render_json().expect("json").len() < 32 * 1024);
}
