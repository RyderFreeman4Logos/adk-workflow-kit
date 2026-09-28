use std::num::NonZeroU64;

use serde_json::Value;
use workflow_runtime::{
    Actionability, ComponentId, GitHubIssueMetadata, GitHubIssueState, ISSUE_PLAN_MAX_CARDS,
    InMemoryArtifactStore, IssueCardV1, IssuePlanError, IssuePlanTitle, OfflineComment,
    OfflineIssueContent, PriorityDependency, PriorityEffort, PriorityImpact, PriorityInputs,
    PriorityUrgency, TrustPolicy, build_canonical_issue_artifact, build_todo_plan,
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

fn titles(ids: &[&str]) -> Vec<IssuePlanTitle> {
    ids.iter()
        .map(|id| IssuePlanTitle::new(*id, format!("title for {id}")))
        .collect::<Result<_, _>>()
        .expect("titles")
}

#[test]
fn explicit_dag_is_dependency_legal_reduced_and_priority_stable() {
    let cards = [
        card_with_prerequisites("c", PriorityImpact::Low, &["a", "b"]),
        card("d", PriorityImpact::Low),
        card_with_prerequisites("b", PriorityImpact::Low, &["a"]),
        card("a", PriorityImpact::Low),
    ];
    let plan = build_todo_plan(&cards, &titles(&["a", "b", "c", "d"]))
        .expect("plan")
        .expect_resolved();

    assert_eq!(plan.item_ids(), ["a", "b", "c", "d"]);
    assert_eq!(plan.item("c").expect("c").prerequisites(), ["b"]);
    assert_eq!(plan.item("b").expect("b").prerequisites(), ["a"]);
}

#[test]
fn dependency_order_and_rendering_are_permutation_invariant() {
    let first_cards = [
        card_with_prerequisites("c", PriorityImpact::Medium, &["a", "b"]),
        card("d", PriorityImpact::Medium),
        card_with_prerequisites("b", PriorityImpact::Medium, &["a"]),
        card("a", PriorityImpact::Medium),
    ];
    let second_cards = [
        first_cards[2].clone(),
        first_cards[0].clone(),
        first_cards[3].clone(),
        first_cards[1].clone(),
    ];
    let first = build_todo_plan(&first_cards, &titles(&["a", "b", "c", "d"])).expect("plan");
    let second = build_todo_plan(&second_cards, &titles(&["d", "c", "b", "a"])).expect("plan");

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
        card_with_prerequisites("downstream", PriorityImpact::Low, &["b"]),
        card_with_prerequisites("b", PriorityImpact::Low, &["a"]),
        card_with_prerequisites("a", PriorityImpact::Low, &["b"]),
        card_with_prerequisites("self", PriorityImpact::Low, &["self"]),
        card("disconnected", PriorityImpact::Low),
    ];
    let plan = build_todo_plan(
        &cards,
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
        build_todo_plan(&duplicate, &titles(&["a"])),
        Err(IssuePlanError::DuplicateCardId("a".to_owned()))
    );

    let unknown = [card_with_prerequisites(
        "a",
        PriorityImpact::Low,
        &["missing"],
    )];
    assert_eq!(
        build_todo_plan(&unknown, &titles(&["a"])),
        Err(IssuePlanError::UnknownPrerequisite {
            card_id: "a".to_owned(),
            prerequisite_id: "missing".to_owned(),
        })
    );

    let cards = [card("a", PriorityImpact::Low)];
    assert_eq!(
        build_todo_plan(&cards, &[]),
        Err(IssuePlanError::MissingTitle("a".to_owned()))
    );
    assert_eq!(
        build_todo_plan(&cards, &titles(&["a", "extra"])),
        Err(IssuePlanError::ExtraTitle("extra".to_owned()))
    );
    let duplicate_titles = [
        IssuePlanTitle::new("a", "one").expect("title"),
        IssuePlanTitle::new("a", "two").expect("title"),
    ];
    assert_eq!(
        build_todo_plan(&cards, &duplicate_titles),
        Err(IssuePlanError::DuplicateTitle("a".to_owned()))
    );
}

#[test]
fn titles_are_escaped_in_markdown_but_preserved_in_canonical_json() {
    let cards = [card("a", PriorityImpact::Low)];
    let title = r#"![x](javascript:alert(1)) ~~drop~~ *raw* <img src=x>"#;
    let titles = [IssuePlanTitle::new("a", title).expect("title")];
    let plan = build_todo_plan(&cards, &titles).expect("plan");
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
        build_todo_plan(&cards, &titles(&title_refs)),
        Err(IssuePlanError::TooManyCards)
    );
}

#[test]
fn plan_output_is_bounded_and_contains_priority_order_keys() {
    let cards = [card("a", PriorityImpact::Critical)];
    let plan = build_todo_plan(&cards, &titles(&["a"]))
        .expect("plan")
        .expect_resolved();
    let item = plan.item("a").expect("item");
    assert_eq!(item.priority_order_key(), cards[0].priority_order_key());
    assert!(plan.render_markdown().expect("markdown").len() < 32 * 1024);
    assert!(plan.render_json().expect("json").len() < 32 * 1024);
}
