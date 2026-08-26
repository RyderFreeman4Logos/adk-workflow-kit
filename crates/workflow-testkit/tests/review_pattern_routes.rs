//! REVIEW-002: producer → validator → reviewer → reviser pattern routes.
//!
//! Compiles the review-pattern TOML fixture with registered predicate routes
//! and drives the scripted ADK role agents so that every declared route
//! target is reached (planning-pack `08_REVIEW_REVISE_VALIDATE_RELIABILITY.md`
//! §2, issue #26). No runtime graph executor exists by design: the route walk
//! below is the test-local scripted ADK walk that mirrors the compiled route
//! declarations, and deterministic validator outcomes are consulted directly.

use std::{collections::HashMap, fmt, panic::AssertUnwindSafe, sync::Arc};

use adk_rust::{
    Agent, Artifacts, CallbackContext, Content, InvocationContext, Part, ReadonlyContext,
    RunConfig, Session, State,
    agent::LlmAgentBuilder,
    futures::{FutureExt, StreamExt},
};
use serde_json::{Value, json};
use workflow_compiler::{
    CompiledPlan, PredicateRegistry, RegistryCategory, RegistryEntry, RegistryNotFound,
    compile_str_with_predicates,
};
use workflow_ir::{IrNode, IrNodeKind, IrPredicateRoute, WorkflowIr};
use workflow_review::{
    REVIEW_SCHEMA_VERSION_V1, ReviewDefect, ReviewError, ReviewResult, ReviewSeverity,
    ReviewVerdict,
};
use workflow_runtime::{RunSessionIds, SessionRole};
use workflow_testkit::{NoProgressError, NonProgressDetector, ScriptStep, ScriptedLlm};

const FIXTURE: &str = include_str!("fixtures/review_pattern.workflow.toml");
const NON_PROGRESS_FIXTURE: &str = include_str!("fixtures/non_progress.workflow.toml");
const BYPASS_REVIEWER_FIXTURE: &str = include_str!("fixtures/bypass_reviewer.workflow.toml");
const REVISE_BYPASS_FIXTURE: &str = include_str!("fixtures/revise_bypass.workflow.toml");

/// The route declarations the compiled fixture must carry (planning-pack 08 §2
/// and issue #26): validator verdicts, reviewer verdicts, and the final
/// deterministic validation that gates publish.
const CONTRACT_ROUTES: &[(&str, &str, &str)] = &[
    ("validate", "pass", "review"),
    ("validate", "fail", "revise"),
    ("review", "pass", "validate-final"),
    ("review", "revise", "revise"),
    ("review", "abstain", "abstain"),
    ("validate-final", "pass", "publish"),
    ("validate-final", "fail", "fail"),
];

/// Internal producer-context marker that must never leak into the reviewer
/// session (ADR-0011).
const PRODUCER_MARKER: &str = "producer-internal-note";

const CANDIDATE_V1: &str = "candidate draft v1";
const CANDIDATE_V2: &str = "candidate draft v2";

fn text_response(text: &str) -> adk_rust::LlmResponse {
    adk_rust::LlmResponse::new(Content::new("model").with_text(text))
}

fn text_step(text: &str) -> ScriptStep {
    ScriptStep::new(|_| Ok(()), text_response(text))
}

fn review_json(verdict: ReviewVerdict, summary: &str) -> String {
    review_json_with_defects(verdict, summary, Vec::new())
}

fn review_json_with_defects(
    verdict: ReviewVerdict,
    summary: &str,
    defects: Vec<ReviewDefect>,
) -> String {
    ReviewResult::new(
        REVIEW_SCHEMA_VERSION_V1,
        verdict,
        summary.to_owned(),
        defects,
        0.9,
    )
    .expect("fixture review result must be valid")
    .to_json()
    .expect("fixture review result must serialize")
}

fn reviewer_input(candidate: &str) -> String {
    json!({
        "candidate": candidate,
        "validator_report": {"verdict": "pass"},
    })
    .to_string()
}

fn reviser_input(candidate: &str) -> String {
    json!({
        "candidate": candidate,
        "defects": [{"code": "grounding", "severity": "error", "message": "missing evidence"}],
    })
    .to_string()
}

/// A registry double that resolves the three exact predicate identities the
/// fixture declares and records every resolution (the compiler must never
/// invoke predicate implementations).
struct RecordingRegistry {
    entries: Vec<(String, String)>,
}

impl RecordingRegistry {
    fn new() -> Self {
        Self {
            entries: vec![
                ("validator.verdict@v1".to_owned(), "1.0.0".to_owned()),
                ("reviewer.verdict@v1".to_owned(), "1.0.0".to_owned()),
                ("final-validator.verdict@v1".to_owned(), "1.0.0".to_owned()),
            ],
        }
    }
}

static NOOP: fn() = || {};

impl PredicateRegistry for RecordingRegistry {
    type Implementation = fn();

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        let (_, entry) = self
            .entries
            .iter()
            .find(|(entry_id, entry_version)| entry_id == id && entry_version == version)
            .ok_or_else(|| RegistryNotFound::new(RegistryCategory::Predicate, id, version))?;
        Ok(RegistryEntry::new(&NOOP, entry.as_str(), entry.as_str()))
    }
}

fn compile_fixture(
    registry: &RecordingRegistry,
) -> Result<CompiledPlan, workflow_compiler::CompileError> {
    compile_str_with_predicates("review_pattern.workflow.toml", FIXTURE, registry)
}

// --- ADK role contexts ------------------------------------------------

struct PatternState;

impl State for PatternState {
    fn get(&self, _key: &str) -> Option<Value> {
        None
    }

    fn set(&mut self, _key: String, _value: Value) {}

    fn all(&self) -> HashMap<String, Value> {
        HashMap::new()
    }
}

struct PatternSession {
    id: String,
    state: PatternState,
}

impl Session for PatternSession {
    fn id(&self) -> &str {
        &self.id
    }

    fn app_name(&self) -> &str {
        "workflow-testkit"
    }

    fn user_id(&self) -> &str {
        "review-pattern"
    }

    fn state(&self) -> &dyn State {
        &self.state
    }

    fn conversation_history(&self) -> Vec<Content> {
        Vec::new()
    }
}

struct PatternContext {
    content: Content,
    session: PatternSession,
    config: RunConfig,
}

impl PatternContext {
    fn new(input: &str, session_id: &str) -> Self {
        Self {
            content: Content::new("user").with_text(input),
            session: PatternSession {
                id: session_id.to_owned(),
                state: PatternState,
            },
            config: RunConfig::default(),
        }
    }
}

impl ReadonlyContext for PatternContext {
    fn invocation_id(&self) -> &str {
        "invocation-1"
    }

    fn agent_name(&self) -> &str {
        "review-pattern-role"
    }

    fn user_id(&self) -> &str {
        "user-1"
    }

    fn app_name(&self) -> &str {
        "workflow-testkit"
    }

    fn session_id(&self) -> &str {
        &self.session.id
    }

    fn branch(&self) -> &str {
        ""
    }

    fn user_content(&self) -> &Content {
        &self.content
    }
}

impl CallbackContext for PatternContext {
    fn artifacts(&self) -> Option<Arc<dyn Artifacts>> {
        None
    }
}

impl InvocationContext for PatternContext {
    fn agent(&self) -> Arc<dyn Agent> {
        unreachable!("the scripted role agents do not request ctx.agent()")
    }

    fn memory(&self) -> Option<Arc<dyn adk_rust::Memory>> {
        None
    }

    fn session(&self) -> &dyn Session {
        &self.session
    }

    fn run_config(&self) -> &RunConfig {
        &self.config
    }

    fn end_invocation(&self) {}

    fn ended(&self) -> bool {
        false
    }
}

// --- scripted route walk ----------------------------------------------

/// One ADK role agent: a scripted model plus the exact session/input wiring
/// it runs under.
struct RoleAgent {
    id: &'static str,
    input: String,
    session_id: String,
    llm: Arc<ScriptedLlm>,
}

impl RoleAgent {
    async fn run(&self) -> Result<String, WalkError> {
        let agent = LlmAgentBuilder::new(self.id)
            .model(self.llm.clone())
            .build()
            .map_err(|_| WalkError::AgentBuild)?;
        let context = Arc::new(PatternContext::new(&self.input, &self.session_id));
        let mut events = agent.run(context).await.map_err(|_| WalkError::AgentRun)?;
        let mut text = String::new();
        while let Some(event) = events.next().await {
            let event = event.map_err(|_| WalkError::AgentRun)?;
            if let Some(content) = event.llm_response.content {
                for part in content.parts {
                    if let Part::Text { text: chunk } = part {
                        text.push_str(&chunk);
                    }
                }
            }
        }
        if text.is_empty() {
            return Err(WalkError::EmptyOutput);
        }
        Ok(text)
    }
}

/// The three role agents of the pattern plus the deterministic validator
/// outcomes. The reviser runs under the Producer session (SESSION-001: repair
/// is a producer responsibility).
struct RoleSet {
    producer: RoleAgent,
    reviewer: RoleAgent,
    reviser: RoleAgent,
    validator_results: HashMap<String, &'static str>,
}

impl RoleSet {
    fn new(sessions: &RunSessionIds, scenario: Scenario) -> Self {
        let producer_session = sessions.id(SessionRole::Producer).as_str().to_owned();
        let reviewer_session = sessions.id(SessionRole::Reviewer).as_str().to_owned();
        Self {
            producer: RoleAgent {
                id: "produce",
                input: format!("produce a candidate artifact. {PRODUCER_MARKER}"),
                session_id: producer_session.clone(),
                llm: Arc::new(ScriptedLlm::new(scenario.producer)),
            },
            reviewer: RoleAgent {
                id: "review",
                input: reviewer_input(CANDIDATE_V1),
                session_id: reviewer_session,
                llm: Arc::new(ScriptedLlm::new(scenario.reviewer)),
            },
            reviser: RoleAgent {
                id: "revise",
                input: reviser_input(CANDIDATE_V1),
                session_id: producer_session,
                llm: Arc::new(ScriptedLlm::new(scenario.reviser)),
            },
            validator_results: scenario.validator_results,
        }
    }

    fn for_node(&self, id: &str) -> Option<&RoleAgent> {
        if id == "produce" {
            return Some(&self.producer);
        }
        // The non-progress fixture unrolls the revisit loop as numbered
        // review-N / revise-N nodes; every such id maps to the same role.
        if id == "review"
            || id
                .strip_prefix("review-")
                .is_some_and(|suffix| suffix.parse::<usize>().is_ok())
        {
            return Some(&self.reviewer);
        }
        if id == "revise"
            || id
                .strip_prefix("revise-")
                .is_some_and(|suffix| suffix.parse::<usize>().is_ok())
        {
            return Some(&self.reviser);
        }
        None
    }
}

/// One scripted scenario: the scripted outputs per role and the deterministic
/// validator outcomes keyed by validator node id.
struct Scenario {
    producer: Vec<ScriptStep>,
    reviewer: Vec<ScriptStep>,
    reviser: Vec<ScriptStep>,
    validator_results: HashMap<String, &'static str>,
}

fn scenario_publish() -> Scenario {
    Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&review_json(
            ReviewVerdict::Pass,
            "candidate is acceptable",
        ))],
        reviser: Vec::new(),
        validator_results: HashMap::from([
            ("validate".to_owned(), "pass"),
            ("validate-final".to_owned(), "pass"),
        ]),
    }
}

fn scenario_validator_fail_repair() -> Scenario {
    Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&review_json(
            ReviewVerdict::Pass,
            "must not be consulted",
        ))],
        reviser: vec![text_step(CANDIDATE_V2)],
        validator_results: HashMap::from([
            ("validate".to_owned(), "fail"),
            ("validate-final".to_owned(), "pass"),
        ]),
    }
}

fn scenario_reviewer_revise_repair() -> Scenario {
    Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&review_json(
            ReviewVerdict::Revise,
            "needs revision",
        ))],
        reviser: vec![text_step(CANDIDATE_V2)],
        validator_results: HashMap::from([
            ("validate".to_owned(), "pass"),
            ("validate-final".to_owned(), "pass"),
        ]),
    }
}

fn scenario_reviewer_abstain() -> Scenario {
    Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&review_json(
            ReviewVerdict::Abstain,
            "cannot judge without more evidence",
        ))],
        reviser: Vec::new(),
        validator_results: HashMap::from([("validate".to_owned(), "pass")]),
    }
}

fn scenario_final_validation_fail() -> Scenario {
    Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&review_json(
            ReviewVerdict::Pass,
            "candidate is acceptable",
        ))],
        reviser: Vec::new(),
        validator_results: HashMap::from([
            ("validate".to_owned(), "pass"),
            ("validate-final".to_owned(), "fail"),
        ]),
    }
}

/// A recorded scripted walk: the visited node sequence.
#[derive(Debug)]
struct WalkReport {
    visited: Vec<String>,
}

/// Fail-closed walk failures. Every `Display` is static text: hostile output
/// content, paths, and secrets are never echoed into diagnostics.
#[derive(Debug)]
enum WalkError {
    MissingNode,
    AgentBuild,
    AgentRun,
    EmptyOutput,
    MissingRoleAgent,
    MissingValidatorResult,
    UnknownRouteCase,
    MissingEdge,
    MalformedReview(ReviewError),
    NoProgress(NoProgressError),
    ReviewPassBypassesValidator,
    ReviseBypassesValidator,
}

impl fmt::Display for WalkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            WalkError::MissingNode => "workflow node not found",
            WalkError::AgentBuild => "role agent could not be built",
            WalkError::AgentRun => "role agent run failed",
            WalkError::EmptyOutput => "role agent produced no output",
            WalkError::MissingRoleAgent => "role agent not provided",
            WalkError::MissingValidatorResult => "validator outcome missing",
            WalkError::UnknownRouteCase => "route case not declared",
            WalkError::MissingEdge => "no edge from node",
            WalkError::MalformedReview(_) => "malformed review output",
            WalkError::NoProgress(_) => "no-progress detection failed",
            WalkError::ReviewPassBypassesValidator => "reviewer pass must route to a validator",
            WalkError::ReviseBypassesValidator => {
                "repaired output must be revalidated before the next reviewer or publish"
            }
        })
    }
}

impl std::error::Error for WalkError {}

fn node_kind(ir: &WorkflowIr, id: &str) -> Option<IrNodeKind> {
    ir.nodes()
        .iter()
        .find(|node| node.id().as_str() == id)
        .map(IrNode::kind)
}

fn route_from<'a>(ir: &'a WorkflowIr, id: &str) -> Option<&'a IrPredicateRoute> {
    ir.routes().iter().find(|route| route.from().as_str() == id)
}

fn edge_target<'a>(ir: &'a WorkflowIr, id: &str) -> Option<&'a str> {
    ir.edges()
        .iter()
        .find(|edge| edge.from().as_str() == id)
        .map(|edge| edge.to().as_str())
}

fn verdict_key(verdict: ReviewVerdict) -> &'static str {
    match verdict {
        ReviewVerdict::Pass => "pass",
        ReviewVerdict::Revise => "revise",
        ReviewVerdict::Abstain => "abstain",
    }
}

/// Walks the compiled route graph from the entry, running scripted role
/// agents at agent nodes and consulting deterministic validator outcomes at
/// validator nodes, until a terminal node is reached. A fresh detector with
/// the default cap guards each walk.
async fn walk(plan: &CompiledPlan, roles: &RoleSet) -> Result<WalkReport, WalkError> {
    walk_with_detector(plan, roles, &mut NonProgressDetector::default()).await
}

/// [`walk`] with a caller-owned no-progress detector: when the detector fires,
/// the revisit loop aborts to the already-declared `abstain` terminal
/// (REVIEW-003) instead of continuing.
async fn walk_with_detector(
    plan: &CompiledPlan,
    roles: &RoleSet,
    detector: &mut NonProgressDetector,
) -> Result<WalkReport, WalkError> {
    let ir = plan.ir();
    let mut current = ir.entry_node_id().as_str().to_owned();
    let mut visited = Vec::new();
    // REVIEW-004: set when the current node was reached via a reviewer
    // `revise` route, marking it as a reviser hop whose repaired output must
    // re-enter a validator before the next reviewer or publish.
    let mut just_revised = false;

    loop {
        visited.push(current.clone());
        let kind = node_kind(ir, &current).ok_or(WalkError::MissingNode)?;
        if kind == IrNodeKind::Terminal {
            break;
        }

        let mut parsed_key = None;
        if kind == IrNodeKind::Agent {
            let role = roles
                .for_node(&current)
                .ok_or(WalkError::MissingRoleAgent)?;
            let text = role.run().await?;
            if route_from(ir, &current).is_some() {
                // An agent node with a route is the semantic reviewer; its
                // scripted output must be a schema-valid review result.
                let review = ReviewResult::from_json(&text).map_err(WalkError::MalformedReview)?;
                if let Some(_reason) = detector.observe(&review).map_err(WalkError::NoProgress)? {
                    // REVIEW-003: no progress → the typed abstain terminal.
                    // `reason` is never echoed: its Display is static text.
                    current = "abstain".to_owned();
                    continue;
                }
                parsed_key = Some(verdict_key(review.verdict()));
            }
        }

        current = if let Some(route) = route_from(ir, &current) {
            let key = match parsed_key {
                Some(key) => key,
                None => *roles
                    .validator_results
                    .get(&current)
                    .ok_or(WalkError::MissingValidatorResult)?,
            };
            let target = route
                .cases()
                .iter()
                .find(|case| case.key() == key)
                .ok_or(WalkError::UnknownRouteCase)?;
            let target_id = target.target().as_str();
            // REVIEW-004 §1: a reviewer `pass` (a parsed review verdict) must
            // not route a non-validator; in particular pass → publish is
            // fail-closed. The target id is never echoed: the error is static.
            if parsed_key == Some("pass") && node_kind(ir, target_id) != Some(IrNodeKind::Validator)
            {
                return Err(WalkError::ReviewPassBypassesValidator);
            }
            just_revised = parsed_key == Some("revise");
            target_id.to_owned()
        } else {
            let target_id = edge_target(ir, &current)
                .ok_or(WalkError::MissingEdge)?
                .to_owned();
            // REVIEW-004 §2: a reviser hop's next node must be a validator —
            // repaired output is revalidated before the next reviewer or
            // publish. The target id is never echoed: the error is static.
            if just_revised && node_kind(ir, &target_id) != Some(IrNodeKind::Validator) {
                return Err(WalkError::ReviseBypassesValidator);
            }
            just_revised = false;
            target_id
        };
    }

    Ok(WalkReport { visited })
}

fn request_texts(requests: &[adk_rust::LlmRequest]) -> Vec<String> {
    requests
        .iter()
        .flat_map(|request| &request.contents)
        .flat_map(|content| &content.parts)
        .filter_map(|part| match part {
            Part::Text { text } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

// --- tests -------------------------------------------------------------

#[adk_rust::tokio::test]
async fn scripted_review_pattern_reaches_all_declared_routes() {
    let registry = RecordingRegistry::new();
    let plan = compile_fixture(&registry).expect("review-pattern fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    let mut declared = plan
        .ir()
        .routes()
        .iter()
        .flat_map(|route| {
            route.cases().iter().map(move |case| {
                (
                    route.from().as_str().to_owned(),
                    case.key().to_owned(),
                    case.target().as_str().to_owned(),
                )
            })
        })
        .collect::<Vec<_>>();
    declared.sort();

    let mut expected_routes = CONTRACT_ROUTES
        .iter()
        .map(|(from, key, target)| ((*from).to_owned(), (*key).to_owned(), (*target).to_owned()))
        .collect::<Vec<_>>();
    expected_routes.sort();
    assert_eq!(
        declared, expected_routes,
        "fixture must declare the full review-pattern route set"
    );

    let scenarios: Vec<(Scenario, Vec<&str>)> = vec![
        (
            scenario_publish(),
            vec!["produce", "validate", "review", "validate-final", "publish"],
        ),
        (
            scenario_validator_fail_repair(),
            vec!["produce", "validate", "revise", "validate-final", "publish"],
        ),
        (
            scenario_reviewer_revise_repair(),
            vec![
                "produce",
                "validate",
                "review",
                "revise",
                "validate-final",
                "publish",
            ],
        ),
        (
            scenario_reviewer_abstain(),
            vec!["produce", "validate", "review", "abstain"],
        ),
        (
            scenario_final_validation_fail(),
            vec!["produce", "validate", "review", "validate-final", "fail"],
        ),
    ];

    let mut visited_all = Vec::new();
    for (scenario, expected) in scenarios {
        let roles = RoleSet::new(&sessions, scenario);
        let report = walk(&plan, &roles)
            .await
            .expect("declared scenario must walk to a terminal");
        assert_eq!(
            report.visited,
            expected
                .iter()
                .map(|node| (*node).to_owned())
                .collect::<Vec<_>>()
        );
        visited_all.extend(report.visited);
    }

    for (_, _, target) in &declared {
        assert!(
            visited_all.iter().any(|visited| visited == target),
            "declared route target {target:?} was never reached by a scripted walk"
        );
    }
}

#[adk_rust::tokio::test]
async fn reviewer_pass_cannot_waive_failed_validator() {
    let registry = RecordingRegistry::new();
    let plan = compile_fixture(&registry).expect("review-pattern fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    // The reviewer is scripted to PASS, but the deterministic validator fails:
    // the walk must route to the reviser and the reviewer must never run.
    let scenario = scenario_validator_fail_repair();
    let roles = RoleSet::new(&sessions, scenario);
    let report = walk(&plan, &roles)
        .await
        .expect("repair scenario must walk to a terminal");

    assert_eq!(
        report.visited,
        vec!["produce", "validate", "revise", "validate-final", "publish"]
    );
    assert!(
        !report.visited.iter().any(|node| node == "review"),
        "reviewer must not run when the deterministic validator failed"
    );
    assert_eq!(
        roles
            .reviewer
            .llm
            .remaining_steps()
            .expect("reviewer script state readable"),
        1,
        "reviewer script must stay unconsumed"
    );
    assert!(
        roles
            .reviewer
            .llm
            .requests()
            .expect("reviewer script state readable")
            .is_empty(),
        "reviewer must not be called while the validator outcome is failing"
    );

    // Re-validation also fails: the walk must end at the typed fail terminal,
    // never at publish, with the reviewer still never consulted.
    let scenario2 = Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&review_json(
            ReviewVerdict::Pass,
            "must not be consulted",
        ))],
        reviser: vec![text_step(CANDIDATE_V2)],
        validator_results: HashMap::from([
            ("validate".to_owned(), "fail"),
            ("validate-final".to_owned(), "fail"),
        ]),
    };
    let roles2 = RoleSet::new(&sessions, scenario2);
    let report2 = walk(&plan, &roles2)
        .await
        .expect("fail scenario must walk to a terminal");

    assert_eq!(
        report2.visited,
        vec!["produce", "validate", "revise", "validate-final", "fail"]
    );
    assert!(
        !report2
            .visited
            .iter()
            .any(|node| node == "review" || node == "publish"),
        "a reviewer pass must never waive a failed deterministic validator"
    );
    assert!(
        roles2
            .reviewer
            .llm
            .requests()
            .expect("reviewer script state readable")
            .is_empty()
    );
}

#[adk_rust::tokio::test]
async fn reviewer_pass_cannot_route_straight_to_publish() {
    let registry = RecordingRegistry::new();
    let plan = compile_str_with_predicates(
        "bypass_reviewer.workflow.toml",
        BYPASS_REVIEWER_FIXTURE,
        &registry,
    )
    .expect("bypass-reviewer fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    // The reviewer passes, but the fixture routes straight to publish with no
    // validator in between. The walk must fail closed (REVIEW-004 §1).
    let scenario = Scenario {
        producer: Vec::new(),
        reviewer: vec![text_step(&review_json(ReviewVerdict::Pass, "acceptable"))],
        reviser: Vec::new(),
        validator_results: HashMap::new(),
    };
    let roles = RoleSet::new(&sessions, scenario);
    let error = walk(&plan, &roles)
        .await
        .expect_err("a reviewer pass must never route straight to publish");
    assert_eq!(error.to_string(), "reviewer pass must route to a validator");
}

#[adk_rust::tokio::test]
async fn walk_reenters_validator_after_every_revise() {
    let registry = RecordingRegistry::new();
    let plan = compile_str_with_predicates(
        "revise_bypass.workflow.toml",
        REVISE_BYPASS_FIXTURE,
        &registry,
    )
    .expect("revise-bypass fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    // A reviser hop routes repaired output straight to publish with no
    // revalidation. The walk must fail closed (REVIEW-004 §2).
    let scenario = Scenario {
        producer: Vec::new(),
        reviewer: vec![text_step(&review_json(ReviewVerdict::Revise, "needs work"))],
        reviser: vec![text_step(CANDIDATE_V2)],
        validator_results: HashMap::new(),
    };
    let roles = RoleSet::new(&sessions, scenario);
    let error = walk(&plan, &roles)
        .await
        .expect_err("a reviser hop must re-enter a validator before the next reviewer or publish");
    assert_eq!(
        error.to_string(),
        "repaired output must be revalidated before the next reviewer or publish"
    );
}

#[adk_rust::tokio::test]
async fn revised_candidate_failing_final_validation_never_publishes() {
    let registry = RecordingRegistry::new();
    let plan = compile_fixture(&registry).expect("review-pattern fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    // The reviewer revises, the reviser repairs, but the final validator
    // rejects the repaired candidate: the walk must end at the fail terminal,
    // never at publish (REVIEW-004 §2).
    let scenario = Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&review_json(ReviewVerdict::Revise, "needs work"))],
        reviser: vec![text_step(CANDIDATE_V2)],
        validator_results: HashMap::from([
            ("validate".to_owned(), "pass"),
            ("validate-final".to_owned(), "fail"),
        ]),
    };
    let roles = RoleSet::new(&sessions, scenario);
    let report = walk(&plan, &roles)
        .await
        .expect("revised candidate must walk to a terminal");
    assert_eq!(
        report.visited.last().map(String::as_str),
        Some("fail"),
        "a revisited candidate failing final validation must not publish"
    );
    assert!(
        !report.visited.iter().any(|node| node == "publish"),
        "a revisited candidate failing final validation must never reach publish"
    );
}

#[adk_rust::tokio::test]
async fn valid_revise_then_validated_pass_reaches_publish() {
    let registry = RecordingRegistry::new();
    let plan = compile_fixture(&registry).expect("review-pattern fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    // False-positive guard: a valid revise followed by a validator pass must
    // still reach publish, with a validator explicitly between revise and
    // publish (REVIEW-004 §3).
    let scenario = Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&review_json(ReviewVerdict::Revise, "needs work"))],
        reviser: vec![text_step(CANDIDATE_V2)],
        validator_results: HashMap::from([
            ("validate".to_owned(), "pass"),
            ("validate-final".to_owned(), "pass"),
        ]),
    };
    let roles = RoleSet::new(&sessions, scenario);
    let report = walk(&plan, &roles)
        .await
        .expect("a valid revise then validated pass must reach publish");
    assert_eq!(
        report.visited,
        vec![
            "produce",
            "validate",
            "review",
            "revise",
            "validate-final",
            "publish"
        ]
    );
}

#[adk_rust::tokio::test]
async fn producer_and_reviewer_sessions_stay_isolated() {
    let registry = RecordingRegistry::new();
    let plan = compile_fixture(&registry).expect("review-pattern fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    let producer_id = sessions.id(SessionRole::Producer).as_str().to_owned();
    let reviewer_id = sessions.id(SessionRole::Reviewer).as_str().to_owned();
    assert_ne!(
        producer_id, reviewer_id,
        "producer and reviewer sessions must differ"
    );

    let scenario = scenario_publish();
    let roles = RoleSet::new(&sessions, scenario);
    assert_eq!(roles.producer.session_id, producer_id);
    assert_eq!(roles.reviewer.session_id, reviewer_id);
    assert_eq!(
        roles.reviser.session_id, producer_id,
        "reviser runs under the Producer session (SESSION-001)"
    );

    walk(&plan, &roles)
        .await
        .expect("publish scenario must walk to a terminal");

    let producer_requests = roles
        .producer
        .llm
        .requests()
        .expect("producer script state readable");
    let reviewer_requests = roles
        .reviewer
        .llm
        .requests()
        .expect("reviewer script state readable");
    assert_eq!(producer_requests.len(), 1);
    assert_eq!(reviewer_requests.len(), 1);

    let producer_text = request_texts(&producer_requests).concat();
    let reviewer_text = request_texts(&reviewer_requests).concat();
    assert!(
        producer_text.contains(PRODUCER_MARKER),
        "producer context must carry its own marker"
    );
    assert!(
        !reviewer_text.contains(PRODUCER_MARKER),
        "producer-only reasoning must not leak into the reviewer session"
    );
}

#[adk_rust::tokio::test]
async fn hostile_scripted_outputs_are_not_echoed_in_diagnostics() {
    const HOSTILE_PATH: &str = "/etc/shadow";
    const HOSTILE_SECRET: &str = "secret-token=abcd1234";
    const HOSTILE_SUMMARY: &str = "findings at /etc/shadow with secret-token=abcd1234";

    let registry = RecordingRegistry::new();
    let plan = compile_fixture(&registry).expect("review-pattern fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    let hostile_review = review_json_with_defects(
        ReviewVerdict::Pass,
        HOSTILE_SUMMARY,
        vec![ReviewDefect::new(
            "unsupported_claim".to_owned(),
            ReviewSeverity::Warning,
            Some(HOSTILE_PATH.to_owned()),
            vec!["artifact:opaque".to_owned()],
            format!("claims at {HOSTILE_SECRET}"),
            None,
        )],
    );

    // The hostile review output is valid schema data: the walk must succeed
    // end-to-end with the hostile payload flowing through as opaque data and
    // producing no diagnostics at all.
    let scenario_ok = Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&hostile_review)],
        reviser: Vec::new(),
        validator_results: HashMap::from([
            ("validate".to_owned(), "pass"),
            ("validate-final".to_owned(), "pass"),
        ]),
    };
    let roles_ok = RoleSet::new(&sessions, scenario_ok);
    let report = walk(&plan, &roles_ok)
        .await
        .expect("hostile review output must not fail the walk");
    assert_eq!(
        report.visited.last().expect("walk must reach a terminal"),
        "publish"
    );
    assert_eq!(
        roles_ok
            .reviewer
            .llm
            .remaining_steps()
            .expect("reviewer script state readable"),
        0,
        "hostile review output must be consumed"
    );
    assert_eq!(
        roles_ok
            .reviewer
            .llm
            .requests()
            .expect("reviewer script state readable")
            .len(),
        1
    );

    // The hostile content is carried as opaque ReviewResult data, never as a
    // diagnostic: the message fields round-trip through the typed payload.
    let parsed = ReviewResult::from_json(&hostile_review).expect("hostile payload is schema-valid");
    assert!(parsed.defects()[0].message().contains(HOSTILE_SECRET));

    // A later, unrelated failure still fails closed with a static diagnostic
    // that never echoes the hostile content that flowed through the walk.
    let scenario_err = Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![text_step(&hostile_review)],
        reviser: Vec::new(),
        validator_results: HashMap::from([("validate".to_owned(), "pass")]),
    };
    let roles_err = RoleSet::new(&sessions, scenario_err);
    let error = walk(&plan, &roles_err)
        .await
        .expect_err("missing final validator outcome must fail closed");

    let display = error.to_string();
    assert_eq!(display, "validator outcome missing");
    assert!(!display.contains(HOSTILE_PATH));
    assert!(!display.contains(HOSTILE_SECRET));
}

#[adk_rust::tokio::test]
async fn malformed_scripted_review_output_fails_closed_without_panic() {
    const PASS_WITH_CRITICAL: &str = r#"{
        "schema_version": 1,
        "verdict": "pass",
        "summary": "passes anyway",
        "defects": [{"code": "critical", "severity": "critical", "message": "exploit"}],
        "confidence": 0.9
    }"#;

    let registry = RecordingRegistry::new();
    let plan = compile_fixture(&registry).expect("review-pattern fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    for malformed in ["not json at all", PASS_WITH_CRITICAL] {
        let scenario = Scenario {
            producer: vec![text_step(CANDIDATE_V1)],
            reviewer: vec![text_step(malformed)],
            reviser: Vec::new(),
            validator_results: HashMap::from([("validate".to_owned(), "pass")]),
        };
        let roles = RoleSet::new(&sessions, scenario);
        let error = AssertUnwindSafe(walk(&plan, &roles))
            .catch_unwind()
            .await
            .expect("malformed review output must not panic");
        let error = error.expect_err("malformed review output must fail closed");

        assert!(
            matches!(
                &error,
                WalkError::MalformedReview(review_error)
                    if matches!(
                        review_error,
                        ReviewError::Decode { .. } | ReviewError::PassWithErrorOrCriticalDefects
                    )
            ),
            "malformed review output must fail closed as a typed review error"
        );
        assert_eq!(error.to_string(), "malformed review output");
    }
}

/// Deterministic validator outcomes for the non-progress fixture after the
/// REVIEW-004 rewire: every repair hop gets revalidated at its own validator
/// node (validate-1..validate-23) before the next reviewer, plus the shared
/// head `validate` and tail `validate-final` validators.
fn non_progress_validator_results() -> HashMap<String, &'static str> {
    let mut results = HashMap::from([
        ("validate".to_owned(), "pass"),
        ("validate-final".to_owned(), "pass"),
    ]);
    for n in 1..=23 {
        results.insert(format!("validate-{n}"), "pass");
    }
    results
}

fn compile_non_progress_fixture(
    registry: &RecordingRegistry,
) -> Result<CompiledPlan, workflow_compiler::CompileError> {
    compile_str_with_predicates("non_progress.workflow.toml", NON_PROGRESS_FIXTURE, registry)
}

#[adk_rust::tokio::test]
async fn progressing_revisions_still_reach_publish() {
    let registry = RecordingRegistry::new();
    let plan = compile_non_progress_fixture(&registry).expect("non-progress fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    // The reviewer revises twice with brand-new output each time and then
    // passes; the reviser produces a fresh candidate per hop. Nothing repeats,
    // so the no-progress detector must stay silent and the walk must reach
    // publish (false-positive guard, REVIEW-003).
    let scenario = Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: vec![
            text_step(&review_json(ReviewVerdict::Revise, "revise round one")),
            text_step(&review_json(ReviewVerdict::Revise, "revise round two")),
            text_step(&review_json(ReviewVerdict::Pass, "finally acceptable")),
        ],
        reviser: vec![text_step(CANDIDATE_V2), text_step("candidate draft v3")],
        validator_results: non_progress_validator_results(),
    };
    let roles = RoleSet::new(&sessions, scenario);
    let mut detector = NonProgressDetector::default();
    let report = walk_with_detector(&plan, &roles, &mut detector)
        .await
        .expect("progressing scenario must walk to a terminal");
    assert_eq!(
        report.visited.last().map(String::as_str),
        Some("publish"),
        "progressing revisions must still reach publish"
    );
}

#[adk_rust::tokio::test]
async fn non_progress_loop_abstains_within_run_bounds() {
    let registry = RecordingRegistry::new();
    let plan = compile_non_progress_fixture(&registry).expect("non-progress fixture must compile");
    let sessions = RunSessionIds::allocate().expect("session ids must allocate");

    // The reviewer always returns a *new* distinct revise verdict, so no
    // fingerprint repeats: only the detector's round cap can stop the loop.
    // The fixture unrolls 24 hops; the cap (MODEL_TURNS_BOUND, borrowed from
    // RUN-002 RunLimitKind::ModelTurns) must fire long before the tail.
    let reviewer_steps = (0..24)
        .map(|round| {
            text_step(&review_json(
                ReviewVerdict::Revise,
                &format!("revision round {round}"),
            ))
        })
        .collect::<Vec<_>>();
    let reviser_steps = (0..24)
        .map(|round| text_step(&format!("candidate draft round {round}")))
        .collect::<Vec<_>>();
    let scenario = Scenario {
        producer: vec![text_step(CANDIDATE_V1)],
        reviewer: reviewer_steps,
        reviser: reviser_steps,
        validator_results: non_progress_validator_results(),
    };
    let roles = RoleSet::new(&sessions, scenario);
    let mut detector = NonProgressDetector::default();
    let report = walk_with_detector(&plan, &roles, &mut detector)
        .await
        .expect("bounded walk must terminate at a terminal");
    assert_eq!(
        report.visited.last().map(String::as_str),
        Some("abstain"),
        "a non-progress loop must abstain within the run bound"
    );
    assert!(
        !report.visited.iter().any(|node| node == "publish"),
        "the run bound must fire before the unrolled fixture tail reaches publish"
    );
}
