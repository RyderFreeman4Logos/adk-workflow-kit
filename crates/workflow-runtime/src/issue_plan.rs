//! Deterministic explicit dependency plan over admitted issue cards.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt::{self, Write as _},
};

use serde::Serialize;

use crate::{ComponentId, IssueCardV1, PriorityOrderKey, typed_protocol::escape_markdown};

/// Maximum admitted cards. Graph work is rejected before it begins.
pub const ISSUE_PLAN_MAX_CARDS: usize = 64;
/// Maximum explicit edges admitted for one plan.
pub const ISSUE_PLAN_MAX_EDGES: usize = ISSUE_PLAN_MAX_CARDS * ISSUE_PLAN_MAX_CARDS;
const ISSUE_PLAN_MAX_RENDERED_BYTES: usize = 32 * 1024;

/// Caller-supplied title keyed by an admitted card identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuePlanTitle {
    id: String,
    title: String,
}

impl IssuePlanTitle {
    /// Admits a bounded title for one card identifier.
    pub fn new(id: impl Into<String>, title: impl Into<String>) -> Result<Self, IssuePlanError> {
        let id = ComponentId::new(id.into()).map_err(|_| IssuePlanError::EmptyTitle)?;
        let title = title.into();
        if title.trim().is_empty() || title.chars().any(char::is_control) || title.len() > 4 * 1024
        {
            return Err(IssuePlanError::EmptyTitle);
        }
        Ok(Self {
            id: id.as_str().to_owned(),
            title,
        })
    }
}

/// A caller-supplied issue edge; generic card prerequisites are not issue edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitIssueEdge {
    predecessor_id: String,
    dependent_id: String,
}

impl ExplicitIssueEdge {
    /// Admits one bounded, caller-supplied predecessor-to-dependent edge.
    pub fn new(
        predecessor_id: impl Into<String>,
        dependent_id: impl Into<String>,
    ) -> Result<Self, IssuePlanError> {
        let predecessor_id = predecessor_id.into();
        let dependent_id = dependent_id.into();
        ComponentId::new(predecessor_id.clone())
            .map_err(|_| IssuePlanError::InvalidEdgeEndpoint)?;
        ComponentId::new(dependent_id.clone()).map_err(|_| IssuePlanError::InvalidEdgeEndpoint)?;
        Ok(Self {
            predecessor_id,
            dependent_id,
        })
    }

    /// Returns the explicit predecessor card identifier.
    pub fn predecessor_id(&self) -> &str {
        &self.predecessor_id
    }

    /// Returns the explicit dependent card identifier.
    pub fn dependent_id(&self) -> &str {
        &self.dependent_id
    }
}

/// Fail-closed input errors for an explicit dependency plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssuePlanError {
    /// More cards were supplied than the planner admits.
    TooManyCards,
    /// More explicit edges were supplied than the planner admits.
    TooManyEdges,
    /// Two cards use the same identifier.
    DuplicateCardId(String),
    /// An explicit edge endpoint does not name an admitted card.
    UnknownEdgeEndpoint(String),
    /// An explicit edge endpoint is empty, contains a control character, or exceeds its bound.
    InvalidEdgeEndpoint,
    /// An admitted card has no title.
    MissingTitle(String),
    /// A title names a card that was not admitted.
    ExtraTitle(String),
    /// Two titles name the same card.
    DuplicateTitle(String),
    /// A title is empty, contains a control character, or exceeds its bound.
    EmptyTitle,
    /// Canonical Markdown or JSON exceeds its byte bound.
    RenderedTooLarge,
}

impl fmt::Display for IssuePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyCards => formatter.write_str("issue plan exceeds its card bound"),
            Self::TooManyEdges => formatter.write_str("issue plan exceeds its explicit edge bound"),
            Self::DuplicateCardId(id) => write!(formatter, "duplicate issue-card id: {id}"),
            Self::UnknownEdgeEndpoint(id) => {
                write!(formatter, "explicit issue edge names unknown card {id}")
            }
            Self::InvalidEdgeEndpoint => {
                formatter.write_str("explicit issue edge endpoint is invalid")
            }
            Self::MissingTitle(id) => write!(formatter, "missing title for card {id}"),
            Self::ExtraTitle(id) => write!(formatter, "extra title for unknown card {id}"),
            Self::DuplicateTitle(id) => write!(formatter, "duplicate title for card {id}"),
            Self::EmptyTitle => formatter.write_str("issue-plan title is empty or too large"),
            Self::RenderedTooLarge => formatter.write_str("issue plan render exceeds its bound"),
        }
    }
}

impl Error for IssuePlanError {}

/// One planned item and its reduced direct prerequisites.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TodoItem {
    id: String,
    title: String,
    prerequisites: Vec<String>,
    priority_order_key: PriorityOrderKey,
}

impl TodoItem {
    /// Returns the card identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the caller-supplied title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns reduced direct prerequisites, predecessor first.
    pub fn prerequisites(&self) -> &[String] {
        &self.prerequisites
    }

    /// Returns the card priority key used as the stable tie-breaker.
    pub fn priority_order_key(&self) -> &PriorityOrderKey {
        &self.priority_order_key
    }
}

/// Resolved order or exact unresolved strongly connected components.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TodoPlan {
    /// Dependency-legal order with transitively reduced edges.
    Resolved(Vec<TodoItem>),
    /// Self and multinode cycles, without downstream residue.
    Unresolved {
        /// Planned items in stable card order.
        items: Vec<TodoItem>,
        /// Exact SCCs, each sorted, then ordered by first member.
        cycles: Vec<Vec<String>>,
    },
}

impl TodoPlan {
    /// Returns the resolved plan or panics when a cycle was reported.
    pub fn expect_resolved(self) -> Self {
        match self {
            Self::Resolved(_) => self,
            Self::Unresolved { .. } => panic!("todo plan is unresolved"),
        }
    }

    /// Returns planned item identifiers in output order.
    pub fn item_ids(&self) -> Vec<&str> {
        self.items().iter().map(|item| item.id.as_str()).collect()
    }

    /// Returns one planned item by identifier.
    pub fn item(&self, id: &str) -> Option<&TodoItem> {
        self.items().iter().find(|item| item.id == id)
    }

    /// Returns exact unresolved SCCs. A resolved plan has none.
    pub fn cycles(&self) -> &[Vec<String>] {
        match self {
            Self::Resolved(_) => &[],
            Self::Unresolved { cycles, .. } => cycles,
        }
    }

    /// Renders escaped Markdown. Titles are never treated as render-safe.
    pub fn render_markdown(&self) -> Result<String, IssuePlanError> {
        let mut rendered = String::new();
        let status = match self {
            Self::Resolved(_) => "resolved",
            Self::Unresolved { .. } => "unresolved",
        };
        writeln!(rendered, "status: {status}").expect("String cannot fail");
        for item in self.items() {
            writeln!(
                rendered,
                "- {} {}",
                escape_markdown(&item.id),
                escape_markdown(&item.title)
            )
            .expect("String cannot fail");
        }
        for cycle in self.cycles() {
            writeln!(
                rendered,
                "cycle: {}",
                cycle
                    .iter()
                    .map(|id| escape_markdown(id))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
            .expect("String cannot fail");
        }
        bounded(rendered)
    }

    /// Renders canonical JSON with caller titles preserved exactly.
    pub fn render_json(&self) -> Result<String, IssuePlanError> {
        let status = match self {
            Self::Resolved(_) => "resolved",
            Self::Unresolved { .. } => "unresolved",
        };
        let payload = serde_json::json!({
            "status": status,
            "items": self.items(),
            "cycles": self.cycles(),
        });
        bounded(serde_json::to_string(&payload).expect("plan JSON cannot fail"))
    }

    fn items(&self) -> &[TodoItem] {
        match self {
            Self::Resolved(items) | Self::Unresolved { items, .. } => items,
        }
    }
}

/// Builds a deterministic plan from explicit issue edges and caller-supplied titles.
pub fn build_todo_plan(
    cards: &[IssueCardV1],
    edges: &[ExplicitIssueEdge],
    titles: &[IssuePlanTitle],
) -> Result<TodoPlan, IssuePlanError> {
    if cards.len() > ISSUE_PLAN_MAX_CARDS || titles.len() > ISSUE_PLAN_MAX_CARDS {
        return Err(IssuePlanError::TooManyCards);
    }
    if edges.len() > ISSUE_PLAN_MAX_EDGES {
        return Err(IssuePlanError::TooManyEdges);
    }
    let mut by_id = BTreeMap::<String, &IssueCardV1>::new();
    for card in cards {
        if by_id.insert(card.id().to_owned(), card).is_some() {
            return Err(IssuePlanError::DuplicateCardId(card.id().to_owned()));
        }
    }
    let mut title_by_id = BTreeMap::<String, String>::new();
    for title in titles {
        if !by_id.contains_key(&title.id) {
            return Err(IssuePlanError::ExtraTitle(title.id.clone()));
        }
        if title_by_id
            .insert(title.id.clone(), title.title.clone())
            .is_some()
        {
            return Err(IssuePlanError::DuplicateTitle(title.id.clone()));
        }
    }
    for id in by_id.keys() {
        if !title_by_id.contains_key(id) {
            return Err(IssuePlanError::MissingTitle(id.clone()));
        }
    }
    let mut predecessors = BTreeMap::<String, BTreeSet<String>>::new();
    let mut successors = BTreeMap::<String, BTreeSet<String>>::new();
    for id in by_id.keys() {
        predecessors.insert(id.clone(), BTreeSet::new());
        successors.insert(id.clone(), BTreeSet::new());
    }
    for edge in edges {
        if !by_id.contains_key(edge.predecessor_id()) {
            return Err(IssuePlanError::UnknownEdgeEndpoint(
                edge.predecessor_id().to_owned(),
            ));
        }
        if !by_id.contains_key(edge.dependent_id()) {
            return Err(IssuePlanError::UnknownEdgeEndpoint(
                edge.dependent_id().to_owned(),
            ));
        }
        predecessors
            .get_mut(edge.dependent_id())
            .expect("dependent")
            .insert(edge.predecessor_id().to_owned());
        successors
            .get_mut(edge.predecessor_id())
            .expect("predecessor")
            .insert(edge.dependent_id().to_owned());
    }
    let cycles = strongly_connected(&successors);
    let reduced = if cycles.is_empty() {
        transitive_reduction(&predecessors, &successors)
    } else {
        predecessors.clone()
    };
    let mut items = Vec::new();
    for id in ordered_ids(&successors, &by_id, cycles.is_empty()) {
        items.push(TodoItem {
            title: title_by_id[&id].clone(),
            prerequisites: reduced[&id].iter().cloned().collect(),
            priority_order_key: by_id[&id].priority_order_key().clone(),
            id,
        });
    }
    let plan = if cycles.is_empty() {
        TodoPlan::Resolved(items)
    } else {
        TodoPlan::Unresolved { items, cycles }
    };
    plan.render_markdown()?;
    plan.render_json()?;
    Ok(plan)
}

fn ordered_ids(
    successors: &BTreeMap<String, BTreeSet<String>>,
    cards: &BTreeMap<String, &IssueCardV1>,
    acyclic: bool,
) -> Vec<String> {
    if !acyclic {
        return successors.keys().cloned().collect();
    }
    let mut indegree = BTreeMap::<String, usize>::new();
    for id in successors.keys() {
        indegree.insert(id.clone(), 0);
    }
    for dependents in successors.values() {
        for dependent in dependents {
            *indegree.get_mut(dependent).expect("dependent") += 1;
        }
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::new();
    while !ready.is_empty() {
        let id = ready
            .iter()
            .max_by(|left, right| {
                cards
                    .get(*left)
                    .expect("card")
                    .priority_order_key()
                    .cmp(cards.get(*right).expect("card").priority_order_key())
            })
            .expect("ready card")
            .clone();
        ready.remove(&id);
        ordered.push(id.clone());
        for dependent in &successors[&id] {
            let degree = indegree.get_mut(dependent).expect("dependent");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    ordered
}

fn transitive_reduction(
    predecessors: &BTreeMap<String, BTreeSet<String>>,
    successors: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    predecessors
        .iter()
        .map(|(id, direct)| {
            let reduced = direct
                .iter()
                .filter(|predecessor| {
                    !direct.iter().any(|other| {
                        *predecessor != other && reaches(successors, predecessor, other)
                    })
                })
                .cloned()
                .collect();
            (id.clone(), reduced)
        })
        .collect()
}

fn reaches(successors: &BTreeMap<String, BTreeSet<String>>, from: &str, target: &str) -> bool {
    let mut seen = BTreeSet::new();
    let mut pending = VecDeque::from([from.to_owned()]);
    while let Some(id) = pending.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }
        for successor in &successors[&id] {
            if successor == target {
                return true;
            }
            pending.push_back(successor.clone());
        }
    }
    false
}

struct SccState<'a> {
    successors: &'a BTreeMap<String, BTreeSet<String>>,
    index: BTreeMap<String, usize>,
    low: BTreeMap<String, usize>,
    stack: Vec<String>,
    stacked: BTreeSet<String>,
    next: usize,
    cycles: Vec<Vec<String>>,
}
fn strongly_connected(successors: &BTreeMap<String, BTreeSet<String>>) -> Vec<Vec<String>> {
    let mut state = SccState {
        successors,
        index: BTreeMap::new(),
        low: BTreeMap::new(),
        stack: Vec::new(),
        stacked: BTreeSet::new(),
        next: 0,
        cycles: Vec::new(),
    };
    let ids = state.successors.keys().cloned().collect::<Vec<_>>();
    for id in ids {
        if !state.index.contains_key(&id) {
            state.visit(&id);
        }
    }
    state.cycles.sort();
    state.cycles
}

impl SccState<'_> {
    fn visit(&mut self, id: &str) {
        let ordinal = self.next;
        self.next += 1;
        self.index.insert(id.to_owned(), ordinal);
        self.low.insert(id.to_owned(), ordinal);
        self.stack.push(id.to_owned());
        self.stacked.insert(id.to_owned());
        let neighbors = self
            .successors
            .get(id)
            .into_iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        for neighbor in neighbors {
            if !self.index.contains_key(&neighbor) {
                self.visit(&neighbor);
                let neighbor_low = self.low[&neighbor];
                let own_low = self.low.get_mut(id).expect("low");
                *own_low = (*own_low).min(neighbor_low);
            } else if self.stacked.contains(&neighbor) {
                let neighbor_index = self.index[&neighbor];
                let own_low = self.low.get_mut(id).expect("low");
                *own_low = (*own_low).min(neighbor_index);
            }
        }
        if self.low[id] == self.index[id] {
            let mut component = Vec::new();
            while let Some(member) = self.stack.pop() {
                self.stacked.remove(&member);
                let root = member == id;
                component.push(member);
                if root {
                    break;
                }
            }
            component.sort();
            if component.len() > 1 || self.successors[id].contains(id) {
                self.cycles.push(component);
            }
        }
    }
}

fn bounded(rendered: String) -> Result<String, IssuePlanError> {
    if rendered.len() > ISSUE_PLAN_MAX_RENDERED_BYTES {
        Err(IssuePlanError::RenderedTooLarge)
    } else {
        Ok(rendered)
    }
}
