use std::cell::RefCell;

use workflow_compiler::{
    compile_str, compile_str_with_predicates, validate_graph, CompileError, GraphValidationError,
    PredicateRegistry, RegistryCategory, RegistryEntry, RegistryNotFound, WorkflowLock,
    WorkflowLockError,
};
use workflow_ir::WorkflowIr;
use workflow_spec::parse_str;

const ROUTED: &str = r#"
schema_version = 1
edges = []

[workflow]
id = "routed"
version = "1"
entry = "decide"

[[nodes]]
id = "decide"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[routes]]
from = "decide"
predicate = { id = "predicate@opaque", version = "v1+exact" }
cases = { publish = "done", revise = "done" }
"#;

struct RecordingRegistry {
    id: &'static str,
    version: &'static str,
    calls: RefCell<Vec<(String, String)>>,
    implementation: fn(),
}

impl RecordingRegistry {
    fn exact(id: &'static str, version: &'static str) -> Self {
        Self {
            id,
            version,
            calls: RefCell::new(Vec::new()),
            implementation: || panic!("compiler must not invoke predicate implementations"),
        }
    }
}

impl PredicateRegistry for RecordingRegistry {
    type Implementation = fn();

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        self.calls
            .borrow_mut()
            .push((id.to_owned(), version.to_owned()));
        if (id, version) == (self.id, self.version) {
            Ok(RegistryEntry::new(
                &self.implementation,
                self.id,
                self.version,
            ))
        } else {
            Err(RegistryNotFound::new(
                RegistryCategory::Predicate,
                id,
                version,
            ))
        }
    }
}

fn graph_error(source: &str) -> GraphValidationError {
    let spec =
        parse_str("predicate-graph.workflow.toml", source).expect("graph fixture should parse");
    validate_graph(&WorkflowIr::from(&spec)).expect_err("graph fixture should fail")
}

fn node_id(ir: &WorkflowIr, value: &str) -> workflow_ir::NodeId {
    ir.nodes()
        .iter()
        .find(|node| node.id().as_str() == value)
        .expect("fixture node should exist")
        .id()
        .clone()
}

#[test]
fn compile_str_with_predicates_resolves_exact_version_and_binds_cases_without_invoking() {
    let plan = {
        let registry = RecordingRegistry::exact("predicate@opaque", "v1+exact");
        let plan = compile_str_with_predicates("routed.workflow.toml", ROUTED, &registry)
            .expect("registered predicate route should compile");
        assert_eq!(
            *registry.calls.borrow(),
            [("predicate@opaque".to_owned(), "v1+exact".to_owned())]
        );
        plan
    };

    assert_eq!(plan.registry_binding_count(), 1);
    assert!(matches!(
        WorkflowLock::try_from_plan(&plan),
        Err(WorkflowLockError::UnsupportedSemanticResources {
            registry_binding_count: 1
        })
    ));
    assert_eq!(plan.ir().routes().len(), 1);
    assert_eq!(
        plan.ir().routes()[0]
            .cases()
            .iter()
            .map(|case| (case.key(), case.target().as_str()))
            .collect::<Vec<_>>(),
        [("publish", "done"), ("revise", "done")]
    );
}

#[test]
fn compile_str_with_predicates_rejects_missing_exact_predicate() {
    let registry = RecordingRegistry::exact("predicate@opaque", "different-version");
    let error = compile_str_with_predicates("missing-predicate.workflow.toml", ROUTED, &registry)
        .expect_err("missing exact predicate should fail");

    match error {
        CompileError::Registry(error) => {
            assert_eq!(error.category(), RegistryCategory::Predicate);
            assert_eq!(error.id(), "predicate@opaque");
            assert_eq!(error.version(), "v1+exact");
        }
        other => panic!("expected registry error, got {other:?}"),
    }
}

#[test]
fn compile_str_without_predicates_rejects_registered_routes() {
    assert!(matches!(
        compile_str("registry-required.workflow.toml", ROUTED),
        Err(CompileError::PredicateRegistryRequired)
    ));
}

#[test]
fn predicate_route_arcs_participate_in_graph_validation() {
    let valid = WorkflowIr::from(
        &parse_str("valid-route.workflow.toml", ROUTED).expect("valid fixture should parse"),
    );
    assert_eq!(validate_graph(&valid), Ok(()));

    let registry = RecordingRegistry::exact("predicate@opaque", "v1+exact");
    assert!(matches!(
        compile_str_with_predicates(
            "invalid-before-resolution.workflow.toml",
            &ROUTED.replacen(
                "cases = { publish = \"done\", revise = \"done\" }",
                "cases = {}",
                1,
            ),
            &registry,
        ),
        Err(CompileError::Graph(GraphValidationError::EmptyRouteCases))
    ));
    assert!(registry.calls.borrow().is_empty());

    let cycle = WorkflowIr::from(
        &parse_str(
            "route-cycle.workflow.toml",
            r#"
schema_version = 1
edges = []

[workflow]
id = "cycle"
version = "1"
entry = "a"

[[nodes]]
id = "a"
kind = "agent"

[[nodes]]
id = "b"
kind = "action"

[[nodes]]
id = "done"
kind = "terminal"

[[routes]]
from = "a"
predicate = { id = "a", version = "1" }
cases = { next = "b" }

[[routes]]
from = "b"
predicate = { id = "b", version = "1" }
cases = { again = "a", finish = "done" }
"#,
        )
        .expect("cycle fixture should parse"),
    );
    assert_eq!(
        validate_graph(&cycle),
        Err(GraphValidationError::Cycle {
            node_ids: vec![node_id(&cycle, "a"), node_id(&cycle, "b")],
        })
    );

    let cannot_reach_terminal = graph_error(&ROUTED.replacen(
        "[[nodes]]\nid = \"done\"\nkind = \"terminal\"",
        "[[nodes]]\nid = \"done\"\nkind = \"terminal\"\n\n[[nodes]]\nid = \"sink\"\nkind = \"action\"",
        1,
    ).replacen(
        "cases = { publish = \"done\", revise = \"done\" }",
        "cases = { publish = \"done\", revise = \"sink\" }",
        1,
    ));
    assert!(matches!(
        cannot_reach_terminal,
        GraphValidationError::CannotReachTerminal { node_id }
            if node_id.as_str() == "sink"
    ));

    assert_eq!(
        graph_error(&ROUTED.replacen(
            "cases = { publish = \"done\", revise = \"done\" }",
            "cases = {}",
            1,
        )),
        GraphValidationError::EmptyRouteCases
    );
    assert_eq!(
        graph_error(&format!(
            "{ROUTED}\n[[routes]]\nfrom = \"decide\"\npredicate = {{ id = \"other\", version = \"1\" }}\ncases = {{ done = \"done\" }}\n"
        )),
        GraphValidationError::DuplicateRouteOrigin
    );
    assert_eq!(
        graph_error(&ROUTED.replacen(
            "edges = []",
            "[[edges]]\nfrom = \"decide\"\nto = \"done\"",
            1,
        )),
        GraphValidationError::MixedRouteAndEdgeOrigin
    );
    assert_eq!(
        graph_error(&ROUTED.replacen("from = \"decide\"", "from = \"missing\"", 1)),
        GraphValidationError::DanglingRoute
    );
    assert_eq!(
        graph_error(&ROUTED.replacen("publish = \"done\"", "publish = \"missing\"", 1)),
        GraphValidationError::DanglingRoute
    );

    for (field_path, source) in [
        (
            "routes[].from",
            ROUTED.replacen("from = \"decide\"", "from = \"\"", 1),
        ),
        (
            "routes[].predicate.id",
            ROUTED.replacen("id = \"predicate@opaque\"", "id = \"\"", 1),
        ),
        (
            "routes[].predicate.version",
            ROUTED.replacen("version = \"v1+exact\"", "version = \"\"", 1),
        ),
        (
            "routes[].cases[].key",
            ROUTED.replacen("publish = \"done\"", "\"\" = \"done\"", 1),
        ),
        (
            "routes[].cases[].target",
            ROUTED.replacen("publish = \"done\"", "publish = \"\"", 1),
        ),
    ] {
        assert_eq!(
            graph_error(&source),
            GraphValidationError::InvalidIdentifier { field_path }
        );
    }
}
