use workflow_compiler::{GraphValidationError, MissingEdgeEndpoint, validate_graph};
use workflow_ir::WorkflowIr;
use workflow_spec::parse_str;

fn ir(source: &str) -> WorkflowIr {
    WorkflowIr::from(&parse_str("graph.workflow.toml", source).expect("fixture should parse"))
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
fn accepts_a_single_terminal_node() {
    let ir = ir(r#"
schema_version = 1
edges = []

[workflow]
id = "single-terminal"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"
"#);

    assert_eq!(validate_graph(&ir), Ok(()));
}

#[test]
fn accepts_a_branching_dag() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "branching"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "left"
kind = "action"

[[nodes]]
id = "right"
kind = "validator"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "start"
to = "left"

[[edges]]
from = "start"
to = "right"

[[edges]]
from = "left"
to = "done"

[[edges]]
from = "right"
to = "done"
"#);

    assert_eq!(validate_graph(&ir), Ok(()));
}

#[test]
fn rejects_duplicate_node_ids_with_their_exact_count() {
    let ir = ir(r#"
schema_version = 1
edges = []

[workflow]
id = "duplicates"
version = "1"
entry = "done"

[[nodes]]
id = "dup"
kind = "agent"

[[nodes]]
id = "dup"
kind = "terminal"

[[nodes]]
id = "done"
kind = "terminal"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::DuplicateNodeId {
            node_id: node_id(&ir, "dup"),
            occurrences: 2,
        })
    );
}

#[test]
fn rejects_a_missing_entry_node() {
    let ir = ir(r#"
schema_version = 1
edges = []

[workflow]
id = "missing-entry"
version = "1"
entry = "absent"

[[nodes]]
id = "done"
kind = "terminal"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::MissingEntryNode {
            entry_node_id: ir.entry_node_id().clone(),
        })
    );
}

#[test]
fn rejects_dangling_origins_destinations_and_both_endpoints() {
    for (source, from, to, missing) in [
        (
            r#"
schema_version = 1

[workflow]
id = "origin"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "missing"
to = "done"
"#,
            "missing",
            "done",
            MissingEdgeEndpoint::Origin,
        ),
        (
            r#"
schema_version = 1

[workflow]
id = "destination"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "start"
to = "missing"
"#,
            "start",
            "missing",
            MissingEdgeEndpoint::Destination,
        ),
        (
            r#"
schema_version = 1

[workflow]
id = "both"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "missing-from"
to = "missing-to"
"#,
            "missing-from",
            "missing-to",
            MissingEdgeEndpoint::Both,
        ),
    ] {
        let ir = ir(source);
        assert_eq!(
            validate_graph(&ir),
            Err(GraphValidationError::DanglingEdge {
                from: ir
                    .edges()
                    .iter()
                    .find(|edge| edge.from().as_str() == from && edge.to().as_str() == to)
                    .expect("fixture edge should exist")
                    .from()
                    .clone(),
                to: ir
                    .edges()
                    .iter()
                    .find(|edge| edge.from().as_str() == from && edge.to().as_str() == to)
                    .expect("fixture edge should exist")
                    .to()
                    .clone(),
                missing,
            })
        );
    }
}

#[test]
fn chooses_the_canonical_first_dangling_edge() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "canonical-edge"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "z"
to = "missing-z"

[[edges]]
from = "a"
to = "missing-a"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::DanglingEdge {
            from: ir.edges()[0].from().clone(),
            to: ir.edges()[0].to().clone(),
            missing: MissingEdgeEndpoint::Both,
        })
    );
}

#[test]
fn rejects_canonical_first_unreachable_node_before_a_disconnected_cycle() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "unreachable"
version = "1"
entry = "entry"

[[nodes]]
id = "entry"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "cycle-a"
kind = "agent"

[[nodes]]
id = "cycle-b"
kind = "agent"

[[nodes]]
id = "orphan"
kind = "terminal"

[[edges]]
from = "entry"
to = "done"

[[edges]]
from = "cycle-a"
to = "cycle-b"

[[edges]]
from = "cycle-b"
to = "cycle-a"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::UnreachableNode {
            node_id: node_id(&ir, "cycle-a"),
        })
    );
}

#[test]
fn rejects_when_no_reachable_terminal_exists() {
    let ir = ir(r#"
schema_version = 1
edges = []

[workflow]
id = "no-terminal"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::NoReachableTerminal)
    );
}

#[test]
fn rejects_a_reachable_non_terminal_sink() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "sink"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "sink"
kind = "action"

[[edges]]
from = "start"
to = "done"

[[edges]]
from = "start"
to = "sink"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::CannotReachTerminal {
            node_id: node_id(&ir, "sink"),
        })
    );
}

#[test]
fn rejects_a_two_node_cycle_even_with_a_terminal_exit() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "two-cycle"
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

[[edges]]
from = "a"
to = "b"

[[edges]]
from = "b"
to = "a"

[[edges]]
from = "b"
to = "done"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::UnboundedCycle {
            node_ids: vec![node_id(&ir, "a"), node_id(&ir, "b")],
        })
    );
}

#[test]
fn rejects_a_self_loop_even_with_a_terminal_exit() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "self-loop"
version = "1"
entry = "loop"

[[nodes]]
id = "loop"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "loop"
to = "loop"

[[edges]]
from = "loop"
to = "done"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::UnboundedCycle {
            node_ids: vec![node_id(&ir, "loop")],
        })
    );
}

#[test]
fn accepts_duplicate_edges() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "duplicate-edges"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "start"
to = "done"

[[edges]]
from = "start"
to = "done"
"#);

    assert_eq!(validate_graph(&ir), Ok(()));
}

#[test]
fn accepts_a_terminal_with_outgoing_edges_when_all_nodes_are_live() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "terminal-outgoing"
version = "1"
entry = "first"

[[nodes]]
id = "first"
kind = "terminal"

[[nodes]]
id = "middle"
kind = "agent"

[[nodes]]
id = "last"
kind = "terminal"

[[edges]]
from = "first"
to = "middle"

[[edges]]
from = "middle"
to = "last"
"#);

    assert_eq!(validate_graph(&ir), Ok(()));
}

#[test]
fn resolves_structural_errors_before_derived_graph_claims() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "structural-first"
version = "1"
entry = "missing-entry"

[[nodes]]
id = "duplicate"
kind = "agent"

[[nodes]]
id = "duplicate"
kind = "terminal"

[[edges]]
from = "duplicate"
to = "missing-target"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::DuplicateNodeId {
            node_id: node_id(&ir, "duplicate"),
            occurrences: 2,
        })
    );
}

#[test]
fn chooses_the_canonical_first_of_multiple_cycles() {
    let ir = ir(r#"
schema_version = 1

[workflow]
id = "multiple-cycles"
version = "1"
entry = "entry"

[[nodes]]
id = "entry"
kind = "agent"

[[nodes]]
id = "a"
kind = "agent"

[[nodes]]
id = "b"
kind = "agent"

[[nodes]]
id = "x"
kind = "agent"

[[nodes]]
id = "y"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "entry"
to = "a"

[[edges]]
from = "entry"
to = "x"

[[edges]]
from = "a"
to = "b"

[[edges]]
from = "b"
to = "a"

[[edges]]
from = "b"
to = "done"

[[edges]]
from = "x"
to = "y"

[[edges]]
from = "y"
to = "x"

[[edges]]
from = "y"
to = "done"
"#);

    assert_eq!(
        validate_graph(&ir),
        Err(GraphValidationError::UnboundedCycle {
            node_ids: vec![node_id(&ir, "a"), node_id(&ir, "b")],
        })
    );
}

#[test]
fn distinguishes_a_singleton_scc_without_a_loop_from_a_self_loop() {
    let acyclic = ir(r#"
schema_version = 1

[workflow]
id = "singleton"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "start"
to = "done"
"#);
    assert_eq!(validate_graph(&acyclic), Ok(()));

    let looped = ir(r#"
schema_version = 1

[workflow]
id = "singleton-loop"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "done"
to = "done"
"#);
    assert_eq!(
        validate_graph(&looped),
        Err(GraphValidationError::UnboundedCycle {
            node_ids: vec![node_id(&looped, "done")],
        })
    );
}

#[test]
fn validates_a_large_iterative_dag_without_stack_growth() {
    const NODES: usize = 1_024;
    let mut source = String::from(
        "schema_version = 1\n\n[workflow]\nid = \"large\"\nversion = \"1\"\nentry = \"n0000\"\n",
    );
    for index in 0..NODES {
        let kind = if index + 1 == NODES {
            "terminal"
        } else {
            "agent"
        };
        source.push_str(&format!(
            "\n[[nodes]]\nid = \"n{index:04}\"\nkind = \"{kind}\"\n"
        ));
    }
    for index in 0..NODES - 1 {
        source.push_str(&format!(
            "\n[[edges]]\nfrom = \"n{index:04}\"\nto = \"n{:04}\"\n",
            index + 1
        ));
    }

    assert_eq!(validate_graph(&ir(&source)), Ok(()));
}
