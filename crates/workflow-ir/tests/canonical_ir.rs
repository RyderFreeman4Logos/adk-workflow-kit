use workflow_ir::{IrNodeKind, IrRouteOperator, IrSchemaVersion, WorkflowIr};
use workflow_spec::{parse_str, RouteOperator, UnsupportedRouteOperator};

const ROUTE_OPERATOR_PAIRS: [(RouteOperator, IrRouteOperator); 9] = [
    (RouteOperator::Equals, IrRouteOperator::Equals),
    (RouteOperator::NotEquals, IrRouteOperator::NotEquals),
    (RouteOperator::IsTrue, IrRouteOperator::IsTrue),
    (RouteOperator::IsFalse, IrRouteOperator::IsFalse),
    (RouteOperator::Exists, IrRouteOperator::Exists),
    (RouteOperator::IsEmpty, IrRouteOperator::IsEmpty),
    (RouteOperator::EnumCase, IrRouteOperator::EnumCase),
    (RouteOperator::NumericRange, IrRouteOperator::NumericRange),
    (RouteOperator::StatusClass, IrRouteOperator::StatusClass),
];

const NONCANONICAL_ROUTE_OPERATORS: [&str; 18] = [
    "",
    " equals",
    "equals ",
    "Equals",
    "EQUALS",
    "not-equals",
    "equal",
    "not_equal",
    "true",
    "false",
    "exist",
    "empty",
    "enum",
    "numeric_ranges",
    "status_classes",
    "range",
    "status",
    "contains",
];

const GOLDEN_WORKFLOW: &str = r#"
schema_version = 1

[workflow]
id = "w"
version = "1"
entry = "a"

[[nodes]]
id = "b"
kind = "agent"

[[nodes]]
id = "a"
kind = "terminal"

[[edges]]
from = "b"
to = "a"

[[edges]]
from = "a"
to = "b"
"#;

#[test]
fn route_operators_map_exhaustively_and_preserve_identity() {
    let mut mapped = Vec::new();

    for (operator, expected) in ROUTE_OPERATOR_PAIRS {
        let actual = IrRouteOperator::from(operator);
        assert_eq!(actual, expected);
        assert_eq!(actual.as_str(), operator.as_str());
        assert!(!mapped.contains(&actual));
        mapped.push(actual);
    }

    assert_eq!(mapped.len(), 9);
}

#[test]
fn invalid_route_operator_names_never_construct_ir() {
    for input in NONCANONICAL_ROUTE_OPERATORS {
        let mut constructed = 0;
        let result: Result<IrRouteOperator, UnsupportedRouteOperator> =
            input.parse::<RouteOperator>().map(|operator| {
                constructed += 1;
                IrRouteOperator::from(operator)
            });

        let error = result.expect_err("noncanonical operator should not construct IR");
        assert_eq!(constructed, 0);
        assert_eq!(error.input(), input);
    }
}

#[test]
fn lowers_to_a_normalized_source_free_ir_with_a_stable_hash() {
    let spec = parse_str("first.workflow.toml", GOLDEN_WORKFLOW).expect("fixture should parse");
    let ir = WorkflowIr::from(&spec);

    assert_eq!(ir.schema_version(), IrSchemaVersion::V1);
    assert_eq!(ir.workflow_id().as_str(), "w");
    assert_eq!(ir.workflow_version(), "1");
    assert_eq!(ir.entry_node_id().as_str(), "a");
    assert_eq!(
        ir.nodes()
            .iter()
            .map(|node| (node.id().as_str(), node.kind()))
            .collect::<Vec<_>>(),
        vec![("a", IrNodeKind::Terminal), ("b", IrNodeKind::Agent)]
    );
    assert_eq!(
        ir.edges()
            .iter()
            .map(|edge| (edge.from().as_str(), edge.to().as_str()))
            .collect::<Vec<_>>(),
        vec![("a", "b"), ("b", "a")]
    );
    assert_eq!(
        ir.canonical_hash().as_bytes(),
        &[
            0x86, 0x41, 0x4c, 0xb6, 0xa6, 0x6a, 0x7e, 0x5c, 0x07, 0xb5, 0xfc, 0x17, 0xbe, 0x4e,
            0xb1, 0x19, 0x85, 0x9f, 0xda, 0xd4, 0xff, 0x10, 0x1c, 0x1a, 0x48, 0xd7, 0xb6, 0x34,
            0xb3, 0xc4, 0xe8, 0x30,
        ]
    );
}

#[test]
fn source_path_and_declaration_order_do_not_change_identity() {
    let reordered = GOLDEN_WORKFLOW
        .replace(
            r#"[[nodes]]
id = "b"
kind = "agent"

[[nodes]]
id = "a"
kind = "terminal""#,
            r#"[[nodes]]
id = "a"
kind = "terminal"

[[nodes]]
id = "b"
kind = "agent""#,
        )
        .replace(
            r#"[[edges]]
from = "b"
to = "a"

[[edges]]
from = "a"
to = "b""#,
            r#"[[edges]]
from = "a"
to = "b"

[[edges]]
from = "b"
to = "a""#,
        );
    let first = WorkflowIr::from(
        &parse_str("relative/first.workflow.toml", GOLDEN_WORKFLOW).expect("fixture should parse"),
    );
    let second = WorkflowIr::from(
        &parse_str("/absolute/other.workflow.toml", &reordered).expect("fixture should parse"),
    );

    assert_eq!(first, second);
    assert_eq!(first.canonical_hash(), second.canonical_hash());
}

#[test]
fn preserves_duplicates_and_dangling_references_without_validation() {
    let source = GOLDEN_WORKFLOW
        .replace("entry = \"a\"", "entry = \"missing-entry\"")
        .replace(
            "[[edges]]\nfrom = \"b\"\nto = \"a\"",
            "[[edges]]\nfrom = \"b\"\nto = \"missing\"\n\n[[edges]]\nfrom = \"b\"\nto = \"missing\"",
        )
        .replace(
            "[[nodes]]\nid = \"b\"\nkind = \"agent\"",
            "[[nodes]]\nid = \"b\"\nkind = \"agent\"\n\n[[nodes]]\nid = \"b\"\nkind = \"agent\"",
        );
    let ir =
        WorkflowIr::from(&parse_str("invalid-graph.toml", &source).expect("fixture should parse"));

    assert_eq!(ir.entry_node_id().as_str(), "missing-entry");
    assert_eq!(ir.nodes().len(), 3);
    assert_eq!(ir.edges().len(), 3);
    assert_eq!(
        ir.edges()
            .iter()
            .filter(|edge| edge.to().as_str() == "missing")
            .count(),
        2
    );
}
