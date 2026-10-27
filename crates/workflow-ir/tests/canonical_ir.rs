use sha2::{Digest, Sha256};
use workflow_ir::{
    CANONICAL_IR_WIRE_VERSION_V2, IrNodeKind, IrRouteOperator, IrSchemaVersion, WorkflowIr,
};
use workflow_spec::{RouteOperator, UnsupportedRouteOperator, parse_str};

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
fn route_free_v1_canonical_golden_remains_unchanged() {
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
fn registered_predicate_routes_use_canonical_wire_v2() {
    let spec = parse_str(
        "routes.workflow.toml",
        r#"
schema_version = 1
edges = []

[workflow]
id = "route"
version = "1"
entry = "a"

[[nodes]]
id = "z"
kind = "action"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "a"
kind = "agent"

[[routes]]
from = "z"
predicate = { id = "pred-z", version = "2" }
cases = { only = "done" }

[[routes]]
from = "a"
predicate = { id = "pred-a", version = "1" }
cases = { z = "done", a = "done" }
"#,
    )
    .expect("route fixture should parse");
    let ir = WorkflowIr::from(&spec);

    assert_eq!(CANONICAL_IR_WIRE_VERSION_V2, 2);
    assert_eq!(
        ir.routes()
            .iter()
            .map(|route| {
                (
                    route.from().as_str(),
                    route.predicate().id(),
                    route.predicate().version(),
                    route
                        .cases()
                        .iter()
                        .map(|case| (case.key(), case.target().as_str()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>(),
        [
            ("a", "pred-a", "1", vec![("a", "done"), ("z", "done")]),
            ("z", "pred-z", "2", vec![("only", "done")]),
        ]
    );

    let mut wire = b"adk-workflow-kit/workflow-ir\0".to_vec();
    wire.extend_from_slice(&2_u16.to_be_bytes());
    wire.extend_from_slice(&1_u32.to_be_bytes());
    for frame in ["route", "1", "a"] {
        wire.extend_from_slice(&(frame.len() as u64).to_be_bytes());
        wire.extend_from_slice(frame.as_bytes());
    }
    wire.extend_from_slice(&3_u64.to_be_bytes());
    for (node, kind) in [("a", 1_u8), ("done", 6), ("z", 2)] {
        wire.extend_from_slice(&(node.len() as u64).to_be_bytes());
        wire.extend_from_slice(node.as_bytes());
        wire.push(kind);
    }
    wire.extend_from_slice(&0_u64.to_be_bytes());
    wire.extend_from_slice(&2_u64.to_be_bytes());
    for (from, predicate_id, version, cases) in [
        ("a", "pred-a", "1", vec![("a", "done"), ("z", "done")]),
        ("z", "pred-z", "2", vec![("only", "done")]),
    ] {
        for frame in [from, predicate_id, version] {
            wire.extend_from_slice(&(frame.len() as u64).to_be_bytes());
            wire.extend_from_slice(frame.as_bytes());
        }
        wire.extend_from_slice(&(cases.len() as u64).to_be_bytes());
        for (key, target) in cases {
            for frame in [key, target] {
                wire.extend_from_slice(&(frame.len() as u64).to_be_bytes());
                wire.extend_from_slice(frame.as_bytes());
            }
        }
    }

    assert_eq!(
        ir.canonical_hash().as_bytes(),
        Sha256::digest(wire).as_slice()
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

#[test]
fn trajectory_v15_closed_modes_and_legacy_compact_bytes_match_independent_goldens() {
    fn frame(out: &mut Vec<u8>, text: &str) {
        out.extend_from_slice(&(text.len() as u64).to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    let cases = [
        (
            None,
            false,
            12u16,
            "e8842fc3a5f41c393b1c14c090d837b44575cb42f84b8caa35fa1679a77c3e57",
        ),
        (
            None,
            true,
            14,
            "e3bfdb5ef1748a3dcf5654bd03ecaa198672c388efb072418d4f0ef63223a5b8",
        ),
        (
            Some((1, None)),
            false,
            13,
            "31bb3410a0145f51258faf1da99cab453bc03f67616663f7fbeefdebff162e56",
        ),
        (
            Some((1, None)),
            true,
            14,
            "505898ace984a48f55556af69373b85d2590517e58a24e462162858f14f7505e",
        ),
        (
            Some((2, None)),
            false,
            13,
            "72d3c1e0f0dd42fe3a7ded0337141ac77f0aa1dda4fb5704cc7e027889aed186",
        ),
        (
            Some((2, None)),
            true,
            14,
            "5197e527354a8041c7de9b8377c468e7c68d44ee3d2ed6a5168d355a90742bf7",
        ),
        (
            Some((3, Some("disabled"))),
            false,
            15,
            "7ae2e0ed9cbaf9c0c7e4f53690edf3c39ebe1bfc4ca6087c2d9ae215b3acb1a8",
        ),
        (
            Some((3, Some("disabled"))),
            true,
            15,
            "256e82a65e5fcff19352795aa92252d527200199abb96edb3f1d271cec20c1bb",
        ),
        (
            Some((3, Some("semantic"))),
            false,
            15,
            "7ddd41987c4fa116c367e25c58300e520c2a659cac7731436366ea08d7c35e3b",
        ),
        (
            Some((3, Some("semantic"))),
            true,
            15,
            "ce126cfd6b262386dede86fe0d399f1630563f5c8d81fa9747988a0905c74570",
        ),
    ];
    for (trajectory, compact, version, golden) in cases {
        let behavioral = if trajectory.is_some_and(|(schema, _)| schema == 1) {
            1u16
        } else {
            2
        };
        let mut text = format!(
            "schema_version=1\nedges=[]\n[workflow]\nid='w'\nversion='1'\nentry='a'\n[[nodes]]\nid='a'\nkind='terminal'\n[nodes.untrusted_text]\nschema_version=1\nmax_input_bytes=65536\nen=true\nzh=true\nja=true\n[nodes.untrusted_text.behavioral]\nschema_version={behavioral}\nmax_steps=8\ntimeout_ms=1000\n"
        );
        if let Some((schema, mode)) = trajectory {
            text.push_str(&format!(
                "[nodes.untrusted_text.behavioral.trajectory]\nschema_version={schema}\n"
            ));
            if let Some(mode) = mode {
                text.push_str(&format!("observer_mode='{mode}'\n"));
            }
        }
        if compact {
            text.push_str(
                "[compact_state_exchange]\nfrom='code.investigation'\nto='grounded.answer'\n",
            );
        }
        let ir = WorkflowIr::from(&parse_str("wire", &text).unwrap());
        let mut bytes = b"adk-workflow-kit/workflow-ir\0".to_vec();
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        for value in ["w", "1", "a"] {
            frame(&mut bytes, value);
        }
        bytes.extend_from_slice(&1u64.to_be_bytes());
        frame(&mut bytes, "a");
        bytes.extend_from_slice(&[6, 1]);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&65536u64.to_be_bytes());
        bytes.extend_from_slice(&[1, 1, 1, 1]);
        bytes.extend_from_slice(&behavioral.to_be_bytes());
        bytes.extend_from_slice(&8u64.to_be_bytes());
        bytes.extend_from_slice(&1000u64.to_be_bytes());
        if version >= 13 {
            match trajectory {
                None => bytes.push(0),
                Some((schema, mode)) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&(schema as u16).to_be_bytes());
                    if version == 15 {
                        match mode {
                            None => bytes.push(0),
                            Some(mode) => {
                                bytes.extend_from_slice(&[1, u8::from(mode == "semantic")])
                            }
                        }
                    }
                }
            }
        }
        bytes.push(0);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        if compact {
            frame(&mut bytes, "code.investigation");
            frame(&mut bytes, "grounded.answer");
        }
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            golden,
            "independent fixture encoding"
        );
        assert_eq!(ir.canonical_wire_version(), version);
        assert_eq!(
            ir.canonical_hash().as_bytes(),
            Sha256::digest(&bytes).as_slice()
        );
    }
}
