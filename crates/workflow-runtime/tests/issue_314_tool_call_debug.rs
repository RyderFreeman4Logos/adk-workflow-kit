use serde_json::json;
use workflow_runtime::ToolCall;

#[test]
fn tool_call_debug_redacts_model_controlled_fields_and_preserves_arguments() {
    const DIRECT_MARKER: &str = "SYNTHETIC_PRIVATE_DIRECT";
    const NESTED_MARKER: &str = "SYNTHETIC_PRIVATE_NESTED";

    let direct_arguments = json!({"SYNTHETIC_PRIVATE_DIRECT": DIRECT_MARKER});
    let nested_arguments = json!({"outer": {"SYNTHETIC_PRIVATE_NESTED": NESTED_MARKER}});
    let direct_serialized = serde_json::to_vec(&direct_arguments).expect("direct args serialize");
    let nested_serialized = serde_json::to_vec(&nested_arguments).expect("nested args serialize");

    let direct = ToolCall::new(
        "model-selected-tool",
        "direct-call-id",
        "actor-scope",
        direct_arguments.clone(),
    );
    let nested = ToolCall::new(
        "model-selected-tool",
        "nested-call-id",
        "actor-scope",
        nested_arguments.clone(),
    );

    assert_eq!(direct.name(), "model-selected-tool");
    assert_eq!(direct.call_id(), "direct-call-id");
    assert_eq!(direct.actor(), "actor-scope");
    assert_eq!(direct.arguments(), &direct_arguments);
    assert_eq!(nested.name(), "model-selected-tool");
    assert_eq!(nested.call_id(), "nested-call-id");
    assert_eq!(nested.actor(), "actor-scope");
    assert_eq!(nested.arguments(), &nested_arguments);

    let direct_debug = format!("{direct:?}");
    let nested_debug = format!("{nested:?}");
    let collection_debug = format!("{:?}", vec![direct.clone(), nested.clone()]);

    assert!(
        !direct_debug.contains(DIRECT_MARKER),
        "direct Debug exposed its private argument marker"
    );
    assert!(
        !nested_debug.contains(NESTED_MARKER),
        "nested Debug exposed its private argument marker"
    );
    for marker in [DIRECT_MARKER, NESTED_MARKER] {
        assert!(
            !collection_debug.contains(marker),
            "Vec Debug exposed a private argument marker"
        );
    }

    for diagnostic in [&direct_debug, &nested_debug, &collection_debug] {
        for field in [
            "ToolCall",
            "name",
            "call_id",
            "actor",
            "arguments",
            "<redacted>",
        ] {
            assert!(
                diagnostic.contains(field),
                "missing safe structure: {field}"
            );
        }
        for identifier in [
            "model-selected-tool",
            "direct-call-id",
            "nested-call-id",
            "actor-scope",
        ] {
            assert!(
                !diagnostic.contains(identifier),
                "Debug exposed a model-controlled identifier"
            );
        }
    }

    assert_eq!(
        serde_json::to_vec(direct.arguments()).expect("direct args still serialize"),
        direct_serialized
    );
    assert_eq!(
        serde_json::to_vec(nested.arguments()).expect("nested args still serialize"),
        nested_serialized
    );
}
