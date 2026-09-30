use std::{
    fs,
    num::NonZeroU64,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::json;
use workflow_runtime::{
    CapabilityIntersection, ChildSandbox, InMemoryArtifactStore, RunContext, RunId, RunLimits,
    RunSandbox, SandboxCapability, ToolBridge, ToolBridgeError, ToolCall, ToolCallContext,
    ToolEnvelope, ToolFlags, ToolProvenance, ToolRegistration, WorkdirManager,
    argument_fingerprint,
};

fn context_debug_sandbox() -> RunSandbox {
    let base = std::env::temp_dir().join(format!("issue-314-context-debug-{}", std::process::id()));
    fs::create_dir_all(&base).expect("sandbox base must exist");
    let context = RunContext::new(
        RunId::new(format!("context-debug-{}", std::process::id())).expect("fixture run ID"),
        RunLimits::new(
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
        ),
    );
    let workdir = WorkdirManager::new(&base)
        .expect("sandbox base must be trusted")
        .allocate(context.run_id())
        .expect("sandbox workdir must allocate");
    RunSandbox::new(context, workdir, [SandboxCapability::FilesystemRead])
        .expect("sandbox must bind its run workdir")
}

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

#[test]
fn tool_call_context_debug_redacts_private_fields_without_changing_handler_data() {
    const TOOL_NAME: &str = "context-debug-tool";
    const CALL_ID: &str = "SYNTHETIC_PRIVATE_CONTEXT_CALL_ID";
    const ACTOR: &str = "SYNTHETIC_PRIVATE_CONTEXT_ACTOR";
    const ARGUMENT_MARKER: &str = "SYNTHETIC_PRIVATE_CONTEXT_ARGUMENT";
    const IMPLEMENTATION_DIGEST: &str = "SYNTHETIC_PRIVATE_CONTEXT_IMPLEMENTATION_DIGEST";
    const NOW: Duration = Duration::from_secs(10);
    const TIMEOUT: Duration = Duration::from_secs(2);

    let arguments = json!({"private": ARGUMENT_MARKER});
    let expected_fingerprint = argument_fingerprint(&arguments);
    let registration = ToolRegistration::for_types::<serde_json::Value, serde_json::Value>(
        TOOL_NAME,
        ToolProvenance::new("registry.fixture", "1.0.0"),
        ToolFlags::new(true, true, true),
    )
    .expect("fixture registration")
    .with_timeout(NonZeroU64::new(2_000).expect("positive timeout"))
    .with_required_capabilities([SandboxCapability::FilesystemRead])
    .with_implementation_digest(IMPLEMENTATION_DIGEST);
    let authority =
        CapabilityIntersection::all_for_tool(TOOL_NAME, [SandboxCapability::FilesystemRead]);
    let captured = Arc::new(Mutex::new(None));
    let handler_capture = Arc::clone(&captured);
    let mut bridge = ToolBridge::new(context_debug_sandbox());
    bridge
        .register(
            registration,
            move |_: &ChildSandbox<'_>,
                  context: &ToolCallContext,
                  handler_arguments: &serde_json::Value|
                  -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
                let fields_before = (
                    context.call_id().to_owned(),
                    context.actor().to_owned(),
                    context.argument_fingerprint().to_owned(),
                    context.idempotency_key().to_owned(),
                    context.implementation_digest().to_owned(),
                    context.deadline(),
                );
                let direct = format!("{context:?}");
                let pretty = format!("{context:#?}");
                let nested = format!("{:?}", Some(context));
                let fields_after = (
                    context.call_id().to_owned(),
                    context.actor().to_owned(),
                    context.argument_fingerprint().to_owned(),
                    context.idempotency_key().to_owned(),
                    context.implementation_digest().to_owned(),
                    context.deadline(),
                );
                *handler_capture
                    .lock()
                    .unwrap_or_else(|_| panic!("context snapshot was poisoned")) = Some((
                    fields_before,
                    fields_after,
                    handler_arguments.clone(),
                    direct,
                    pretty,
                    nested,
                ));
                Ok(ToolEnvelope::success(
                    json!({"ok": true}),
                    ToolProvenance::new("registry.fixture", "1.0.0"),
                ))
            },
        )
        .expect("handler registers");

    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(1_024).expect("positive limit"),
        NonZeroU64::new(16).expect("positive page limit"),
    );
    bridge
        .invoke(
            ToolCall::new(TOOL_NAME, CALL_ID, ACTOR, arguments.clone()),
            &authority,
            None,
            NOW,
            &mut artifacts,
        )
        .expect("authorized fixture call executes");

    let (fields_before, fields_after, handler_arguments, direct, pretty, nested) = captured
        .lock()
        .unwrap_or_else(|_| panic!("context snapshot was poisoned"))
        .take()
        .unwrap_or_else(|| panic!("handler did not capture context"));
    let secrets = [
        CALL_ID,
        ACTOR,
        ARGUMENT_MARKER,
        fields_before.2.as_str(),
        fields_before.3.as_str(),
        IMPLEMENTATION_DIGEST,
    ];
    for diagnostic in [direct.as_str(), pretty.as_str(), nested.as_str()] {
        for secret in secrets.iter().copied() {
            assert!(
                !diagnostic.contains(secret),
                "ToolCallContext Debug exposed a private field"
            );
        }
    }

    for diagnostic in [direct.as_str(), pretty.as_str(), nested.as_str()] {
        for field in [
            "ToolCallContext",
            "call_id",
            "actor",
            "argument_fingerprint",
            "idempotency_key",
            "implementation_digest",
            "deadline",
            "<redacted>",
        ] {
            assert!(diagnostic.contains(field), "missing safe context structure");
        }
    }
    assert!(fields_before.0 == CALL_ID, "handler call ID changed");
    assert!(fields_before.1 == ACTOR, "handler actor changed");
    assert!(
        fields_before.2 == expected_fingerprint,
        "handler argument fingerprint changed"
    );
    assert!(
        !fields_before.3.is_empty(),
        "handler idempotency key was missing"
    );
    assert!(
        fields_before.4 == IMPLEMENTATION_DIGEST,
        "handler implementation digest changed"
    );
    assert!(fields_before.5 == NOW + TIMEOUT, "handler deadline changed");
    assert!(
        fields_before == fields_after,
        "Debug formatting changed handler fields"
    );
    assert!(handler_arguments == arguments, "handler arguments changed");
}
