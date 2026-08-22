use serde_json::json;
use workflow_runtime::{
    PureTransformBackend, PureTransformError, PureTransformRequest, PureTransformRequestError,
    RequestedCapabilities, SandboxCapability,
};

const IDENTITY_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm header
    0x01, 0x08, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x02, 0x7f, 0x7f, // (i32, i32) -> (i32, i32)
    0x03, 0x02, 0x01, 0x00, // one function using type 0
    0x05, 0x03, 0x01, 0x00, 0x01, // one memory with one page
    0x07, 0x16, 0x02, 0x06, b'm', b'e', b'm', b'o', b'r', b'y', 0x02, 0x00, 0x09, b't', b'r', b'a',
    b'n', b's', b'f', b'o', b'r', b'm', 0x00, 0x00, // exports memory and transform
    0x0a, 0x08, 0x01, 0x06, 0x00, 0x20, 0x00, 0x20, 0x01, 0x0b, // return input ptr/len
];

const IMPORTING_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm header
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // () -> ()
    0x02, 0x0d, 0x01, 0x04, b'h', b'o', b's', b't', 0x04, b'c', b'a', b'l', b'l', 0x00,
    0x00, // one unsupported host function import
];

const OVERSIZED_MEMORY_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm header
    0x01, 0x08, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x02, 0x7f, 0x7f, // (i32, i32) -> (i32, i32)
    0x03, 0x02, 0x01, 0x00, // one function using type 0
    0x05, 0x03, 0x01, 0x00, 0x41, // 65-page memory declaration
    0x07, 0x16, 0x02, 0x06, b'm', b'e', b'm', b'o', b'r', b'y', 0x02, 0x00, 0x09, b't', b'r', b'a',
    b'n', b's', b'f', b'o', b'r', b'm', 0x00, 0x00, // exports memory and transform
    0x0a, 0x08, 0x01, 0x06, 0x00, 0x20, 0x00, 0x20, 0x01, 0x0b, // return input ptr/len
];

const GROWING_MEMORY_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm header
    0x01, 0x08, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x02, 0x7f, 0x7f, // (i32, i32) -> (i32, i32)
    0x03, 0x02, 0x01, 0x00, // one function using type 0
    0x05, 0x03, 0x01, 0x00, 0x01, // one memory with one page
    0x07, 0x16, 0x02, 0x06, b'm', b'e', b'm', b'o', b'r', b'y', 0x02, 0x00, 0x09, b't', b'r', b'a',
    b'n', b's', b'f', b'o', b'r', b'm', 0x00, 0x00, // exports memory and transform
    0x0a, 0x13, 0x01, 0x11, 0x00, 0x41, 0x40, 0x40, 0x00, 0x41, 0x7f, 0x46, 0x04, 0x40, 0x00, 0x0b,
    0x20, 0x00, 0x20, 0x01, 0x0b, // trap if growth is refused
];

#[test]
fn pure_transform_executes_json() {
    let request = PureTransformRequest::new(
        IDENTITY_WASM,
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("JSON transform request must be valid");

    let output = PureTransformBackend::new()
        .execute(&request)
        .expect("empty-import JSON transform must execute");

    assert_eq!(output, json!({"value": 7}));
}

#[test]
fn pure_transform_denies_host_capabilities_before_instantiation() {
    for capability in [
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::Network,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::EnvironmentVariables,
    ] {
        let request = PureTransformRequest::new(
            IDENTITY_WASM,
            json!({"value": 7}),
            RequestedCapabilities::new([capability]),
        )
        .expect("capability denial request must be valid");
        let error = PureTransformBackend::new()
            .execute(&request)
            .expect_err("pure transforms must not expose host capabilities");
        match error {
            PureTransformError::Capabilities(missing) => {
                assert_eq!(missing.missing(), &[capability]);
            }
            other => panic!("expected capability denial, got {other:?}"),
        }
    }
}

#[test]
fn pure_transform_rejects_guest_imports_before_instantiation() {
    let request = PureTransformRequest::new(
        IMPORTING_WASM,
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("importing module request must be valid");
    let error = PureTransformBackend::new()
        .execute(&request)
        .expect_err("guest imports must fail closed");

    assert!(matches!(error, PureTransformError::UnsupportedImports));
    assert_eq!(
        error.to_string(),
        "pure transform module has unsupported imports"
    );
}

#[test]
fn pure_transform_rejects_a_missing_module() {
    let request = PureTransformRequest::new(
        [],
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("missing module request must be valid");
    let error = PureTransformBackend::new()
        .execute(&request)
        .expect_err("a missing module must fail closed");

    assert!(matches!(error, PureTransformError::MissingModule));
    assert_eq!(error.to_string(), "pure transform module is missing");
}

#[test]
fn pure_transform_rejects_oversized_declared_memory() {
    let request = PureTransformRequest::new(
        OVERSIZED_MEMORY_WASM,
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("oversized memory request must be valid");
    let error = PureTransformBackend::new()
        .execute(&request)
        .expect_err("oversized declared memory must fail closed");

    assert!(matches!(error, PureTransformError::InstantiationFailed));
    assert_eq!(
        error.to_string(),
        "pure transform module could not be instantiated"
    );
}

#[test]
fn pure_transform_rejects_guest_memory_growth() {
    let request = PureTransformRequest::new(
        GROWING_MEMORY_WASM,
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("growing memory request must be valid");
    let error = PureTransformBackend::new()
        .execute(&request)
        .expect_err("guest memory growth must fail closed");

    assert!(
        matches!(error, PureTransformError::TransformFailed),
        "unexpected growth failure: {error:?}"
    );
    assert_eq!(error.to_string(), "pure transform execution failed");
}

#[test]
fn pure_transform_rejects_oversized_input_without_echoing_it() {
    let hostile = "hostile-secret-".repeat(PureTransformRequest::MAX_JSON_BYTES);
    let error = PureTransformRequest::new(
        IDENTITY_WASM,
        json!({"payload": hostile}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .err()
    .expect("oversized input must fail closed");

    assert!(matches!(error, PureTransformRequestError::InputTooLarge));
    assert_eq!(error.to_string(), "pure transform input exceeds the limit");
    assert!(!error.to_string().contains("hostile-secret"));
}
