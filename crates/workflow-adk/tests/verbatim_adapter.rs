use workflow_adk::{VerbatimAdapterErrorKind, VerbatimPlatformAdapter, VerbatimRequest};

const CANARY_LEAK_63: &[u8] = b"adk_rust::LlmRequest<CANARY_LEAK_63>";
const CANARY_ADAPTER_63: &[u8] = br#"{"value":"CANARY_ADAPTER_63"}"#;

#[test]
fn boundary_rejects_adk_type_leakage_with_typed_redacted_diagnostic() {
    let request = VerbatimRequest::new("verbatim/request", CANARY_LEAK_63)
        .expect("fixture request must be structurally valid");

    let error = VerbatimPlatformAdapter::new()
        .accept(request)
        .expect_err("ADK type leakage must fail closed");

    assert_eq!(error.kind(), VerbatimAdapterErrorKind::TypeLeakage);
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("adk_rust::LlmRequest"));
    assert!(!rendered.contains("CANARY_LEAK_63"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn adapter_accepts_verbatim_request_without_adk_surface() {
    let request = VerbatimRequest::new("verbatim/request", CANARY_ADAPTER_63)
        .expect("fixture request must be structurally valid");

    let accepted = VerbatimPlatformAdapter::new()
        .accept(request)
        .expect("valid Verbatim-side request must be accepted");

    assert_eq!(accepted.path(), "verbatim/request");
    assert_eq!(accepted.payload_len(), CANARY_ADAPTER_63.len());
}
