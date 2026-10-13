use super::*;

#[test]
fn issue_329_schema_is_distinct_from_json_syntax() {
    let contract = output_contract();
    let malformed = contract.decode(b"{").unwrap_err();
    let schema = contract.decode(br#"{"answer":42}"#).unwrap_err();
    assert_ne!(schema, malformed);
}

use workflow_runtime::{SchemaKeyword, StructuredOutputError};

fn spec(output: StructuredOutputContract, retries: u8) -> ModelInvocationSpec {
    ModelInvocationSpec::new(
        PromptProtocol::new(
            "PRIVATE_QUESTION",
            vec![],
            output.schema().clone(),
            json!({}),
            TrustDomain::TrustedGoal,
        )
        .unwrap(),
        "PRIVATE_SOURCE",
        ProviderRouteIdentity::new(
            workflow_adk::model_profiles::ModelProfileIdentity::new("placeholder", "1"),
            "none",
            "none",
            "none",
            "none",
        ),
        InferenceBudget::medium().with_max_retries(retries).unwrap(),
        output,
    )
    .unwrap()
}

async fn reject_on_route(
    contract: StructuredOutputContract,
    output: &str,
) -> workflow_adk::ModelRouteTerminalError {
    let first = ModelRouteCandidate::new(ModelRole::Worker, "PRIVATE_PROFILE", "1");
    let second = ModelRouteCandidate::new(ModelRole::Worker, "second", "1");
    let mut registry = ModelProfileRegistry::new();
    registry
        .register(FakeModelProfile::new(
            "PRIVATE_PROFILE",
            "1",
            "PRIVATE_MODEL",
            [output],
        ))
        .unwrap();
    registry
        .register(FakeModelProfile::new("second", "1", "model", ["unused"]))
        .unwrap();
    let later = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let snapshot = ModelRouteSnapshot::new(
        registry,
        [first.clone(), second.clone()],
        ModelRouteAuthorization::new([first, second.clone()]),
    )
    .unwrap()
    .with_test_llm(second, later.clone())
    .unwrap();
    let error = ModelRoutePublisher::new(snapshot)
        .policy(Instant::now() + Duration::from_secs(5))
        .invoke(
            &spec(contract, 0),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteTerminalErrorKind::Protocol
    );
    assert_eq!(error.attempts().len(), 1);
    assert_eq!(error.attempts()[0].ordinal(), 1);
    assert_eq!(
        error.attempts()[0].kind(),
        workflow_adk::ModelRouteAttemptKind::Protocol
    );
    assert_eq!(error.profile_error(), None);
    assert_eq!(error.upstream_status_code(), None);
    assert_eq!(error.output_error(), error.attempts()[0].output_error());
    assert_eq!(later.calls.load(Ordering::SeqCst), 0);
    error
}

#[tokio::test]
async fn issue_329_structured_route_keeps_syntax_trailing_size_and_schema_distinct() {
    for (output, expected) in [
        ("{".to_owned(), StructuredOutputError::InvalidJson),
        (
            "{} PRIVATE_TRAILING".to_owned(),
            StructuredOutputError::TrailingBytes,
        ),
        (
            "PRIVATE_OVERSIZED".repeat(100),
            StructuredOutputError::OutputTooLarge,
        ),
        (
            r#"{"answer":42}"#.to_owned(),
            StructuredOutputError::SchemaViolation {
                keyword: SchemaKeyword::Type,
                citation_index: None,
                window_index: None,
            },
        ),
    ] {
        let error = reject_on_route(output_contract(), &output).await;
        assert_eq!(error.output_error(), Some(expected));
        let diagnostics = format!("{error:?}{error}{:?}{expected}", error.attempts());
        for marker in [
            "PRIVATE_QUESTION",
            "PRIVATE_SOURCE",
            "PRIVATE_PROFILE",
            "PRIVATE_MODEL",
            "PRIVATE_TRAILING",
            "PRIVATE_OVERSIZED",
            "answer",
        ] {
            assert!(!diagnostics.contains(marker));
        }
    }
    // Invalid UTF-8 cannot exist in an SDK text String; verify the public byte boundary.
    assert_eq!(
        output_contract().decode(&[0xff]),
        Err(StructuredOutputError::InvalidUtf8)
    );
}

#[tokio::test]
async fn issue_329_schema_keywords_and_only_recognized_numeric_indices_survive() {
    for (schema, value, keyword, citation_index, window_index) in [
        (
            json!({"properties":{"citations":{"items":{"anyOf":[{"const":"PRIVATE_EXPECTED"},{"const":"PRIVATE_OTHER"}]}}}}),
            json!({"citations":["PRIVATE_VALUE"]}),
            SchemaKeyword::AnyOf,
            Some(0),
            None,
        ),
        (
            json!({"properties":{"windows":{"items":{"minimum":3}}}}),
            json!({"windows":[3,1]}),
            SchemaKeyword::Minimum,
            None,
            Some(1),
        ),
        (
            json!({"properties":{"citations":{"properties":{"0":{"type":"string"}}}}}),
            json!({"citations":{"0":42}}),
            SchemaKeyword::Type,
            None,
            None,
        ),
        (
            json!({"properties":{"PRIVATE_PATH/~":{"items":{"const":"PRIVATE_EXPECTED"}}}}),
            json!({"PRIVATE_PATH/~":["PRIVATE_VALUE"]}),
            SchemaKeyword::Const,
            None,
            None,
        ),
        (
            json!({"properties":{"PRIVATE_PATH":{"properties":{"citations":{"items":{"type":"string"}}}}}}),
            json!({"PRIVATE_PATH":{"citations":[42]}}),
            SchemaKeyword::Type,
            None,
            None,
        ),
        (
            json!({"required":["PRIVATE_REQUIRED"]}),
            json!({}),
            SchemaKeyword::Required,
            None,
            None,
        ),
        (
            json!({"additionalProperties":false}),
            json!({"PRIVATE_PROPERTY":"PRIVATE_VALUE"}),
            // The pinned validator specializes this schema to a false-schema error.
            SchemaKeyword::FalseSchema,
            None,
            None,
        ),
        (
            json!({"properties":{"known":{"type":"string"}},"additionalProperties":false}),
            json!({"PRIVATE_PROPERTY":"PRIVATE_VALUE"}),
            SchemaKeyword::AdditionalProperties,
            None,
            None,
        ),
    ] {
        let contract = StructuredOutputContract::new(schema, 1024).unwrap();
        let output = serde_json::to_string(&value).unwrap();
        let expected = StructuredOutputError::SchemaViolation {
            keyword,
            citation_index,
            window_index,
        };
        assert_eq!(contract.decode(output.as_bytes()), Err(expected));
        let error = reject_on_route(contract, &output).await;
        assert_eq!(error.output_error(), Some(expected));
        let diagnostics = format!("{error:?}{error}{expected:?}{expected}");
        assert!(!diagnostics.contains("PRIVATE_"));
    }
}

#[tokio::test]
async fn issue_329_schema_rejection_preserves_existing_retry_budget() {
    let candidate = ModelRouteCandidate::new(ModelRole::Worker, "first", "1");
    let registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "first",
            "1",
            "model",
            [r#"{"answer":42}"#, r#"{"answer":"valid"}"#],
        ))
        .unwrap();
    let snapshot = ModelRouteSnapshot::new(
        registry,
        [candidate.clone()],
        ModelRouteAuthorization::new([candidate]),
    )
    .unwrap();
    let result = ModelRoutePublisher::new(snapshot)
        .policy(Instant::now() + Duration::from_secs(5))
        .invoke(
            &spec(output_contract(), 1),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.attempts(), 2);
    assert_eq!(result.output(), &json!({"answer":"valid"}));
}

async fn reject_empty_property_index(field: &str) {
    let contract = StructuredOutputContract::new(
        json!({"properties":{"":{"properties":{field:{"items":{"type":"string"}}}}}}),
        1024,
    )
    .unwrap();
    let output = serde_json::to_string(&json!({"":{field:[42]},field:["valid"]})).unwrap();
    let expected = StructuredOutputError::SchemaViolation {
        keyword: SchemaKeyword::Type,
        citation_index: None,
        window_index: None,
    };
    assert_eq!(contract.decode(output.as_bytes()), Err(expected));
    let error = reject_on_route(contract, &output).await;
    assert_eq!(error.output_error(), Some(expected));
}

#[tokio::test]
async fn issue_329_empty_property_cannot_alias_root_citations() {
    reject_empty_property_index("citations").await;
}

#[tokio::test]
async fn issue_329_empty_property_cannot_alias_root_windows() {
    reject_empty_property_index("windows").await;
}
