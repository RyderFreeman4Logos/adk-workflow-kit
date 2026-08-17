use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use workflow_runtime::{ToolFlags, ToolProvenance, ToolRegistration, ToolRegistrationError};

const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Deserialize)]
struct EmptyReferenceInput;

impl JsonSchema for EmptyReferenceInput {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("EmptyReferenceInput")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({"$ref": ""})
    }
}

#[derive(Deserialize)]
struct MalformedReferenceInput;

impl JsonSchema for MalformedReferenceInput {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("MalformedReferenceInput")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({"$ref": "#not-a-json-pointer"})
    }
}

#[derive(Deserialize)]
struct ExternalReferenceInput;

impl JsonSchema for ExternalReferenceInput {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ExternalReferenceInput")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({"$ref": "https://example.invalid/schema"})
    }
}

#[derive(Deserialize)]
struct OversizedInput;

impl JsonSchema for OversizedInput {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("OversizedInput")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let mut schema = Map::new();
        schema.insert("type".to_owned(), Value::String("string".to_owned()));
        schema.insert(
            "description".to_owned(),
            Value::String(format!("secret-input-{}", "x".repeat(65_536))),
        );
        schema.into()
    }
}

#[derive(Serialize)]
struct ExternalReferenceOutput;

impl JsonSchema for ExternalReferenceOutput {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ExternalReferenceOutput")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({"$ref": "https://example.invalid/output-schema"})
    }
}

#[derive(Serialize)]
struct OversizedOutput;

impl JsonSchema for OversizedOutput {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("OversizedOutput")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let mut schema = Map::new();
        schema.insert("type".to_owned(), Value::String("string".to_owned()));
        schema.insert(
            "description".to_owned(),
            Value::String(format!("secret-output-{}", "x".repeat(65_536))),
        );
        schema.into()
    }
}

fn assert_error(
    result: Result<ToolRegistration, ToolRegistrationError>,
    expected: ToolRegistrationError,
    secret: Option<&str>,
) {
    match result {
        Err(error) => {
            assert_eq!(error, expected);
            if let Some(secret) = secret {
                assert!(!error.to_string().contains(secret));
                assert!(!format!("{error:?}").contains(secret));
            }
        }
        Ok(_) => panic!("registration unexpectedly succeeded"),
    }
}

fn assert_invalid_flags(value: Value) {
    match ToolFlags::from_json_value(&value) {
        Err(error) => assert_eq!(error, ToolRegistrationError::InvalidFlags),
        Ok(_) => panic!("invalid flags unexpectedly succeeded"),
    }
}

#[test]
fn generates_exact_draft_2020_12_input_and_enveloped_output_schema() {
    let registration = match ToolRegistration::for_types::<String, String>(
        "echo",
        ToolProvenance::new("registry.echo", "1.0.0"),
        ToolFlags::default(),
    ) {
        Ok(registration) => registration,
        Err(error) => panic!("registration must succeed: {error}"),
    };

    assert_eq!(
        registration.input_schema().get("$schema"),
        Some(&Value::String(DRAFT_2020_12.to_owned()))
    );
    assert_eq!(
        registration.output_schema().get("$schema"),
        Some(&Value::String(DRAFT_2020_12.to_owned()))
    );
    assert_eq!(
        registration.input_schema().get("type"),
        Some(&Value::String("string".to_owned()))
    );

    match registration.output_schema().get("oneOf") {
        Some(Value::Array(variants)) => {
            assert!(!variants.is_empty());
            assert!(registration.output_schema().to_string().contains("status"));
            assert!(registration
                .output_schema()
                .to_string()
                .contains("provenance"));
        }
        _ => panic!("output schema must describe ToolEnvelope variants"),
    }
}

#[test]
fn preserves_flags_and_exact_provenance_without_dispatch() {
    let provenance = ToolProvenance::new("opaque tool/id", "opaque version value");
    let registration = match ToolRegistration::for_types::<String, String>(
        "3-run_tool",
        provenance.clone(),
        ToolFlags::new(true, false, true),
    ) {
        Ok(registration) => registration,
        Err(error) => panic!("registration must succeed: {error}"),
    };

    assert_eq!(registration.name(), "3-run_tool");
    assert_eq!(registration.provenance(), &provenance);
    assert!(registration.flags().read_only());
    assert!(!registration.flags().concurrency_safe());
    assert!(registration.flags().idempotent());

    let serialized = match serde_json::to_value(&registration) {
        Ok(serialized) => serialized,
        Err(error) => panic!("registration serialization must succeed: {error}"),
    };
    match serialized.get("flags") {
        Some(flags) => assert_eq!(
            flags,
            &json!({"read_only": true, "concurrency_safe": false, "idempotent": true})
        ),
        None => panic!("registration must serialize nested flags"),
    }
    assert!(serialized.get("read_only").is_none());
}

#[test]
fn rejects_empty_hostile_and_oversized_names_and_provenance() {
    assert_error(
        ToolRegistration::for_types::<String, String>(
            "",
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::EmptyName,
        None,
    );
    assert_error(
        ToolRegistration::for_types::<String, String>(
            "<hostile-tool>",
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::InvalidName,
        Some("<hostile-tool>"),
    );
    let oversized_name = "a".repeat(65);
    assert_error(
        ToolRegistration::for_types::<String, String>(
            oversized_name.clone(),
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::NameTooLong,
        Some(&oversized_name),
    );
    assert_error(
        ToolRegistration::for_types::<String, String>(
            "echo",
            ToolProvenance::new("", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::EmptyToolId,
        None,
    );
    assert_error(
        ToolRegistration::for_types::<String, String>(
            "echo",
            ToolProvenance::new("registry.echo", ""),
            ToolFlags::default(),
        ),
        ToolRegistrationError::EmptyToolVersion,
        None,
    );
}

#[test]
fn rejects_empty_malformed_external_ref_and_oversized_schemas_privately() {
    assert_error(
        ToolRegistration::for_types::<EmptyReferenceInput, String>(
            "echo",
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::InvalidInputSchema,
        None,
    );
    assert_error(
        ToolRegistration::for_types::<MalformedReferenceInput, String>(
            "echo",
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::InvalidInputSchema,
        Some("#not-a-json-pointer"),
    );
    assert_error(
        ToolRegistration::for_types::<ExternalReferenceInput, String>(
            "echo",
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::InvalidInputSchema,
        Some("https://example.invalid/schema"),
    );
    assert_error(
        ToolRegistration::for_types::<OversizedInput, String>(
            "echo",
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::InputSchemaTooLarge,
        Some("secret-input"),
    );
    assert_error(
        ToolRegistration::for_types::<String, ExternalReferenceOutput>(
            "echo",
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::InvalidOutputSchema,
        Some("https://example.invalid/output-schema"),
    );
    assert_error(
        ToolRegistration::for_types::<String, OversizedOutput>(
            "echo",
            ToolProvenance::new("registry.echo", "1.0.0"),
            ToolFlags::default(),
        ),
        ToolRegistrationError::OutputSchemaTooLarge,
        Some("secret-output"),
    );
}

#[test]
fn rejects_unknown_or_malformed_flags_without_privilege_expansion() {
    match ToolFlags::from_json_value(&json!({})) {
        Ok(flags) => {
            assert!(!flags.read_only());
            assert!(!flags.concurrency_safe());
            assert!(!flags.idempotent());
        }
        Err(error) => panic!("empty flags must be accepted: {error}"),
    }
    match ToolFlags::from_json_value(&json!({
        "read_only": true,
        "concurrency_safe": true,
        "idempotent": true
    })) {
        Ok(flags) => {
            assert!(flags.read_only());
            assert!(flags.concurrency_safe());
            assert!(flags.idempotent());
        }
        Err(error) => panic!("known boolean flags must be accepted: {error}"),
    }

    assert_invalid_flags(json!(true));
    assert_invalid_flags(json!({"read_only": "true"}));
    assert_invalid_flags(json!({"read_only": true, "unexpected": false}));
    assert_invalid_flags(json!({"long_running": true}));
}
