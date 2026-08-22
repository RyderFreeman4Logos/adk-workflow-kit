use std::fmt;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

const DRAFT_2020_12_SCHEMA: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_SCHEMA_BYTES: usize = 65_536;

/// One typed terminal result from a tool invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolEnvelope<T> {
    /// The tool produced a typed payload.
    Success {
        /// The successful tool payload.
        payload: T,
        /// The exact registered tool identity that produced the payload.
        provenance: ToolProvenance,
        /// The next page offset when more result bytes are available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_offset: Option<u64>,
        /// An opaque artifact handle for externally retained result bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        artifact_id: Option<String>,
    },
    /// The tool completed successfully with no result.
    Empty {
        /// The exact registered tool identity that completed.
        provenance: ToolProvenance,
    },
    /// The tool could not produce a result.
    Failure {
        /// The fixed failure category.
        failure: ToolFailure,
        /// The exact registered tool identity that failed.
        provenance: ToolProvenance,
    },
}

impl<T> ToolEnvelope<T> {
    /// Returns the exact registered tool identity for this result.
    pub fn provenance(&self) -> &ToolProvenance {
        match self {
            Self::Success { provenance, .. }
            | Self::Empty { provenance }
            | Self::Failure { provenance, .. } => provenance,
        }
    }
}

/// A fixed category for a tool result failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailure {
    /// The caller supplied invalid tool input.
    InvalidInput,
    /// The requested tool result does not exist.
    NotFound,
    /// The tool cannot currently provide a result.
    Unavailable,
    /// The tool failed without a more specific public category.
    Internal,
}

impl fmt::Display for ToolFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "tool input was invalid",
            Self::NotFound => "tool result was not found",
            Self::Unavailable => "tool was unavailable",
            Self::Internal => "tool failed internally",
        })
    }
}

impl std::error::Error for ToolFailure {}

/// Exact registry identity for a tool result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolProvenance {
    tool_id: String,
    tool_version: String,
}

impl ToolProvenance {
    /// Creates provenance from the exact registered tool ID and version.
    pub fn new(tool_id: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_id: tool_id.into(),
            tool_version: tool_version.into(),
        }
    }

    /// Returns the exact registered tool ID.
    pub fn tool_id(&self) -> &str {
        &self.tool_id
    }

    /// Returns the exact registered tool version.
    pub fn tool_version(&self) -> &str {
        &self.tool_version
    }
}

/// A fixed, privacy-safe reason that structured tool output was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredOutputError {
    /// The output exceeded the caller-supplied byte ceiling.
    OutputTooLarge,
    /// The output was not valid UTF-8.
    InvalidUtf8,
    /// The output was not a valid tool envelope document.
    InvalidJson,
    /// The output contained non-whitespace bytes after its envelope.
    TrailingBytes,
}

impl fmt::Display for StructuredOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OutputTooLarge => "structured tool output exceeds the limit",
            Self::InvalidUtf8 => "structured tool output is not valid UTF-8",
            Self::InvalidJson => "structured tool output is invalid",
            Self::TrailingBytes => "structured tool output has trailing bytes",
        })
    }
}

impl std::error::Error for StructuredOutputError {}

/// Decodes one bounded, strict JSON tool envelope from output bytes.
pub fn decode_structured_tool_output<T>(
    bytes: &[u8],
    max_output_bytes: usize,
) -> Result<ToolEnvelope<T>, StructuredOutputError>
where
    T: DeserializeOwned,
{
    if bytes.len() > max_output_bytes {
        return Err(StructuredOutputError::OutputTooLarge);
    }
    std::str::from_utf8(bytes).map_err(|_| StructuredOutputError::InvalidUtf8)?;

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let envelope = ToolEnvelope::deserialize(&mut deserializer)
        .map_err(|_| StructuredOutputError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| StructuredOutputError::TrailingBytes)?;
    Ok(envelope)
}

/// A validated, non-executable description of a typed tool.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolRegistration {
    name: String,
    provenance: ToolProvenance,
    input_schema: Value,
    output_schema: Value,
    flags: ToolFlags,
}

impl ToolRegistration {
    /// Generates validated Draft 2020-12 schemas for a tool's input and enveloped output.
    pub fn for_types<I, O>(
        name: impl Into<String>,
        provenance: ToolProvenance,
        flags: ToolFlags,
    ) -> Result<Self, ToolRegistrationError>
    where
        I: DeserializeOwned + schemars::JsonSchema,
        O: Serialize + schemars::JsonSchema,
    {
        let name = name.into();
        validate_name(&name)?;
        validate_provenance(&provenance)?;

        let input_schema = generate_schema::<I>(
            schemars::generate::SchemaSettings::draft2020_12().for_deserialize(),
            ToolRegistrationError::InvalidInputSchema,
            ToolRegistrationError::InputSchemaTooLarge,
        )?;
        let output_schema = generate_schema::<ToolEnvelope<O>>(
            schemars::generate::SchemaSettings::draft2020_12().for_serialize(),
            ToolRegistrationError::InvalidOutputSchema,
            ToolRegistrationError::OutputSchemaTooLarge,
        )?;

        Ok(Self {
            name,
            provenance,
            input_schema,
            output_schema,
            flags,
        })
    }

    /// Returns the validated tool name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact registry provenance for this tool.
    pub fn provenance(&self) -> &ToolProvenance {
        &self.provenance
    }

    /// Returns the validated Draft 2020-12 input schema.
    pub fn input_schema(&self) -> &Value {
        &self.input_schema
    }

    /// Returns the validated Draft 2020-12 enveloped output schema.
    pub fn output_schema(&self) -> &Value {
        &self.output_schema
    }

    /// Returns the independently declared execution-safety flags.
    pub fn flags(&self) -> ToolFlags {
        self.flags
    }
}

/// Independently declared execution-safety properties for a tool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ToolFlags {
    read_only: bool,
    concurrency_safe: bool,
    idempotent: bool,
}

impl ToolFlags {
    /// Creates flags without deriving policy from any other flag.
    pub fn new(read_only: bool, concurrency_safe: bool, idempotent: bool) -> Self {
        Self {
            read_only,
            concurrency_safe,
            idempotent,
        }
    }

    /// Returns whether the tool declares that it does not modify state.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Returns whether the tool declares that concurrent execution is safe.
    pub fn concurrency_safe(&self) -> bool {
        self.concurrency_safe
    }

    /// Returns whether the tool declares that repeated calls are idempotent.
    pub fn idempotent(&self) -> bool {
        self.idempotent
    }

    /// Parses the complete fixed flag set from a JSON object.
    pub fn from_json_value(value: &Value) -> Result<Self, ToolRegistrationError> {
        let Some(object) = value.as_object() else {
            return Err(ToolRegistrationError::InvalidFlags);
        };

        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "read_only" | "concurrency_safe" | "idempotent"
            )
        }) {
            return Err(ToolRegistrationError::InvalidFlags);
        }

        Ok(Self::new(
            flag_value(object, "read_only")?,
            flag_value(object, "concurrency_safe")?,
            flag_value(object, "idempotent")?,
        ))
    }
}

/// A fixed, privacy-safe reason that tool registration was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolRegistrationError {
    /// The supplied name was empty.
    EmptyName,
    /// The supplied name contained unsupported characters.
    InvalidName,
    /// The supplied name exceeded the byte limit.
    NameTooLong,
    /// The provenance tool ID was empty.
    EmptyToolId,
    /// The provenance tool version was empty.
    EmptyToolVersion,
    /// The generated input schema was invalid.
    InvalidInputSchema,
    /// The generated input schema exceeded the byte limit.
    InputSchemaTooLarge,
    /// The generated output schema was invalid.
    InvalidOutputSchema,
    /// The generated output schema exceeded the byte limit.
    OutputSchemaTooLarge,
    /// The supplied flags were invalid.
    InvalidFlags,
}

impl fmt::Display for ToolRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyName => "tool name must not be empty",
            Self::InvalidName => "tool name contains unsupported characters",
            Self::NameTooLong => "tool name exceeds 64 bytes",
            Self::EmptyToolId => "tool provenance ID must not be empty",
            Self::EmptyToolVersion => "tool provenance version must not be empty",
            Self::InvalidInputSchema => "tool input schema is invalid",
            Self::InputSchemaTooLarge => "tool input schema exceeds 65536 bytes",
            Self::InvalidOutputSchema => "tool output schema is invalid",
            Self::OutputSchemaTooLarge => "tool output schema exceeds 65536 bytes",
            Self::InvalidFlags => "tool flags are invalid",
        })
    }
}

impl std::error::Error for ToolRegistrationError {}

fn validate_name(name: &str) -> Result<(), ToolRegistrationError> {
    if name.is_empty() {
        return Err(ToolRegistrationError::EmptyName);
    }
    if name.len() > 64 {
        return Err(ToolRegistrationError::NameTooLong);
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ToolRegistrationError::InvalidName);
    }
    Ok(())
}

fn validate_provenance(provenance: &ToolProvenance) -> Result<(), ToolRegistrationError> {
    if provenance.tool_id().is_empty() {
        return Err(ToolRegistrationError::EmptyToolId);
    }
    if provenance.tool_version().is_empty() {
        return Err(ToolRegistrationError::EmptyToolVersion);
    }
    Ok(())
}

fn generate_schema<T>(
    settings: schemars::generate::SchemaSettings,
    invalid_error: ToolRegistrationError,
    too_large_error: ToolRegistrationError,
) -> Result<Value, ToolRegistrationError>
where
    T: schemars::JsonSchema,
{
    let schema = serde_json::to_value(settings.into_generator().into_root_schema_for::<T>())
        .map_err(|_| invalid_error)?;
    validate_schema(schema, invalid_error, too_large_error)
}

fn validate_schema(
    schema: Value,
    invalid_error: ToolRegistrationError,
    too_large_error: ToolRegistrationError,
) -> Result<Value, ToolRegistrationError> {
    let encoded = serde_json::to_vec(&schema).map_err(|_| invalid_error)?;
    if encoded.len() > MAX_SCHEMA_BYTES {
        return Err(too_large_error);
    }

    let Some(root) = schema.as_object().filter(|root| !root.is_empty()) else {
        return Err(invalid_error);
    };
    if root.get("$schema").and_then(Value::as_str) != Some(DRAFT_2020_12_SCHEMA)
        || !has_only_local_references(&schema)
        || jsonschema::meta::validate(&schema).is_err()
    {
        return Err(invalid_error);
    }

    Ok(schema)
}

fn has_only_local_references(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().all(has_only_local_references),
        Value::Object(object) => object.iter().all(|(key, value)| {
            (key != "$ref"
                || value
                    .as_str()
                    .is_some_and(|reference| reference == "#" || reference.starts_with("#/")))
                && has_only_local_references(value)
        }),
        _ => true,
    }
}

fn flag_value(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<bool, ToolRegistrationError> {
    match object.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(ToolRegistrationError::InvalidFlags),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_OUTPUT_BYTES: usize = 512;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        value: String,
    }

    const VALID_JSON: &[u8] = br#"{"status":"success","payload":{"value":"ok"},"provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#;

    #[test]
    fn valid_structured_output_is_the_terminal_success_path() {
        assert!(matches!(
            decode_structured_tool_output::<Payload>(VALID_JSON, MAX_OUTPUT_BYTES),
            Ok(ToolEnvelope::Success { .. })
        ));
    }

    #[test]
    fn invalid_structured_output_fails_closed_without_echoing_input() {
        let partial_json = &VALID_JSON[..VALID_JSON.len() - 1];
        assert_eq!(
            decode_structured_tool_output::<Payload>(partial_json, MAX_OUTPUT_BYTES),
            Err(StructuredOutputError::InvalidJson)
        );

        assert_eq!(
            decode_structured_tool_output::<Payload>(b"not-json", 1),
            Err(StructuredOutputError::OutputTooLarge)
        );

        assert_eq!(
            decode_structured_tool_output::<Payload>(&[b'{', 0xff], MAX_OUTPUT_BYTES),
            Err(StructuredOutputError::InvalidUtf8)
        );

        let mut trailing_bytes = VALID_JSON.to_vec();
        trailing_bytes.extend_from_slice(b"{}");
        assert_eq!(
            decode_structured_tool_output::<Payload>(&trailing_bytes, MAX_OUTPUT_BYTES),
            Err(StructuredOutputError::TrailingBytes)
        );

        for document in [
            br#"{"status":"success","payload":{"value":"ok"},"provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"},"hostile":"payload"}"#
                .as_slice(),
            br#"{"status":"success","payload":{"value":"ok","hostile":"payload"},"provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#
                .as_slice(),
            br#"{"status":"success","payload":{"value":"ok"},"provenance":{"tool_id":"registry.tool","tool_version":"1.2.3","hostile":"payload"}}"#
                .as_slice(),
        ] {
            let error = decode_structured_tool_output::<Payload>(document, MAX_OUTPUT_BYTES)
                .expect_err("extra fields must fail closed");
            assert_eq!(error, StructuredOutputError::InvalidJson);
            assert_eq!(error.to_string(), "structured tool output is invalid");
            assert!(!error.to_string().contains("payload"));
        }
    }
}
