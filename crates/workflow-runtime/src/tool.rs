use std::{fmt, num::NonZeroU64};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::SandboxCapability;

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
    /// Creates a successful result without exposing its wire representation.
    pub fn success(payload: T, provenance: ToolProvenance) -> Self {
        Self::Success {
            payload,
            provenance,
            next_offset: None,
            artifact_id: None,
        }
    }

    /// Creates an explicit successful empty result.
    pub fn empty(provenance: ToolProvenance) -> Self {
        Self::Empty { provenance }
    }

    /// Creates a typed failure result.
    pub fn failure(failure: ToolFailure, provenance: ToolProvenance) -> Self {
        Self::Failure {
            failure,
            provenance,
        }
    }

    /// Maps a successful payload while preserving terminal metadata.
    pub fn map_payload<U>(self, map: impl FnOnce(T) -> U) -> ToolEnvelope<U> {
        match self {
            Self::Success {
                payload,
                provenance,
                next_offset,
                artifact_id,
            } => ToolEnvelope::Success {
                payload: map(payload),
                provenance,
                next_offset,
                artifact_id,
            },
            Self::Empty { provenance } => ToolEnvelope::Empty { provenance },
            Self::Failure {
                failure,
                provenance,
            } => ToolEnvelope::Failure {
                failure,
                provenance,
            },
        }
    }

    /// Adds opaque retained-output metadata to a successful result.
    pub fn with_artifact(mut self, artifact_id: String, next_offset: Option<u64>) -> Self {
        if let Self::Success {
            next_offset: current_offset,
            artifact_id: current_artifact,
            ..
        } = &mut self
        {
            *current_offset = next_offset;
            *current_artifact = Some(artifact_id);
        }
        self
    }

    /// Returns the next byte offset when the result is paged.
    pub fn next_offset(&self) -> Option<u64> {
        match self {
            Self::Success { next_offset, .. } => *next_offset,
            Self::Empty { .. } | Self::Failure { .. } => None,
        }
    }

    /// Returns the opaque artifact handle when the result is paged.
    pub fn artifact_id(&self) -> Option<&str> {
        match self {
            Self::Success { artifact_id, .. } => artifact_id.as_deref(),
            Self::Empty { .. } | Self::Failure { .. } => None,
        }
    }

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
    T: DeserializeOwned + Serialize + schemars::JsonSchema,
{
    if bytes.len() > max_output_bytes {
        return Err(StructuredOutputError::OutputTooLarge);
    }
    std::str::from_utf8(bytes).map_err(|_| StructuredOutputError::InvalidUtf8)?;

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let document =
        Value::deserialize(&mut deserializer).map_err(|_| StructuredOutputError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| StructuredOutputError::TrailingBytes)?;

    let raw_payload = document.get("payload").cloned();
    if document.get("status").and_then(Value::as_str) == Some("success") {
        let raw_payload = raw_payload
            .as_ref()
            .ok_or(StructuredOutputError::InvalidJson)?;
        let schema = closed_payload_schema::<T>()?;
        let validator =
            jsonschema::validator_for(&schema).map_err(|_| StructuredOutputError::InvalidJson)?;
        if !validator.is_valid(raw_payload) {
            return Err(StructuredOutputError::InvalidJson);
        }
    }

    let envelope: ToolEnvelope<T> =
        serde_json::from_value(document).map_err(|_| StructuredOutputError::InvalidJson)?;
    if let ToolEnvelope::Success { payload, .. } = &envelope {
        let raw_payload = raw_payload
            .as_ref()
            .ok_or(StructuredOutputError::InvalidJson)?;
        let serialized_payload =
            serde_json::to_value(payload).map_err(|_| StructuredOutputError::InvalidJson)?;
        if raw_payload != &serialized_payload {
            return Err(StructuredOutputError::InvalidJson);
        }
    }

    Ok(envelope)
}

fn closed_payload_schema<T>() -> Result<Value, StructuredOutputError>
where
    T: schemars::JsonSchema,
{
    let mut schema = serde_json::to_value(
        schemars::generate::SchemaSettings::draft2020_12()
            .for_deserialize()
            .with(|settings| settings.inline_subschemas = true)
            .into_generator()
            .into_root_schema_for::<T>(),
    )
    .map_err(|_| StructuredOutputError::InvalidJson)?;
    if !close_schema(&mut schema) {
        return Err(StructuredOutputError::InvalidJson);
    }
    Ok(schema)
}

fn close_schema(schema: &mut Value) -> bool {
    match schema {
        Value::Bool(open) => !*open,
        Value::Object(object) => {
            if object.contains_key("$ref") {
                return false;
            }
            if !object.keys().any(|key| {
                ![
                    "$schema",
                    "$id",
                    "$anchor",
                    "$comment",
                    "title",
                    "description",
                    "default",
                    "examples",
                    "deprecated",
                    "readOnly",
                    "writeOnly",
                ]
                .contains(&key.as_str())
            }) {
                return false;
            }
            let is_object = object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "object")
                || object
                    .get("type")
                    .and_then(Value::as_array)
                    .is_some_and(|types| types.iter().any(|kind| kind.as_str() == Some("object")));
            if is_object
                || object.contains_key("properties")
                || object.contains_key("additionalProperties")
                || object.contains_key("patternProperties")
                || object.contains_key("unevaluatedProperties")
            {
                object.insert("additionalProperties".to_owned(), false.into());
                object.insert("unevaluatedProperties".to_owned(), false.into());
                object.remove("patternProperties");
            }

            for key in ["properties", "$defs", "definitions", "dependentSchemas"] {
                if let Some(Value::Object(children)) = object.get_mut(key)
                    && !children.values_mut().all(close_schema)
                {
                    return false;
                }
            }
            for key in [
                "items",
                "contains",
                "propertyNames",
                "not",
                "if",
                "then",
                "else",
            ] {
                if let Some(child) = object.get_mut(key)
                    && !close_schema(child)
                {
                    return false;
                }
            }
            for key in ["prefixItems", "allOf", "anyOf", "oneOf"] {
                if let Some(Value::Array(children)) = object.get_mut(key)
                    && !children.iter_mut().all(close_schema)
                {
                    return false;
                }
            }
            true
        }
        Value::Array(children) => children.iter_mut().all(close_schema),
        Value::Null | Value::Number(_) | Value::String(_) => true,
    }
}

/// A validated, non-executable description of a typed tool.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolRegistration {
    name: String,
    provenance: ToolProvenance,
    input_schema: Value,
    #[serde(skip)]
    handler_output_schema: Value,
    output_schema: Value,
    flags: ToolFlags,
    required_capabilities: Vec<SandboxCapability>,
    required_scopes: Vec<String>,
    timeout_ms: NonZeroU64,
    inline_output_limit_bytes: NonZeroU64,
    paging: bool,
    idempotency: ToolIdempotency,
    implementation_digest: String,
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
        let handler_output_schema = generate_schema::<ToolEnvelope<O>>(
            schemars::generate::SchemaSettings::draft2020_12().for_serialize(),
            ToolRegistrationError::InvalidOutputSchema,
            ToolRegistrationError::OutputSchemaTooLarge,
        )?;
        let mut output_schema = handler_output_schema.clone();
        add_paged_payload_schema(&mut output_schema)?;
        let output_schema = validate_schema(
            output_schema,
            ToolRegistrationError::InvalidOutputSchema,
            ToolRegistrationError::OutputSchemaTooLarge,
        )?;
        let implementation_digest =
            implementation_digest(&name, &provenance, &input_schema, &output_schema);

        Ok(Self {
            name,
            provenance,
            input_schema,
            handler_output_schema,
            output_schema,
            flags,
            required_capabilities: Vec::new(),
            required_scopes: Vec::new(),
            timeout_ms: NonZeroU64::new(30_000).expect("constant is positive"),
            inline_output_limit_bytes: NonZeroU64::new(64 * 1024).expect("constant is positive"),
            paging: false,
            idempotency: ToolIdempotency::NotRequired,
            implementation_digest,
        })
    }

    /// Replaces the generated input schema for a dynamically configured tool.
    pub fn with_input_schema(mut self, schema: Value) -> Result<Self, ToolRegistrationError> {
        self.input_schema = validate_schema(
            schema,
            ToolRegistrationError::InvalidInputSchema,
            ToolRegistrationError::InputSchemaTooLarge,
        )?;
        self.implementation_digest = implementation_digest(
            &self.name,
            &self.provenance,
            &self.input_schema,
            &self.output_schema,
        );
        Ok(self)
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

    /// Returns the strict handler-owned output schema before bridge paging.
    pub(crate) fn handler_output_schema(&self) -> &Value {
        &self.handler_output_schema
    }

    /// Returns the independently declared execution-safety flags.
    pub fn flags(&self) -> ToolFlags {
        self.flags
    }

    /// Adds the capability classes required by this tool.
    pub fn with_required_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = SandboxCapability>,
    ) -> Self {
        self.required_capabilities = capabilities.into_iter().collect();
        self.required_capabilities
            .sort_unstable_by_key(SandboxCapability::as_str);
        self.required_capabilities.dedup();
        self
    }

    /// Adds caller scopes required by this tool.
    pub fn with_required_scopes<S>(mut self, scopes: impl IntoIterator<Item = S>) -> Self
    where
        S: Into<String>,
    {
        self.required_scopes = scopes.into_iter().map(Into::into).collect();
        self.required_scopes.sort_unstable();
        self.required_scopes.dedup();
        self
    }

    /// Sets the per-call timeout.
    pub fn with_timeout(mut self, timeout_ms: NonZeroU64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Sets the maximum inline serialized output size.
    pub fn with_inline_output_limit(mut self, limit_bytes: NonZeroU64) -> Self {
        self.inline_output_limit_bytes = limit_bytes;
        self
    }

    /// Enables or disables artifact paging for oversized output.
    pub fn with_paging(mut self, paging: bool) -> Self {
        self.paging = paging;
        self
    }

    /// Sets the side-effect idempotency strategy.
    pub fn with_idempotency(mut self, idempotency: ToolIdempotency) -> Self {
        self.idempotency = idempotency;
        self
    }

    /// Sets the externally supplied implementation digest.
    pub fn with_implementation_digest(mut self, digest: impl Into<String>) -> Self {
        self.implementation_digest = digest.into();
        self
    }

    /// Returns the required sandbox capability classes.
    pub fn required_capabilities(&self) -> &[SandboxCapability] {
        &self.required_capabilities
    }

    /// Returns the required caller scopes.
    pub fn required_scopes(&self) -> &[String] {
        &self.required_scopes
    }

    /// Returns the per-call timeout in milliseconds.
    pub const fn timeout_ms(&self) -> NonZeroU64 {
        self.timeout_ms
    }

    /// Returns the maximum inline serialized output size.
    pub const fn inline_output_limit_bytes(&self) -> NonZeroU64 {
        self.inline_output_limit_bytes
    }

    /// Returns whether oversized results may be retained and paged.
    pub const fn paging(&self) -> bool {
        self.paging
    }

    /// Returns the declared idempotency strategy.
    pub const fn idempotency(&self) -> ToolIdempotency {
        self.idempotency
    }

    /// Returns the stable implementation digest.
    pub fn implementation_digest(&self) -> &str {
        &self.implementation_digest
    }
}

/// The closed idempotency strategies for registered tools.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolIdempotency {
    /// The tool has no side effects and needs no idempotency key.
    #[default]
    NotRequired,
    /// Side effects are deduplicated with a bridge-generated stable key.
    StableKey,
}

fn implementation_digest(
    name: &str,
    provenance: &ToolProvenance,
    input_schema: &Value,
    output_schema: &Value,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(provenance.tool_id().as_bytes());
    hasher.update([0]);
    hasher.update(provenance.tool_version().as_bytes());
    hasher.update(serde_json::to_vec(input_schema).expect("schema serialization cannot fail"));
    hasher.update(serde_json::to_vec(output_schema).expect("schema serialization cannot fail"));
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

fn add_paged_payload_schema(schema: &mut Value) -> Result<(), ToolRegistrationError> {
    let variants = schema
        .get_mut("oneOf")
        .and_then(Value::as_array_mut)
        .ok_or(ToolRegistrationError::InvalidOutputSchema)?;
    let success = variants
        .iter_mut()
        .find(|variant| {
            variant
                .pointer("/properties/status/const")
                .and_then(Value::as_str)
                == Some("success")
        })
        .ok_or(ToolRegistrationError::InvalidOutputSchema)?;
    let properties = success
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .ok_or(ToolRegistrationError::InvalidOutputSchema)?;
    let typed_payload = properties
        .remove("payload")
        .ok_or(ToolRegistrationError::InvalidOutputSchema)?;
    properties.insert(
        "payload".to_owned(),
        serde_json::json!({
            "anyOf": [
                typed_payload,
                {
                    "type": "object",
                    "properties": { "preview": { "type": "string" } },
                    "required": ["preview"],
                    "additionalProperties": false,
                },
            ],
        }),
    );
    Ok(())
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

    #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        value: String,
    }

    #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
    struct LoosePayload {
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
    fn unknown_payload_fields_fail_closed_without_payload_opt_in() {
        let document = br#"{"status":"success","payload":{"value":"ok","hostile":"payload"},"provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#;

        let error = decode_structured_tool_output::<LoosePayload>(document, MAX_OUTPUT_BYTES)
            .expect_err("unknown payload fields must fail closed");
        assert_eq!(error, StructuredOutputError::InvalidJson);
        assert_eq!(error.to_string(), "structured tool output is invalid");
        assert!(!error.to_string().contains("payload"));
    }

    #[test]
    fn unknown_payload_fields_fail_closed_for_json_value() {
        let document = br#"{"status":"success","payload":{"value":"ok","hostile":"payload"},"provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#;

        let error = decode_structured_tool_output::<Value>(document, MAX_OUTPUT_BYTES)
            .expect_err("unknown payload fields must fail closed");
        assert_eq!(error, StructuredOutputError::InvalidJson);
        assert_eq!(error.to_string(), "structured tool output is invalid");
        assert!(!error.to_string().contains("payload"));
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
