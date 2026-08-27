use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use workflow_runtime::{BubblewrapReceipt, RunSandbox, SandboxCapability, SandboxExecutionError};

use crate::{SkillActivationReceipt, SkillId, SkillManifest, SkillResourceId};

const MAX_RUNTIME_MANIFEST_BYTES: usize = 65_536;
const MAX_VERSION_BYTES: usize = 128;
const MAX_SCRIPT_PATH_BYTES: usize = 1_024;
const MAX_SCHEMA_BYTES: usize = 65_536;
const MAX_SCRIPTS: usize = 64;
const MAX_RESOURCES: usize = 256;
const DRAFT_2020_12_SCHEMA: &str = "https://json-schema.org/draft/2020-12/schema";

/// A validated non-executable script declaration from `skill.runtime.toml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredSkillScript {
    id: SkillId,
    path: String,
    runtime: String,
    sha256: String,
    input_schema: SkillResourceId,
    output_schema: SkillResourceId,
    capabilities: Vec<SandboxCapability>,
}

impl DeclaredSkillScript {
    /// Returns the declared script identifier.
    pub fn id(&self) -> &SkillId {
        &self.id
    }

    /// Returns the package-relative script path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the declared script runtime.
    pub fn runtime(&self) -> &str {
        &self.runtime
    }
}

/// A validated non-executable resource declaration from `skill.runtime.toml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredSkillResource {
    id: SkillResourceId,
    sha256: String,
}

impl DeclaredSkillResource {
    /// Returns the declared resource identifier.
    pub fn id(&self) -> &SkillResourceId {
        &self.id
    }
}

/// The fixed runtime selected for a planned Skill script.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptRuntime {
    /// The only runtime admitted by the v0 planner.
    Python3,
}

/// A non-executable plan for one declared Skill script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptPlan {
    script_id: SkillId,
    runtime: ScriptRuntime,
    path: String,
    input_sha256: String,
    capabilities: Vec<SandboxCapability>,
}

impl ScriptPlan {
    /// Returns the exact declared script identifier.
    pub fn script_id(&self) -> &SkillId {
        &self.script_id
    }

    /// Returns the fixed runtime selected by the planner.
    pub fn runtime(&self) -> ScriptRuntime {
        self.runtime
    }

    /// Returns the package-relative declared script path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the SHA-256 identity of the accepted input JSON bytes.
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    /// Executes this registered plan inside a capability-narrowed child sandbox.
    pub fn execute(&self, sandbox: &RunSandbox) -> Result<BubblewrapReceipt, ScriptExecutionError> {
        let child = sandbox
            .child(self.capabilities.iter().copied())
            .map_err(ScriptExecutionError::sandbox)?;
        match self.runtime {
            // RunWorkdir materializes the already lock-bound script bytes at this fixed path.
            ScriptRuntime::Python3 => child
                .execute_python_script("content.bin")
                .map_err(ScriptExecutionError::sandbox),
        }
    }
}

/// A closed execution failure for a registered Skill script plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptExecutionErrorKind {
    /// Planning denied the requested registered script ID or input.
    Denied(ScriptDeniedKind),
    /// The run sandbox rejected or failed the child execution.
    Sandbox(SandboxExecutionError),
}

/// A privacy-safe error from registered Skill script execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptExecutionError {
    kind: ScriptExecutionErrorKind,
}

impl ScriptExecutionError {
    fn denied(error: ScriptDenied) -> Self {
        Self {
            kind: ScriptExecutionErrorKind::Denied(error.kind()),
        }
    }

    fn sandbox(error: SandboxExecutionError) -> Self {
        Self {
            kind: ScriptExecutionErrorKind::Sandbox(error),
        }
    }

    /// Returns the stable, payload-free failure category.
    pub const fn kind(self) -> ScriptExecutionErrorKind {
        self.kind
    }
}

impl fmt::Display for ScriptExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ScriptExecutionErrorKind::Denied(_) => "registered script execution denied",
            ScriptExecutionErrorKind::Sandbox(_) => "registered script sandbox execution failed",
        })
    }
}

impl std::error::Error for ScriptExecutionError {}

/// A fixed privacy-safe denial category for Skill script planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptDeniedKind {
    /// The requested script identifier was not declared.
    UnknownScript,
    /// The declaration path is outside the script path grammar.
    InvalidScriptPath,
    /// The declaration runtime is outside the closed allowlist.
    UnknownRuntime,
    /// The input JSON is absent, oversized, malformed, or schema-invalid.
    InvalidInput,
    /// The runtime lock does not bind the requested declaration.
    LockMismatch,
    /// The planner encountered an invalid internal policy state.
    InvalidPolicy,
}

impl fmt::Display for ScriptDeniedKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self)
    }
}

/// A privacy-safe denial from the ID-only script planner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ScriptDenied {
    kind: ScriptDeniedKind,
}

impl ScriptDenied {
    fn new(kind: ScriptDeniedKind) -> Self {
        Self { kind }
    }

    /// Returns the fixed denial category without any authored payload.
    pub fn kind(self) -> ScriptDeniedKind {
        self.kind
    }
}

impl fmt::Debug for ScriptDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.kind)
    }
}

impl fmt::Display for ScriptDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.kind)
    }
}

impl std::error::Error for ScriptDenied {}

fn lock_binds_script(
    manifest: &SkillRuntimeManifest,
    lock: &SkillRuntimeLock,
    script: &DeclaredSkillScript,
) -> bool {
    if lock.lock_version != 1
        || lock.skill_id != manifest.skill_id.as_str()
        || lock.skill_version != manifest.skill_version
        || lock.scripts.len() != manifest.scripts.len()
        || lock.resources.len() != manifest.resources.len()
    {
        return false;
    }

    let Some(locked_script) = lock
        .scripts
        .iter()
        .find(|locked_script| locked_script.id == script.id.as_str())
    else {
        return false;
    };
    let capabilities = script
        .capabilities
        .iter()
        .map(|capability| capability.as_str())
        .collect::<Vec<_>>();
    if locked_script.path != script.path
        || locked_script.runtime != script.runtime
        || locked_script.sha256 != script.sha256
        || locked_script.input_schema != script.input_schema.as_str()
        || locked_script.output_schema != script.output_schema.as_str()
        || locked_script.capabilities
            != capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect::<Vec<_>>()
    {
        return false;
    }

    if !manifest.resources.iter().all(|resource| {
        lock.resources
            .iter()
            .find(|locked_resource| locked_resource.id == resource.id.as_str())
            .is_some_and(|locked_resource| locked_resource.sha256 == resource.sha256)
    }) {
        return false;
    }

    for schema_id in [&script.input_schema, &script.output_schema] {
        let Some(bytes) = lock.schemas.get(schema_id) else {
            return false;
        };
        let Some(resource) = lock
            .resources
            .iter()
            .find(|resource| resource.id == schema_id.as_str())
        else {
            return false;
        };
        if digest(bytes) != resource.sha256 {
            return false;
        }
    }
    true
}

/// Plans one declared Skill script by ID without constructing an execution backend request.
pub fn plan_script_execution(
    manifest: &SkillRuntimeManifest,
    lock: &SkillRuntimeLock,
    script_id: &str,
    input_json: &[u8],
) -> Result<ScriptPlan, ScriptDenied> {
    let Some(script) = manifest.script(script_id) else {
        return Err(ScriptDenied::new(ScriptDeniedKind::UnknownScript));
    };
    if !lock_binds_script(manifest, lock, script) {
        return Err(ScriptDenied::new(ScriptDeniedKind::LockMismatch));
    }
    if !is_script_path(&script.path) {
        return Err(ScriptDenied::new(ScriptDeniedKind::InvalidScriptPath));
    }
    if script.runtime != "python3" {
        return Err(ScriptDenied::new(ScriptDeniedKind::UnknownRuntime));
    }
    if input_json.is_empty() || input_json.len() > MAX_SCHEMA_BYTES {
        return Err(ScriptDenied::new(ScriptDeniedKind::InvalidInput));
    }
    let input = serde_json::from_slice::<Value>(input_json)
        .map_err(|_| ScriptDenied::new(ScriptDeniedKind::InvalidInput))?;
    let Some(schema_bytes) = lock.schemas.get(&script.input_schema) else {
        return Err(ScriptDenied::new(ScriptDeniedKind::LockMismatch));
    };
    let schema = serde_json::from_slice::<Value>(schema_bytes)
        .map_err(|_| ScriptDenied::new(ScriptDeniedKind::InvalidPolicy))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|_| ScriptDenied::new(ScriptDeniedKind::InvalidPolicy))?;
    if !validator.is_valid(&input) {
        return Err(ScriptDenied::new(ScriptDeniedKind::InvalidInput));
    }
    Ok(ScriptPlan {
        script_id: script.id.clone(),
        runtime: ScriptRuntime::Python3,
        path: script.path.clone(),
        input_sha256: digest(input_json),
        capabilities: script.capabilities.clone(),
    })
}

/// Plans and executes one declared Skill script ID through a narrowed child sandbox.
pub fn execute_registered_script(
    manifest: &SkillRuntimeManifest,
    lock: &SkillRuntimeLock,
    script_id: &str,
    input_json: &[u8],
    sandbox: &RunSandbox,
) -> Result<BubblewrapReceipt, ScriptExecutionError> {
    plan_script_execution(manifest, lock, script_id, input_json)
        .map_err(ScriptExecutionError::denied)?
        .execute(sandbox)
}

/// A bounded, canonicalized v1 Skill runtime manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillRuntimeManifest {
    skill_id: SkillId,
    skill_version: String,
    scripts: Vec<DeclaredSkillScript>,
    resources: Vec<DeclaredSkillResource>,
}

impl SkillRuntimeManifest {
    /// Parses a bounded v1 runtime declaration without executing any script.
    pub fn parse(bytes: &[u8]) -> Result<Self, SkillRuntimeManifestError> {
        if bytes.is_empty() {
            return Err(SkillRuntimeManifestError::Empty);
        }
        if bytes.len() > MAX_RUNTIME_MANIFEST_BYTES {
            return Err(SkillRuntimeManifestError::TooLarge);
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| SkillRuntimeManifestError::InvalidUtf8)?;
        let raw = toml::from_str::<RawManifest>(text)
            .map_err(|_| SkillRuntimeManifestError::InvalidToml)?;
        if raw.schema_version != 1 {
            return Err(SkillRuntimeManifestError::UnsupportedVersion);
        }

        let skill_id = SkillId::new(&raw.skill.id)
            .map_err(|_| SkillRuntimeManifestError::InvalidSkillIdentifier)?;
        if !is_valid_version(&raw.skill.version) {
            return Err(SkillRuntimeManifestError::InvalidSkillVersion);
        }
        if raw.scripts.len() > MAX_SCRIPTS {
            return Err(SkillRuntimeManifestError::TooManyScripts);
        }
        if raw.resources.len() > MAX_RESOURCES {
            return Err(SkillRuntimeManifestError::TooManyResources);
        }
        if raw.scripts.is_empty() && raw.resources.is_empty() {
            return Err(SkillRuntimeManifestError::EmptyDeclarations);
        }

        let resources = parse_resources(raw.resources)?;
        let resource_ids = resources
            .iter()
            .map(|resource| resource.id.clone())
            .collect::<BTreeSet<_>>();
        let scripts = parse_scripts(raw.scripts, &resource_ids)?;

        Ok(Self {
            skill_id,
            skill_version: raw.skill.version,
            scripts,
            resources,
        })
    }

    /// Parses a v1 runtime declaration for one exact activated Skill without execution.
    pub fn parse_for_activation(
        activation: &SkillActivationReceipt<'_>,
        bytes: &[u8],
    ) -> Result<Self, SkillRuntimeManifestError> {
        let manifest = Self::parse(bytes)?;
        if manifest.skill_id != *activation.id() || manifest.skill_version != activation.version() {
            return Err(SkillRuntimeManifestError::ActivationMismatch);
        }
        Ok(manifest)
    }

    /// Returns the exact activated Skill identifier.
    pub fn skill_id(&self) -> &SkillId {
        &self.skill_id
    }

    /// Returns the exact activated Skill version.
    pub fn skill_version(&self) -> &str {
        &self.skill_version
    }

    /// Returns declared scripts in canonical identifier order.
    pub fn scripts(&self) -> &[DeclaredSkillScript] {
        &self.scripts
    }

    /// Returns declared resources in canonical resource identifier order.
    pub fn resources(&self) -> &[DeclaredSkillResource] {
        &self.resources
    }

    /// Looks up one declared script without interpreting its path or runtime.
    pub fn script(&self, id: &str) -> Option<&DeclaredSkillScript> {
        self.scripts
            .binary_search_by(|script| script.id.as_str().cmp(id))
            .ok()
            .map(|index| &self.scripts[index])
    }

    fn canonical_toml(&self) -> Result<String, toml::ser::Error> {
        let scripts = self
            .scripts
            .iter()
            .map(|script| CanonicalScript {
                id: script.id.as_str(),
                path: &script.path,
                runtime: &script.runtime,
                sha256: &script.sha256,
                input_schema: script.input_schema.as_str(),
                output_schema: script.output_schema.as_str(),
                capabilities: script
                    .capabilities
                    .iter()
                    .map(SandboxCapability::as_str)
                    .collect(),
            })
            .collect();
        let resources = self
            .resources
            .iter()
            .map(|resource| CanonicalResource {
                id: resource.id.as_str(),
                sha256: &resource.sha256,
            })
            .collect();
        toml::to_string(&CanonicalManifest {
            schema_version: 1,
            skill: CanonicalSkill {
                id: self.skill_id.as_str(),
                version: &self.skill_version,
            },
            scripts,
            resources,
        })
    }
}

/// A fixed-category failure while parsing a Skill runtime manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillRuntimeManifestError {
    /// The manifest has no bytes.
    Empty,
    /// The manifest exceeds its fixed byte limit.
    TooLarge,
    /// The manifest is not UTF-8.
    InvalidUtf8,
    /// The manifest is malformed or contains unknown fields.
    InvalidToml,
    /// The manifest schema version is unsupported.
    UnsupportedVersion,
    /// The declared Skill identifier is invalid.
    InvalidSkillIdentifier,
    /// The declared Skill version is invalid.
    InvalidSkillVersion,
    /// The declaration does not match its activation receipt.
    ActivationMismatch,
    /// The manifest declares neither scripts nor resources.
    EmptyDeclarations,
    /// The manifest exceeds the script count limit.
    TooManyScripts,
    /// The manifest exceeds the resource count limit.
    TooManyResources,
    /// A script declaration is invalid.
    InvalidScript,
    /// A script declaration duplicates an identifier or path.
    DuplicateScript,
    /// A resource declaration is invalid.
    InvalidResource,
    /// A resource declaration duplicates an identifier.
    DuplicateResource,
    /// A schema reference is invalid or absent from declared resources.
    InvalidSchemaReference,
    /// A capability is unknown or repeated.
    InvalidCapability,
    /// A declared digest is invalid.
    InvalidDigest,
}

impl fmt::Display for SkillRuntimeManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "skill runtime manifest is empty",
            Self::TooLarge => "skill runtime manifest is too large",
            Self::InvalidUtf8 => "skill runtime manifest is not valid UTF-8",
            Self::InvalidToml => "skill runtime manifest is invalid",
            Self::UnsupportedVersion => "skill runtime manifest version is unsupported",
            Self::InvalidSkillIdentifier => "skill runtime manifest Skill identifier is invalid",
            Self::InvalidSkillVersion => "skill runtime manifest Skill version is invalid",
            Self::ActivationMismatch => "skill runtime manifest activation does not match",
            Self::EmptyDeclarations => "skill runtime manifest has no declarations",
            Self::TooManyScripts => "skill runtime manifest has too many scripts",
            Self::TooManyResources => "skill runtime manifest has too many resources",
            Self::InvalidScript => "skill runtime manifest script declaration is invalid",
            Self::DuplicateScript => "skill runtime manifest has a duplicate script declaration",
            Self::InvalidResource => "skill runtime manifest resource declaration is invalid",
            Self::DuplicateResource => {
                "skill runtime manifest has a duplicate resource declaration"
            }
            Self::InvalidSchemaReference => "skill runtime manifest schema reference is invalid",
            Self::InvalidCapability => "skill runtime manifest capability declaration is invalid",
            Self::InvalidDigest => "skill runtime manifest digest is invalid",
        })
    }
}

impl std::error::Error for SkillRuntimeManifestError {}

/// An immutable v1 identity lock for validated Skill runtime declarations and bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillRuntimeLock {
    lock_version: u16,
    skill_id: String,
    skill_version: String,
    skill_markdown_sha256: String,
    runtime_manifest_sha256: String,
    scripts: Vec<LockedScript>,
    resources: Vec<LockedResource>,
    schemas: BTreeMap<SkillResourceId, Vec<u8>>,
}

impl SkillRuntimeLock {
    /// Locks one manifest and its exact declared byte collections entirely in memory.
    pub fn try_from_declared_bytes<'a, S, R>(
        manifest: &SkillRuntimeManifest,
        skill_markdown: &[u8],
        script_bytes: S,
        resource_bytes: R,
    ) -> Result<Self, SkillRuntimeLockError>
    where
        S: IntoIterator<Item = (&'a str, &'a [u8])>,
        R: IntoIterator<Item = (&'a SkillResourceId, &'a [u8])>,
    {
        if SkillManifest::parse(Path::new(manifest.skill_id.as_str()), skill_markdown).is_err() {
            return Err(SkillRuntimeLockError::InvalidSkillMarkdown);
        }

        let supplied_scripts = collect_scripts(script_bytes)?;
        let supplied_resources = collect_resources(resource_bytes)?;
        if supplied_scripts.len() != manifest.scripts.len()
            || supplied_resources.len() != manifest.resources.len()
        {
            return Err(SkillRuntimeLockError::InputSetMismatch);
        }

        for script in &manifest.scripts {
            let bytes = match supplied_scripts.get(script.id.as_str()) {
                Some(bytes) => *bytes,
                None => return Err(SkillRuntimeLockError::InputSetMismatch),
            };
            if digest(bytes) != script.sha256 {
                return Err(SkillRuntimeLockError::DigestMismatch);
            }
        }
        for resource in &manifest.resources {
            let bytes = match supplied_resources.get(&resource.id) {
                Some(bytes) => *bytes,
                None => return Err(SkillRuntimeLockError::InputSetMismatch),
            };
            if digest(bytes) != resource.sha256 {
                return Err(SkillRuntimeLockError::DigestMismatch);
            }
        }
        let mut schemas = BTreeMap::new();
        for script in &manifest.scripts {
            let input = match supplied_resources.get(&script.input_schema) {
                Some(bytes) => *bytes,
                None => return Err(SkillRuntimeLockError::InputSetMismatch),
            };
            validate_schema(input)?;
            schemas
                .entry(script.input_schema.clone())
                .or_insert_with(|| input.to_vec());
            let output = match supplied_resources.get(&script.output_schema) {
                Some(bytes) => *bytes,
                None => return Err(SkillRuntimeLockError::InputSetMismatch),
            };
            validate_schema(output)?;
            schemas
                .entry(script.output_schema.clone())
                .or_insert_with(|| output.to_vec());
        }

        let runtime_manifest = manifest
            .canonical_toml()
            .map_err(|_| SkillRuntimeLockError::Serialization)?;
        let scripts = manifest
            .scripts
            .iter()
            .map(|script| LockedScript {
                id: script.id.as_str().to_owned(),
                path: script.path.clone(),
                runtime: script.runtime.clone(),
                sha256: script.sha256.clone(),
                input_schema: script.input_schema.as_str().to_owned(),
                output_schema: script.output_schema.as_str().to_owned(),
                capabilities: script
                    .capabilities
                    .iter()
                    .map(|capability| capability.as_str().to_owned())
                    .collect(),
            })
            .collect();
        let resources = manifest
            .resources
            .iter()
            .map(|resource| LockedResource {
                id: resource.id.as_str().to_owned(),
                sha256: resource.sha256.clone(),
            })
            .collect();

        Ok(Self {
            lock_version: 1,
            skill_id: manifest.skill_id.as_str().to_owned(),
            skill_version: manifest.skill_version.clone(),
            skill_markdown_sha256: digest(skill_markdown),
            runtime_manifest_sha256: digest(runtime_manifest.as_bytes()),
            scripts,
            resources,
            schemas,
        })
    }

    /// Returns whether this lock belongs to the exact declared Skill identity.
    pub fn matches_skill(&self, skill_id: &SkillId, skill_version: &str) -> bool {
        self.skill_id == skill_id.as_str() && self.skill_version == skill_version
    }

    /// Returns the exact locked Skill markdown digest.
    pub fn skill_markdown_sha256(&self) -> &str {
        &self.skill_markdown_sha256
    }

    /// Returns the exact locked runtime manifest digest.
    pub fn runtime_manifest_sha256(&self) -> &str {
        &self.runtime_manifest_sha256
    }

    /// Serializes the exact deterministic v1 TOML lock document in memory.
    pub fn to_toml(&self) -> Result<String, SkillRuntimeLockError> {
        toml::to_string(&CanonicalLock {
            lock_version: self.lock_version,
            skill_id: &self.skill_id,
            skill_version: &self.skill_version,
            skill_markdown_sha256: &self.skill_markdown_sha256,
            runtime_manifest_sha256: &self.runtime_manifest_sha256,
            scripts: self
                .scripts
                .iter()
                .map(|script| CanonicalScript {
                    id: &script.id,
                    path: &script.path,
                    runtime: &script.runtime,
                    sha256: &script.sha256,
                    input_schema: &script.input_schema,
                    output_schema: &script.output_schema,
                    capabilities: script.capabilities.iter().map(String::as_str).collect(),
                })
                .collect(),
            resources: self
                .resources
                .iter()
                .map(|resource| CanonicalResource {
                    id: &resource.id,
                    sha256: &resource.sha256,
                })
                .collect(),
        })
        .map_err(|_| SkillRuntimeLockError::Serialization)
    }
}

/// A fixed-category failure while creating or serializing a Skill runtime lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillRuntimeLockError {
    /// The supplied `SKILL.md` does not pass existing manifest validation.
    InvalidSkillMarkdown,
    /// Declared script or resource bytes are missing, extra, or duplicated.
    InputSetMismatch,
    /// Declared content bytes do not match their digest.
    DigestMismatch,
    /// A referenced schema has invalid bytes or violates its schema contract.
    InvalidSchema,
    /// A referenced schema exceeds its fixed byte limit.
    SchemaTooLarge,
    /// Canonical TOML serialization failed.
    Serialization,
}

impl fmt::Display for SkillRuntimeLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSkillMarkdown => "skill runtime lock Skill markdown is invalid",
            Self::InputSetMismatch => "skill runtime lock declared bytes do not match",
            Self::DigestMismatch => "skill runtime lock digest does not match",
            Self::InvalidSchema => "skill runtime lock schema is invalid",
            Self::SchemaTooLarge => "skill runtime lock schema is too large",
            Self::Serialization => "skill runtime lock serialization failed",
        })
    }
}

impl std::error::Error for SkillRuntimeLockError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema_version: u16,
    skill: RawSkill,
    #[serde(default)]
    scripts: Vec<RawScript>,
    #[serde(default)]
    resources: Vec<RawResource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSkill {
    id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScript {
    id: String,
    path: String,
    runtime: String,
    sha256: String,
    input_schema: String,
    output_schema: String,
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResource {
    id: String,
    sha256: String,
}

#[derive(Serialize)]
struct CanonicalManifest<'a> {
    schema_version: u16,
    skill: CanonicalSkill<'a>,
    scripts: Vec<CanonicalScript<'a>>,
    resources: Vec<CanonicalResource<'a>>,
}

#[derive(Serialize)]
struct CanonicalSkill<'a> {
    id: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct CanonicalScript<'a> {
    id: &'a str,
    path: &'a str,
    runtime: &'a str,
    sha256: &'a str,
    input_schema: &'a str,
    output_schema: &'a str,
    capabilities: Vec<&'a str>,
}

#[derive(Serialize)]
struct CanonicalResource<'a> {
    id: &'a str,
    sha256: &'a str,
}

#[derive(Serialize)]
struct CanonicalLock<'a> {
    lock_version: u16,
    skill_id: &'a str,
    skill_version: &'a str,
    skill_markdown_sha256: &'a str,
    runtime_manifest_sha256: &'a str,
    scripts: Vec<CanonicalScript<'a>>,
    resources: Vec<CanonicalResource<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LockedScript {
    id: String,
    path: String,
    runtime: String,
    sha256: String,
    input_schema: String,
    output_schema: String,
    capabilities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LockedResource {
    id: String,
    sha256: String,
}

fn parse_resources(
    raw_resources: Vec<RawResource>,
) -> Result<Vec<DeclaredSkillResource>, SkillRuntimeManifestError> {
    let mut ids = BTreeSet::new();
    let mut resources = Vec::with_capacity(raw_resources.len());
    for raw in raw_resources {
        let id = SkillResourceId::new(&raw.id)
            .map_err(|_| SkillRuntimeManifestError::InvalidResource)?;
        if contains_glob_metacharacter(id.as_str()) {
            return Err(SkillRuntimeManifestError::InvalidResource);
        }
        if !ids.insert(id.clone()) {
            return Err(SkillRuntimeManifestError::DuplicateResource);
        }
        if !is_digest(&raw.sha256) {
            return Err(SkillRuntimeManifestError::InvalidDigest);
        }
        resources.push(DeclaredSkillResource {
            id,
            sha256: raw.sha256,
        });
    }
    resources.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(resources)
}

fn parse_scripts(
    raw_scripts: Vec<RawScript>,
    resource_ids: &BTreeSet<SkillResourceId>,
) -> Result<Vec<DeclaredSkillScript>, SkillRuntimeManifestError> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut scripts = Vec::with_capacity(raw_scripts.len());
    for raw in raw_scripts {
        let id = SkillId::new(&raw.id).map_err(|_| SkillRuntimeManifestError::InvalidScript)?;
        if !ids.insert(id.clone()) {
            return Err(SkillRuntimeManifestError::DuplicateScript);
        }
        if !is_script_path(&raw.path) {
            return Err(SkillRuntimeManifestError::InvalidScript);
        }
        if !paths.insert(raw.path.clone()) {
            return Err(SkillRuntimeManifestError::DuplicateScript);
        }
        if !is_digest(&raw.sha256) {
            return Err(SkillRuntimeManifestError::InvalidDigest);
        }
        let input_schema = parse_schema_reference(&raw.input_schema, resource_ids)?;
        let output_schema = parse_schema_reference(&raw.output_schema, resource_ids)?;
        let capabilities = parse_capabilities(raw.capabilities)?;
        scripts.push(DeclaredSkillScript {
            id,
            path: raw.path,
            runtime: raw.runtime,
            sha256: raw.sha256,
            input_schema,
            output_schema,
            capabilities,
        });
    }
    scripts.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(scripts)
}

fn parse_schema_reference(
    raw: &str,
    resource_ids: &BTreeSet<SkillResourceId>,
) -> Result<SkillResourceId, SkillRuntimeManifestError> {
    let id =
        SkillResourceId::new(raw).map_err(|_| SkillRuntimeManifestError::InvalidSchemaReference)?;
    if !id.as_str().starts_with("references/")
        || contains_glob_metacharacter(id.as_str())
        || !resource_ids.contains(&id)
    {
        return Err(SkillRuntimeManifestError::InvalidSchemaReference);
    }
    Ok(id)
}

fn parse_capabilities(
    raw_capabilities: Vec<String>,
) -> Result<Vec<SandboxCapability>, SkillRuntimeManifestError> {
    let mut capabilities = Vec::with_capacity(raw_capabilities.len());
    for raw in raw_capabilities {
        let capability = match raw.as_str() {
            "filesystem.read" => SandboxCapability::FilesystemRead,
            "filesystem.write" => SandboxCapability::FilesystemWrite,
            "network" => SandboxCapability::Network,
            "process.spawn" => SandboxCapability::ProcessSpawn,
            "limit.pids" => SandboxCapability::MaximumPids,
            "limit.cpu_time" => SandboxCapability::CpuTime,
            "limit.wall_time" => SandboxCapability::WallTime,
            "limit.idle_time" => SandboxCapability::IdleTime,
            "limit.memory" => SandboxCapability::Memory,
            "limit.output_bytes" => SandboxCapability::OutputBytes,
            "limit.open_files" => SandboxCapability::OpenFiles,
            "environment.variables" => SandboxCapability::EnvironmentVariables,
            "syscall.profile" => SandboxCapability::SyscallProfile,
            "identity.user_group" => SandboxCapability::UserGroupIdentity,
            "device.access" => SandboxCapability::DeviceAccess,
            _ => return Err(SkillRuntimeManifestError::InvalidCapability),
        };
        if capabilities.contains(&capability) {
            return Err(SkillRuntimeManifestError::InvalidCapability);
        }
        capabilities.push(capability);
    }
    capabilities.sort_unstable_by_key(SandboxCapability::as_str);
    Ok(capabilities)
}

fn is_valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VERSION_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_script_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_SCRIPT_PATH_BYTES
        || value.starts_with('/')
        || value.chars().any(char::is_control)
        || contains_glob_metacharacter(value)
        || contains_script_path_metacharacter(value)
    {
        return false;
    }
    let mut components = value.split('/');
    if components.next() != Some("scripts") {
        return false;
    }
    let mut has_script_component = false;
    for component in components {
        if component.is_empty() || matches!(component, "." | "..") {
            return false;
        }
        has_script_component = true;
    }
    has_script_component
}

fn contains_glob_metacharacter(value: &str) -> bool {
    value
        .chars()
        .any(|character| matches!(character, '*' | '?' | '[' | ']' | '{' | '}' | '!'))
}

fn contains_script_path_metacharacter(value: &str) -> bool {
    value.chars().any(|character| {
        character.is_whitespace()
            || matches!(
                character,
                ';' | '|'
                    | '&'
                    | '$'
                    | '`'
                    | '\''
                    | '"'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | '!'
                    | '#'
                    | '\\'
            )
    })
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn collect_scripts<'a, S>(
    script_bytes: S,
) -> Result<BTreeMap<String, &'a [u8]>, SkillRuntimeLockError>
where
    S: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let mut collected = BTreeMap::new();
    for (id, bytes) in script_bytes {
        if collected.insert(id.to_owned(), bytes).is_some() {
            return Err(SkillRuntimeLockError::InputSetMismatch);
        }
    }
    Ok(collected)
}

fn collect_resources<'a, R>(
    resource_bytes: R,
) -> Result<BTreeMap<SkillResourceId, &'a [u8]>, SkillRuntimeLockError>
where
    R: IntoIterator<Item = (&'a SkillResourceId, &'a [u8])>,
{
    let mut collected = BTreeMap::new();
    for (id, bytes) in resource_bytes {
        if collected.insert(id.clone(), bytes).is_some() {
            return Err(SkillRuntimeLockError::InputSetMismatch);
        }
    }
    Ok(collected)
}

fn validate_schema(bytes: &[u8]) -> Result<(), SkillRuntimeLockError> {
    if bytes.is_empty() {
        return Err(SkillRuntimeLockError::InvalidSchema);
    }
    if bytes.len() > MAX_SCHEMA_BYTES {
        return Err(SkillRuntimeLockError::SchemaTooLarge);
    }
    let schema =
        serde_json::from_slice::<Value>(bytes).map_err(|_| SkillRuntimeLockError::InvalidSchema)?;
    let Some(root) = schema.as_object().filter(|root| !root.is_empty()) else {
        return Err(SkillRuntimeLockError::InvalidSchema);
    };
    if root.get("$schema").and_then(Value::as_str) != Some(DRAFT_2020_12_SCHEMA)
        || !has_only_local_references(&schema)
        || jsonschema::meta::validate(&schema).is_err()
    {
        return Err(SkillRuntimeLockError::InvalidSchema);
    }
    Ok(())
}

fn has_only_local_references(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().all(has_only_local_references),
        Value::Object(object) => object.iter().all(|(key, value)| {
            (!matches!(key.as_str(), "$ref" | "$dynamicRef")
                || value
                    .as_str()
                    .is_some_and(|reference| reference.starts_with('#')))
                && has_only_local_references(value)
        }),
        _ => true,
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        num::NonZeroU64,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        DeclaredSkillResource, DeclaredSkillScript, ScriptDeniedKind, ScriptExecutionErrorKind,
        ScriptPlan, ScriptRuntime, SkillRuntimeLock, SkillRuntimeManifest,
        execute_registered_script, is_script_path, plan_script_execution,
    };
    use crate::{SkillId, SkillResourceId};
    use sha2::{Digest, Sha256};
    use workflow_runtime::{
        Materialization, RunContext, RunId, RunLimits, RunSandbox, SandboxCapability,
        SandboxExecutionError, WorkdirManager,
    };

    static NEXT_SANDBOX: AtomicU64 = AtomicU64::new(0);

    const SCHEMA: &[u8] = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}"#;
    const SKILL_MARKDOWN: &[u8] =
        b"---\nname: valid-skill\ndescription: A bounded skill.\n---\n# Instructions\n";
    const SCRIPT_BYTES: &[u8] = b"print('ok')\n";

    fn fixture_with_runtime(runtime: &str) -> (SkillRuntimeManifest, SkillRuntimeLock) {
        let skill_id = SkillId::new("valid-skill").expect("fixture skill ID");
        let schema_id = SkillResourceId::new("references/schema.json").expect("fixture schema ID");
        let script_id = SkillId::new("script").expect("fixture script ID");
        let script_digest = digest(SCRIPT_BYTES);
        let schema_digest = digest(SCHEMA);
        let manifest = SkillRuntimeManifest {
            skill_id: skill_id.clone(),
            skill_version: "1.2.3".to_owned(),
            scripts: vec![DeclaredSkillScript {
                id: script_id,
                path: "scripts/normalize.py".to_owned(),
                runtime: runtime.to_owned(),
                sha256: script_digest,
                input_schema: schema_id.clone(),
                output_schema: schema_id.clone(),
                capabilities: Vec::new(),
            }],
            resources: vec![DeclaredSkillResource {
                id: schema_id.clone(),
                sha256: schema_digest,
            }],
        };
        let lock = SkillRuntimeLock::try_from_declared_bytes(
            &manifest,
            SKILL_MARKDOWN,
            [("script", SCRIPT_BYTES)],
            [(&schema_id, SCHEMA)],
        )
        .expect("fixture lock");
        (manifest, lock)
    }

    fn fixture() -> (SkillRuntimeManifest, SkillRuntimeLock) {
        fixture_with_runtime("python3")
    }

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn script_path_with_shell_metacharacters_is_rejected_before_execution() {
        assert!(!is_script_path("scripts/run;rm"));
    }

    #[test]
    fn caller_cannot_supply_path_or_command() {
        let (manifest, lock) = fixture();
        let denial = plan_script_execution(
            &manifest,
            &lock,
            "script",
            br#"{"value":"ok","path":"/tmp/escape","command":"rm -rf /"}"#,
        )
        .expect_err("undeclared path and command fields must be rejected");
        assert_eq!(denial.kind(), ScriptDeniedKind::InvalidInput);
    }

    #[test]
    fn lock_mismatch_denies_before_plan() {
        let (manifest, mut lock) = fixture();
        lock.skill_version = "9.9.9".to_owned();
        let denial = plan_script_execution(&manifest, &lock, "script", br#"{"value":"ok"}"#)
            .expect_err("a lock for another version must be denied");
        assert_eq!(denial.kind(), ScriptDeniedKind::LockMismatch);
    }

    #[test]
    fn valid_script_id_produces_non_executable_plan() {
        let (manifest, lock) = fixture();
        let input = br#"{"value":"ok"}"#;
        let plan: ScriptPlan =
            plan_script_execution(&manifest, &lock, "script", input).expect("valid plan");
        assert_eq!(plan.script_id().as_str(), "script");
        assert_eq!(plan.runtime(), ScriptRuntime::Python3);
        assert_eq!(plan.path(), "scripts/normalize.py");
        assert_eq!(plan.input_sha256(), digest(input));
    }

    #[test]
    fn invalid_input_fails_schema_without_echo() {
        let (manifest, lock) = fixture();
        let denial = plan_script_execution(
            &manifest,
            &lock,
            "script",
            br#"{"value":42,"secret":"SECRET_MARKER"}"#,
        )
        .expect_err("schema-invalid input must be denied");
        assert_eq!(denial.kind(), ScriptDeniedKind::InvalidInput);
        assert!(!denial.to_string().contains("SECRET_MARKER"));
        assert!(!format!("{denial:?}").contains("SECRET_MARKER"));
    }

    #[test]
    fn unknown_runtime_is_rejected() {
        let (manifest, lock) = fixture_with_runtime("ruby");
        let denial = plan_script_execution(&manifest, &lock, "script", br#"{}"#)
            .expect_err("unknown runtimes must be denied");
        assert_eq!(denial.kind(), ScriptDeniedKind::UnknownRuntime);
    }

    #[test]
    fn denial_redacts_secret_and_payload_markers() {
        let (manifest, lock) = fixture();
        let denial = plan_script_execution(
            &manifest,
            &lock,
            "SECRET_SCRIPT_ID",
            br#"{"value":"PAYLOAD_MARKER","secret":"SECRET_MARKER"}"#,
        )
        .expect_err("unknown hostile IDs must be denied");
        assert_eq!(denial.kind(), ScriptDeniedKind::UnknownScript);
        for rendered in [denial.to_string(), format!("{denial:?}")] {
            assert!(!rendered.contains("SECRET_SCRIPT_ID"));
            assert!(!rendered.contains("PAYLOAD_MARKER"));
            assert!(!rendered.contains("SECRET_MARKER"));
        }
    }

    fn execution_fixture(
        capabilities: Vec<SandboxCapability>,
    ) -> (SkillRuntimeManifest, SkillRuntimeLock) {
        let skill_id = SkillId::new("valid-skill").expect("fixture skill ID");
        let schema_id = SkillResourceId::new("references/schema.json").expect("fixture schema ID");
        let script_id = SkillId::new("script").expect("fixture script ID");
        let manifest = SkillRuntimeManifest {
            skill_id: skill_id.clone(),
            skill_version: "1.2.3".to_owned(),
            scripts: vec![DeclaredSkillScript {
                id: script_id,
                path: "scripts/normalize.py".to_owned(),
                runtime: "python3".to_owned(),
                sha256: digest(SCRIPT_BYTES),
                input_schema: schema_id.clone(),
                output_schema: schema_id.clone(),
                capabilities,
            }],
            resources: vec![DeclaredSkillResource {
                id: schema_id.clone(),
                sha256: digest(SCHEMA),
            }],
        };
        let lock = SkillRuntimeLock::try_from_declared_bytes(
            &manifest,
            SKILL_MARKDOWN,
            [("script", SCRIPT_BYTES)],
            [(&schema_id, SCHEMA)],
        )
        .expect("fixture lock");
        (manifest, lock)
    }

    fn sandbox(capabilities: Vec<SandboxCapability>) -> RunSandbox {
        let sequence = NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "workflow-compiler-skill-runtime-{}-{}",
            std::process::id(),
            sequence
        ));
        fs::create_dir(&base).expect("fixture base must be unique");
        let context = RunContext::new(
            RunId::new(format!("script-{sequence}")).expect("fixture run ID"),
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
            .expect("fixture base must be trusted")
            .materialize(
                context.run_id(),
                &Materialization {
                    skills: Some(SCRIPT_BYTES.to_vec()),
                    ..Materialization::default()
                },
            )
            .expect("fixture workdir must materialize");
        RunSandbox::new(context, workdir, capabilities).expect("fixture sandbox must bind")
    }

    #[test]
    fn unknown_script_id_is_denied_before_child_sandbox_creation() {
        let (manifest, lock) = execution_fixture(vec![SandboxCapability::Network]);
        let sandbox = sandbox(Vec::new());

        let error =
            execute_registered_script(&manifest, &lock, "unknown", br#"{"value":"ok"}"#, &sandbox)
                .expect_err("unknown script IDs must be denied before sandbox creation");

        assert_eq!(
            error.kind(),
            ScriptExecutionErrorKind::Denied(ScriptDeniedKind::UnknownScript)
        );
    }

    #[test]
    fn script_plan_capabilities_cannot_exceed_parent_sandbox() {
        let (manifest, lock) = execution_fixture(vec![SandboxCapability::Network]);
        let sandbox = sandbox(vec![
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ]);

        let error =
            execute_registered_script(&manifest, &lock, "script", br#"{"value":"ok"}"#, &sandbox)
                .expect_err("child sandbox must not expand its parent authority");

        assert_eq!(
            error.kind(),
            ScriptExecutionErrorKind::Sandbox(SandboxExecutionError::CapabilityDenied)
        );
    }

    #[test]
    fn registered_script_plan_executes_in_a_child_sandbox() {
        let (manifest, lock) = execution_fixture(vec![
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ]);
        let sandbox = sandbox(vec![
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ]);

        let receipt =
            execute_registered_script(&manifest, &lock, "script", br#"{"value":"ok"}"#, &sandbox)
                .expect("registered plan must execute in a child sandbox");

        assert_eq!(receipt.stdout(), b"ok\n");
    }

    #[test]
    fn unknown_script_id_is_denied_without_backend() {
        let (manifest, lock) = fixture();
        let denial = plan_script_execution(&manifest, &lock, "unknown", br#"{}"#)
            .expect_err("unknown script IDs must be denied");
        assert_eq!(denial.kind(), ScriptDeniedKind::UnknownScript);
        assert_eq!(denial.to_string(), "UnknownScript");
    }
}
