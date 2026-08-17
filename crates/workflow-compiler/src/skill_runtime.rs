use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use workflow_runtime::SandboxCapability;

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

/// A validated non-executable resource declaration from `skill.runtime.toml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredSkillResource {
    id: SkillResourceId,
    sha256: String,
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
    /// Parses a v1 runtime declaration for one exact activated Skill without execution.
    pub fn parse_for_activation(
        activation: &SkillActivationReceipt<'_>,
        bytes: &[u8],
    ) -> Result<Self, SkillRuntimeManifestError> {
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
        if skill_id != *activation.id() || raw.skill.version != activation.version() {
            return Err(SkillRuntimeManifestError::ActivationMismatch);
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
        for script in &manifest.scripts {
            let input = match supplied_resources.get(&script.input_schema) {
                Some(bytes) => *bytes,
                None => return Err(SkillRuntimeLockError::InputSetMismatch),
            };
            validate_schema(input)?;
            let output = match supplied_resources.get(&script.output_schema) {
                Some(bytes) => *bytes,
                None => return Err(SkillRuntimeLockError::InputSetMismatch),
            };
            validate_schema(output)?;
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
        })
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
        if SkillId::new(&raw.runtime).is_err() {
            return Err(SkillRuntimeManifestError::InvalidScript);
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
            (key != "$ref"
                || value
                    .as_str()
                    .is_some_and(|reference| reference == "#" || reference.starts_with("#/")))
                && has_only_local_references(value)
        }),
        _ => true,
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
