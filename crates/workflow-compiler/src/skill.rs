use std::{ffi::OsStr, fmt, path::Path};

use crate::SkillRegistry;

const MAX_SKILL_MARKDOWN_BYTES: usize = 65_536;
const MAX_SKILL_ID_BYTES: usize = 64;
const MAX_DESCRIPTION_SCALARS: usize = 1_024;
const MAX_COMPATIBILITY_SCALARS: usize = 500;

/// A validated Agent Skills identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SkillId(String);

impl SkillId {
    /// Validates and owns a canonical Agent Skills identifier.
    pub fn new(raw: &str) -> Result<Self, SkillIdError> {
        if raw.is_empty() {
            return Err(SkillIdError::Empty);
        }
        if raw.len() > MAX_SKILL_ID_BYTES {
            return Err(SkillIdError::TooLong);
        }
        if !raw.is_ascii()
            || raw.starts_with('-')
            || raw.ends_with('-')
            || raw.contains("--")
            || raw
                .bytes()
                .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
        {
            return Err(SkillIdError::InvalidSyntax);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Returns the validated identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A failure while validating a Skill identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillIdError {
    /// The identifier is empty.
    Empty,
    /// The identifier exceeds the fixed byte limit.
    TooLong,
    /// The identifier does not use the permitted syntax.
    InvalidSyntax,
}

impl fmt::Display for SkillIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "skill ID is empty",
            Self::TooLong => "skill ID is too long",
            Self::InvalidSyntax => "skill ID has invalid syntax",
        })
    }
}

impl std::error::Error for SkillIdError {}

/// A parsed, non-executable Agent Skills manifest.
pub struct SkillManifest {
    id: SkillId,
    description: String,
    body: String,
}

impl SkillManifest {
    /// Parses a bounded `SKILL.md` document for one exact skill directory name.
    pub fn parse(
        skill_directory: &Path,
        skill_markdown: &[u8],
    ) -> Result<Self, SkillManifestError> {
        if skill_markdown.len() > MAX_SKILL_MARKDOWN_BYTES {
            return Err(SkillManifestError::TooLarge);
        }
        let document =
            std::str::from_utf8(skill_markdown).map_err(|_| SkillManifestError::InvalidUtf8)?;
        let (frontmatter, body) = split_frontmatter(document)?;
        let fields = parse_frontmatter(frontmatter)?;
        let name = fields.name.ok_or(SkillManifestError::MissingName)?;
        let id = SkillId::new(&name).map_err(SkillManifestError::InvalidName)?;
        let directory_name = skill_directory
            .file_name()
            .and_then(OsStr::to_str)
            .filter(|name| !name.is_empty())
            .ok_or(SkillManifestError::InvalidDirectoryName)?;
        if directory_name != id.as_str() {
            return Err(SkillManifestError::DirectoryNameMismatch);
        }
        let description = fields
            .description
            .ok_or(SkillManifestError::MissingDescription)?;

        Ok(Self {
            id,
            description,
            body: body.to_owned(),
        })
    }

    /// Returns the metadata safe to retain during discovery.
    pub fn discovery_metadata(&self) -> SkillDiscoveryMetadata {
        SkillDiscoveryMetadata {
            id: self.id.clone(),
            description: self.description.clone(),
        }
    }
}

/// Discovery-only Agent Skills metadata.
pub struct SkillDiscoveryMetadata {
    id: SkillId,
    description: String,
}

impl SkillDiscoveryMetadata {
    /// Returns the validated discovered Skill identifier.
    pub fn id(&self) -> &SkillId {
        &self.id
    }

    /// Returns the bounded, trimmed discovery description.
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// A successful explicit Skill activation with borrowed instructions.
pub struct SkillActivationReceipt<'a> {
    id: &'a SkillId,
    version: &'a str,
    instructions: &'a str,
}

impl<'a> SkillActivationReceipt<'a> {
    /// Returns the exact registry-bound Skill identifier.
    pub fn id(&self) -> &SkillId {
        self.id
    }

    /// Returns the exact registry-bound Skill version.
    pub fn version(&self) -> &str {
        self.version
    }

    /// Returns the instruction body after the frontmatter closing delimiter.
    pub fn instructions(&self) -> &str {
        self.instructions
    }
}

/// Resolves one exact Skill version and returns only its borrowed instructions.
pub fn activate_skill<'a, R>(
    registry: &'a R,
    id: &SkillId,
    version: &str,
) -> Result<SkillActivationReceipt<'a>, SkillActivationError>
where
    R: SkillRegistry<Implementation = SkillManifest>,
{
    let entry = match registry.resolve(id.as_str(), version) {
        Ok(entry) => entry,
        Err(_) => return Err(SkillActivationError::NotRegistered),
    };
    let manifest = entry.implementation();
    if entry.id() != id.as_str() || entry.id() != manifest.id.as_str() {
        return Err(SkillActivationError::RegistryIdentityMismatch);
    }

    Ok(SkillActivationReceipt {
        id: &manifest.id,
        version: entry.version(),
        instructions: &manifest.body,
    })
}

/// A failure while parsing a bounded Agent Skills manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SkillManifestError {
    /// The raw document exceeds its single fixed limit.
    TooLarge,
    /// The raw document is not valid UTF-8.
    InvalidUtf8,
    /// The document lacks a complete frontmatter delimiter pair.
    MissingFrontmatter,
    /// The frontmatter is malformed or uses an unsupported shape.
    InvalidFrontmatter,
    /// The required name field is absent.
    MissingName,
    /// The required name field violates the Skill ID invariant.
    InvalidName(SkillIdError),
    /// The required description field is absent.
    MissingDescription,
    /// The description is empty after trimming or exceeds its scalar limit.
    InvalidDescription,
    /// The compatibility field is empty after trimming or exceeds its scalar limit.
    InvalidCompatibility,
    /// The supplied path has no UTF-8 terminal directory name.
    InvalidDirectoryName,
    /// The directory name and validated manifest name differ.
    DirectoryNameMismatch,
}

impl fmt::Display for SkillManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("skill manifest is too large"),
            Self::InvalidUtf8 => formatter.write_str("skill manifest is not valid UTF-8"),
            Self::MissingFrontmatter => {
                formatter.write_str("skill manifest is missing frontmatter")
            }
            Self::InvalidFrontmatter => {
                formatter.write_str("skill manifest frontmatter is invalid")
            }
            Self::MissingName => formatter.write_str("skill manifest is missing name"),
            Self::InvalidName(error) => {
                write!(formatter, "skill manifest name is invalid: {error}")
            }
            Self::MissingDescription => {
                formatter.write_str("skill manifest is missing description")
            }
            Self::InvalidDescription => {
                formatter.write_str("skill manifest description is invalid")
            }
            Self::InvalidCompatibility => {
                formatter.write_str("skill manifest compatibility is invalid")
            }
            Self::InvalidDirectoryName => {
                formatter.write_str("skill manifest directory name is invalid")
            }
            Self::DirectoryNameMismatch => {
                formatter.write_str("skill manifest directory name does not match skill ID")
            }
        }
    }
}

impl std::error::Error for SkillManifestError {}

/// A failure while explicitly activating one exact registry Skill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillActivationError {
    /// No exact registry entry exists for the requested ID and version.
    NotRegistered,
    /// The resolved registry identity disagrees with the requested manifest identity.
    RegistryIdentityMismatch,
}

impl fmt::Display for SkillActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotRegistered => "skill is not registered",
            Self::RegistryIdentityMismatch => "registry skill identity does not match manifest",
        })
    }
}

impl std::error::Error for SkillActivationError {}

struct FrontmatterFields {
    name: Option<String>,
    description: Option<String>,
}

fn split_frontmatter(document: &str) -> Result<(&str, &str), SkillManifestError> {
    let (opening, mut cursor) =
        next_line(document, 0).ok_or(SkillManifestError::MissingFrontmatter)?;
    if strip_cr(opening) != "---" {
        return Err(SkillManifestError::MissingFrontmatter);
    }
    let frontmatter_start = cursor;

    while cursor < document.len() {
        let (line, next) = match next_line(document, cursor) {
            Some(line) => line,
            None => break,
        };
        if strip_cr(line) == "---" {
            return Ok((&document[frontmatter_start..cursor], &document[next..]));
        }
        cursor = next;
    }

    Err(SkillManifestError::MissingFrontmatter)
}

fn next_line(input: &str, start: usize) -> Option<(&str, usize)> {
    if start > input.len() {
        return None;
    }
    let remaining = &input[start..];
    match remaining.find('\n') {
        Some(offset) => Some((&input[start..start + offset], start + offset + 1)),
        None => Some((&input[start..], input.len())),
    }
}

fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

fn parse_frontmatter(frontmatter: &str) -> Result<FrontmatterFields, SkillManifestError> {
    let frontmatter =
        serde_yaml::from_str(frontmatter).map_err(|_| SkillManifestError::InvalidFrontmatter)?;
    let mapping = match frontmatter {
        serde_yaml::Value::Mapping(mapping) => mapping,
        _ => return Err(SkillManifestError::InvalidFrontmatter),
    };
    let mut fields = FrontmatterFields {
        name: None,
        description: None,
    };
    let mut license_seen = false;
    let mut compatibility_seen = false;
    let mut allowed_tools_seen = false;
    let mut metadata_seen = false;

    for (key, value) in mapping {
        let key = yaml_string(key)?;
        match key.as_str() {
            "name" => set_field(&mut fields.name, yaml_string(value)?)?,
            "description" => {
                let description = yaml_string(value)?;
                let description = description.trim();
                if description.is_empty() || description.chars().count() > MAX_DESCRIPTION_SCALARS {
                    return Err(SkillManifestError::InvalidDescription);
                }
                set_field(&mut fields.description, description.to_owned())?;
            }
            "license" => {
                if license_seen {
                    return Err(SkillManifestError::InvalidFrontmatter);
                }
                let _license = yaml_string(value)?;
                license_seen = true;
            }
            "compatibility" => {
                if compatibility_seen {
                    return Err(SkillManifestError::InvalidFrontmatter);
                }
                let compatibility = yaml_string(value)?;
                let compatibility = compatibility.trim();
                if compatibility.is_empty()
                    || compatibility.chars().count() > MAX_COMPATIBILITY_SCALARS
                {
                    return Err(SkillManifestError::InvalidCompatibility);
                }
                compatibility_seen = true;
            }
            "metadata" => {
                if metadata_seen {
                    return Err(SkillManifestError::InvalidFrontmatter);
                }
                validate_metadata(value)?;
                metadata_seen = true;
            }
            "allowed-tools" => {
                if allowed_tools_seen {
                    return Err(SkillManifestError::InvalidFrontmatter);
                }
                let _allowed_tools = yaml_string(value)?;
                allowed_tools_seen = true;
            }
            _ => return Err(SkillManifestError::InvalidFrontmatter),
        }
    }

    Ok(fields)
}

fn set_field(field: &mut Option<String>, value: String) -> Result<(), SkillManifestError> {
    if field.replace(value).is_some() {
        return Err(SkillManifestError::InvalidFrontmatter);
    }
    Ok(())
}

fn validate_metadata(value: serde_yaml::Value) -> Result<(), SkillManifestError> {
    let mapping = match value {
        serde_yaml::Value::Mapping(mapping) => mapping,
        _ => return Err(SkillManifestError::InvalidFrontmatter),
    };
    for (key, value) in mapping {
        let _key = yaml_string(key)?;
        let _value = yaml_string(value)?;
    }
    Ok(())
}

fn yaml_string(value: serde_yaml::Value) -> Result<String, SkillManifestError> {
    match value {
        serde_yaml::Value::String(value) => Ok(value),
        _ => Err(SkillManifestError::InvalidFrontmatter),
    }
}
