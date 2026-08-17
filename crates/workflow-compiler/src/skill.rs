use std::{collections::BTreeSet, ffi::OsStr, fmt, path::Path};

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
    let mut fields = FrontmatterFields {
        name: None,
        description: None,
    };
    let mut license_seen = false;
    let mut compatibility_seen = false;
    let mut allowed_tools_seen = false;
    let mut metadata: Option<Metadata> = None;
    let mut metadata_active = false;

    for raw_line in frontmatter.lines() {
        let line = strip_cr(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line.starts_with('\t') {
            return Err(SkillManifestError::InvalidFrontmatter);
        }
        if line.starts_with(' ') {
            if !metadata_active {
                return Err(SkillManifestError::InvalidFrontmatter);
            }
            let metadata = metadata
                .as_mut()
                .ok_or(SkillManifestError::InvalidFrontmatter)?;
            if !metadata.requires_entry {
                return Err(SkillManifestError::InvalidFrontmatter);
            }
            let (key, value) = split_mapping(trimmed)?;
            validate_metadata_entry(key, value, metadata)?;
            continue;
        }

        if metadata_active
            && metadata
                .as_ref()
                .is_some_and(|metadata| !metadata.is_complete())
        {
            return Err(SkillManifestError::InvalidFrontmatter);
        }
        metadata_active = false;
        let (key, value) = split_mapping(line)?;
        match key {
            "name" => set_field(&mut fields.name, parse_string(value)?)?,
            "description" => {
                let description = parse_string(value)?;
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
                let _license = parse_string(value)?;
                license_seen = true;
            }
            "compatibility" => {
                if compatibility_seen {
                    return Err(SkillManifestError::InvalidFrontmatter);
                }
                let compatibility = parse_string(value)?;
                let compatibility = compatibility.trim();
                if compatibility.is_empty()
                    || compatibility.chars().count() > MAX_COMPATIBILITY_SCALARS
                {
                    return Err(SkillManifestError::InvalidCompatibility);
                }
                compatibility_seen = true;
            }
            "metadata" => {
                if metadata.is_some() {
                    return Err(SkillManifestError::InvalidFrontmatter);
                }
                metadata = Some(Metadata::new(value)?);
                metadata_active = true;
            }
            "allowed-tools" => {
                if allowed_tools_seen {
                    return Err(SkillManifestError::InvalidFrontmatter);
                }
                let _allowed_tools = parse_string(value)?;
                allowed_tools_seen = true;
            }
            _ => return Err(SkillManifestError::InvalidFrontmatter),
        }
    }

    if metadata_active
        && metadata
            .as_ref()
            .is_some_and(|metadata| !metadata.is_complete())
    {
        return Err(SkillManifestError::InvalidFrontmatter);
    }
    Ok(fields)
}

fn split_mapping(line: &str) -> Result<(&str, &str), SkillManifestError> {
    let (key, value) = line
        .split_once(':')
        .ok_or(SkillManifestError::InvalidFrontmatter)?;
    let key = key.trim();
    if key.is_empty() {
        return Err(SkillManifestError::InvalidFrontmatter);
    }
    Ok((key, value))
}

fn set_field(field: &mut Option<String>, value: String) -> Result<(), SkillManifestError> {
    if field.replace(value).is_some() {
        return Err(SkillManifestError::InvalidFrontmatter);
    }
    Ok(())
}

struct Metadata {
    entries: BTreeSet<String>,
    requires_entry: bool,
}

impl Metadata {
    fn new(value: &str) -> Result<Self, SkillManifestError> {
        let value = without_comment(value).trim();
        if value.is_empty() {
            return Ok(Self {
                entries: BTreeSet::new(),
                requires_entry: true,
            });
        }
        if value == "{}" {
            return Ok(Self {
                entries: BTreeSet::new(),
                requires_entry: false,
            });
        }
        let inner = value
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            .ok_or(SkillManifestError::InvalidFrontmatter)?;
        let mut metadata = Self {
            entries: BTreeSet::new(),
            requires_entry: false,
        };
        for entry in inner.split(',') {
            let (key, value) = split_mapping(entry)?;
            validate_metadata_entry(key, value, &mut metadata)?;
        }
        if metadata.entries.is_empty() {
            return Err(SkillManifestError::InvalidFrontmatter);
        }
        Ok(metadata)
    }

    fn is_complete(&self) -> bool {
        !self.requires_entry || !self.entries.is_empty()
    }
}

fn validate_metadata_entry(
    key: &str,
    value: &str,
    metadata: &mut Metadata,
) -> Result<(), SkillManifestError> {
    let key = parse_string(key)?;
    let _value = parse_string(value)?;
    if !metadata.entries.insert(key) {
        return Err(SkillManifestError::InvalidFrontmatter);
    }
    Ok(())
}

fn parse_string(raw: &str) -> Result<String, SkillManifestError> {
    let value = without_comment(raw).trim();
    if value.is_empty()
        || looks_like_non_string_scalar(value)
        || value.starts_with(['[', '{', '|', '>'])
    {
        return Err(SkillManifestError::InvalidFrontmatter);
    }
    match value.chars().next() {
        Some('\'') => parse_single_quoted(value),
        Some('"') => parse_double_quoted(value),
        Some(_) if value.ends_with(['\'', '"']) => Err(SkillManifestError::InvalidFrontmatter),
        Some(_) => Ok(value.to_owned()),
        None => Err(SkillManifestError::InvalidFrontmatter),
    }
}

fn looks_like_non_string_scalar(value: &str) -> bool {
    if value.eq_ignore_ascii_case("null")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("false")
        || matches!(
            value,
            "~" | ".inf" | ".Inf" | ".INF" | ".nan" | ".NaN" | ".NAN"
        )
    {
        return true;
    }
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'0'..=b'9')) || matches!(bytes, [b'+' | b'-', b'0'..=b'9', ..])
}

fn without_comment(value: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some(delimiter) if character == delimiter => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == '#' => return &value[..index],
            None => {}
        }
    }
    value
}

fn parse_single_quoted(value: &str) -> Result<String, SkillManifestError> {
    let inner = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .ok_or(SkillManifestError::InvalidFrontmatter)?;
    let mut parsed = String::with_capacity(inner.len());
    let mut characters = inner.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\'' && characters.next_if_eq(&'\'').is_none() {
            return Err(SkillManifestError::InvalidFrontmatter);
        }
        parsed.push(character);
    }
    Ok(parsed)
}

fn parse_double_quoted(value: &str) -> Result<String, SkillManifestError> {
    let inner = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(SkillManifestError::InvalidFrontmatter)?;
    let mut parsed = String::with_capacity(inner.len());
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character == '"' {
            return Err(SkillManifestError::InvalidFrontmatter);
        }
        if character != '\\' {
            parsed.push(character);
            continue;
        }
        let escaped = characters
            .next()
            .ok_or(SkillManifestError::InvalidFrontmatter)?;
        match escaped {
            '0' => parsed.push('\0'),
            'a' => parsed.push('\u{7}'),
            'b' => parsed.push('\u{8}'),
            't' => parsed.push('\t'),
            'n' => parsed.push('\n'),
            'v' => parsed.push('\u{b}'),
            'f' => parsed.push('\u{c}'),
            'r' => parsed.push('\r'),
            'e' => parsed.push('\u{1b}'),
            ' ' => parsed.push(' '),
            '"' => parsed.push('"'),
            '/' => parsed.push('/'),
            '\\' => parsed.push('\\'),
            'N' => parsed.push('\u{85}'),
            '_' => parsed.push('\u{a0}'),
            'L' => parsed.push('\u{2028}'),
            'P' => parsed.push('\u{2029}'),
            'x' => push_unicode_escape(&mut characters, 2, &mut parsed)?,
            'u' => push_unicode_escape(&mut characters, 4, &mut parsed)?,
            'U' => push_unicode_escape(&mut characters, 8, &mut parsed)?,
            _ => return Err(SkillManifestError::InvalidFrontmatter),
        }
    }
    Ok(parsed)
}

fn push_unicode_escape(
    characters: &mut std::str::Chars<'_>,
    digits: usize,
    output: &mut String,
) -> Result<(), SkillManifestError> {
    let mut encoded = String::with_capacity(digits);
    for _ in 0..digits {
        encoded.push(
            characters
                .next()
                .ok_or(SkillManifestError::InvalidFrontmatter)?,
        );
    }
    let codepoint =
        u32::from_str_radix(&encoded, 16).map_err(|_| SkillManifestError::InvalidFrontmatter)?;
    let character = char::from_u32(codepoint).ok_or(SkillManifestError::InvalidFrontmatter)?;
    output.push(character);
    Ok(())
}
