use std::fmt;

use serde::Deserialize;
use workflow_runtime::{ArtifactId, RunId};

use crate::{SkillId, SkillRuntimeLock};

const MAX_PACKAGE_BYTES: usize = 65_536;
const MAX_EVIDENCE: usize = 64;
const MAX_REVIEW_REFS: usize = 64;
const MAX_REF_BYTES: usize = 256;
const SCHEMA_VERSION: u16 = 1;

/// The closed v1 categories of structural evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillEvidenceKind {
    /// A run completed successfully.
    SuccessfulRun,
    /// A run failed.
    FailedRun,
    /// A correction was recorded.
    Correction,
    /// An output was accepted.
    AcceptedOutput,
    /// An output was rejected.
    RejectedOutput,
}

/// The closed planning stages carried by v1 promotion metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillPlanningStage {
    /// Personal use.
    Personal,
    /// Candidate promotion.
    Candidate,
    /// Validated use.
    Validated,
    /// Production use.
    Production,
    /// Organization-wide standard.
    OrganizationStandard,
    /// Retired use.
    Retired,
}

/// One validated, redacted structural evidence reference.
#[derive(Clone, Eq, PartialEq)]
pub struct SkillEvidence {
    kind: SkillEvidenceKind,
    artifact_ref: ArtifactId,
    run_ref: Option<RunId>,
}

impl fmt::Debug for SkillEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillEvidence")
    }
}

impl SkillEvidence {
    /// Returns the closed evidence category.
    pub fn kind(&self) -> SkillEvidenceKind {
        self.kind
    }

    /// Returns the existing runtime artifact identity.
    pub fn artifact_ref(&self) -> &ArtifactId {
        &self.artifact_ref
    }

    /// Returns the optional existing runtime run identity.
    pub fn run_ref(&self) -> Option<&RunId> {
        self.run_ref.as_ref()
    }
}

/// Descriptive promotion metadata; it does not authorize a transition.
#[derive(Clone, Eq, PartialEq)]
pub struct SkillPromotion {
    stage: SkillPlanningStage,
    owner_ref: String,
    review_refs: Vec<String>,
}

impl fmt::Debug for SkillPromotion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillPromotion")
    }
}

impl SkillPromotion {
    /// Returns the declared planning stage.
    pub fn stage(&self) -> SkillPlanningStage {
        self.stage
    }

    /// Returns the validated opaque owner reference.
    pub fn owner_ref(&self) -> &str {
        &self.owner_ref
    }

    /// Returns validated opaque review references.
    pub fn review_refs(&self) -> &[String] {
        &self.review_refs
    }
}

/// A validated, non-authorizing v1 redacted Skill evidence package.
#[derive(Clone, Eq, PartialEq)]
pub struct SkillEvidencePackage {
    skill_id: SkillId,
    skill_version: String,
    skill_markdown_sha256: String,
    runtime_manifest_sha256: String,
    scope_ref: String,
    evidence: Vec<SkillEvidence>,
    promotion: SkillPromotion,
}

impl fmt::Debug for SkillEvidencePackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillEvidencePackage")
    }
}

impl SkillEvidencePackage {
    /// Parses one strict JSON package against supplied declared Skill/runtime identities.
    pub fn parse(
        bytes: &[u8],
        expected_skill_id: &SkillId,
        expected_skill_version: &str,
        runtime_lock: &SkillRuntimeLock,
        known_artifacts: &[ArtifactId],
    ) -> Result<Self, SkillEvidenceError> {
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(SkillEvidenceError::TooLarge);
        }
        let raw = serde_json::from_slice::<RawPackage>(bytes).map_err(map_json_error)?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(SkillEvidenceError::UnsupportedSchemaVersion);
        }

        let scope_ref = raw.scope_ref.ok_or(SkillEvidenceError::InvalidScopeRef)?;
        if !is_valid_opaque_ref(&scope_ref) {
            return Err(SkillEvidenceError::InvalidScopeRef);
        }
        let raw_evidence = raw.evidence.ok_or(SkillEvidenceError::EmptyEvidence)?;
        if raw_evidence.is_empty() {
            return Err(SkillEvidenceError::EmptyEvidence);
        }

        if raw_evidence.len() > MAX_EVIDENCE {
            return Err(SkillEvidenceError::TooManyEvidence);
        }
        if raw.promotion.review_refs.len() > MAX_REVIEW_REFS {
            return Err(SkillEvidenceError::TooManyReviewRefs);
        }
        if !is_valid_opaque_ref(&raw.promotion.owner_ref) {
            return Err(SkillEvidenceError::InvalidOwnerRef);
        }
        if raw
            .promotion
            .review_refs
            .iter()
            .any(|review_ref| !is_valid_opaque_ref(review_ref))
        {
            return Err(SkillEvidenceError::InvalidReviewRef);
        }

        let skill_id =
            SkillId::new(&raw.skill.id).map_err(|_| SkillEvidenceError::InvalidSkillId)?;
        if skill_id != *expected_skill_id || raw.skill.version != expected_skill_version {
            return Err(SkillEvidenceError::SkillIdentityMismatch);
        }
        if raw.runtime.skill_markdown_sha256 != runtime_lock.skill_markdown_sha256()
            || raw.runtime.runtime_manifest_sha256 != runtime_lock.runtime_manifest_sha256()
        {
            return Err(SkillEvidenceError::RuntimeIdentityMismatch);
        }

        let evidence = raw_evidence
            .into_iter()
            .map(|raw| {
                let kind = parse_kind(&raw.kind)?;
                let artifact_ref = known_artifacts
                    .iter()
                    .find(|artifact| artifact.as_str() == raw.artifact_ref)
                    .cloned()
                    .ok_or(SkillEvidenceError::UnknownArtifactRef)?;
                let run_ref = raw
                    .run_ref
                    .map(|run| RunId::new(run).map_err(|_| SkillEvidenceError::InvalidRunRef))
                    .transpose()?;
                Ok(SkillEvidence {
                    kind,
                    artifact_ref,
                    run_ref,
                })
            })
            .collect::<Result<Vec<_>, SkillEvidenceError>>()?;

        let promotion = SkillPromotion {
            stage: parse_stage(&raw.promotion.stage)?,
            owner_ref: raw.promotion.owner_ref,
            review_refs: raw.promotion.review_refs,
        };

        Ok(Self {
            skill_id,
            skill_version: raw.skill.version,
            skill_markdown_sha256: raw.runtime.skill_markdown_sha256,
            runtime_manifest_sha256: raw.runtime.runtime_manifest_sha256,
            scope_ref,
            evidence,
            promotion,
        })
    }

    /// Returns the validated Skill identifier.
    pub fn skill_id(&self) -> &SkillId {
        &self.skill_id
    }

    /// Returns the validated Skill version.
    pub fn skill_version(&self) -> &str {
        &self.skill_version
    }

    /// Returns the locked Skill markdown digest declared by the package.
    pub fn skill_markdown_sha256(&self) -> &str {
        &self.skill_markdown_sha256
    }

    /// Returns the locked runtime manifest digest declared by the package.
    pub fn runtime_manifest_sha256(&self) -> &str {
        &self.runtime_manifest_sha256
    }

    /// Returns the validated opaque authorized scope reference.
    pub fn scope_ref(&self) -> &str {
        &self.scope_ref
    }

    /// Returns structural evidence references in document order.
    pub fn evidence(&self) -> &[SkillEvidence] {
        &self.evidence
    }

    /// Returns descriptive promotion metadata.
    pub fn promotion(&self) -> &SkillPromotion {
        &self.promotion
    }
}

/// A static failure while validating a redacted evidence package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillEvidenceError {
    /// The package is not valid JSON.
    InvalidJson,
    /// The package contains a raw or unknown payload field.
    UnknownPayloadField,
    /// The package schema version is unsupported.
    UnsupportedSchemaVersion,
    /// The package Skill identifier is invalid.
    InvalidSkillId,
    /// The package Skill identity does not match the supplied identity.
    SkillIdentityMismatch,
    /// The package runtime lock identity does not match the supplied lock.
    RuntimeIdentityMismatch,
    /// The package scope reference is invalid.
    InvalidScopeRef,
    /// The package has no evidence entries.
    EmptyEvidence,
    /// The package has too many evidence entries.
    TooManyEvidence,
    /// The package evidence kind is unknown.
    UnknownEvidenceKind,
    /// The package artifact reference is not among supplied opaque artifacts.
    UnknownArtifactRef,
    /// The package run reference is invalid.
    InvalidRunRef,
    /// The package planning stage is unknown.
    UnknownPlanningStage,
    /// The package owner reference is invalid.
    InvalidOwnerRef,
    /// The package has too many review references.
    TooManyReviewRefs,
    /// A package review reference is invalid.
    InvalidReviewRef,
    /// The package exceeds the bounded input size.
    TooLarge,
}

impl fmt::Display for SkillEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidJson => "skill evidence package is invalid",
            Self::UnknownPayloadField => "skill evidence package contains an unsupported field",
            Self::UnsupportedSchemaVersion => "skill evidence package version is unsupported",
            Self::InvalidSkillId => "skill evidence package Skill ID is invalid",
            Self::SkillIdentityMismatch => "skill evidence package Skill identity does not match",
            Self::RuntimeIdentityMismatch => {
                "skill evidence package runtime identity does not match"
            }
            Self::InvalidScopeRef => "skill evidence package scope reference is invalid",
            Self::EmptyEvidence => "skill evidence package has no evidence",
            Self::TooManyEvidence => "skill evidence package has too much evidence",
            Self::UnknownEvidenceKind => "skill evidence package evidence kind is unknown",
            Self::UnknownArtifactRef => "skill evidence package artifact reference is unknown",
            Self::InvalidRunRef => "skill evidence package run reference is invalid",
            Self::UnknownPlanningStage => "skill evidence package planning stage is unknown",
            Self::InvalidOwnerRef => "skill evidence package owner reference is invalid",
            Self::TooManyReviewRefs => "skill evidence package has too many review references",
            Self::InvalidReviewRef => "skill evidence package review reference is invalid",
            Self::TooLarge => "skill evidence package is too large",
        })
    }
}

impl std::error::Error for SkillEvidenceError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackage {
    schema_version: u16,
    skill: RawSkill,
    runtime: RawRuntime,
    scope_ref: Option<String>,
    evidence: Option<Vec<RawEvidence>>,
    promotion: RawPromotion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSkill {
    id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntime {
    skill_markdown_sha256: String,
    runtime_manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    kind: String,
    artifact_ref: String,
    run_ref: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPromotion {
    stage: String,
    owner_ref: String,
    review_refs: Vec<String>,
}

fn is_valid_opaque_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REF_BYTES
        && value != "global"
        && value != "default"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
}

fn map_json_error(error: serde_json::Error) -> SkillEvidenceError {
    if error.to_string().starts_with("unknown field") {
        SkillEvidenceError::UnknownPayloadField
    } else {
        SkillEvidenceError::InvalidJson
    }
}

fn parse_kind(raw: &str) -> Result<SkillEvidenceKind, SkillEvidenceError> {
    match raw {
        "successful_run" => Ok(SkillEvidenceKind::SuccessfulRun),
        "failed_run" => Ok(SkillEvidenceKind::FailedRun),
        "correction" => Ok(SkillEvidenceKind::Correction),
        "accepted_output" => Ok(SkillEvidenceKind::AcceptedOutput),
        "rejected_output" => Ok(SkillEvidenceKind::RejectedOutput),
        _ => Err(SkillEvidenceError::UnknownEvidenceKind),
    }
}

fn parse_stage(raw: &str) -> Result<SkillPlanningStage, SkillEvidenceError> {
    match raw {
        "personal" => Ok(SkillPlanningStage::Personal),
        "candidate" => Ok(SkillPlanningStage::Candidate),
        "validated" => Ok(SkillPlanningStage::Validated),
        "production" => Ok(SkillPlanningStage::Production),
        "organization-standard" => Ok(SkillPlanningStage::OrganizationStandard),
        "retired" => Ok(SkillPlanningStage::Retired),
        _ => Err(SkillEvidenceError::UnknownPlanningStage),
    }
}
