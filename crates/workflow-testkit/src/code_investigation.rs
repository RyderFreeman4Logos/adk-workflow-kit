//! A bounded, offline, read-only code-investigation dogfood workflow.
//!
//! The public surface contains project-owned data only. ADK values are used only
//! inside the deterministic fake-model and graph exercise helpers.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Component, Path},
    sync::Arc,
};

use adk_rust::{
    Agent, AgentCapabilities, Content, Event, EventStream, InvocationContext, Llm, LlmRequest,
    LlmResponse, Part, async_trait, futures::StreamExt, tokio::sync::Mutex,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_adk::model_profiles::{
    CredentialBroker, CredentialHandle, ModelProfileRegistry, OpenAiCompatibleProfile,
};
use workflow_compiler::{
    PredicateRegistry, RegistryCategory, RegistryEntry, RegistryNotFound, SkillManifest,
    compile_str_with_predicates,
};
use workflow_review::ReviewVerdict;

const ARTIFACT_PAGE_BYTES: usize = 256;
const FIXTURE_WORKFLOW: &str = include_str!("../tests/fixtures/code_investigation/workflow.toml");
const FIXTURE_RETRY: &str = include_str!("../tests/fixtures/code_investigation/repo/src/retry.rs");
const FIXTURE_LIB: &str = include_str!("../tests/fixtures/code_investigation/repo/src/lib.rs");

/// The published ADK version exercised by this dogfood.
pub const ADK_RUST_VERSION: &str = "2.1.0";
/// The schema version of an investigation answer artifact.
pub const ANSWER_SCHEMA_VERSION: u8 = 1;

/// The only tools available to investigators and reviewers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ReadOnlyTool {
    /// Lexical or regular-expression source search.
    SearchCode,
    /// Reads an inclusive line range from a source file.
    ReadSourceRange,
    /// Lists entries below a logical directory.
    ListDirectory,
    /// Finds a symbol declaration using lexical inspection.
    InspectSymbol,
    /// Reads a bounded page from a retained artifact.
    ReadArtifact,
    /// Validates and closes an investigation answer.
    FinishInvestigation,
    /// Validates and closes a reviewer answer.
    FinishReview,
}

impl ReadOnlyTool {
    /// Returns every permitted tool in stable order.
    pub const fn all() -> [Self; 7] {
        [
            Self::SearchCode,
            Self::ReadSourceRange,
            Self::ListDirectory,
            Self::InspectSymbol,
            Self::ReadArtifact,
            Self::FinishInvestigation,
            Self::FinishReview,
        ]
    }

    /// Returns the wire name used by the fake model.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SearchCode => "search_code",
            Self::ReadSourceRange => "read_source_range",
            Self::ListDirectory => "list_directory",
            Self::InspectSymbol => "inspect_symbol",
            Self::ReadArtifact => "read_artifact",
            Self::FinishInvestigation => "finish_investigation",
            Self::FinishReview => "finish_review",
        }
    }
}

/// Stable, closed diagnostic categories. Details are intentionally not retained.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum DiagnosticCode {
    InvalidPath,
    ShellMetacharacter,
    ForbiddenPath,
    SymlinkEscape,
    PathNotFound,
    InvalidQuery,
    InvalidRange,
    EvidenceClaimBinding,
    EvidenceDigestMismatch,
    EvidenceRangeMissing,
    EvidenceSnippetMissing,
    SnapshotMismatch,
    SchemaInvalid,
    IllegalStageTransition,
    CheckpointInvalid,
    ReplayMismatch,
    CoverageExhausted,
    ModelFailed,
    GraphFailed,
    ArtifactFailed,
    LiveDisabled,
    LiveProfileUnavailable,
    ReviewAbstained,
}

impl DiagnosticCode {
    /// Returns the stable diagnostic code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPath => "invalid_path",
            Self::ShellMetacharacter => "shell_metacharacter",
            Self::ForbiddenPath => "forbidden_path",
            Self::SymlinkEscape => "symlink_escape",
            Self::PathNotFound => "path_not_found",
            Self::InvalidQuery => "invalid_query",
            Self::InvalidRange => "invalid_range",
            Self::EvidenceClaimBinding => "evidence_claim_binding",
            Self::EvidenceDigestMismatch => "evidence_digest_mismatch",
            Self::EvidenceRangeMissing => "evidence_range_missing",
            Self::EvidenceSnippetMissing => "evidence_snippet_missing",
            Self::SnapshotMismatch => "snapshot_mismatch",
            Self::SchemaInvalid => "schema_invalid",
            Self::IllegalStageTransition => "illegal_stage_transition",
            Self::CheckpointInvalid => "checkpoint_invalid",
            Self::ReplayMismatch => "replay_mismatch",
            Self::CoverageExhausted => "coverage_exhausted",
            Self::ModelFailed => "model_failed",
            Self::GraphFailed => "graph_failed",
            Self::ArtifactFailed => "artifact_failed",
            Self::LiveDisabled => "live_disabled",
            Self::LiveProfileUnavailable => "live_profile_unavailable",
            Self::ReviewAbstained => "review_abstained",
        }
    }
}

impl fmt::Debug for DiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A privacy-safe investigation failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InvestigationError {
    code: DiagnosticCode,
}

impl InvestigationError {
    const fn new(code: DiagnosticCode) -> Self {
        Self { code }
    }

    /// Returns the closed diagnostic category.
    pub const fn code(self) -> DiagnosticCode {
        self.code
    }

    /// Returns a redaction-safe debug rendering.
    pub fn debug_string(self) -> String {
        format!("{self:?}")
    }

    /// Returns a redaction-safe display rendering.
    pub fn display_string(self) -> String {
        self.to_string()
    }
}

impl fmt::Debug for InvestigationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvestigationError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for InvestigationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "investigation failed ({})", self.code.as_str())
    }
}

impl std::error::Error for InvestigationError {}

/// A source range with a verified content digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceRange {
    path: String,
    start_line: usize,
    end_line: usize,
    snippet: String,
    digest: String,
}

impl SourceRange {
    /// Returns the logical source path.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns the inclusive first line.
    pub const fn start_line(&self) -> usize {
        self.start_line
    }
    /// Returns the inclusive last line.
    pub const fn end_line(&self) -> usize {
        self.end_line
    }
    /// Returns the exact quoted source text.
    pub fn snippet(&self) -> &str {
        &self.snippet
    }
    /// Returns the source-file digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// One lexical source-search hit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodeMatch {
    path: String,
    line: usize,
    snippet: String,
}

impl CodeMatch {
    /// Returns the hit path.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns the one-based hit line.
    pub const fn line(&self) -> usize {
        self.line
    }
    /// Returns the matching source line.
    pub fn snippet(&self) -> &str {
        &self.snippet
    }
}

/// An immutable logical fixture repository.
#[derive(Clone, Debug)]
pub struct FixtureRepo {
    files: BTreeMap<String, String>,
    symlinks: BTreeMap<String, String>,
}

impl FixtureRepo {
    /// Creates the synthetic Rust repository required by M1-14.
    pub fn synthetic() -> Self {
        let mut files = BTreeMap::new();
        files.insert(
            "Cargo.toml".to_owned(),
            include_str!("../tests/fixtures/code_investigation/repo/Cargo.toml").to_owned(),
        );
        files.insert("src/lib.rs".to_owned(), FIXTURE_LIB.to_owned());
        files.insert("src/retry.rs".to_owned(), FIXTURE_RETRY.to_owned());
        Self {
            files,
            symlinks: BTreeMap::new(),
        }
    }

    /// Creates the checked-in kit repository snapshot for live dogfood.
    fn kit_repo() -> Self {
        Self::from_files([
            (
                "Cargo.toml".to_owned(),
                include_str!("../../../Cargo.toml").to_owned(),
            ),
            (
                "crates/workflow-testkit/src/code_investigation.rs".to_owned(),
                include_str!("code_investigation.rs").to_owned(),
            ),
        ])
    }

    /// Creates a repository from logical files for containment tests.
    pub fn from_files(files: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            files: files.into_iter().collect(),
            symlinks: BTreeMap::new(),
        }
    }

    /// Adds a logical symlink without touching the host filesystem.
    pub fn with_symlink(mut self, path: impl Into<String>, target: impl Into<String>) -> Self {
        self.symlinks.insert(path.into(), target.into());
        self
    }

    /// Returns the checked-in illustrative workflow source.
    pub fn workflow_toml(&self) -> &'static str {
        FIXTURE_WORKFLOW
    }

    /// Builds the immutable snapshot used by evidence validation.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot::from_parts(self.files.clone(), self.symlinks.clone())
    }

    /// Searches source files without shell or network access.
    pub fn search_code(
        &self,
        query: &str,
        path: Option<&str>,
    ) -> Result<Vec<CodeMatch>, InvestigationError> {
        self.snapshot().search_code(query, path)
    }

    /// Reads an inclusive source range after containment checks.
    pub fn read_source_range(
        &self,
        path: &str,
        start_line: usize,
        end_line: usize,
    ) -> Result<SourceRange, InvestigationError> {
        self.snapshot()
            .read_source_range(path, start_line, end_line)
    }

    /// Lists immediate logical entries below a checked directory.
    pub fn list_directory(&self, path: &str) -> Result<Vec<String>, InvestigationError> {
        self.snapshot().list_directory(path)
    }
}

/// Immutable snapshot identity and source content used to ground claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    id: String,
    files: BTreeMap<String, String>,
    symlinks: BTreeMap<String, String>,
    digests: BTreeMap<String, String>,
}

impl Snapshot {
    fn from_parts(files: BTreeMap<String, String>, symlinks: BTreeMap<String, String>) -> Self {
        let digests = files
            .iter()
            .map(|(path, source)| (path.clone(), digest(source.as_bytes())))
            .collect::<BTreeMap<_, _>>();
        let mut hasher = Sha256::new();
        for (path, source) in &files {
            hasher.update(path.as_bytes());
            hasher.update([0]);
            hasher.update(source.as_bytes());
            hasher.update([0]);
        }
        let id = format!("sha256:{:x}", hasher.finalize());
        Self {
            id,
            files,
            symlinks,
            digests,
        }
    }

    /// Returns the snapshot content identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns a file's verified digest.
    pub fn digest_for(&self, path: &str) -> Option<&str> {
        self.digests.get(path).map(String::as_str)
    }

    /// Returns the source for a safe logical path.
    pub fn source(&self, path: &str) -> Result<&str, InvestigationError> {
        let resolved = self.resolve(path)?;
        self.files
            .get(&resolved)
            .map(String::as_str)
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::PathNotFound))
    }

    /// Searches all or one logical directory using a bounded lexical scan.
    pub fn search_code(
        &self,
        query: &str,
        path: Option<&str>,
    ) -> Result<Vec<CodeMatch>, InvestigationError> {
        if query.trim().is_empty() {
            return Err(InvestigationError::new(DiagnosticCode::InvalidQuery));
        }
        let prefix = path.map(validate_path).transpose()?;
        let query = query.to_ascii_lowercase();
        let mut matches = Vec::new();
        for (file, source) in &self.files {
            if prefix
                .as_deref()
                .is_some_and(|prefix| file != prefix && !file.starts_with(&format!("{prefix}/")))
            {
                continue;
            }
            for (index, line) in source.lines().enumerate() {
                if line.to_ascii_lowercase().contains(&query) {
                    matches.push(CodeMatch {
                        path: file.clone(),
                        line: index + 1,
                        snippet: line.to_owned(),
                    });
                }
            }
        }
        let preferred_path = format!("{query}.rs");
        matches.sort_by_key(|hit| {
            (
                !hit.path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name == preferred_path),
                hit.path.clone(),
                hit.line,
            )
        });
        Ok(matches)
    }

    /// Reads an inclusive source range and binds its exact file digest.
    pub fn read_source_range(
        &self,
        path: &str,
        start_line: usize,
        end_line: usize,
    ) -> Result<SourceRange, InvestigationError> {
        if start_line == 0 || end_line < start_line {
            return Err(InvestigationError::new(DiagnosticCode::InvalidRange));
        }
        let resolved = self.resolve(path)?;
        let source = self
            .files
            .get(&resolved)
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::PathNotFound))?;
        let lines = source.lines().collect::<Vec<_>>();
        if end_line > lines.len() {
            return Err(InvestigationError::new(DiagnosticCode::InvalidRange));
        }
        Ok(SourceRange {
            path: path.to_owned(),
            start_line,
            end_line,
            snippet: lines[start_line - 1..end_line].join("\n"),
            digest: self
                .digests
                .get(&resolved)
                .cloned()
                .ok_or_else(|| InvestigationError::new(DiagnosticCode::PathNotFound))?,
        })
    }

    /// Lists immediate descendants, never host filesystem entries.
    pub fn list_directory(&self, path: &str) -> Result<Vec<String>, InvestigationError> {
        let path = validate_path(path)?;
        let prefix = if path == "." {
            String::new()
        } else {
            format!("{path}/")
        };
        let mut entries = self
            .files
            .keys()
            .chain(self.symlinks.keys())
            .filter_map(|candidate| {
                let remainder = candidate.strip_prefix(&prefix)?;
                (!remainder.is_empty())
                    .then_some(remainder.split('/').next().unwrap_or(remainder).to_owned())
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries.dedup();
        Ok(entries)
    }

    fn resolve(&self, path: &str) -> Result<String, InvestigationError> {
        validate_path(path)?;
        let mut current = path.to_owned();
        for _ in 0..8 {
            let Some(target) = self.symlinks.get(&current) else {
                return Ok(current);
            };
            validate_path(target).map_err(|error| {
                if error.code() == DiagnosticCode::InvalidPath {
                    InvestigationError::new(DiagnosticCode::SymlinkEscape)
                } else {
                    error
                }
            })?;
            current = target.clone();
        }
        Err(InvestigationError::new(DiagnosticCode::SymlinkEscape))
    }
}

/// Read-only tool facade shared by investigator and reviewer stages.
pub struct ReadOnlyTools<'a> {
    snapshot: &'a Snapshot,
}

impl<'a> ReadOnlyTools<'a> {
    /// Binds the tool facade to one immutable snapshot.
    pub fn new(snapshot: &'a Snapshot) -> Self {
        Self { snapshot }
    }

    /// Returns the fixed first-party tool set.
    pub const fn available() -> [ReadOnlyTool; 7] {
        ReadOnlyTool::all()
    }

    /// Runs `search_code`.
    pub fn search_code(
        &self,
        query: &str,
        path: Option<&str>,
    ) -> Result<Vec<CodeMatch>, InvestigationError> {
        self.snapshot.search_code(query, path)
    }

    /// Runs `read_source_range`.
    pub fn read_source_range(
        &self,
        path: &str,
        start_line: usize,
        end_line: usize,
    ) -> Result<SourceRange, InvestigationError> {
        self.snapshot.read_source_range(path, start_line, end_line)
    }

    /// Runs `list_directory`.
    pub fn list_directory(&self, path: &str) -> Result<Vec<String>, InvestigationError> {
        self.snapshot.list_directory(path)
    }

    /// Runs `inspect_symbol` as a lexical declaration search.
    pub fn inspect_symbol(
        &self,
        symbol: &str,
        path: Option<&str>,
    ) -> Result<Vec<CodeMatch>, InvestigationError> {
        self.snapshot.search_code(&format!("fn {symbol}"), path)
    }
}

/// Validates a logical path before any source or artifact lookup.
pub fn validate_path(path: &str) -> Result<String, InvestigationError> {
    if path.is_empty() || Path::new(path).is_absolute() || path.starts_with('\\') {
        return Err(InvestigationError::new(DiagnosticCode::InvalidPath));
    }
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return Err(InvestigationError::new(DiagnosticCode::InvalidPath));
    }
    if path
        .chars()
        .any(|character| ";&|$><`!{}[]()".contains(character))
    {
        return Err(InvestigationError::new(DiagnosticCode::ShellMetacharacter));
    }
    if path.split(['/', '\\']).any(|part| part == "..") {
        return Err(InvestigationError::new(DiagnosticCode::InvalidPath));
    }
    let forbidden = [
        ".git",
        ".hg",
        ".svn",
        ".hermes",
        "target",
        "node_modules",
        "secrets",
        ".env",
    ];
    if path
        .split(['/', '\\'])
        .any(|part| forbidden.contains(&part))
    {
        return Err(InvestigationError::new(DiagnosticCode::ForbiddenPath));
    }
    if Path::new(path)
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        return Err(InvestigationError::new(DiagnosticCode::InvalidPath));
    }
    Ok(path.to_owned())
}

/// A claim whose evidence must be bound to the same semantic claim ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    id: String,
    text: String,
    evidence: Vec<Evidence>,
}

impl Claim {
    /// Creates a claim with no evidence; finalization will reject it.
    pub fn new(id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            text: text.into(),
            evidence: Vec::new(),
        }
    }
    /// Returns the semantic claim ID.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the claim text.
    pub fn text(&self) -> &str {
        &self.text
    }
    /// Returns all bound evidence references.
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }
    /// Returns mutable evidence for negative validation tests.
    pub fn evidence_mut(&mut self) -> &mut Vec<Evidence> {
        &mut self.evidence
    }
    fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
}

/// One claim-to-source binding retained in the answer artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    claim_id: String,
    path: String,
    start_line: usize,
    end_line: usize,
    digest: String,
    snippet: String,
}

impl Evidence {
    /// Creates an evidence reference from a verified source range.
    pub fn from_range(claim_id: impl Into<String>, range: &SourceRange) -> Self {
        Self {
            claim_id: claim_id.into(),
            path: range.path.clone(),
            start_line: range.start_line,
            end_line: range.end_line,
            digest: range.digest.clone(),
            snippet: range.snippet.clone(),
        }
    }
    /// Returns the semantic claim ID bound by this reference.
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }
    /// Returns the logical source path.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns the inclusive first line.
    pub const fn start_line(&self) -> usize {
        self.start_line
    }
    /// Returns the inclusive last line.
    pub const fn end_line(&self) -> usize {
        self.end_line
    }
    /// Returns the claimed source-file digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// Returns the quoted source snippet.
    pub fn snippet(&self) -> &str {
        &self.snippet
    }
    /// Mutates only the semantic claim ID for fail-closed contract tests.
    pub fn set_claim_id(&mut self, claim_id: impl Into<String>) {
        self.claim_id = claim_id.into();
    }
    /// Mutates only the digest for fail-closed contract tests.
    pub fn set_digest(&mut self, digest: impl Into<String>) {
        self.digest = digest.into();
    }
}

/// The structured answer artifact emitted by `finish_investigation`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationAnswer {
    schema_version: u8,
    snapshot_id: String,
    claims: Vec<Claim>,
}

impl InvestigationAnswer {
    fn empty(snapshot_id: &str) -> Self {
        Self {
            schema_version: ANSWER_SCHEMA_VERSION,
            snapshot_id: snapshot_id.to_owned(),
            claims: Vec::new(),
        }
    }
    /// Returns the answer schema version.
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }
    /// Returns the snapshot identity bound by this answer.
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
    /// Returns all findings.
    pub fn claims(&self) -> &[Claim] {
        &self.claims
    }
    /// Returns mutable findings for fail-closed validation tests.
    pub fn claims_mut(&mut self) -> &mut Vec<Claim> {
        &mut self.claims
    }
}

/// Deterministically validates every answer/evidence binding.
pub fn validate_answer(
    answer: &InvestigationAnswer,
    snapshot: &Snapshot,
) -> Result<(), InvestigationError> {
    if answer.schema_version != ANSWER_SCHEMA_VERSION {
        return Err(InvestigationError::new(DiagnosticCode::SchemaInvalid));
    }
    if answer.snapshot_id != snapshot.id {
        return Err(InvestigationError::new(DiagnosticCode::SnapshotMismatch));
    }
    let mut claim_ids = std::collections::BTreeSet::new();
    for claim in &answer.claims {
        if claim.id.is_empty() || !claim_ids.insert(&claim.id) || claim.evidence.is_empty() {
            return Err(InvestigationError::new(DiagnosticCode::SchemaInvalid));
        }
        for evidence in &claim.evidence {
            if evidence.claim_id != claim.id {
                return Err(InvestigationError::new(
                    DiagnosticCode::EvidenceClaimBinding,
                ));
            }
            let source = snapshot.source(&evidence.path)?;
            if snapshot.digest_for(&evidence.path) != Some(evidence.digest.as_str()) {
                return Err(InvestigationError::new(
                    DiagnosticCode::EvidenceDigestMismatch,
                ));
            }
            let lines = source.lines().collect::<Vec<_>>();
            if evidence.start_line == 0
                || evidence.end_line < evidence.start_line
                || evidence.end_line > lines.len()
            {
                return Err(InvestigationError::new(
                    DiagnosticCode::EvidenceRangeMissing,
                ));
            }
            let expected = lines[evidence.start_line - 1..evidence.end_line].join("\n");
            if expected != evidence.snippet {
                return Err(InvestigationError::new(
                    DiagnosticCode::EvidenceSnippetMissing,
                ));
            }
        }
    }
    Ok(())
}

/// Finalizes an investigation only after deterministic grounding validation.
pub fn finish_investigation(
    answer: InvestigationAnswer,
    snapshot: &Snapshot,
) -> Result<InvestigationAnswer, InvestigationError> {
    validate_answer(&answer, snapshot)?;
    Ok(answer)
}

/// Finalizes a reviewer result through the same read-only validator.
pub fn finish_review(
    answer: InvestigationAnswer,
    snapshot: &Snapshot,
) -> Result<InvestigationAnswer, InvestigationError> {
    finish_review_with_verdict(answer, snapshot, ReviewVerdict::Pass)
}

fn finish_review_with_verdict(
    answer: InvestigationAnswer,
    snapshot: &Snapshot,
    verdict: ReviewVerdict,
) -> Result<InvestigationAnswer, InvestigationError> {
    if !matches!(verdict, ReviewVerdict::Pass) {
        return Err(InvestigationError::new(DiagnosticCode::ReviewAbstained));
    }
    validate_answer(&answer, snapshot)?;
    Ok(answer)
}

/// Public workflow stages; transitions are enforced by `InvestigationSession`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum InvestigationStage {
    PrepareWorkspace,
    Planner,
    SearchCode,
    InspectEvidence,
    CoverageDecision,
    Draft,
    GroundingValidation,
    Review,
    Revise,
    Publish,
    Abstain,
}

impl InvestigationStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PrepareWorkspace => "prepare_workspace",
            Self::Planner => "planner",
            Self::SearchCode => "search_code",
            Self::InspectEvidence => "inspect_evidence",
            Self::CoverageDecision => "coverage_decision",
            Self::Draft => "draft",
            Self::GroundingValidation => "grounding_validation",
            Self::Review => "review",
            Self::Revise => "revise",
            Self::Publish => "publish",
            Self::Abstain => "abstain",
        }
    }
}

/// A public stage cursor that rejects illegal graph jumps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationSession {
    current: InvestigationStage,
}

impl InvestigationSession {
    fn new() -> Self {
        Self {
            current: InvestigationStage::PrepareWorkspace,
        }
    }

    /// Returns the current stage.
    pub const fn current(&self) -> InvestigationStage {
        self.current
    }

    /// Advances only along the bounded workflow graph.
    pub fn advance(&mut self, next: InvestigationStage) -> Result<(), InvestigationError> {
        let allowed = match self.current {
            InvestigationStage::PrepareWorkspace => next == InvestigationStage::Planner,
            InvestigationStage::Planner => next == InvestigationStage::SearchCode,
            InvestigationStage::SearchCode => next == InvestigationStage::InspectEvidence,
            InvestigationStage::InspectEvidence => next == InvestigationStage::CoverageDecision,
            InvestigationStage::CoverageDecision => matches!(
                next,
                InvestigationStage::SearchCode
                    | InvestigationStage::Draft
                    | InvestigationStage::Abstain
            ),
            InvestigationStage::Draft => {
                matches!(
                    next,
                    InvestigationStage::GroundingValidation | InvestigationStage::Abstain
                )
            }
            InvestigationStage::GroundingValidation => {
                matches!(
                    next,
                    InvestigationStage::Review | InvestigationStage::Abstain
                )
            }
            InvestigationStage::Review => {
                matches!(
                    next,
                    InvestigationStage::Revise
                        | InvestigationStage::Publish
                        | InvestigationStage::Abstain
                )
            }
            InvestigationStage::Revise => {
                matches!(
                    next,
                    InvestigationStage::GroundingValidation
                        | InvestigationStage::Review
                        | InvestigationStage::Publish
                )
            }
            InvestigationStage::Publish | InvestigationStage::Abstain => false,
        };
        if allowed {
            self.current = next;
            Ok(())
        } else {
            Err(InvestigationError::new(
                DiagnosticCode::IllegalStageTransition,
            ))
        }
    }
}

/// One model-selected read-only tool call in the project-owned trace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    tool: ReadOnlyTool,
    route: String,
    query: String,
    path: Option<String>,
}

impl ToolCall {
    /// Returns the selected first-party tool.
    pub const fn tool(&self) -> ReadOnlyTool {
        self.tool
    }
    /// Returns the stage route that admitted the call.
    pub fn route(&self) -> &str {
        &self.route
    }
    /// Returns the model-selected search query actually passed to the tool.
    pub fn query(&self) -> &str {
        &self.query
    }
    /// Returns the model-selected optional search path actually passed to the tool.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

/// One result retained in graph state for a read-only tool call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    tool: ReadOnlyTool,
    route: String,
    output: Value,
}

impl ToolResult {
    /// Returns the tool that produced this result.
    pub const fn tool(&self) -> ReadOnlyTool {
        self.tool
    }
    /// Returns the route that admitted this result.
    pub fn route(&self) -> &str {
        &self.route
    }
    /// Returns the structured tool output.
    pub const fn output(&self) -> &Value {
        &self.output
    }
}

/// A deterministic structural trace suitable for replay validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InvestigationTrace {
    stages: Vec<String>,
    routes: Vec<String>,
    tool_calls: Vec<ToolCall>,
    tool_results: Vec<ToolResult>,
    llm_requests: usize,
    adk_graph_exercised: bool,
    adk_terminal: Option<String>,
}

impl InvestigationTrace {
    /// Returns the project-owned stage trace.
    pub fn stages(&self) -> &[String] {
        &self.stages
    }
    /// Returns all conditional route labels.
    pub fn routes(&self) -> &[String] {
        &self.routes
    }
    /// Returns model-selected tool calls.
    pub fn tool_calls(&self) -> &[ToolCall] {
        &self.tool_calls
    }
    /// Returns tool results retained in graph state.
    pub fn tool_results(&self) -> &[ToolResult] {
        &self.tool_results
    }
    /// Returns the number of fake-model LLM requests.
    pub const fn llm_requests(&self) -> usize {
        self.llm_requests
    }
    /// Returns whether a real ADK `GraphAgent` was translated and invoked.
    pub const fn adk_graph_exercised(&self) -> bool {
        self.adk_graph_exercised
    }
    /// Returns the terminal node reached by the compiled ADK graph.
    pub fn adk_terminal(&self) -> Option<&str> {
        self.adk_terminal.as_deref()
    }

    fn digest(&self) -> String {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        digest(&encoded)
    }
}

/// A durable, payload-free checkpoint for fresh-process resume.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationCheckpoint {
    snapshot_id: String,
    step: usize,
    state_digest: String,
}

impl InvestigationCheckpoint {
    /// Returns the source snapshot identity.
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
    /// Returns the bounded checkpoint step.
    pub const fn step(&self) -> usize {
        self.step
    }
}

/// Terminal result for a fake investigation or a resumed investigation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationResult {
    status: InvestigationStatus,
    answer: InvestigationAnswer,
    snapshot: Snapshot,
    trace: InvestigationTrace,
    checkpoint: Option<InvestigationCheckpoint>,
    artifact: String,
    replay_digest: String,
}

impl InvestigationResult {
    /// Returns the terminal status.
    pub const fn status(&self) -> InvestigationStatus {
        self.status
    }
    /// Returns the structured answer.
    pub fn answer(&self) -> &InvestigationAnswer {
        &self.answer
    }
    /// Returns the bound source snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    /// Returns the structural trace.
    pub fn trace(&self) -> &InvestigationTrace {
        &self.trace
    }
    /// Returns the durable checkpoint, when execution was interrupted.
    pub fn checkpoint(&self) -> Option<&InvestigationCheckpoint> {
        self.checkpoint.as_ref()
    }
    /// Reads one bounded retained artifact page.
    pub fn inspect_artifact(&self, page: usize) -> Result<String, InvestigationError> {
        let bytes = self.artifact.as_bytes();
        let start = page
            .checked_mul(ARTIFACT_PAGE_BYTES)
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::ArtifactFailed))?;
        if start >= bytes.len() {
            return Err(InvestigationError::new(DiagnosticCode::ArtifactFailed));
        }
        let end = (start + ARTIFACT_PAGE_BYTES).min(bytes.len());
        String::from_utf8(bytes[start..end].to_vec())
            .map_err(|_| InvestigationError::new(DiagnosticCode::ArtifactFailed))
    }
    /// Validates the structural replay digest without rerunning untrusted code.
    pub fn replay_validate(&self) -> Result<(), InvestigationError> {
        (self.trace.digest() == self.replay_digest)
            .then_some(())
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::ReplayMismatch))
    }
}

/// Closed terminal statuses exposed by the dogfood.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvestigationStatus {
    Published,
    Killed,
    Abstained,
}

/// The fixture-owned Skill, prompt, and schema resources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixturePackage {
    skill_id: String,
    resource_count: usize,
}

impl FixturePackage {
    fn load() -> Result<Self, InvestigationError> {
        let plan = compile_str_with_predicates(
            "code-investigation.workflow.toml",
            FIXTURE_WORKFLOW,
            &PredicateFixture,
        )
        .map_err(|_| InvestigationError::new(DiagnosticCode::SchemaInvalid))?;
        let resources = [
            (
                "skills/code-investigation/SKILL.md",
                include_bytes!(
                    "../tests/fixtures/code_investigation/skills/code-investigation/SKILL.md"
                )
                .as_slice(),
                "sha256:c4adb08d04aa18d9f870310301d4782a5ea2c5344d024fd4136bab5ffb4fc189",
            ),
            (
                "prompts/planner.md",
                include_bytes!("../tests/fixtures/code_investigation/prompts/planner.md")
                    .as_slice(),
                "sha256:88514865356dc67787a99259300895827f21cbaab0c7b42f0add7fef3d2ec325",
            ),
            (
                "prompts/reviewer.md",
                include_bytes!("../tests/fixtures/code_investigation/prompts/reviewer.md")
                    .as_slice(),
                "sha256:632f3f0af5d7c5454696e9bac01f9e2849bbd99b7cf44ca316bcde284c93bce7",
            ),
            (
                "prompts/reviser.md",
                include_bytes!("../tests/fixtures/code_investigation/prompts/reviser.md")
                    .as_slice(),
                "sha256:0493c534da1c066f01d23e87a3426f0ec2184e80ae5f7e25e2b16db6c9a72142",
            ),
            (
                "schemas/investigation-input.json",
                include_bytes!(
                    "../tests/fixtures/code_investigation/schemas/investigation-input.json"
                )
                .as_slice(),
                "sha256:079e99957548044be0471e22c626114585d9edc01991cc178175145ab745b397",
            ),
            (
                "schemas/investigation-output.json",
                include_bytes!(
                    "../tests/fixtures/code_investigation/schemas/investigation-output.json"
                )
                .as_slice(),
                "sha256:373e0b3773fc555083922d63e745efd1c22822680ce0a111ced8c6a80828f764",
            ),
        ];
        let declared = plan.ir().resources();
        if declared.len() != resources.len()
            || resources.iter().any(|(path, _, expected_digest)| {
                !declared.iter().any(|resource| {
                    resource.path() == *path && resource.sha256() == *expected_digest
                })
            })
        {
            return Err(InvestigationError::new(DiagnosticCode::SchemaInvalid));
        }
        for (path, bytes, expected_digest) in resources {
            if digest(bytes) != expected_digest {
                return Err(InvestigationError::new(DiagnosticCode::SchemaInvalid));
            }
            if path.ends_with(".json")
                && !serde_json::from_slice::<serde_json::Value>(bytes)
                    .is_ok_and(|value| value.is_object())
            {
                return Err(InvestigationError::new(DiagnosticCode::SchemaInvalid));
            }
        }
        SkillManifest::parse(
            Path::new("code-investigation"),
            include_bytes!(
                "../tests/fixtures/code_investigation/skills/code-investigation/SKILL.md"
            ),
        )
        .map_err(|_| InvestigationError::new(DiagnosticCode::SchemaInvalid))?;
        Ok(Self {
            skill_id: "code-investigation".to_owned(),
            resource_count: resources.len(),
        })
    }

    /// Returns the validated Skill identifier.
    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }

    /// Returns the number of digest-checked package resources.
    pub const fn resource_count(&self) -> usize {
        self.resource_count
    }
}

/// The production-shaped offline investigation harness.
#[derive(Clone, Debug)]
pub struct SyntheticInvestigation {
    repo: FixtureRepo,
}

impl SyntheticInvestigation {
    /// Loads and verifies the fixture Skill package.
    pub fn fixture_package() -> Result<FixturePackage, InvestigationError> {
        FixturePackage::load()
    }

    /// Creates a bounded investigation over one immutable logical repository.
    pub fn new(repo: FixtureRepo) -> Self {
        Self { repo }
    }

    /// Creates a fresh public stage cursor.
    pub fn session(&self) -> InvestigationSession {
        InvestigationSession::new()
    }

    /// Runs the deterministic fake-model GREEN path.
    pub async fn run_fake(&self) -> Result<InvestigationResult, InvestigationError> {
        self.run_fake_with_review(ReviewVerdict::Pass).await
    }

    /// Runs the fake model with one structured reviewer verdict for route coverage.
    pub async fn run_fake_with_review(
        &self,
        requested_verdict: ReviewVerdict,
    ) -> Result<InvestigationResult, InvestigationError> {
        let _package = Self::fixture_package()?;
        let predicate_registry = PredicateFixture;
        let plan = compile_str_with_predicates(
            "fixtures/code_investigation/workflow.toml",
            FIXTURE_WORKFLOW,
            &predicate_registry,
        )
        .map_err(|_| InvestigationError::new(DiagnosticCode::SchemaInvalid))?;
        let _canonical_ir_hash = plan.ir().canonical_hash();

        let graph =
            run_investigation_graph(self.clone(), requested_verdict, None, None, None).await?;
        let status = match graph.terminal.as_str() {
            "publish" => InvestigationStatus::Published,
            "abstain" => InvestigationStatus::Abstained,
            _ => return Err(InvestigationError::new(DiagnosticCode::GraphFailed)),
        };
        let answer = graph
            .answer
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::GraphFailed))?;
        let artifact = serde_json::to_string(&answer)
            .map_err(|_| InvestigationError::new(DiagnosticCode::ArtifactFailed))?;
        let trace = InvestigationTrace {
            stages: graph.stages,
            routes: graph.routes,
            tool_calls: graph.calls,
            tool_results: graph.tool_results,
            llm_requests: 1,
            adk_graph_exercised: true,
            adk_terminal: Some(graph.terminal),
        };
        let replay_digest = trace.digest();
        Ok(InvestigationResult {
            status,
            answer,
            snapshot: graph.snapshot,
            trace,
            checkpoint: None,
            artifact,
            replay_digest,
        })
    }

    /// Stops after a bounded real trace prefix and writes its checkpoint.
    pub async fn run_until_kill(
        &self,
        step: usize,
    ) -> Result<InvestigationResult, InvestigationError> {
        if step == 0 {
            return Err(InvestigationError::new(DiagnosticCode::CheckpointInvalid));
        }
        let _package = Self::fixture_package()?;
        let graph =
            run_investigation_graph(self.clone(), ReviewVerdict::Pass, None, None, Some(step))
                .await?;
        let trace = graph
            .captured_trace
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::CheckpointInvalid))?;
        killed_from_trace(graph.snapshot, trace, step)
    }

    /// Resumes from a checkpoint as a fresh, stateless process would.
    pub async fn resume(
        &self,
        checkpoint: &InvestigationCheckpoint,
    ) -> Result<InvestigationResult, InvestigationError> {
        let expected = self.run_until_kill(checkpoint.step).await?;
        if expected.checkpoint.as_ref() != Some(checkpoint) {
            return Err(InvestigationError::new(DiagnosticCode::CheckpointInvalid));
        }
        let graph = run_investigation_graph(
            self.clone(),
            ReviewVerdict::Pass,
            Some(checkpoint.step),
            Some(&expected.trace),
            None,
        )
        .await?;
        let answer = graph
            .answer
            .clone()
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::GraphFailed))?;
        let status = match graph.terminal.as_str() {
            "publish" => InvestigationStatus::Published,
            "abstain" => InvestigationStatus::Abstained,
            _ => return Err(InvestigationError::new(DiagnosticCode::GraphFailed)),
        };
        let artifact = serde_json::to_string(&answer)
            .map_err(|_| InvestigationError::new(DiagnosticCode::ArtifactFailed))?;
        let trace = InvestigationTrace {
            stages: graph.stages,
            routes: graph.routes,
            tool_calls: graph.calls,
            tool_results: graph.tool_results,
            llm_requests: 1,
            adk_graph_exercised: true,
            adk_terminal: Some(graph.terminal),
        };
        let replay_digest = trace.digest();
        Ok(InvestigationResult {
            status,
            answer,
            snapshot: graph.snapshot,
            trace,
            checkpoint: None,
            artifact,
            replay_digest,
        })
    }

    fn expected_answer(
        &self,
        tools: &ReadOnlyTools<'_>,
    ) -> Result<InvestigationAnswer, InvestigationError> {
        let snapshot = tools.snapshot;
        let claims = [
            (
                "finding-default-retry",
                "The default path retries transient failures.",
                "default_retry",
            ),
            (
                "finding-bypass",
                "The explicit bypass path skips retry.",
                "bypass_retry",
            ),
            (
                "finding-feature-bypass",
                "The feature-gated bypass is not enabled by default.",
                "feature_gated_bypass",
            ),
            (
                "finding-misleading-name",
                "The misleading name is not a retry implementation.",
                "misleading_retry_name",
            ),
            (
                "finding-dead-code",
                "Dead code is retained as an uncalled helper.",
                "dead_code",
            ),
            (
                "finding-test-helper",
                "The test-only helper is scoped to tests.",
                "test_only_helper",
            ),
        ]
        .into_iter()
        .map(|(id, text, needle)| {
            let hit = tools
                .search_code(needle, Some("src"))?
                .into_iter()
                .next()
                .ok_or_else(|| InvestigationError::new(DiagnosticCode::PathNotFound))?;
            let range = tools.read_source_range(&hit.path, hit.line, hit.line)?;
            Ok(Claim::new(id, text).with_evidence(Evidence::from_range(id, &range)))
        })
        .collect::<Result<Vec<_>, InvestigationError>>()?;
        Ok(InvestigationAnswer {
            schema_version: ANSWER_SCHEMA_VERSION,
            snapshot_id: snapshot.id.clone(),
            claims,
        })
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn checkpoint_for(
    snapshot: &Snapshot,
    trace: &InvestigationTrace,
    step: usize,
) -> InvestigationCheckpoint {
    InvestigationCheckpoint {
        snapshot_id: snapshot.id.clone(),
        step,
        state_digest: digest(format!("{}:{step}:{}", snapshot.id, trace.digest()).as_bytes()),
    }
}

fn strict_trace_prefix(prefix: &InvestigationTrace, completed: &InvestigationTrace) -> bool {
    fn strict_prefix<T: PartialEq>(prefix: &[T], completed: &[T]) -> bool {
        prefix.len() < completed.len() && completed.starts_with(prefix)
    }

    strict_prefix(&prefix.stages, &completed.stages)
        && strict_prefix(&prefix.routes, &completed.routes)
        && strict_prefix(&prefix.tool_calls, &completed.tool_calls)
        && strict_prefix(&prefix.tool_results, &completed.tool_results)
}

fn killed_from_trace(
    snapshot: Snapshot,
    trace: InvestigationTrace,
    step: usize,
) -> Result<InvestigationResult, InvestigationError> {
    let checkpoint = checkpoint_for(&snapshot, &trace, step);
    let artifact = serde_json::to_string(&trace)
        .map_err(|_| InvestigationError::new(DiagnosticCode::ArtifactFailed))?;
    let replay_digest = trace.digest();
    Ok(InvestigationResult {
        status: InvestigationStatus::Killed,
        answer: InvestigationAnswer::empty(&snapshot.id),
        snapshot,
        trace,
        checkpoint: Some(checkpoint),
        artifact,
        replay_digest,
    })
}

struct ModelToolCall {
    tool: ReadOnlyTool,
    query: String,
    path: Option<String>,
}

async fn fake_model_tool(query: &str, path: Option<&str>) -> Option<ModelToolCall> {
    let query = query.to_owned();
    let path = path.map(ToOwned::to_owned);
    let model = crate::ScriptedLlm::new(vec![crate::ScriptStep::new(
        move |request| {
            (request.model == "code-investigation-fake")
                .then_some(())
                .ok_or_else(|| "unexpected fake model request".to_owned())
        },
        LlmResponse::new(Content {
            role: "model".to_owned(),
            parts: vec![Part::FunctionCall {
                name: ReadOnlyTool::SearchCode.as_str().to_owned(),
                args: json!({"query": query, "path": path}),
                id: Some("search-1".to_owned()),
                thought_signature: None,
            }],
        }),
    )]);
    let mut stream = model
        .generate_content(
            LlmRequest::new("code-investigation-fake", Vec::new()),
            false,
        )
        .await
        .ok()?;
    let response = stream.next().await?.ok()?;
    response
        .content?
        .parts
        .into_iter()
        .find_map(|part| match part {
            Part::FunctionCall { name, args, .. } if name == ReadOnlyTool::SearchCode.as_str() => {
                Some(ModelToolCall {
                    tool: ReadOnlyTool::SearchCode,
                    query: args.get("query")?.as_str()?.to_owned(),
                    path: args
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned),
                })
            }
            _ => None,
        })
}

struct GraphExercise {
    terminal: String,
    routes: Vec<String>,
    snapshot: Snapshot,
    answer: Option<InvestigationAnswer>,
    stages: Vec<String>,
    calls: Vec<ToolCall>,
    tool_results: Vec<ToolResult>,
    captured_trace: Option<InvestigationTrace>,
}

struct GraphRun {
    investigation: SyntheticInvestigation,
    requested_verdict: ReviewVerdict,
    snapshot: Snapshot,
    session: InvestigationSession,
    stages: Vec<String>,
    routes: Vec<String>,
    calls: Vec<ToolCall>,
    tool_results: Vec<ToolResult>,
    answer: Option<InvestigationAnswer>,
    error: Option<InvestigationError>,
    prefix: Option<InvestigationTrace>,
    capture_step: Option<usize>,
    captured_trace: Option<InvestigationTrace>,
}

fn restore_session(
    mut session: InvestigationSession,
    prefix: &InvestigationTrace,
    resume_after: Option<usize>,
) -> Result<InvestigationSession, InvestigationError> {
    let step =
        resume_after.ok_or_else(|| InvestigationError::new(DiagnosticCode::CheckpointInvalid))?;
    if step == 0 || step != prefix.stages.len() {
        return Err(InvestigationError::new(DiagnosticCode::CheckpointInvalid));
    }
    for (index, stage_name) in prefix.stages.iter().enumerate() {
        let stage = match stage_name.as_str() {
            "prepare_workspace" => InvestigationStage::PrepareWorkspace,
            "planner" => InvestigationStage::Planner,
            "search_code" => InvestigationStage::SearchCode,
            "inspect_evidence" => InvestigationStage::InspectEvidence,
            "coverage_decision" => InvestigationStage::CoverageDecision,
            "draft" => InvestigationStage::Draft,
            "grounding_validation" => InvestigationStage::GroundingValidation,
            "review" => InvestigationStage::Review,
            "revise" => InvestigationStage::Revise,
            "publish" => InvestigationStage::Publish,
            "abstain" => InvestigationStage::Abstain,
            _ => return Err(InvestigationError::new(DiagnosticCode::CheckpointInvalid)),
        };
        if index == 0 {
            if stage != InvestigationStage::PrepareWorkspace {
                return Err(InvestigationError::new(DiagnosticCode::CheckpointInvalid));
            }
        } else {
            session
                .advance(stage)
                .map_err(|_| InvestigationError::new(DiagnosticCode::CheckpointInvalid))?;
        }
    }
    Ok(session)
}

impl GraphRun {
    fn new(
        investigation: SyntheticInvestigation,
        requested_verdict: ReviewVerdict,
        resume_after: Option<usize>,
        prefix: Option<&InvestigationTrace>,
        capture_step: Option<usize>,
    ) -> Result<Self, InvestigationError> {
        let snapshot = investigation.repo.snapshot();
        let prefix = prefix.cloned();
        let session = prefix.as_ref().map_or_else(
            || Ok(investigation.session()),
            |prefix| restore_session(investigation.session(), prefix, resume_after),
        )?;
        Ok(Self {
            snapshot,
            session,
            investigation,
            requested_verdict,
            stages: Vec::new(),
            routes: Vec::new(),
            calls: Vec::new(),
            tool_results: Vec::new(),
            answer: None,
            error: None,
            prefix,
            capture_step,
            captured_trace: None,
        })
    }

    async fn execute(&mut self, node: &str) -> String {
        if let Some(output) = self.skipped_output(node).map(str::to_owned) {
            if node == "draft" && self.answer.is_none() {
                match self
                    .investigation
                    .expected_answer(&ReadOnlyTools::new(&self.snapshot))
                {
                    Ok(answer) => self.answer = Some(answer),
                    Err(error) => {
                        self.error = Some(error);
                        return self.event(node, "abstain");
                    }
                }
            }
            return self.event(node, &output);
        }
        if self.error.is_some() {
            return self.event(node, "abstain");
        }
        let output = match self.execute_node(node).await {
            Ok(output) => output,
            Err(error) => {
                self.error = Some(error);
                "abstain"
            }
        };
        self.routes.push(match node {
            "coverage_decision" | "retry_coverage_decision" | "grounding_validation" | "review" => {
                format!("{node}:{output}")
            }
            _ => node.to_owned(),
        });
        self.event(node, output)
    }

    fn skipped_output(&self, node: &str) -> Option<&str> {
        let prefix = self.prefix.as_ref()?;
        prefix.routes.iter().find_map(|route| {
            if route == node {
                Some("skipped")
            } else {
                route
                    .strip_prefix(node)
                    .and_then(|route| route.strip_prefix(':'))
            }
        })
    }

    async fn execute_node(&mut self, node: &str) -> Result<&'static str, InvestigationError> {
        match node {
            "prepare_workspace" => {
                self.stages
                    .push(InvestigationStage::PrepareWorkspace.as_str().to_owned());
                Ok("prepared")
            }
            "planner" => {
                self.advance(InvestigationStage::Planner)?;
                Ok("planned")
            }
            "search_code" => {
                self.search("retry", "search_code").await?;
                Ok("searched")
            }
            "inspect_evidence" => {
                self.inspect("retry", "inspect_evidence")?;
                Ok("inspected")
            }
            "coverage_decision" => {
                self.advance(InvestigationStage::CoverageDecision)?;
                Ok("insufficient")
            }
            "retry_search_code" => {
                self.search("pub", "retry_search_code").await?;
                Ok("searched")
            }
            "retry_inspect_evidence" => {
                self.inspect("retry", "retry_inspect_evidence")?;
                Ok("inspected")
            }
            "retry_coverage_decision" => {
                self.advance(InvestigationStage::CoverageDecision)?;
                Ok("sufficient")
            }
            "draft" => {
                self.advance(InvestigationStage::Draft)?;
                self.answer = Some(
                    self.investigation
                        .expected_answer(&ReadOnlyTools::new(&self.snapshot))?,
                );
                Ok("drafted")
            }
            "grounding_validation" => {
                self.advance(InvestigationStage::GroundingValidation)?;
                let answer = self
                    .answer
                    .take()
                    .ok_or_else(|| InvestigationError::new(DiagnosticCode::GraphFailed))?;
                self.answer = Some(finish_investigation(answer, &self.snapshot)?);
                Ok("valid")
            }
            "review" => {
                self.advance(InvestigationStage::Review)?;
                let answer = self
                    .answer
                    .as_ref()
                    .ok_or_else(|| InvestigationError::new(DiagnosticCode::GraphFailed))?;
                if self.requested_verdict == ReviewVerdict::Pass {
                    finish_review(answer.clone(), &self.snapshot)?;
                    Ok("pass")
                } else {
                    Ok("abstain")
                }
            }
            "revise" => {
                self.advance(InvestigationStage::Revise)?;
                Ok("revised")
            }
            _ => Ok("abstain"),
        }
    }

    fn trace(&self, terminal: Option<&str>) -> InvestigationTrace {
        let mut stages = self
            .prefix
            .as_ref()
            .map_or_else(Vec::new, |trace| trace.stages.clone());
        stages.extend(self.stages.iter().cloned());
        let mut routes = self
            .prefix
            .as_ref()
            .map_or_else(Vec::new, |trace| trace.routes.clone());
        routes.extend(self.routes.iter().cloned());
        if let Some(terminal) = terminal {
            routes.push(terminal.to_owned());
        }
        let mut tool_calls = self
            .prefix
            .as_ref()
            .map_or_else(Vec::new, |trace| trace.tool_calls.clone());
        tool_calls.extend(self.calls.iter().cloned());
        let mut tool_results = self
            .prefix
            .as_ref()
            .map_or_else(Vec::new, |trace| trace.tool_results.clone());
        tool_results.extend(self.tool_results.iter().cloned());
        InvestigationTrace {
            llm_requests: usize::from(!tool_calls.is_empty()),
            stages,
            routes,
            tool_calls,
            tool_results,
            adk_graph_exercised: false,
            adk_terminal: None,
        }
    }

    fn event(&mut self, node: &str, output: &str) -> String {
        let trace = self.trace(None);
        if self.capture_step == Some(trace.stages.len()) {
            self.captured_trace = Some(trace.clone());
        }
        let mut state = serde_json::Map::new();
        state.insert("investigation:stages".to_owned(), json!(trace.stages));
        state.insert("investigation:routes".to_owned(), json!(trace.routes));
        state.insert(
            "investigation:tool_calls".to_owned(),
            json!(trace.tool_calls),
        );
        state.insert(
            "investigation:tool_results".to_owned(),
            json!(trace.tool_results),
        );
        if let Some(answer) = &self.answer {
            state.insert("investigation:answer".to_owned(), json!(answer));
        }
        state.insert(format!("route:{node}"), json!(output));
        json!({"output": output, "state": state}).to_string()
    }

    fn advance(&mut self, next: InvestigationStage) -> Result<(), InvestigationError> {
        self.session.advance(next)?;
        self.stages.push(next.as_str().to_owned());
        Ok(())
    }

    async fn search(&mut self, query: &str, route: &str) -> Result<(), InvestigationError> {
        self.advance(InvestigationStage::SearchCode)?;
        let selected_call = fake_model_tool(query, Some("src"))
            .await
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::ModelFailed))?;
        let hits = ReadOnlyTools::new(&self.snapshot)
            .search_code(&selected_call.query, selected_call.path.as_deref())
            .map_err(|_| InvestigationError::new(DiagnosticCode::CoverageExhausted))?;
        self.tool_results.push(ToolResult {
            tool: selected_call.tool,
            route: route.to_owned(),
            output: json!(hits),
        });
        self.calls.push(ToolCall {
            tool: selected_call.tool,
            route: route.to_owned(),
            query: selected_call.query,
            path: selected_call.path,
        });
        Ok(())
    }

    fn inspect(&mut self, query: &str, route: &str) -> Result<(), InvestigationError> {
        self.advance(InvestigationStage::InspectEvidence)?;
        let tools = ReadOnlyTools::new(&self.snapshot);
        let hits = tools.search_code(query, Some("src"))?;
        let hit = hits
            .iter()
            .find(|hit| hit.path() == "src/retry.rs")
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::CoverageExhausted))?;
        self.tool_results.push(ToolResult {
            tool: ReadOnlyTool::SearchCode,
            route: route.to_owned(),
            output: json!(hits),
        });
        let range = tools.read_source_range(hit.path(), hit.line(), hit.line())?;
        self.tool_results.push(ToolResult {
            tool: ReadOnlyTool::ReadSourceRange,
            route: route.to_owned(),
            output: json!(range),
        });
        self.calls.push(ToolCall {
            tool: ReadOnlyTool::ReadSourceRange,
            route: route.to_owned(),
            query: query.to_owned(),
            path: Some(hit.path().to_owned()),
        });
        Ok(())
    }

    fn finish(&mut self, terminal: &str) -> Result<GraphExercise, InvestigationError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let terminal_stage = match terminal {
            "publish" => InvestigationStage::Publish,
            "abstain" => InvestigationStage::Abstain,
            _ => return Err(InvestigationError::new(DiagnosticCode::GraphFailed)),
        };
        if self.session.current() != terminal_stage {
            self.advance(terminal_stage)?;
        }
        let completed_trace = self.trace(Some(terminal));
        if self.capture_step == Some(completed_trace.stages.len()) {
            self.captured_trace = Some(completed_trace.clone());
        }
        match self.captured_trace.take() {
            Some(captured_trace) if strict_trace_prefix(&captured_trace, &completed_trace) => {
                self.captured_trace = Some(captured_trace);
            }
            _ => {}
        }
        Ok(GraphExercise {
            terminal: terminal.to_owned(),
            routes: self.routes.clone(),
            snapshot: self.snapshot.clone(),
            answer: self.answer.clone(),
            stages: self.stages.clone(),
            calls: self.calls.clone(),
            tool_results: self.tool_results.clone(),
            captured_trace: self.captured_trace.take(),
        })
    }
}

struct GraphRouteAgent {
    name: String,
    run: Arc<Mutex<GraphRun>>,
}

#[async_trait]
impl Agent for GraphRouteAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "deterministic code-investigation graph agent"
    }

    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            shared_state: true,
            ..AgentCapabilities::default()
        }
    }

    async fn run(&self, _context: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        let output = self.run.lock().await.execute(&self.name).await;
        let mut event = Event::new(&self.name);
        event.set_content(Content::new("assistant").with_text(output));
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])))
    }
}

async fn run_investigation_graph(
    investigation: SyntheticInvestigation,
    requested_verdict: ReviewVerdict,
    resume_after: Option<usize>,
    prefix: Option<&InvestigationTrace>,
    capture_step: Option<usize>,
) -> Result<GraphExercise, InvestigationError> {
    let plan = compile_str_with_predicates(
        "fixtures/code_investigation/workflow.toml",
        FIXTURE_WORKFLOW,
        &PredicateFixture,
    )
    .map_err(|_| InvestigationError::new(DiagnosticCode::GraphFailed))?;
    let run = Arc::new(Mutex::new(GraphRun::new(
        investigation,
        requested_verdict,
        resume_after,
        prefix,
        capture_step,
    )?));
    let agents: BTreeMap<String, Arc<dyn Agent>> = [
        "prepare_workspace",
        "planner",
        "search_code",
        "inspect_evidence",
        "coverage_decision",
        "retry_search_code",
        "retry_inspect_evidence",
        "retry_coverage_decision",
        "draft",
        "grounding_validation",
        "review",
        "revise",
    ]
    .into_iter()
    .map(|name| {
        (
            name.to_owned(),
            Arc::new(GraphRouteAgent {
                name: name.to_owned(),
                run: Arc::clone(&run),
            }) as Arc<dyn Agent>,
        )
    })
    .collect();
    let graph = workflow_adk::AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .map_err(|_| InvestigationError::new(DiagnosticCode::GraphFailed))?;
    let state = graph
        .invoke(
            adk_rust::graph::prelude::State::new(),
            adk_rust::graph::prelude::ExecutionConfig::new("code-investigation"),
        )
        .await
        .map_err(|_| InvestigationError::new(DiagnosticCode::GraphFailed))?;
    let terminal = state
        .get("terminal")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| InvestigationError::new(DiagnosticCode::GraphFailed))?
        .to_owned();
    let mut exercise = run.lock().await.finish(&terminal)?;
    let mut routes: Vec<String> = state
        .get("investigation:routes")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or_else(|| InvestigationError::new(DiagnosticCode::GraphFailed))?;
    let prefix_route_count = prefix.map_or(0, |trace| trace.routes.len());
    if prefix_route_count > 0 {
        routes.drain(..prefix_route_count.min(routes.len()));
    }
    if !routes.iter().any(|route| route == &terminal) {
        routes.push(terminal.clone());
    }
    exercise.routes = routes;
    let mut calls: Vec<ToolCall> = state
        .get("investigation:tool_calls")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or_else(|| InvestigationError::new(DiagnosticCode::GraphFailed))?;
    let prefix_call_count = prefix.map_or(0, |trace| trace.tool_calls.len());
    if prefix_call_count > 0 {
        calls.drain(..prefix_call_count.min(calls.len()));
    }
    exercise.calls = calls;
    let mut tool_results: Vec<ToolResult> = state
        .get("investigation:tool_results")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or_else(|| InvestigationError::new(DiagnosticCode::GraphFailed))?;
    let prefix_result_count = prefix.map_or(0, |trace| trace.tool_results.len());
    if prefix_result_count > 0 {
        tool_results.drain(..prefix_result_count.min(tool_results.len()));
    }
    exercise.tool_results = tool_results;
    exercise.answer = state
        .get("investigation:answer")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    Ok(exercise)
}

struct PredicateFixture;

impl PredicateRegistry for PredicateFixture {
    type Implementation = ();

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        let valid = matches!(
            (id, version),
            ("coverage.decision@v1", "1.0.0")
                | ("review.verdict@v1", "1.0.0")
                | ("grounding.verdict@v1", "1.0.0")
        );
        if valid {
            static IMPLEMENTATION: () = ();
            let (resolved_id, resolved_version) = match (id, version) {
                ("coverage.decision@v1", "1.0.0") => ("coverage.decision@v1", "1.0.0"),
                ("review.verdict@v1", "1.0.0") => ("review.verdict@v1", "1.0.0"),
                _ => ("grounding.verdict@v1", "1.0.0"),
            };
            Ok(RegistryEntry::new(
                &IMPLEMENTATION,
                resolved_id,
                resolved_version,
            ))
        } else {
            Err(RegistryNotFound::new(
                RegistryCategory::Predicate,
                id,
                version,
            ))
        }
    }
}

/// Result of attempting an optional live dogfood.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveStatus {
    Skipped,
    Published,
    Abstained,
}

/// A live result that never reads credentials or provider configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveResult {
    status: LiveStatus,
    diagnostic: Option<InvestigationError>,
}

impl LiveResult {
    /// Returns the live execution status.
    pub const fn status(self) -> LiveStatus {
        self.status
    }
    /// Returns the safe diagnostic, if live execution abstained.
    pub const fn diagnostic(self) -> Option<InvestigationError> {
        self.diagnostic
    }
    /// Returns whether live execution was skipped.
    pub const fn is_skipped(self) -> bool {
        matches!(self.status, LiveStatus::Skipped)
    }
    /// Returns whether live execution published.
    pub const fn is_published(self) -> bool {
        matches!(self.status, LiveStatus::Published)
    }
    /// Returns whether live execution abstained.
    pub const fn is_abstained(self) -> bool {
        matches!(self.status, LiveStatus::Abstained)
    }
}

/// Explicit opt-in switch for a future local OpenAI-compatible profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LiveDogfood {
    enabled: bool,
}

impl LiveDogfood {
    /// Enables the live attempt without consulting environment or config.
    pub const fn opt_in() -> Self {
        Self { enabled: true }
    }

    /// Runs the opt-in gate without reading any credential value.
    pub async fn run(self) -> LiveResult {
        self.run_with_broker(&CredentialBroker::new()).await
    }

    async fn run_with_broker(self, broker: &CredentialBroker) -> LiveResult {
        if !self.enabled {
            return LiveResult {
                status: LiveStatus::Skipped,
                diagnostic: None,
            };
        }

        let profile = OpenAiCompatibleProfile::new(
            "code-investigation-live",
            "1",
            "code-investigation",
            "https://127.0.0.1:0/v1",
            CredentialHandle::secret_provider("ADK_WORKFLOW_KIT_M1_14_API_KEY"),
        );
        let registry = match ModelProfileRegistry::new().with_worker(profile) {
            Ok(registry) => registry,
            Err(_) => {
                return LiveResult {
                    status: LiveStatus::Abstained,
                    diagnostic: Some(InvestigationError::new(
                        DiagnosticCode::LiveProfileUnavailable,
                    )),
                };
            }
        };
        let worker = match registry.bind_worker(broker) {
            Ok(worker) => worker,
            Err(_) => {
                return LiveResult {
                    status: LiveStatus::Abstained,
                    diagnostic: Some(InvestigationError::new(
                        DiagnosticCode::LiveProfileUnavailable,
                    )),
                };
            }
        };
        if attempt_live_kit_repo(&worker).await.is_ok() {
            LiveResult {
                status: LiveStatus::Published,
                diagnostic: None,
            }
        } else {
            LiveResult {
                status: LiveStatus::Abstained,
                diagnostic: Some(InvestigationError::new(DiagnosticCode::ModelFailed)),
            }
        }
    }
}

async fn attempt_live_kit_repo(
    worker: &workflow_adk::model_profiles::ModelBinding,
) -> Result<(), InvestigationError> {
    let snapshot = FixtureRepo::kit_repo().snapshot();
    let tools = ReadOnlyTools::new(&snapshot);
    let hit = tools
        .search_code("workflow", Some("crates/workflow-testkit/src"))?
        .into_iter()
        .next()
        .ok_or_else(|| InvestigationError::new(DiagnosticCode::PathNotFound))?;
    let evidence = tools.read_source_range(hit.path(), hit.line(), hit.line())?;
    let mut stream = worker
        .generate_content(
            LlmRequest::new(
                "code-investigation-live",
                vec![Content::new("user").with_text(evidence.snippet())],
            ),
            false,
        )
        .await
        .map_err(|_| InvestigationError::new(DiagnosticCode::ModelFailed))?;
    stream
        .next()
        .await
        .ok_or_else(|| InvestigationError::new(DiagnosticCode::ModelFailed))?
        .map_err(|_| InvestigationError::new(DiagnosticCode::ModelFailed))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use workflow_adk::model_profiles::{SecretProvider, SecretValue};

    use super::*;

    struct TestSecrets;

    impl SecretProvider for TestSecrets {
        fn resolve(
            &self,
            _handle: &str,
        ) -> Result<SecretValue, workflow_adk::model_profiles::CredentialError> {
            Ok(SecretValue::new("test-only"))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_dogfood_reuses_the_callers_async_runtime() {
        let broker = CredentialBroker::new().with_secret_provider(Arc::new(TestSecrets));
        let live = LiveDogfood::opt_in().run_with_broker(&broker).await;
        assert!(live.is_abstained());
        assert_eq!(
            live.diagnostic().map(InvestigationError::code),
            Some(DiagnosticCode::ModelFailed)
        );
    }
}
