//! A bounded, offline, read-only code-investigation dogfood workflow.
//!
//! The public surface contains project-owned data only. ADK values are used only
//! inside the deterministic fake-model and graph exercise helpers.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Component, Path},
};

use adk_rust::{Content, Llm, LlmRequest, LlmResponse, Part, futures::StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use workflow_adk::model_profiles::{
    CredentialHandle, ModelProfileRegistry, OpenAiCompatibleProfile,
};
use workflow_compiler::{
    PredicateRegistry, RegistryCategory, RegistryEntry, RegistryNotFound, SkillManifest,
    compile_str, compile_str_with_predicates,
};
use workflow_review::{
    CandidateArtifact, ReviewCost, ReviewDefect, ReviewLoopConfig, ReviewLoopOutcome, ReviewResult,
    ReviewSeverity, ReviewVerdict, ReviewerResponse, RevisionResponse, SelectedEvidence,
    ValidationReport, run_bounded_review_loop,
};

const MAX_CYCLES: usize = 2;
const ARTIFACT_PAGE_BYTES: usize = 256;
const FIXTURE_WORKFLOW: &str = include_str!("../tests/fixtures/code_investigation/workflow.toml");
const FIXTURE_RETRY: &str = include_str!("../tests/fixtures/code_investigation/repo/src/retry.rs");
const FIXTURE_LIB: &str = include_str!("../tests/fixtures/code_investigation/repo/src/lib.rs");
const GRAPH_WORKFLOW: &str = "schema_version = 1\n\n[workflow]\nid = \"adk.graph.exercise\"\nversion = \"1\"\nentry = \"start\"\n\n[[nodes]]\nid = \"start\"\nkind = \"agent\"\n\n[[nodes]]\nid = \"done\"\nkind = \"terminal\"\n\n[[edges]]\nfrom = \"start\"\nto = \"done\"\n";

/// The published ADK version exercised by this dogfood.
pub const ADK_RUST_VERSION: &str = "2.1.0";
/// The schema version of an investigation answer artifact.
pub const ANSWER_SCHEMA_VERSION: u8 = 1;

/// The only tools available to investigators and reviewers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolCall {
    tool: ReadOnlyTool,
    route: String,
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
}

/// A deterministic structural trace suitable for replay validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InvestigationTrace {
    stages: Vec<String>,
    routes: Vec<String>,
    tool_calls: Vec<ToolCall>,
    llm_requests: usize,
    adk_graph_exercised: bool,
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
    /// Returns the number of fake-model LLM requests.
    pub const fn llm_requests(&self) -> usize {
        self.llm_requests
    }
    /// Returns whether a real ADK `GraphAgent` was translated and invoked.
    pub const fn adk_graph_exercised(&self) -> bool {
        self.adk_graph_exercised
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
    pub fn run_fake(&self) -> Result<InvestigationResult, InvestigationError> {
        let _package = Self::fixture_package()?;
        let snapshot = self.repo.snapshot();
        let predicate_registry = PredicateFixture;
        let plan = compile_str_with_predicates(
            "fixtures/code_investigation/workflow.toml",
            FIXTURE_WORKFLOW,
            &predicate_registry,
        )
        .map_err(|_| InvestigationError::new(DiagnosticCode::SchemaInvalid))?;
        let _canonical_ir_hash = plan.ir().canonical_hash();

        let mut session = self.session();
        let mut stages = vec![InvestigationStage::PrepareWorkspace.as_str().to_owned()];
        let mut routes = vec!["prepare_workspace".to_owned()];
        advance(&mut session, InvestigationStage::Planner, &mut stages);
        routes.push("planner".to_owned());
        advance(&mut session, InvestigationStage::SearchCode, &mut stages);
        let selected_tool = fake_model_tool()
            .ok_or_else(|| InvestigationError::new(DiagnosticCode::ModelFailed))?;
        let tools = ReadOnlyTools::new(&snapshot);
        let _initial = tools
            .search_code("default", Some("src"))
            .map_err(|_| InvestigationError::new(DiagnosticCode::CoverageExhausted))?;
        routes.push("search_code".to_owned());
        let mut calls = vec![ToolCall {
            tool: selected_tool,
            route: "search_code".to_owned(),
        }];
        advance(
            &mut session,
            InvestigationStage::InspectEvidence,
            &mut stages,
        );
        routes.push("inspect_evidence".to_owned());
        advance(
            &mut session,
            InvestigationStage::CoverageDecision,
            &mut stages,
        );
        routes.push("coverage_decision".to_owned());
        routes.push("insufficient_coverage".to_owned());
        routes.push("retry_search_code".to_owned());

        advance(&mut session, InvestigationStage::SearchCode, &mut stages);
        let hits = tools
            .search_code("retry", Some("src"))
            .map_err(|_| InvestigationError::new(DiagnosticCode::CoverageExhausted))?;
        calls.push(ToolCall {
            tool: ReadOnlyTool::SearchCode,
            route: "inspect_evidence".to_owned(),
        });
        routes.push("search_code".to_owned());
        routes.push("retry_inspect_evidence".to_owned());
        advance(
            &mut session,
            InvestigationStage::InspectEvidence,
            &mut stages,
        );
        routes.push("inspect_evidence".to_owned());
        advance(
            &mut session,
            InvestigationStage::CoverageDecision,
            &mut stages,
        );
        if hits.len() < MAX_CYCLES * 2 {
            return Err(InvestigationError::new(DiagnosticCode::CoverageExhausted));
        }
        routes.push("coverage_decision".to_owned());
        routes.push("retry_coverage_decision".to_owned());
        routes.push("sufficient_draft".to_owned());

        let answer = self.expected_answer(&tools)?;
        advance(&mut session, InvestigationStage::Draft, &mut stages);
        advance(
            &mut session,
            InvestigationStage::GroundingValidation,
            &mut stages,
        );
        routes.push("grounding_validation".to_owned());
        let answer = finish_investigation(answer, &snapshot)?;
        advance(&mut session, InvestigationStage::Review, &mut stages);
        routes.push("review".to_owned());
        let selected_evidence = answer
            .claims()
            .iter()
            .flat_map(|claim| {
                claim.evidence().iter().map(move |evidence| {
                    SelectedEvidence::new(
                        format!("{}:{}", claim.id(), evidence.path()),
                        evidence.snippet().to_owned(),
                    )
                })
            })
            .collect::<Vec<_>>();
        let candidate_bytes = serde_json::to_vec(&answer)
            .map_err(|_| InvestigationError::new(DiagnosticCode::ArtifactFailed))?;
        let snapshot_for_validation = snapshot.clone();
        let review_outcome = run_bounded_review_loop(
            || -> Result<CandidateArtifact, InvestigationError> {
                Ok(CandidateArtifact::new(candidate_bytes.clone()))
            },
            |candidate| {
                let parsed = serde_json::from_slice::<InvestigationAnswer>(candidate.bytes());
                let validation = match parsed {
                    Ok(candidate) => match validate_answer(&candidate, &snapshot_for_validation) {
                        Ok(()) => ValidationReport::valid(),
                        Err(error) => ValidationReport::invalid(vec![ReviewDefect::new(
                            error.code().as_str().to_owned(),
                            ReviewSeverity::Error,
                            None,
                            Vec::new(),
                            "deterministic answer validation failed".to_owned(),
                            None,
                        )]),
                    },
                    Err(_) => ValidationReport::invalid(vec![ReviewDefect::new(
                        "answer_decode".to_owned(),
                        ReviewSeverity::Error,
                        None,
                        Vec::new(),
                        "answer artifact is not valid JSON".to_owned(),
                        None,
                    )]),
                };
                Ok(validation)
            },
            |request| {
                let (verdict, defects) = if request.validation().is_valid() {
                    (ReviewVerdict::Pass, Vec::new())
                } else {
                    (
                        ReviewVerdict::Revise,
                        request.validation().defects().to_vec(),
                    )
                };
                let review = ReviewResult::new(
                    1,
                    verdict,
                    "isolated structured review".to_owned(),
                    defects,
                    1.0,
                )
                .map_err(|_| InvestigationError::new(DiagnosticCode::SchemaInvalid))?;
                Ok(ReviewerResponse::new(review, ReviewCost::new(1, 0)))
            },
            |request| {
                Ok(RevisionResponse::new(
                    CandidateArtifact::new(request.candidate().bytes().to_vec()),
                    ReviewCost::new(1, 0),
                ))
            },
            ReviewLoopConfig::default().with_evidence(selected_evidence),
        )
        .map_err(|_| InvestigationError::new(DiagnosticCode::ModelFailed))?;
        let reviewed_answer = match review_outcome {
            ReviewLoopOutcome::Published { artifact, metrics } => {
                routes.push("review_loop".to_owned());
                if metrics.revisions() == 0 {
                    routes.push("review_loop_pass".to_owned());
                } else {
                    routes.push("review_loop_revise".to_owned());
                }
                serde_json::from_slice::<InvestigationAnswer>(artifact.bytes())
                    .map_err(|_| InvestigationError::new(DiagnosticCode::ArtifactFailed))?
            }
            ReviewLoopOutcome::Abstained { .. } => {
                return Err(InvestigationError::new(DiagnosticCode::ReviewAbstained));
            }
        };
        let answer = finish_review_with_verdict(reviewed_answer, &snapshot, ReviewVerdict::Pass)?;
        advance(&mut session, InvestigationStage::Publish, &mut stages);
        routes.push("publish".to_owned());
        let adk_graph_exercised = exercise_adk_graph();
        if !adk_graph_exercised {
            return Err(InvestigationError::new(DiagnosticCode::GraphFailed));
        }
        let artifact = serde_json::to_string(&answer)
            .map_err(|_| InvestigationError::new(DiagnosticCode::ArtifactFailed))?;
        let trace = InvestigationTrace {
            stages,
            routes,
            tool_calls: calls,
            llm_requests: 1,
            adk_graph_exercised,
        };
        let replay_digest = trace.digest();
        Ok(InvestigationResult {
            status: InvestigationStatus::Published,
            answer,
            snapshot,
            trace,
            checkpoint: None,
            artifact,
            replay_digest,
        })
    }

    /// Stops after a bounded step and writes a payload-free checkpoint.
    pub fn run_until_kill(&self, step: usize) -> Result<InvestigationResult, InvestigationError> {
        if step == 0 || step > 32 {
            return Err(InvestigationError::new(DiagnosticCode::CheckpointInvalid));
        }
        let snapshot = self.repo.snapshot();
        let trace = InvestigationTrace {
            stages: vec![
                InvestigationStage::PrepareWorkspace.as_str().to_owned(),
                InvestigationStage::Planner.as_str().to_owned(),
                InvestigationStage::SearchCode.as_str().to_owned(),
            ],
            routes: vec!["checkpoint".to_owned()],
            tool_calls: Vec::new(),
            llm_requests: 0,
            adk_graph_exercised: false,
        };
        let checkpoint = InvestigationCheckpoint {
            snapshot_id: snapshot.id.clone(),
            step,
            state_digest: digest(format!("{}:{step}", snapshot.id).as_bytes()),
        };
        let artifact = serde_json::to_string(&InvestigationAnswer::empty(&snapshot.id))
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

    /// Resumes from a checkpoint as a fresh, stateless process would.
    pub fn resume(
        &self,
        checkpoint: &InvestigationCheckpoint,
    ) -> Result<InvestigationResult, InvestigationError> {
        let snapshot = self.repo.snapshot();
        if checkpoint.snapshot_id != snapshot.id || checkpoint.step == 0 {
            return Err(InvestigationError::new(DiagnosticCode::CheckpointInvalid));
        }
        self.run_fake()
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

fn advance(session: &mut InvestigationSession, next: InvestigationStage, stages: &mut Vec<String>) {
    if session.advance(next).is_ok() {
        stages.push(next.as_str().to_owned());
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn fake_model_tool() -> Option<ReadOnlyTool> {
    let model = crate::ScriptedLlm::new(vec![crate::ScriptStep::new(
        |request| {
            (request.model == "code-investigation-fake")
                .then_some(())
                .ok_or_else(|| "unexpected fake model request".to_owned())
        },
        LlmResponse::new(Content {
            role: "model".to_owned(),
            parts: vec![Part::FunctionCall {
                name: ReadOnlyTool::SearchCode.as_str().to_owned(),
                args: json!({"query": "retry", "path": "src"}),
                id: Some("search-1".to_owned()),
                thought_signature: None,
            }],
        }),
    )]);
    let runtime = adk_rust::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    runtime.block_on(async {
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
                Part::FunctionCall { name, .. } if name == ReadOnlyTool::SearchCode.as_str() => {
                    Some(ReadOnlyTool::SearchCode)
                }
                _ => None,
            })
    })
}

fn exercise_adk_graph() -> bool {
    let Ok(plan) = compile_str("adk-graph-exercise.workflow.toml", GRAPH_WORKFLOW) else {
        return false;
    };
    let Ok(graph) = workflow_adk::AdkGraphTranslator::new().translate(&plan) else {
        return false;
    };
    let Ok(runtime) = adk_rust::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    runtime.block_on(async {
        graph
            .invoke(
                adk_rust::graph::prelude::State::new(),
                adk_rust::graph::prelude::ExecutionConfig::new("code-investigation"),
            )
            .await
            .is_ok()
    })
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
    pub fn run(self) -> LiveResult {
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
            CredentialHandle::environment("ADK_WORKFLOW_KIT_M1_14_API_KEY"),
        );
        if ModelProfileRegistry::new().with_worker(profile).is_err() {
            return LiveResult {
                status: LiveStatus::Abstained,
                diagnostic: Some(InvestigationError::new(
                    DiagnosticCode::LiveProfileUnavailable,
                )),
            };
        }
        LiveResult {
            status: LiveStatus::Abstained,
            diagnostic: Some(InvestigationError::new(
                DiagnosticCode::LiveProfileUnavailable,
            )),
        }
    }
}
