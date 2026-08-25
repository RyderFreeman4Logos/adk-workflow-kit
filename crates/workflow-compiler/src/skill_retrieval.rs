use std::cmp::Reverse;

use crate::{SkillActivationError, SkillId, SkillManifest, SkillRegistry};

/// An immutable capability set carried through compiler-boundary retrieval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillCapabilitySet(Vec<String>);

impl SkillCapabilitySet {
    /// Creates a capability set without changing its supplied values.
    pub fn new<I, S>(capabilities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(capabilities.into_iter().map(Into::into).collect())
    }

    /// Returns the capability values in their original order.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

/// One already-declared Skill version eligible for retrieval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillDeclaration {
    id: SkillId,
    version: String,
}

impl SkillDeclaration {
    /// Creates a registry-bound Skill declaration.
    pub fn new(id: SkillId, version: impl Into<String>) -> Self {
        Self {
            id,
            version: version.into(),
        }
    }

    /// Returns the declared Skill identifier.
    pub fn id(&self) -> &SkillId {
        &self.id
    }

    /// Returns the declared Skill version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A deterministically ranked Skill candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillCandidate {
    id: SkillId,
    version: String,
    score: usize,
}

impl SkillCandidate {
    /// Returns the candidate Skill identifier.
    pub fn id(&self) -> &SkillId {
        &self.id
    }

    /// Returns the candidate Skill version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the deterministic relevance score.
    pub fn score(&self) -> usize {
        self.score
    }
}

/// A typed diagnostic for a declaration that could not become a candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillRetrievalDiagnostic {
    declaration: SkillDeclaration,
    error: SkillActivationError,
}

impl SkillRetrievalDiagnostic {
    /// Returns the declaration that produced this diagnostic.
    pub fn declaration(&self) -> &SkillDeclaration {
        &self.declaration
    }

    /// Returns the typed retrieval failure.
    pub fn error(&self) -> SkillActivationError {
        self.error
    }
}

/// Retrieval output containing candidates, diagnostics, and unchanged capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillRetrievalResult {
    candidates: Vec<SkillCandidate>,
    diagnostics: Vec<SkillRetrievalDiagnostic>,
    capabilities: SkillCapabilitySet,
}

impl SkillRetrievalResult {
    /// Returns candidates ordered by descending relevance and stable identity.
    pub fn candidates(&self) -> &[SkillCandidate] {
        &self.candidates
    }

    /// Returns typed diagnostics for declarations that were not candidates.
    pub fn diagnostics(&self) -> &[SkillRetrievalDiagnostic] {
        &self.diagnostics
    }

    /// Returns the exact capability set supplied to retrieval.
    pub fn capabilities(&self) -> &SkillCapabilitySet {
        &self.capabilities
    }
}

/// Ranks already-declared Skills without changing the input capability set.
pub fn retrieve_skill_candidates<R>(
    registry: &R,
    declarations: &[SkillDeclaration],
    query: &str,
    capabilities: SkillCapabilitySet,
) -> SkillRetrievalResult
where
    R: SkillRegistry<Implementation = SkillManifest>,
{
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let mut candidates = Vec::new();
    let mut diagnostics = Vec::new();

    for declaration in declarations {
        let entry = match registry.resolve(declaration.id.as_str(), declaration.version()) {
            Ok(entry) => entry,
            Err(_) => {
                diagnostics.push(SkillRetrievalDiagnostic {
                    declaration: declaration.clone(),
                    error: SkillActivationError::NotRegistered,
                });
                continue;
            }
        };
        let metadata = entry.implementation().discovery_metadata();
        if entry.id() != declaration.id.as_str() || metadata.id() != declaration.id() {
            diagnostics.push(SkillRetrievalDiagnostic {
                declaration: declaration.clone(),
                error: SkillActivationError::RegistryIdentityMismatch,
            });
            continue;
        }
        let haystack =
            format!("{} {}", metadata.id().as_str(), metadata.description()).to_lowercase();
        let score = terms
            .iter()
            .filter(|term| haystack.contains(term.as_str()))
            .count();
        candidates.push(SkillCandidate {
            id: declaration.id.clone(),
            version: declaration.version.clone(),
            score,
        });
    }

    candidates.sort_by_key(|candidate| {
        (
            Reverse(candidate.score),
            candidate.id.clone(),
            candidate.version.clone(),
        )
    });

    SkillRetrievalResult {
        candidates,
        diagnostics,
        capabilities,
    }
}
