//! Deterministic, source-addressed continuation state with explicit history links.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The only wire version admitted by this reducer.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct StateVersion;

impl TryFrom<u32> for StateVersion {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        (value == 1)
            .then_some(Self)
            .ok_or("unsupported compact state version")
    }
}

impl From<StateVersion> for u32 {
    fn from(_: StateVersion) -> Self {
        1
    }
}

/// An immutable retained source artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    /// Lowercase hexadecimal SHA-256 digest of the retained artifact.
    pub artifact_id: String,
    /// Exact byte length of the artifact.
    pub byte_len: u64,
}

/// Logical source identities and their immutable artifacts.
pub type SourceIndex = BTreeMap<String, SourceRecord>;

/// A half-open byte range in a retained source artifact.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub source: String,
    pub start: u64,
    pub end: u64,
}

/// The minimal identity-bearing categories needed by the relation contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Fact,
    Proposal,
    Decision,
}

/// A source-addressed assertion whose relations are always explicit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateEntry {
    pub kind: EntryKind,
    pub scope: String,
    pub key: String,
    pub text: String,
    pub provenance: BTreeSet<SourceRef>,
    pub supersedes: BTreeSet<String>,
    pub contradicts: BTreeSet<String>,
}

/// An additive delta. There is no delete or winner-selection operation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateDelta {
    pub schema_version: StateVersion,
    pub sources: SourceIndex,
    pub entries: Vec<StateEntry>,
}

/// Closed errors that do not include untrusted source text or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StateError {
    #[error("invalid compact state document")]
    Document,
    #[error("invalid compact state entry")]
    Entry,
    #[error("invalid compact state source")]
    Source,
    #[error("compact state identity collision")]
    Identity,
}

/// The relation kind exposed by [`CompactState::relations`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Contradicts,
    Supersedes,
}

/// An explicit link, including whether its target is currently present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StateRelation {
    pub source: String,
    pub kind: RelationKind,
    pub target: String,
    pub target_present: bool,
}

/// Canonical state. Union retains every compatible entry and every explicit link.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StateDelta", into = "StateDelta")]
pub struct CompactState {
    sources: SourceIndex,
    entries: BTreeMap<String, StateEntry>,
}

impl TryFrom<StateDelta> for CompactState {
    type Error = StateError;

    fn try_from(delta: StateDelta) -> Result<Self, Self::Error> {
        Self::default().apply(&delta)
    }
}

impl From<CompactState> for StateDelta {
    fn from(state: CompactState) -> Self {
        Self {
            schema_version: StateVersion,
            sources: state.sources,
            entries: state.entries.into_values().collect(),
        }
    }
}

/// True only for the lowercase hexadecimal SHA-256 form used by entry links.
pub fn valid_state_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn normalize(entry: &StateEntry) -> StateEntry {
    let mut normalized = entry.clone();
    normalized.text = entry
        .text
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    normalized
}

/// Stable content identity. Provenance and explicit links are grow-only history.
pub fn entry_id(entry: &StateEntry) -> Result<String, StateError> {
    let entry = normalize(entry);
    let bytes = serde_json::to_vec(&(1u32, entry.kind, &entry.scope, &entry.key, &entry.text))
        .map_err(|_| StateError::Document)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl CompactState {
    /// Entries are keyed by stable content identity and retained without deletion.
    pub fn entries(&self) -> &BTreeMap<String, StateEntry> {
        &self.entries
    }

    /// Source bindings used to validate every provenance range.
    pub fn sources(&self) -> &SourceIndex {
        &self.sources
    }

    /// Atomically apply an additive delta; no input is mutated on rejection.
    pub fn apply(&self, delta: &StateDelta) -> Result<Self, StateError> {
        let mut next = self.clone();
        for (source_id, source) in &delta.sources {
            if source_id.trim().is_empty()
                || !valid_state_digest(&source.artifact_id)
                || source.byte_len == 0
                || next
                    .sources
                    .get(source_id)
                    .is_some_and(|existing| existing != source)
            {
                return Err(StateError::Source);
            }
            next.sources.insert(source_id.clone(), source.clone());
        }

        for original in &delta.entries {
            let entry = normalize(original);
            if entry.scope.trim().is_empty()
                || entry.key.trim().is_empty()
                || entry.text.is_empty()
                || entry.provenance.is_empty()
            {
                return Err(StateError::Entry);
            }
            for provenance in &entry.provenance {
                let source = next
                    .sources
                    .get(&provenance.source)
                    .ok_or(StateError::Source)?;
                if provenance.source.trim().is_empty()
                    || provenance.start >= provenance.end
                    || provenance.end > source.byte_len
                {
                    return Err(StateError::Source);
                }
            }

            let id = entry_id(&entry)?;
            if entry
                .supersedes
                .iter()
                .chain(&entry.contradicts)
                .any(|target| !valid_state_digest(target) || target == &id)
            {
                return Err(StateError::Entry);
            }

            if let Some(existing) = next.entries.get_mut(&id) {
                if (
                    existing.kind,
                    &existing.scope,
                    &existing.key,
                    &existing.text,
                ) != (entry.kind, &entry.scope, &entry.key, &entry.text)
                {
                    return Err(StateError::Identity);
                }
                existing.provenance.extend(entry.provenance);
                existing.supersedes.extend(entry.supersedes);
                existing.contradicts.extend(entry.contradicts);
            } else {
                next.entries.insert(id, entry);
            }
        }
        Ok(next)
    }

    /// Set union; order of application does not choose a winner.
    pub fn union(&self, other: &Self) -> Result<Self, StateError> {
        self.apply(&StateDelta::from(other.clone()))
    }

    /// Compatibility name for callers that use merge terminology.
    pub fn merge(&self, other: &Self) -> Result<Self, StateError> {
        self.union(other)
    }

    /// Stable JSON with source and entry order fixed by B-tree ordering.
    pub fn to_json(&self) -> Result<String, StateError> {
        serde_json::to_string(self).map_err(|_| StateError::Document)
    }

    /// Deserialize through the same validating reducer used by [`Self::apply`].
    pub fn from_json(document: &str) -> Result<Self, StateError> {
        serde_json::from_str(document).map_err(|_| StateError::Document)
    }

    /// Return every explicit link in stable source/kind/target order.
    pub fn relations(&self) -> Vec<StateRelation> {
        let mut relations = Vec::new();
        for (source, entry) in &self.entries {
            for target in &entry.contradicts {
                relations.push(StateRelation {
                    source: source.clone(),
                    kind: RelationKind::Contradicts,
                    target: target.clone(),
                    target_present: self.entries.contains_key(target),
                });
            }
            for target in &entry.supersedes {
                relations.push(StateRelation {
                    source: source.clone(),
                    kind: RelationKind::Supersedes,
                    target: target.clone(),
                    target_present: self.entries.contains_key(target),
                });
            }
        }
        relations.sort_by(|left, right| {
            left.source
                .cmp(&right.source)
                .then(left.kind.cmp(&right.kind))
                .then(left.target.cmp(&right.target))
        });
        relations
    }
}
