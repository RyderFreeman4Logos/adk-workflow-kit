//! Deterministic, source-addressed continuation state with explicit history links.
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The only wire version admitted by this reducer.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct StateVersion;

impl TryFrom<u32> for StateVersion {
    type Error = StateError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        (value == 1).then_some(Self).ok_or(StateError::Document)
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
    /// Caller-asserted lowercase hexadecimal SHA-256 digest of the retained
    /// artifact; this IR does not verify it against external artifact bytes.
    pub artifact_id: String,
    /// Producer-asserted byte length; external artifact bytes are not available
    /// to this IR, so callers must verify this assertion against the artifact.
    pub byte_len: u64,
}

/// Logical source identities and their immutable artifacts. Applying a delta
/// rejects rebinding an existing logical ID to a different record.
pub type SourceIndex = BTreeMap<String, SourceRecord>;

/// A half-open byte range pinned to one retained source artifact.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub source: String,
    /// Lowercase digest of the artifact addressed by this range.
    pub artifact_id: String,
    pub start: u64,
    pub end: u64,
}

/// Categories are identity-bearing. A proposal, alternative, or failed approach
/// never becomes a decision, and completion stays distinct from pending work.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// Current desired outcome.
    Objective,
    /// Reported fact, not independently verified truth.
    Fact,
    /// An explicitly recorded commitment.
    Decision,
    /// A restriction on future actions.
    Constraint,
    /// Work not yet completed.
    PendingTask,
    /// Work explicitly recorded as completed.
    CompletedTask,
    /// Attempt that failed; never a completed task.
    FailedApproach,
    /// An artifact reference; its bytes remain external.
    Artifact,
    /// An unresolved question.
    OpenQuestion,
    /// An exact environment value; never executed by this library.
    EnvironmentBinding,
    /// A proposal, not a commitment.
    Proposal,
    /// An alternative, not a commitment.
    Alternative,
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

/// An additive, self-contained delta. Every source referenced by provenance
/// must be repeated in `sources`; there is no delete or winner-selection
/// operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateDelta {
    pub schema_version: StateVersion,
    pub sources: SourceIndex,
    pub entries: Vec<StateEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateDeltaWire {
    schema_version: StateVersion,
    #[serde(deserialize_with = "deserialize_source_index")]
    sources: SourceIndexWire,
    entries: Vec<StateEntry>,
}

struct SourceIndexWire {
    sources: SourceIndex,
    has_duplicate: bool,
}

fn deserialize_source_index<'de, D>(deserializer: D) -> Result<SourceIndexWire, D::Error>
where
    D: Deserializer<'de>,
{
    struct SourceIndexVisitor;

    impl<'de> Visitor<'de> for SourceIndexVisitor {
        type Value = SourceIndexWire;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a source object with unique logical IDs")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut sources = BTreeMap::new();
            let mut has_duplicate = false;
            while let Some((source_id, source)) = map.next_entry::<String, SourceRecord>()? {
                has_duplicate |= sources.insert(source_id, source).is_some();
            }
            Ok(SourceIndexWire {
                sources,
                has_duplicate,
            })
        }
    }

    deserializer.deserialize_map(SourceIndexVisitor)
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

impl StateDelta {
    fn from_wire(wire: StateDeltaWire) -> Result<Self, StateError> {
        if wire.sources.has_duplicate {
            return Err(StateError::Source);
        }
        Ok(Self {
            schema_version: wire.schema_version,
            sources: wire.sources.sources,
            entries: wire.entries,
        })
    }
}

impl<'de> Deserialize<'de> for StateDelta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let delta = StateDelta::from_wire(StateDeltaWire::deserialize(deserializer)?)
            .map_err(<D::Error as serde::de::Error>::custom)?;
        CompactState::try_from(delta.clone()).map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(delta)
    }
}

/// True only for the lowercase hexadecimal SHA-256 form used by entry links.
pub fn valid_state_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Stable content identity. Provenance and explicit links are grow-only history.
pub fn entry_id(entry: &StateEntry) -> Result<String, StateError> {
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

    /// Atomically apply a self-contained additive delta; no input is mutated on rejection.
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
            let entry = original.clone();
            if entry.scope.trim().is_empty()
                || entry.key.trim().is_empty()
                || entry.text.is_empty()
                || entry.provenance.is_empty()
            {
                return Err(StateError::Entry);
            }
            for provenance in &entry.provenance {
                if !delta.sources.contains_key(&provenance.source) {
                    return Err(StateError::Source);
                }
                let source = next
                    .sources
                    .get(&provenance.source)
                    .ok_or(StateError::Source)?;
                if provenance.source.trim().is_empty()
                    || provenance.artifact_id != source.artifact_id
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

    /// Stable JSON with source and entry order fixed by B-tree ordering.
    pub fn to_json(&self) -> Result<String, StateError> {
        serde_json::to_string(self).map_err(|_| StateError::Document)
    }

    /// Deserialize through the same validating reducer used by [`Self::apply`].
    pub fn from_json(document: &str) -> Result<Self, StateError> {
        let wire: StateDeltaWire =
            serde_json::from_str(document).map_err(|_| StateError::Document)?;
        Self::try_from(StateDelta::from_wire(wire)?)
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

    /// Trusted continuation view: sorted identities, relations, and source refs.
    /// Entry text and source bytes are never copied into the document.
    pub fn render(&self) -> Result<String, StateError> {
        let mut lines = vec!["CompactState v1".to_owned()];
        for (source_id, source) in &self.sources {
            lines.push(format!(
                "source {} {} {}",
                display_token(source_id),
                source.artifact_id,
                source.byte_len
            ));
        }
        for (id, entry) in &self.entries {
            lines.push(format!(
                "entry {} {}",
                id,
                serde_json::to_string(&entry.kind).map_err(|_| StateError::Document)?
            ));
            for source in &entry.provenance {
                lines.push(format!(
                    "ref {} {}#{}-{}",
                    id,
                    display_token(&source.source),
                    source.start,
                    source.end
                ));
            }
            for relation in &self.relations() {
                if relation.source == *id {
                    lines.push(format!(
                        "link {} {} {} {}",
                        id,
                        serde_json::to_string(&relation.kind).map_err(|_| StateError::Document)?,
                        relation.target,
                        u8::from(relation.target_present)
                    ));
                }
            }
        }
        Ok(format!("    {}", lines.join("\n    ")))
    }
}

fn display_token(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}
