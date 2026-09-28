//! Artifact-backed exchange for validated compact-state deltas.

use std::{fmt, num::NonZeroU64};

use serde_json::Value;
use sha2::{Digest, Sha256};
use workflow_ir::compact_state::{
    CompactState, IrCompactStateEndpoint, SourceIndex, SourceRef, StateDelta,
};

use crate::{
    ArtifactId, ArtifactRef, ArtifactStore, CompactStateDelta, Completeness, PageRequest,
    TypedOutput, TypedOutputError, TypedPayload, WorkflowExchange, encode_hex,
};

/// The typed envelope key used by the compact-state exchange.
pub const COMPACT_STATE_KEY: &str = "compact_state";
/// The typed envelope operation used by the compact-state exchange.
pub const COMPACT_STATE_OPERATION: &str = "add";

impl From<IrCompactStateEndpoint> for WorkflowExchange {
    fn from(endpoint: IrCompactStateEndpoint) -> Self {
        match endpoint {
            IrCompactStateEndpoint::CodeInvestigation => Self::CodeInvestigation,
            IrCompactStateEndpoint::GroundedAnswer => Self::GroundedAnswer,
            IrCompactStateEndpoint::MultiHop => Self::MultiHop,
            IrCompactStateEndpoint::Review => Self::Review,
        }
    }
}

const PAGE_LIMIT: NonZeroU64 = match NonZeroU64::new(65_536) {
    Some(limit) => limit,
    None => unreachable!(),
};
const MAX_EXCHANGE_BYTES: usize = (crate::COMPACT_STATE_OUTPUT_TOKEN_BUDGET as usize) * 4 + 256;
const MAX_DELTA_BYTES: usize = 4 * 1024 * 1024;

/// The publication boundary reached before a compact-state exchange failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactStatePublicationPhase {
    /// The canonical delta commit boundary was reached; envelope visibility is unknown.
    PostDeltaCommit,
}

/// The public recovery handle for a partially published compact-state exchange.
#[derive(Clone, Eq, PartialEq)]
pub struct CompactStatePartialPublication {
    delta_artifact: ArtifactId,
    phase: CompactStatePublicationPhase,
}

impl CompactStatePartialPublication {
    /// Returns the committed canonical delta artifact that can be recovered or retried.
    pub fn delta_artifact(&self) -> &ArtifactId {
        &self.delta_artifact
    }

    /// Returns the publication boundary reached by the failed exchange.
    pub fn phase(&self) -> CompactStatePublicationPhase {
        self.phase
    }
}

impl fmt::Debug for CompactStatePartialPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactStatePartialPublication")
            .field("delta_artifact", &"<redacted>")
            .field("phase", &self.phase)
            .finish()
    }
}

/// Payload-free failures at the compact-state artifact boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompactStateExchangeError {
    /// The artifact store rejected a read or write.
    Artifact,
    /// The delta commit boundary was reached; envelope visibility is not established.
    PartialPublication(CompactStatePartialPublication),
    /// The typed envelope failed structural or admission validation.
    InvalidEnvelope,
    /// The state delta was not canonical, valid, or reducible.
    InvalidStateDelta,
    /// A content digest did not match its artifact identity or reference.
    DigestMismatch,
    /// An indexed artifact length did not match the stored bytes.
    LengthMismatch,
    /// A source logical identity was not present in the state index.
    MissingSource,
    /// A source reference did not match its indexed artifact binding.
    SourceBinding,
    /// A source range was not a valid half-open span.
    InvalidSpan,
    /// A store returned a page that could not make bounded progress.
    PageProgress,
    /// The compact-state envelope key did not match the expected key.
    WrongKey,
    /// The compact-state envelope operation did not match the expected operation.
    WrongOperation,
    /// The typed envelope payload was not compact state.
    WrongPayload,
    /// The artifact exceeded the bounded exchange or delta limit.
    Oversized,
}

impl fmt::Display for CompactStateExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Artifact => "artifact store rejected the operation",
            Self::PartialPublication(_) => {
                "compact-state publication is partial after the delta commit"
            }
            Self::InvalidEnvelope => "compact-state envelope is invalid",
            Self::InvalidStateDelta => "compact-state delta is invalid",
            Self::DigestMismatch => "artifact digest does not match its content",
            Self::LengthMismatch => "artifact length does not match its index",
            Self::MissingSource => "compact-state source is missing",
            Self::SourceBinding => "compact-state source binding is invalid",
            Self::InvalidSpan => "compact-state source span is invalid",
            Self::PageProgress => "artifact page made no bounded progress",
            Self::WrongKey => "compact-state envelope key is not admitted",
            Self::WrongOperation => "compact-state envelope operation is not admitted",
            Self::WrongPayload => "typed envelope payload is not compact state",
            Self::Oversized => "compact-state artifact exceeds its bounded limit",
        })
    }
}

impl std::error::Error for CompactStateExchangeError {}

impl CompactStateExchangeError {
    /// Returns the recovery handle when the delta crossed the visibility boundary.
    pub fn partial_publication(&self) -> Option<&CompactStatePartialPublication> {
        match self {
            Self::PartialPublication(partial) => Some(partial),
            _ => None,
        }
    }
}

/// Identifiers returned after publishing a state delta and its typed envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct CompactStateReceipt {
    delta_artifact: ArtifactId,
    envelope_artifact: ArtifactId,
    byte_len: u64,
}

impl CompactStateReceipt {
    /// Returns the content ID of the canonical state-delta artifact.
    pub fn delta_artifact(&self) -> &ArtifactId {
        &self.delta_artifact
    }

    /// Returns the content ID of the admitted typed transport envelope.
    pub fn envelope_artifact(&self) -> &ArtifactId {
        &self.envelope_artifact
    }

    /// Returns the canonical state-delta byte length.
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

impl fmt::Debug for CompactStateReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactStateReceipt")
            .field("delta_artifact", &"<redacted>")
            .field("envelope_artifact", &"<redacted>")
            .field("byte_len", &self.byte_len)
            .finish()
    }
}

/// A bounded page relative to one source range.
#[derive(Clone, Eq, PartialEq)]
pub struct SourcePage {
    bytes: Vec<u8>,
    next_offset: Option<u64>,
}

impl fmt::Debug for SourcePage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourcePage")
            .field("byte_len", &self.bytes.len())
            .field("next_offset", &self.next_offset)
            .finish()
    }
}

impl SourcePage {
    /// Returns opaque bytes from the cited source range.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the next offset relative to the cited range start, if any bytes remain.
    pub fn next_offset(&self) -> Option<u64> {
        self.next_offset
    }
}

/// Publishes one canonical state delta and an admitted compact-state envelope.
///
/// Both artifacts are staged before either is committed. `ArtifactStore` does
/// not provide a transaction spanning the two commits, so a failure after the
/// delta commit intentionally retains that content-addressed delta. Callers
/// own retrying the same delta; its stable ID makes the retry idempotent. Any
/// failure after the delta commit returns that canonical ID in
/// `PartialPublication`, including a store that reports the wrong ID after
/// making content visible. Staging and previsibility commit failures remain
/// `Artifact` under the store's commit-error contract.
pub fn publish_compact_state_delta<S, F, T>(
    store: &mut S,
    from: F,
    to: T,
    delta: &StateDelta,
) -> Result<CompactStateReceipt, CompactStateExchangeError>
where
    S: ArtifactStore,
    F: Into<WorkflowExchange>,
    T: Into<WorkflowExchange>,
{
    let from = from.into();
    let to = to.into();
    CompactState::default()
        .apply(delta)
        .map_err(|_| CompactStateExchangeError::InvalidStateDelta)?;
    let bytes =
        serde_json::to_vec(delta).map_err(|_| CompactStateExchangeError::InvalidStateDelta)?;
    if bytes.is_empty() || bytes.len() > MAX_DELTA_BYTES {
        return Err(CompactStateExchangeError::Oversized);
    }
    let expected = content_id(&bytes).ok_or(CompactStateExchangeError::DigestMismatch)?;
    let artifact_ref = ArtifactRef::new(expected.as_str(), format!("sha256:{}", expected.as_str()))
        .map_err(|_| CompactStateExchangeError::InvalidEnvelope)?;
    let output = TypedOutput::new(
        TypedPayload::CompactState(CompactStateDelta::new(
            COMPACT_STATE_KEY,
            COMPACT_STATE_OPERATION,
            vec![artifact_ref],
        )),
        Completeness::Complete,
    )
    .map_err(|_| CompactStateExchangeError::InvalidEnvelope)?;
    let delta_staged = store
        .stage(&bytes)
        .map_err(|_| CompactStateExchangeError::Artifact)?;
    let envelope_bytes = from.envelope_bytes(to, &output).map_err(map_typed_error)?;
    let expected_envelope =
        content_id(&envelope_bytes).ok_or(CompactStateExchangeError::DigestMismatch)?;
    let envelope_staged = store
        .stage(&envelope_bytes)
        .map_err(|_| CompactStateExchangeError::Artifact)?;
    let delta_artifact = match store.commit(delta_staged) {
        Ok(artifact) if artifact == expected => artifact,
        Ok(_) => {
            return Err(CompactStateExchangeError::PartialPublication(
                CompactStatePartialPublication {
                    delta_artifact: expected,
                    phase: CompactStatePublicationPhase::PostDeltaCommit,
                },
            ));
        }
        Err(_) => return Err(CompactStateExchangeError::Artifact),
    };
    let envelope_artifact = match store.commit(envelope_staged) {
        Ok(artifact) if artifact == expected_envelope => artifact,
        Ok(_) | Err(_) => {
            return Err(CompactStateExchangeError::PartialPublication(
                CompactStatePartialPublication {
                    delta_artifact: delta_artifact.clone(),
                    phase: CompactStatePublicationPhase::PostDeltaCommit,
                },
            ));
        }
    };
    Ok(CompactStateReceipt {
        delta_artifact,
        envelope_artifact,
        byte_len: bytes.len() as u64,
    })
}

/// Admits, verifies, and atomically applies one compact-state delta envelope.
pub fn consume_compact_state_delta<S, F, T>(
    store: &S,
    from: F,
    to: T,
    envelope_artifact: &ArtifactId,
    expected_key: &str,
    expected_op: &str,
    state: &mut CompactState,
) -> Result<CompactStateReceipt, CompactStateExchangeError>
where
    S: ArtifactStore,
    F: Into<WorkflowExchange>,
    T: Into<WorkflowExchange>,
{
    let from = from.into();
    let to = to.into();
    let envelope = read_artifact(store, envelope_artifact, MAX_EXCHANGE_BYTES)?;
    let payload = to.consume_bytes(from, &envelope).map_err(map_typed_error)?;
    if !matches!(payload, TypedPayload::CompactState(_)) {
        return Err(CompactStateExchangeError::WrongPayload);
    }

    let (key, op, delta_artifact) = extract_compact_state_ref(&envelope)?;
    if key != expected_key {
        return Err(CompactStateExchangeError::WrongKey);
    }
    if op != expected_op {
        return Err(CompactStateExchangeError::WrongOperation);
    }
    let delta_bytes = read_artifact(store, &delta_artifact, MAX_DELTA_BYTES)?;
    let delta = serde_json::from_slice::<StateDelta>(&delta_bytes)
        .map_err(|_| CompactStateExchangeError::InvalidStateDelta)?;
    let canonical =
        serde_json::to_vec(&delta).map_err(|_| CompactStateExchangeError::InvalidStateDelta)?;
    if canonical != delta_bytes {
        return Err(CompactStateExchangeError::InvalidStateDelta);
    }
    let next = state
        .apply(&delta)
        .map_err(|_| CompactStateExchangeError::InvalidStateDelta)?;
    *state = next;
    Ok(CompactStateReceipt {
        delta_artifact,
        envelope_artifact: envelope_artifact.clone(),
        byte_len: delta_bytes.len() as u64,
    })
}

/// Reads one source range page after checking its indexed length and digest.
pub fn read_source_ref_page<S: ArtifactStore>(
    store: &S,
    sources: &SourceIndex,
    source_ref: &SourceRef,
    relative_offset: u64,
    limit: NonZeroU64,
) -> Result<SourcePage, CompactStateExchangeError> {
    let record = sources
        .get(&source_ref.source)
        .ok_or(CompactStateExchangeError::MissingSource)?;
    if source_ref.source.trim().is_empty()
        || source_ref.start >= source_ref.end
        || source_ref.end > record.byte_len
    {
        return Err(CompactStateExchangeError::InvalidSpan);
    }
    if source_ref.artifact_id != record.artifact_id {
        return Err(CompactStateExchangeError::SourceBinding);
    }
    let artifact_id = ArtifactId::parse(record.artifact_id.clone())
        .ok_or(CompactStateExchangeError::SourceBinding)?;
    if ArtifactId::parse(source_ref.artifact_id.clone()).is_none() {
        return Err(CompactStateExchangeError::SourceBinding);
    }

    let span_len = source_ref
        .end
        .checked_sub(source_ref.start)
        .ok_or(CompactStateExchangeError::InvalidSpan)?;
    if relative_offset > span_len {
        return Err(CompactStateExchangeError::InvalidSpan);
    }
    let absolute_offset = source_ref
        .start
        .checked_add(relative_offset)
        .ok_or(CompactStateExchangeError::InvalidSpan)?;
    if relative_offset == span_len {
        verify_artifact(
            store,
            &artifact_id,
            record.byte_len,
            absolute_offset,
            absolute_offset,
        )?;
        return Ok(SourcePage {
            bytes: Vec::new(),
            next_offset: None,
        });
    }
    let remaining = span_len - relative_offset;
    let request_limit = limit.get().min(remaining);
    let requested_end = absolute_offset
        .checked_add(request_limit)
        .ok_or(CompactStateExchangeError::InvalidSpan)?;
    let bytes = verify_artifact(
        store,
        &artifact_id,
        record.byte_len,
        absolute_offset,
        requested_end,
    )?;
    let length =
        u64::try_from(bytes.len()).map_err(|_| CompactStateExchangeError::LengthMismatch)?;
    let expected_next = absolute_offset
        .checked_add(length)
        .ok_or(CompactStateExchangeError::PageProgress)?;
    let next_offset = (expected_next < source_ref.end).then_some(expected_next - source_ref.start);
    Ok(SourcePage { bytes, next_offset })
}

fn map_typed_error(error: TypedOutputError) -> CompactStateExchangeError {
    match error {
        TypedOutputError::Truncated | TypedOutputError::OverBudget => {
            CompactStateExchangeError::Oversized
        }
        _ => CompactStateExchangeError::InvalidEnvelope,
    }
}

fn content_id(bytes: &[u8]) -> Option<ArtifactId> {
    ArtifactId::parse(encode_hex(&Sha256::digest(bytes)))
}

fn read_artifact<S: ArtifactStore>(
    store: &S,
    artifact_id: &ArtifactId,
    max_bytes: usize,
) -> Result<Vec<u8>, CompactStateExchangeError> {
    let mut bytes = Vec::with_capacity(max_bytes.min(PAGE_LIMIT.get() as usize));
    let mut offset = 0_u64;
    loop {
        let page = store
            .read_page(artifact_id, PageRequest::new(offset, PAGE_LIMIT))
            .map_err(|_| CompactStateExchangeError::Artifact)?;
        if page.bytes().is_empty() {
            return Err(CompactStateExchangeError::PageProgress);
        }
        if page.bytes().len() > PAGE_LIMIT.get() as usize {
            return Err(CompactStateExchangeError::PageProgress);
        }
        let next_len = bytes
            .len()
            .checked_add(page.bytes().len())
            .ok_or(CompactStateExchangeError::Oversized)?;
        if next_len > max_bytes {
            return Err(CompactStateExchangeError::Oversized);
        }
        bytes.extend_from_slice(page.bytes());
        let page_len = u64::try_from(page.bytes().len())
            .map_err(|_| CompactStateExchangeError::LengthMismatch)?;
        let expected_next = offset
            .checked_add(page_len)
            .ok_or(CompactStateExchangeError::PageProgress)?;
        match page.next_offset() {
            Some(next) if next == expected_next && next > offset => offset = next,
            Some(_) => return Err(CompactStateExchangeError::PageProgress),
            None => {
                if content_id(&bytes).as_ref() != Some(artifact_id) {
                    return Err(CompactStateExchangeError::DigestMismatch);
                }
                return Ok(bytes);
            }
        }
    }
}

fn verify_artifact<S: ArtifactStore>(
    store: &S,
    artifact_id: &ArtifactId,
    expected_len: u64,
    retain_start: u64,
    retain_end: u64,
) -> Result<Vec<u8>, CompactStateExchangeError> {
    if retain_start > retain_end || retain_end > expected_len {
        return Err(CompactStateExchangeError::InvalidSpan);
    }
    let mut hasher = Sha256::new();
    let mut retained = Vec::new();
    let mut offset = 0_u64;
    let mut length = 0_u64;
    loop {
        let page = store
            .read_page(artifact_id, PageRequest::new(offset, PAGE_LIMIT))
            .map_err(|_| CompactStateExchangeError::Artifact)?;
        if page.bytes().is_empty() {
            return Err(CompactStateExchangeError::PageProgress);
        }
        let page_len = u64::try_from(page.bytes().len())
            .map_err(|_| CompactStateExchangeError::LengthMismatch)?;
        if page_len > PAGE_LIMIT.get() {
            return Err(CompactStateExchangeError::PageProgress);
        }
        length = length
            .checked_add(page_len)
            .ok_or(CompactStateExchangeError::LengthMismatch)?;
        if length > expected_len {
            return Err(CompactStateExchangeError::LengthMismatch);
        }
        hasher.update(page.bytes());
        let expected_next = offset
            .checked_add(page_len)
            .ok_or(CompactStateExchangeError::PageProgress)?;
        let overlap_start = retain_start.max(offset);
        let overlap_end = retain_end.min(expected_next);
        if overlap_start < overlap_end {
            let local_start = usize::try_from(overlap_start - offset)
                .map_err(|_| CompactStateExchangeError::LengthMismatch)?;
            let local_end = usize::try_from(overlap_end - offset)
                .map_err(|_| CompactStateExchangeError::LengthMismatch)?;
            retained.extend_from_slice(&page.bytes()[local_start..local_end]);
        }
        match page.next_offset() {
            Some(next) if next == expected_next && next > offset => offset = next,
            Some(_) => return Err(CompactStateExchangeError::PageProgress),
            None => {
                if length != expected_len {
                    return Err(CompactStateExchangeError::LengthMismatch);
                }
                let digest = encode_hex(&hasher.finalize());
                if digest != artifact_id.as_str() {
                    return Err(CompactStateExchangeError::DigestMismatch);
                }
                if u64::try_from(retained.len()).ok() != Some(retain_end - retain_start) {
                    return Err(CompactStateExchangeError::LengthMismatch);
                }
                return Ok(retained);
            }
        }
    }
}

fn extract_compact_state_ref(
    envelope: &[u8],
) -> Result<(String, String, ArtifactId), CompactStateExchangeError> {
    let root = serde_json::from_slice::<Value>(envelope)
        .map_err(|_| CompactStateExchangeError::InvalidEnvelope)?;
    let root = exact_object(&root, &["from", "to", "output"])?;
    let output = root
        .get("output")
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?;
    let output = exact_object(
        output,
        &["schema_version", "node", "completeness", "payload"],
    )?;
    let payload = output
        .get("payload")
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?;
    let payload = exact_object(payload, &["kind", "key", "op", "artifacts"])?;
    if payload.get("kind").and_then(Value::as_str) != Some("compact_state") {
        return Err(CompactStateExchangeError::WrongPayload);
    }
    let key = payload
        .get("key")
        .and_then(Value::as_str)
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?
        .to_owned();
    let op = payload
        .get("op")
        .and_then(Value::as_str)
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?
        .to_owned();
    let artifacts = payload
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?;
    if artifacts.len() != 1 {
        return Err(CompactStateExchangeError::InvalidEnvelope);
    }
    let artifact = exact_object(&artifacts[0], &["artifact_id", "sha256"])?;
    let artifact_id = artifact
        .get("artifact_id")
        .and_then(Value::as_str)
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?;
    let artifact_id = ArtifactId::parse(artifact_id.to_owned())
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?;
    let digest = artifact
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?;
    if digest != format!("sha256:{}", artifact_id.as_str()) {
        return Err(CompactStateExchangeError::DigestMismatch);
    }
    Ok((key, op, artifact_id))
}

fn exact_object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, CompactStateExchangeError> {
    let object = value
        .as_object()
        .ok_or(CompactStateExchangeError::InvalidEnvelope)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(CompactStateExchangeError::InvalidEnvelope);
    }
    Ok(object)
}
