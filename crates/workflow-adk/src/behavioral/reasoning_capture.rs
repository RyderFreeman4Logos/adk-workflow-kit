//! A private process-local artifact lease, reached only by explicit host capture.
#[cfg(test)]
#[path = "reasoning_capture_tests.rs"]
mod tests;
use super::{HostModelProbe, ModelProbeObservation};
use crate::{AdkGraphError, ModelRouteCancellation};
use std::{num::NonZeroU64, time::Instant};
use workflow_runtime::behavioral::trajectory::ReasoningStatus;
use workflow_runtime::{
    ArtifactId, ArtifactPage, ArtifactStore, InMemoryArtifactStore, PageRequest,
};

/// Maximum retained decoded reasoning bytes, aggregated across all Thinking parts.
/// This is not a bound on provider parser allocations or RSS.
pub const MAX_REASONING_BYTES: usize = 16_384;
const PAGE_BYTES: NonZeroU64 = NonZeroU64::new(4096).expect("positive page bound");

/// The trusted reader can complete or reject the observation, never return raw data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasoningCaptureCompletion {
    Complete,
    Rejected,
}

/// Closed content-free failures; no artifact identifiers, bytes or callback errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasoningReadError {
    Denied,
    Unavailable,
    InvalidPage,
}

/// Borrowed access to exactly one unpublished observation's reasoning artifact.
/// No Debug/Serde, owned artifact page, raw identifier or generic store is exposed.
/// Reads are bounded to 4096 bytes and checked against the original deadline and
/// cancellation. At/after expiry no new read is admitted; existing borrows/copies
/// cannot be recalled. The authenticated host reader is responsible for any copies.
///
/// ```compile_fail,E0277
/// use workflow_adk::behavioral::ReasoningCaptureReader;
/// fn debug(reader: &ReasoningCaptureReader<'_>) { println!("{reader:?}"); }
/// ```
/// ```compile_fail,E0277
/// use workflow_adk::behavioral::ReasoningCaptureReader;
/// fn persist(reader: &ReasoningCaptureReader<'_>) { let _ = serde_json::to_string(reader); }
/// ```
pub struct ReasoningCaptureReader<'a> {
    owner: &'a ReasoningArtifact,
    binding: &'a str,
    deadline: Instant,
    cancellation: &'a ModelRouteCancellation,
    page: Option<ArtifactPage>,
}

impl ReasoningCaptureReader<'_> {
    /// Content-free provider visibility, not an observer signal or verdict.
    pub fn status(&self) -> ReasoningStatus {
        if self.owner.id.is_some() {
            ReasoningStatus::Present
        } else {
            ReasoningStatus::Unavailable
        }
    }

    /// Lends one bounded page until the next mutable reader operation. The caller
    /// cannot choose another artifact/run/observation. Expiry denies this operation;
    /// it does not destroy the owner or preempt an executing callback.
    pub fn read(&mut self, offset: u64, limit: NonZeroU64) -> Result<&[u8], ReasoningReadError> {
        self.read_at(offset, limit, Instant::now())
    }

    fn read_at(
        &mut self,
        offset: u64,
        limit: NonZeroU64,
        now: Instant,
    ) -> Result<&[u8], ReasoningReadError> {
        check_access(self.deadline, self.cancellation, now)?;
        if self.binding != self.owner.binding {
            return Err(ReasoningReadError::Denied);
        }
        let id = self
            .owner
            .id
            .as_ref()
            .ok_or(ReasoningReadError::Unavailable)?;
        self.page = Some(
            self.owner
                .store
                .read_page(id, PageRequest::new(offset, limit))
                .map_err(|_| ReasoningReadError::InvalidPage)?,
        );
        self.page
            .as_ref()
            .map(ArtifactPage::bytes)
            .ok_or(ReasoningReadError::InvalidPage)
    }
}

struct ReasoningArtifact {
    store: InMemoryArtifactStore,
    id: Option<ArtifactId>,
    binding: String,
    #[cfg(test)]
    released: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl ReasoningArtifact {
    fn new(bytes: Vec<u8>, binding: String) -> Result<Self, AdkGraphError> {
        let mut store = InMemoryArtifactStore::new(
            NonZeroU64::new(MAX_REASONING_BYTES as u64).ok_or(AdkGraphError::Failed)?,
            PAGE_BYTES,
        );
        let id = if bytes.is_empty() {
            None
        } else {
            Some(store.put(&bytes).map_err(|_| AdkGraphError::Failed)?)
        };
        Ok(Self {
            store,
            id,
            binding,
            #[cfg(test)]
            released: None,
        })
    }
}

#[cfg(test)]
impl Drop for ReasoningArtifact {
    fn drop(&mut self) {
        if let Some(released) = &self.released {
            released.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

fn check_access(
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
    now: Instant,
) -> Result<(), ReasoningReadError> {
    if cancellation.is_cancelled() || now >= deadline {
        Err(ReasoningReadError::Denied)
    } else {
        Ok(())
    }
}

impl HostModelProbe<'_> {
    /// Explicit model-v2/trajectory-v2 capture under an independently enabled live
    /// host approval and capture declaration. Default observe/publish/feedback stay
    /// strict. Only after terminal JSON and sealed-worker success does a trusted
    /// synchronous host reader receive a process-local artifact lease.
    ///
    /// Retention ends when this owner returns/errors/is dropped, not at an exact
    /// wall-clock instant. Cancellation/expiry are checked before callback, on every
    /// read and after callback. An executing callback is cooperative: no hard
    /// preemption, zeroization, or withdrawal of trusted copies is promised. Raw
    /// reasoning never becomes receipt, event, error or canonical-observer input.
    ///
    /// ```compile_fail,E0308
    /// use workflow_adk::behavioral::HostModelProbe;
    /// async fn escape(host: HostModelProbe<'_>) {
    ///     host.observe_with_reasoning_capture(|reader| reader.read(0, 1.try_into().unwrap()).unwrap()).await;
    /// }
    /// ```
    /// A borrow also cannot escape through the callback's captured environment:
    /// ```compile_fail,E0521
    /// use workflow_adk::behavioral::{HostModelProbe, ReasoningCaptureCompletion};
    /// async fn escape(host: HostModelProbe<'_>) {
    ///     let mut escaped = None;
    ///     host.observe_with_reasoning_capture(|reader| {
    ///         escaped = Some(reader.read(0, 1.try_into().unwrap()).unwrap());
    ///         ReasoningCaptureCompletion::Complete
    ///     }).await;
    ///     drop(escaped);
    /// }
    /// ```
    /// The same public setup accepts a consumer returning only the closed result:
    /// ```no_run
    /// use workflow_adk::behavioral::{HostModelProbe, ModelProbeObservation, ReasoningCaptureCompletion};
    /// use workflow_adk::AdkGraphError;
    /// async fn consume(host: HostModelProbe<'_>) -> Result<ModelProbeObservation, AdkGraphError> {
    ///     host.observe_with_reasoning_capture(|reader| {
    ///         let _visibility = reader.status();
    ///         match reader.read(0, 4096.try_into().unwrap()) {
    ///             Ok(bytes) => { let _count = bytes.len(); ReasoningCaptureCompletion::Complete }
    ///             Err(_) => ReasoningCaptureCompletion::Rejected,
    ///         }
    ///     }).await
    /// }
    /// ```
    pub async fn observe_with_reasoning_capture(
        self,
        read: impl FnOnce(&mut ReasoningCaptureReader<'_>) -> ReasoningCaptureCompletion,
    ) -> Result<ModelProbeObservation, AdkGraphError> {
        let deadline = self.route.deadline();
        let cancellation = self.cancellation;
        let run = self.workdir.run_id().as_str().to_owned();
        let (captured, bytes) = self.capture_with_reasoning(true).await?;
        let binding = crate::model_invocation::digest(
            crate::model_invocation::canonical_json(
                &serde_json::json!({"run":run,"observation":captured.observation.report.to_json()
                .map_err(|_| AdkGraphError::Failed)?}),
            )
            .as_bytes(),
        );
        let owner = ReasoningArtifact::new(bytes, binding.clone())?;
        visit(&owner, &binding, deadline, cancellation, read)?;
        Ok(captured.observation)
    }
}

fn visit(
    owner: &ReasoningArtifact,
    binding: &str,
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
    read: impl FnOnce(&mut ReasoningCaptureReader<'_>) -> ReasoningCaptureCompletion,
) -> Result<(), AdkGraphError> {
    check_access(deadline, cancellation, Instant::now())
        .map_err(|_| AdkGraphError::AuthorizationDenied)?;
    let completion = read(&mut ReasoningCaptureReader {
        owner,
        binding,
        deadline,
        cancellation,
        page: None,
    });
    check_access(deadline, cancellation, Instant::now())
        .map_err(|_| AdkGraphError::AuthorizationDenied)?;
    if completion == ReasoningCaptureCompletion::Rejected {
        return Err(AdkGraphError::Failed);
    }
    Ok(())
}

pub(crate) fn declaration_contract() -> serde_json::Value {
    let mut contract = super::model_probe::declaration_contract();
    contract["reasoning_capture"] = serde_json::json!({
        "protocol":"process-local-lease-v1", "max_reasoning_bytes":MAX_REASONING_BYTES,
        "max_page_bytes":PAGE_BYTES.get(), "retention":"owner-return-or-drop",
        "access":"trusted-host-callback-original-deadline", "redaction":"never-published",
    });
    contract
}

/// Completed typed facts and their independent lease disposition. A late denial
/// must not erase a parse that already completed; no raw bytes cross this seam.
pub(super) struct ClosedClaimsRead {
    pub parsed: Option<(
        ReasoningStatus,
        Option<workflow_runtime::behavioral::trajectory::ClosedTrajectoryClaims>,
    )>,
    pub disposition: Result<(), AdkGraphError>,
}

/// Consume the same private lease through its checked reader, exporting typed claims only.
pub(super) fn read_closed_claims(
    bytes: Vec<u8>,
    binding: String,
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
) -> ClosedClaimsRead {
    read_closed_claims_after_parse(bytes, binding, deadline, cancellation, || {})
}

/// The private callback runs after typed parsing and before the unchanged late
/// lease check; it cannot receive or export reasoning bytes.
pub(super) fn read_closed_claims_after_parse(
    bytes: Vec<u8>,
    binding: String,
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
    after_parse: impl FnOnce(),
) -> ClosedClaimsRead {
    let owner = match ReasoningArtifact::new(bytes, binding.clone()) {
        Ok(owner) => owner,
        Err(error) => {
            return ClosedClaimsRead {
                parsed: None,
                disposition: Err(error),
            };
        }
    };
    let mut parsed = None;
    let disposition = visit(&owner, &binding, deadline, cancellation, |reader| {
        let result = if reader.status() == ReasoningStatus::Unavailable {
            (ReasoningStatus::Unavailable, None)
        } else {
            match reader.read(
                0,
                NonZeroU64::new(1025).expect("positive oversize witness bound"),
            ) {
                Ok(bytes) => {
                    workflow_runtime::behavioral::trajectory::parse_closed_claims(Some(bytes))
                }
                Err(_) => return ReasoningCaptureCompletion::Rejected,
            }
        };
        parsed = Some(result);
        after_parse();
        ReasoningCaptureCompletion::Complete
    });
    ClosedClaimsRead {
        parsed,
        disposition,
    }
}
