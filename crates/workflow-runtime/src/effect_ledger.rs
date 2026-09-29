//! Durable host-owned approvals and effect state, separate from graph checkpoints.
//!
//! Callers authenticate approvers and supply trusted policy/goal/clock inputs.
//! Digests are binding identities, not signatures. Raw proposals are never persisted.
//! The operator owns this host boundary; hostile same-UID pathname replacement is out of scope.
//! Reconciliation must resolve an indeterminate effect before retry; exactly-once external effects
//! require backend idempotency and are not implied by this ledger.
use crate::{
    ChildSandbox, FirewallDecision, ToolBridgeError, ToolBridgeErrorKind, ToolCallContext,
    ToolEnvelope, ToolFailure, ToolHandler, ToolRegistration, argument_fingerprint,
    firewall::{FirewallPolicy, ToolProposal, TrustedGoal, token},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
mod executor;
pub use executor::{
    EffectExecutor, ExecutionOutcome, ExecutorRegistry, Postcondition, RemoteObservation,
};

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Component, Path, PathBuf},
    sync::{Mutex, OnceLock},
};

/// Trusted application context; expiry is absolute Unix milliseconds, not process uptime.
#[derive(Clone, Serialize)]
pub struct ApprovalContext {
    pub operation_id: String,
    /// Lower-case SHA-256 of the pinned workflow lock.
    pub workflow_lock: String,
    pub approver: String,
    pub expires_at_unix_ms: u64,
}

/// Immutable request created only after deterministic hard-policy admission.
/// Not deserializable: persisted reports cannot be reconstituted as authority.
pub struct ApprovalRequest {
    approval_digest: String,
    effect_key: String,
    context: ApprovalContext,
    proposal: ToolProposal,
    rule_digest: String,
}
impl ApprovalRequest {
    /// Binds exact goal, canonical tool/arguments, target snapshots, policy, lock,
    /// operation, approver and expiry. Human approval never overrides hard denial.
    pub fn bind(
        goal: &TrustedGoal,
        policy: &FirewallPolicy,
        proposal: ToolProposal,
        context: ApprovalContext,
    ) -> Result<Self, LedgerError> {
        if !token(&context.operation_id, 256)
            || !token(&context.approver, 128)
            || context.expires_at_unix_ms == 0
            || context.workflow_lock.len() != 64
            || !context
                .workflow_lock
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(LedgerError::InvalidInput);
        }
        let decision = policy.evaluate(goal, &proposal);
        if decision.decision() == FirewallDecision::Deny {
            return Err(LedgerError::Denied);
        }
        let effect_key = argument_fingerprint(&json!({"domain":"effect-v1", "goal":goal.id,
            "operation":context.operation_id, "workflow_lock":context.workflow_lock,
            "intent":proposal.intent,"arguments":proposal.arguments}));
        let approval_digest = argument_fingerprint(&json!({"domain":"approval-v1",
            "hard_policy":decision.identity(),"effect_key":effect_key,"context":context}));
        let rule = policy
            .tools
            .get(&proposal.intent.tool_id)
            .ok_or(LedgerError::Denied)?;
        let rule_digest = argument_fingerprint(
            &serde_json::to_value(rule).map_err(|_| LedgerError::InvalidInput)?,
        );
        Ok(Self {
            proposal,
            rule_digest,
            approval_digest,
            effect_key,
            context,
        })
    }
    /// Exact immutable, hard-policy-admitted call for a registered executor.
    pub fn proposal(&self) -> &ToolProposal {
        &self.proposal
    }
    /// Approval identity to display and echo from the authenticated approval channel.
    pub fn approval_digest(&self) -> &str {
        &self.approval_digest
    }
    /// Remote deduplication key; renewing expiry or changing approver never changes it.
    pub fn effect_key(&self) -> &str {
        &self.effect_key
    }
}

/// Persisted closed lifecycle; committed is not success until verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    Proposed,
    Approved,
    Started,
    Committed,
    Verified,
    Failed,
    Indeterminate,
}

/// Privacy-safe failures, with no proposal payload or database path in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerError {
    InvalidInput,
    Denied,
    ApprovalMismatch,
    ApprovalRequired,
    Expired,
    Missing,
    Busy,
    Storage,
    Corrupt,
    ExecutorMismatch,
}
impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "effect ledger: {self:?}")
    }
}
impl std::error::Error for LedgerError {}
impl From<rusqlite::Error> for LedgerError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

/// SQLite FULL/WAL ledger, append-only lifecycle history and cross-process ownership.
/// The caller must provide a private, trusted directory and keep it in place.
pub struct EffectLedger {
    connection: Connection,
    // Keep the admission-bound descriptor alive; SQLite opens through this fd.
    _database: File,
    _lease: Lease,
}
impl EffectLedger {
    /// Opens an on-disk ledger. Another owner fails closed rather than racing a request.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        let parent = private_directory(path.parent().ok_or(LedgerError::InvalidInput)?)?;
        let metadata = fs::metadata(&parent).map_err(|_| LedgerError::Storage)?;
        let path = parent.join(path.file_name().ok_or(LedgerError::InvalidInput)?);
        let lock = path.with_extension("effect-lock");
        // ponytail: one owner per ledger, shard ledgers if independent-effect throughput matters.
        let lease = private_file(&lock, &metadata)?;
        let lease = Lease::acquire(lease, lock)?;
        let database = private_file(&path, &metadata)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            let sidecar = std::path::PathBuf::from(name);
            match fs::symlink_metadata(&sidecar) {
                Ok(_) => {
                    private_file(&sidecar, &metadata)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(LedgerError::Storage),
            }
        }
        let database_path = format!("/proc/self/fd/{}", database.as_raw_fd());
        let connection = Connection::open(database_path)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS effect_ledger_meta (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
            INSERT INTO effect_ledger_meta VALUES(1,1) ON CONFLICT(id) DO NOTHING;
            CREATE TABLE IF NOT EXISTS approvals (effect_key TEXT PRIMARY KEY, approval_digest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS effect_history (sequence INTEGER PRIMARY KEY, effect_key TEXT NOT NULL REFERENCES approvals(effect_key), state TEXT NOT NULL);")?;
        let version: i64 = connection.query_row(
            "SELECT version FROM effect_ledger_meta WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if version != 1 {
            return Err(LedgerError::Corrupt);
        }
        database.sync_all().map_err(|_| LedgerError::Storage)?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| LedgerError::Storage)?;
        Ok(Self {
            connection,
            _database: database,
            _lease: lease,
        })
    }
    /// Records an immutable proposal; replay cannot replace or reapprove an existing key.
    pub fn propose(&mut self, request: &ApprovalRequest) -> Result<EffectState, LedgerError> {
        if self.binding(request)?.is_some() {
            return self.state(request);
        }
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO approvals VALUES(?1,?2)",
            params![request.effect_key, request.approval_digest],
        )?;
        tx.execute(
            "INSERT INTO effect_history(effect_key,state) VALUES(?1,?2)",
            params![request.effect_key, encode(EffectState::Proposed)?],
        )?;
        tx.commit()?;
        Ok(EffectState::Proposed)
    }
    /// Host-only approval entry point. The embedding application authenticates `actor`;
    /// never expose this method directly to untrusted model tool dispatch.
    pub fn approve(
        &mut self,
        request: &ApprovalRequest,
        digest: &str,
        actor: &str,
        now_unix_ms: u64,
    ) -> Result<EffectState, LedgerError> {
        if digest != request.approval_digest || actor != request.context.approver {
            return Err(LedgerError::ApprovalMismatch);
        }
        if now_unix_ms >= request.context.expires_at_unix_ms {
            return Err(LedgerError::Expired);
        }
        match self.state(request)? {
            EffectState::Proposed => self.append(request, EffectState::Approved),
            state => Ok(state),
        }
    }
    /// Returns lifecycle history in durable commit order, without raw arguments.
    pub fn history(&self, request: &ApprovalRequest) -> Result<Vec<EffectState>, LedgerError> {
        self.binding(request)?.ok_or(LedgerError::Missing)?;
        let mut statement = self
            .connection
            .prepare("SELECT state FROM effect_history WHERE effect_key=?1 ORDER BY sequence")?;
        let history = statement
            .query_map([&request.effect_key], |r| r.get::<_, String>(0))?
            .map(|s| serde_json::from_str(&s?).map_err(|_| LedgerError::Corrupt))
            .collect::<Result<Vec<EffectState>, LedgerError>>()?;
        use EffectState::*;
        if history.first() != Some(&Proposed)
            || history.windows(2).any(|pair| {
                !matches!(
                    pair,
                    [Proposed, Approved]
                        | [Approved, Started | Failed]
                        | [Started, Committed | Failed | Indeterminate]
                        | [Indeterminate, Committed | Failed]
                        | [Committed, Verified | Failed]
                )
            })
        {
            return Err(LedgerError::Corrupt);
        }
        Ok(history)
    }
    /// Reads the current state after validating the complete approval identity.
    pub fn state(&self, request: &ApprovalRequest) -> Result<EffectState, LedgerError> {
        self.history(request)?
            .last()
            .copied()
            .ok_or(LedgerError::Corrupt)
    }
    fn binding(&self, request: &ApprovalRequest) -> Result<Option<String>, LedgerError> {
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT approval_digest FROM approvals WHERE effect_key=?1",
                [&request.effect_key],
                |r| r.get(0),
            )
            .optional()?;
        if stored
            .as_ref()
            .is_some_and(|digest| digest != &request.approval_digest)
        {
            return Err(LedgerError::ApprovalMismatch);
        }
        Ok(stored)
    }
    fn append(
        &mut self,
        request: &ApprovalRequest,
        state: EffectState,
    ) -> Result<EffectState, LedgerError> {
        self.connection.execute(
            "INSERT INTO effect_history(effect_key,state) VALUES(?1,?2)",
            params![request.effect_key, encode(state)?],
        )?;
        Ok(state)
    }
}

/// Executes one already-approved effect through the ordinary ToolBridge handler boundary.
/// The request is immutable and the executor registry is matched to its Firewall rule digest.
pub struct DurableEffectHandler {
    request: ApprovalRequest,
    ledger: std::sync::Mutex<EffectLedger>,
    registry: std::sync::Mutex<ExecutorRegistry>,
    registration: ToolRegistration,
}

impl DurableEffectHandler {
    /// Binds a durable request to the executor identity it was admitted for.
    pub fn new(
        request: ApprovalRequest,
        ledger: EffectLedger,
        registry: ExecutorRegistry,
        registration: ToolRegistration,
    ) -> Result<Self, LedgerError> {
        if registration.name() != request.proposal.intent.tool_id
            || registration.provenance().tool_version() != request.proposal.intent.tool_version
        {
            return Err(LedgerError::ExecutorMismatch);
        }
        Ok(Self {
            request,
            ledger: std::sync::Mutex::new(ledger),
            registry: std::sync::Mutex::new(registry),
            registration,
        })
    }

    /// Returns the exact registration used by the handler.
    pub fn registration(&self) -> &ToolRegistration {
        &self.registration
    }

    fn now_unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .unwrap_or(u64::MAX)
    }

    fn bridge_error(error: LedgerError) -> ToolBridgeError {
        let kind = match error {
            LedgerError::InvalidInput => ToolBridgeErrorKind::InvalidInput,
            LedgerError::ApprovalMismatch
            | LedgerError::ApprovalRequired
            | LedgerError::Denied
            | LedgerError::Expired
            | LedgerError::Missing => ToolBridgeErrorKind::ApprovalDenied,
            LedgerError::Busy
            | LedgerError::Storage
            | LedgerError::Corrupt
            | LedgerError::ExecutorMismatch => ToolBridgeErrorKind::HandlerFailed,
        };
        ToolBridgeError::new(kind)
    }
}

impl ToolHandler for DurableEffectHandler {
    fn implementation_identity(&self) -> String {
        format!(
            "durable-effect:{}",
            self.registration.implementation_digest()
        )
    }

    fn registration(&self) -> Option<ToolRegistration> {
        Some(self.registration.clone())
    }

    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        let expected = serde_json::to_value(&self.request.proposal.arguments)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        if arguments != &expected {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        }

        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let mut state = ledger.state(&self.request).map_err(Self::bridge_error)?;
        for _ in 0..4 {
            if matches!(state, EffectState::Verified | EffectState::Failed) {
                break;
            }
            state = ledger
                .advance(&self.request, &mut registry, Self::now_unix_ms())
                .map_err(Self::bridge_error)?;
        }

        match state {
            EffectState::Verified => Ok(ToolEnvelope::success(
                json!({"effect_key": self.request.effect_key(), "state": "verified"}),
                self.registration.provenance().clone(),
            )),
            EffectState::Failed => Ok(ToolEnvelope::failure(
                ToolFailure::Internal,
                self.registration.provenance().clone(),
            )),
            EffectState::Indeterminate
            | EffectState::Started
            | EffectState::Committed
            | EffectState::Proposed
            | EffectState::Approved => {
                Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))
            }
        }
    }
}

fn encode(state: EffectState) -> Result<String, LedgerError> {
    serde_json::to_string(&state).map_err(|_| LedgerError::Corrupt)
}
// Resolve directory links without replacing them; validate every traversed link
// and directory, including intermediate targets that canonicalize alone hides.
fn private_directory(path: &Path) -> Result<PathBuf, LedgerError> {
    let uid = fs::metadata("/proc/self")
        .map_err(|_| LedgerError::Storage)?
        .uid();
    let mut pending = std::env::current_dir()
        .map_err(|_| LedgerError::Storage)?
        .join(path);
    for _ in 0..40 {
        let mut resolved = PathBuf::new();
        let mut redirected = None;
        let mut components = pending.components();
        while let Some(component) = components.next() {
            match component {
                Component::RootDir => resolved.push("/"),
                Component::CurDir => continue,
                Component::ParentDir => {
                    resolved.pop();
                }
                Component::Normal(name) => resolved.push(name),
                Component::Prefix(_) => return Err(LedgerError::InvalidInput),
            }
            let metadata = fs::symlink_metadata(&resolved).map_err(|_| LedgerError::Storage)?;
            if ![0, uid].contains(&metadata.uid()) {
                return Err(LedgerError::InvalidInput);
            }
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(&resolved).map_err(|_| LedgerError::Storage)?;
                redirected = Some(
                    resolved
                        .parent()
                        .ok_or(LedgerError::InvalidInput)?
                        .join(target)
                        .join(components.as_path()),
                );
                break;
            }
            if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
                return Err(LedgerError::InvalidInput);
            }
        }
        if let Some(next) = redirected {
            pending = next;
        } else {
            let metadata = fs::metadata(&resolved).map_err(|_| LedgerError::Storage)?;
            if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                return Err(LedgerError::InvalidInput);
            }
            return Ok(resolved);
        }
    }
    Err(LedgerError::InvalidInput)
}

fn private_file(path: &Path, directory: &fs::Metadata) -> Result<File, LedgerError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                LedgerError::InvalidInput
            } else {
                LedgerError::Storage
            }
        })?;
    let metadata = file.metadata().map_err(|_| LedgerError::Storage)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.uid() != directory.uid()
        || metadata.dev() != directory.dev()
    {
        return Err(LedgerError::InvalidInput);
    }
    Ok(file)
}

static LEASES: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

struct Lease {
    file: File,
    path: PathBuf,
    owner_pid: libc::pid_t,
}

impl Lease {
    fn acquire(file: File, path: PathBuf) -> Result<Self, LedgerError> {
        let leases = LEASES.get_or_init(|| Mutex::new(HashSet::new()));
        let mut held = leases.lock().map_err(|_| LedgerError::Storage)?;
        if !held.insert(path.clone()) {
            return Err(LedgerError::Busy);
        }
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &mut lock) };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            held.remove(&path);
            return Err(
                if error.raw_os_error() == Some(libc::EACCES)
                    || error.raw_os_error() == Some(libc::EAGAIN)
                {
                    LedgerError::Busy
                } else {
                    LedgerError::Storage
                },
            );
        }
        let owner_pid = unsafe { libc::getpid() };
        drop(held);
        Ok(Self {
            file,
            path,
            owner_pid,
        })
    }
}

fn unlock_lease(fd: i32) -> Result<(), ()> {
    let mut unlock = libc::flock {
        l_type: libc::F_UNLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    loop {
        let result = unsafe { libc::fcntl(fd, libc::F_OFD_SETLK, &mut unlock) };
        if result == 0 {
            return Ok(());
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(());
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } == self.owner_pid {
            // Do not rely on close: explicitly release only the process that acquired it.
            // An unexpected unlock failure is fail-stop rather than silently weakening the lease.
            if unlock_lease(self.file.as_raw_fd()).is_err() {
                std::process::abort();
            }
            if let Some(leases) = LEASES.get() {
                let _ = leases.lock().map(|mut held| {
                    held.remove(&self.path);
                });
            }
        }
    }
}
