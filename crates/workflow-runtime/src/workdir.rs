use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{RunId, encode_hex};

/// Allocates one owned filesystem root per run.
///
/// This Linux x86_64-only primitive trusts the caller-managed base. It proves
/// neither ownership, ACLs, mount identity, nor same-UID or multi-tenant
/// isolation. It does not close hostile-parent races after its last identity
/// check, use descriptor-relative deletion or `openat2`, or prevent a process
/// from opening a known sibling host path. Cleanup is safe only after users of
/// the root stop.
pub struct WorkdirManager {
    base: PathBuf,
    base_identity: Identity,
}

impl WorkdirManager {
    /// Uses an existing caller-managed base directory for future allocations.
    pub fn new(base: impl AsRef<Path>) -> Result<Self, WorkdirError> {
        let metadata = fs::symlink_metadata(base.as_ref())
            .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InspectBase, error))?;
        if metadata.file_type().is_symlink() {
            return Err(WorkdirError::new(WorkdirErrorKind::BaseSymlink));
        }
        if !metadata.is_dir() {
            return Err(WorkdirError::new(WorkdirErrorKind::BaseNotDirectory));
        }

        Ok(Self {
            base: fs::canonicalize(base)
                .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InspectBase, error))?,
            base_identity: Identity::from_metadata(&metadata),
        })
    }

    pub(crate) fn base_path(&self) -> &Path {
        &self.base
    }

    /// Allocates a fresh root for `run_id` with no materialized inputs.
    pub fn allocate(&self, run_id: &RunId) -> Result<RunWorkdir, WorkdirError> {
        self.materialize(run_id, &Materialization::default())
    }

    /// Allocates a fresh root for `run_id`, materializing `materialization`
    /// into the immutable `input/`/`package/`/`skills/`/`refs/` directories and
    /// recording each blob's SHA-256 on the manifest.
    pub fn materialize(
        &self,
        run_id: &RunId,
        materialization: &Materialization,
    ) -> Result<RunWorkdir, WorkdirError> {
        self.verify_base()?;
        let mut entropy = File::open("/dev/urandom")
            .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::Entropy, error))?;
        self.allocate_with(
            run_id,
            || {
                let mut bytes = [0_u8; 16];
                entropy
                    .read_exact(&mut bytes)
                    .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::Entropy, error))?;
                Ok(WorkdirId(encode_hex(&bytes)))
            },
            |root, id| initialize_layout(root, id, materialization),
        )
    }

    fn allocate_with<IdSource, Initializer>(
        &self,
        run_id: &RunId,
        mut id_source: IdSource,
        mut initializer: Initializer,
    ) -> Result<RunWorkdir, WorkdirError>
    where
        IdSource: FnMut() -> Result<WorkdirId, WorkdirError>,
        Initializer: FnMut(&Path, &WorkdirId) -> Result<(), WorkdirError>,
    {
        self.verify_base()?;
        for _ in 0..8 {
            let id = id_source()?;
            let root = self.base.join(id.as_str());
            match DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(WorkdirError::with_source(
                        WorkdirErrorKind::CreateRoot,
                        error,
                    ));
                }
            }
            let root_metadata = fs::symlink_metadata(&root)
                .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::CreateRoot, error))?;
            let root_identity = Identity::from_metadata(&root_metadata);
            if let Err(primary) = initializer(&root, &id) {
                return match remove_owned_root(&self.base, self.base_identity, &root, root_identity)
                {
                    Ok(_) => Err(primary),
                    Err(rollback) => Err(WorkdirError::rollback(primary, rollback)),
                };
            }

            return Ok(RunWorkdir {
                run_id: run_id.clone(),
                id,
                root,
                base: self.base.clone(),
                base_identity: self.base_identity,
                root_identity,
                active: true,
            });
        }
        Err(WorkdirError::new(WorkdirErrorKind::AllocationExhausted))
    }

    fn verify_base(&self) -> Result<(), WorkdirError> {
        let metadata = fs::symlink_metadata(&self.base)
            .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InspectBase, error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || Identity::from_metadata(&metadata) != self.base_identity
        {
            Err(WorkdirError::new(WorkdirErrorKind::BaseChanged))
        } else {
            Ok(())
        }
    }
}

fn remove_owned_root(
    base: &Path,
    base_identity: Identity,
    root: &Path,
    root_identity: Identity,
) -> Result<CleanupOutcome, WorkdirError> {
    let base_metadata = fs::symlink_metadata(base)
        .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InspectBase, error))?;
    if base_metadata.file_type().is_symlink()
        || !base_metadata.is_dir()
        || Identity::from_metadata(&base_metadata) != base_identity
    {
        return Err(WorkdirError::new(WorkdirErrorKind::BaseChanged));
    }

    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CleanupOutcome::AlreadyAbsent);
        }
        Err(error) => {
            return Err(WorkdirError::with_source(WorkdirErrorKind::Cleanup, error));
        }
    };
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || Identity::from_metadata(&root_metadata) != root_identity
    {
        return Err(WorkdirError::new(WorkdirErrorKind::RootChanged));
    }

    // Restore owner-write on the four immutable layout dirs so `remove_dir_all`
    // can unlink the `content.bin` children they hold when materialized. Their
    // published run-time mode stays 0o555; this write bit is teardown-only.
    for name in ["input", "package", "skills", "refs"] {
        let _ = fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700));
    }

    match fs::remove_dir_all(root) {
        Ok(()) => Ok(CleanupOutcome::Removed),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(CleanupOutcome::AlreadyAbsent),
        Err(error) => Err(WorkdirError::with_source(WorkdirErrorKind::Cleanup, error)),
    }
}

/// The result of an explicit cleanup request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupOutcome {
    /// The owned root was removed.
    Removed,
    /// The root was already absent or the handle was inactive.
    AlreadyAbsent,
}

static NEXT_OUTPUT_STAGE: AtomicU64 = AtomicU64::new(0);

/// A run-local output directory that becomes visible only after acceptance.
#[derive(Debug)]
pub(crate) struct StagedOutput {
    staging: Option<PathBuf>,
    visible: PathBuf,
}

impl StagedOutput {
    pub(crate) fn path(&self) -> &Path {
        self.staging
            .as_deref()
            .expect("staged output path exists until commit")
    }

    pub(crate) fn commit(mut self) -> Result<(), WorkdirError> {
        let staging = self
            .staging
            .as_ref()
            .expect("staged output path exists until commit");
        let entries = fs::read_dir(staging)
            .and_then(|entries| entries.collect::<Result<Vec<_>, _>>())
            .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::CommitOutput, error))?;
        for entry in &entries {
            let file_type = entry.file_type().map_err(|error| {
                WorkdirError::with_source(WorkdirErrorKind::CommitOutput, error)
            })?;
            if !file_type.is_file() || self.visible.join(entry.file_name()).exists() {
                return Err(WorkdirError::new(WorkdirErrorKind::CommitOutput));
            }
        }
        for entry in entries {
            fs::rename(entry.path(), self.visible.join(entry.file_name())).map_err(|error| {
                WorkdirError::with_source(WorkdirErrorKind::CommitOutput, error)
            })?;
        }
        fs::remove_dir(staging)
            .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::CommitOutput, error))?;
        self.staging = None;
        Ok(())
    }
}

impl Drop for StagedOutput {
    fn drop(&mut self) {
        if let Some(staging) = self.staging.take() {
            let _ = fs::remove_dir_all(staging);
        }
    }
}

#[derive(Serialize)]
struct Manifest<'a> {
    schema_version: u8,
    workdir_id: &'a str,
    paths: ManifestPaths,
    hashes: BTreeMap<&'static str, String>,
}

#[derive(Serialize)]
struct ManifestPaths {
    work: &'static str,
    out: &'static str,
    tmp: &'static str,
    input: &'static str,
    package: &'static str,
    skills: &'static str,
    refs: &'static str,
}

/// Read-only blobs to materialize into a run's immutable directories.
///
/// Each present blob is written as `content.bin` inside its directory, the
/// directory is locked to `0o555`, and the blob's SHA-256 is recorded on the
/// manifest so a later hash check detects mutation.
#[derive(Clone, Default)]
pub struct Materialization {
    pub input: Option<Vec<u8>>,
    pub package: Option<Vec<u8>>,
    pub skills: Option<Vec<u8>>,
    pub refs: Option<Vec<u8>>,
}

fn initialize_layout(
    root: &Path,
    id: &WorkdirId,
    materialization: &Materialization,
) -> Result<(), WorkdirError> {
    for name in ["work", "out", "tmp"] {
        DirBuilder::new()
            .mode(0o700)
            .create(root.join(name))
            .map_err(|error| {
                WorkdirError::with_source(WorkdirErrorKind::InitializeLayout, error)
            })?;
    }

    let mut hashes = BTreeMap::new();
    for (name, bytes) in [
        ("input", materialization.input.as_deref()),
        ("package", materialization.package.as_deref()),
        ("skills", materialization.skills.as_deref()),
        ("refs", materialization.refs.as_deref()),
    ] {
        if let Some(hash) = materialize_immutable_dir(root, name, bytes)? {
            hashes.insert(name, hash);
        }
    }

    let manifest = serde_json::to_vec(&Manifest {
        schema_version: 1,
        workdir_id: id.as_str(),
        paths: ManifestPaths {
            work: "work",
            out: "out",
            tmp: "tmp",
            input: "input",
            package: "package",
            skills: "skills",
            refs: "refs",
        },
        hashes,
    })
    .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InitializeLayout, error))?;
    let temporary = root.join(".manifest.json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InitializeLayout, error))?;
    file.write_all(&manifest)
        .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InitializeLayout, error))?;
    drop(file);
    fs::rename(temporary, root.join("manifest.json"))
        .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::PublishManifest, error))?;
    Ok(())
}

/// Creates one immutable directory, writes its blob if any, locks it read-only,
/// and returns the blob's SHA-256 when materialized.
fn materialize_immutable_dir(
    root: &Path,
    name: &str,
    bytes: Option<&[u8]>,
) -> Result<Option<String>, WorkdirError> {
    let dir = root.join(name);
    DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InitializeLayout, error))?;
    let hash = match bytes {
        Some(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            File::create(dir.join("content.bin"))
                .and_then(|mut file| file.write_all(bytes))
                .map_err(|error| {
                    WorkdirError::with_source(WorkdirErrorKind::InitializeLayout, error)
                })?;
            Some(encode_hex(&hasher.finalize()))
        }
        None => None,
    };
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o555))
        .map_err(|error| WorkdirError::with_source(WorkdirErrorKind::InitializeLayout, error))?;
    Ok(hash)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// A stable workdir failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkdirErrorKind {
    /// The trusted base could not be inspected.
    InspectBase,
    /// The caller path has a final-component symlink.
    BaseSymlink,
    /// The caller path is not a directory.
    BaseNotDirectory,
    /// The trusted base no longer has its recorded identity.
    BaseChanged,
    /// Random allocation bytes could not be obtained.
    Entropy,
    /// An allocation root could not be atomically created.
    CreateRoot,
    /// All permitted allocation attempts collided.
    AllocationExhausted,
    /// A fresh root's layout could not be initialized.
    InitializeLayout,
    /// The completed manifest could not be published.
    PublishManifest,
    /// A failed allocation could not be rolled back safely.
    Rollback,
    /// An allocated root no longer has its recorded identity.
    RootChanged,
    /// A private output staging directory could not be created.
    StageOutput,
    /// Staged output could not be atomically published.
    CommitOutput,
    /// An allocated root could not be removed.
    Cleanup,
}

/// A categorized workdir failure with a privacy-safe message.
#[derive(Debug)]
pub struct WorkdirError {
    kind: WorkdirErrorKind,
    source: Option<BoxError>,
}

type BoxError = Box<dyn Error + Send + Sync>;

impl WorkdirError {
    fn new(kind: WorkdirErrorKind) -> Self {
        Self { kind, source: None }
    }

    fn with_source(kind: WorkdirErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
    }

    fn rollback(mut primary: Self, rollback: Self) -> Self {
        let rollback: BoxError = Box::new(rollback);
        primary.source = Some(match primary.source.take() {
            Some(cause) => Box::new(CauseThen {
                cause,
                next: rollback,
            }),
            None => rollback,
        });
        Self {
            kind: WorkdirErrorKind::Rollback,
            source: Some(Box::new(primary)),
        }
    }

    /// Returns the stable failure category.
    pub fn kind(&self) -> WorkdirErrorKind {
        self.kind
    }
}

impl fmt::Display for WorkdirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            WorkdirErrorKind::InspectBase => "failed to inspect workdir base",
            WorkdirErrorKind::BaseSymlink => "workdir base must not be a symlink",
            WorkdirErrorKind::BaseNotDirectory => "workdir base must be a directory",
            WorkdirErrorKind::BaseChanged => "workdir base identity changed",
            WorkdirErrorKind::Entropy => "failed to obtain workdir entropy",
            WorkdirErrorKind::CreateRoot => "failed to create workdir root",
            WorkdirErrorKind::AllocationExhausted => "workdir allocation attempts exhausted",
            WorkdirErrorKind::InitializeLayout => "failed to initialize workdir layout",
            WorkdirErrorKind::PublishManifest => "failed to publish workdir manifest",
            WorkdirErrorKind::Rollback => "failed to roll back workdir allocation",
            WorkdirErrorKind::RootChanged => "workdir root identity changed",
            WorkdirErrorKind::StageOutput => "failed to stage run output",
            WorkdirErrorKind::CommitOutput => "failed to commit run output",
            WorkdirErrorKind::Cleanup => "failed to clean up workdir root",
        })
    }
}

impl Error for WorkdirError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[derive(Debug)]
struct CauseThen {
    cause: BoxError,
    next: BoxError,
}

impl fmt::Display for CauseThen {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.cause, formatter)
    }
}

impl Error for CauseThen {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.next.as_ref())
    }
}

/// An opaque random allocation identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WorkdirId(String);

impl WorkdirId {
    /// Returns the lowercase hexadecimal identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A run's owned filesystem root.
///
/// Dropping this handle does not remove the root; call [`Self::cleanup`]
/// explicitly after all users of the root have stopped.
pub struct RunWorkdir {
    run_id: RunId,
    id: WorkdirId,
    root: PathBuf,
    base: PathBuf,
    base_identity: Identity,
    root_identity: Identity,
    active: bool,
}

impl RunWorkdir {
    /// Returns the caller's run identifier exactly as supplied.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Returns the allocation identifier.
    pub fn id(&self) -> &WorkdirId {
        &self.id
    }

    /// Returns the allocation root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the published manifest path.
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    /// Returns the mutable work directory.
    pub fn work_dir(&self) -> PathBuf {
        self.root.join("work")
    }

    /// Returns the immutable input directory.
    pub fn input_dir(&self) -> PathBuf {
        self.root.join("input")
    }

    /// Returns the immutable workflow package directory.
    pub fn package_dir(&self) -> PathBuf {
        self.root.join("package")
    }

    /// Returns the immutable active Skill packages directory.
    pub fn skills_dir(&self) -> PathBuf {
        self.root.join("skills")
    }

    /// Returns the immutable external references directory.
    pub fn refs_dir(&self) -> PathBuf {
        self.root.join("refs")
    }

    /// Returns the output directory.
    pub fn out_dir(&self) -> PathBuf {
        self.root.join("out")
    }

    /// Creates an output stage that remains invisible until committed.
    pub(crate) fn stage_output(&self) -> Result<StagedOutput, WorkdirError> {
        for _ in 0..8 {
            let sequence = NEXT_OUTPUT_STAGE.fetch_add(1, Ordering::Relaxed);
            let staging = self
                .root
                .join(format!(".out-stage-{}-{sequence}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&staging) {
                Ok(()) => {
                    return Ok(StagedOutput {
                        staging: Some(staging),
                        visible: self.out_dir(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(WorkdirError::with_source(
                        WorkdirErrorKind::StageOutput,
                        error,
                    ));
                }
            }
        }
        Err(WorkdirError::new(WorkdirErrorKind::StageOutput))
    }

    /// Returns the temporary-files directory.
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Removes this handle's root after all users of it have stopped.
    pub fn cleanup(&mut self) -> Result<CleanupOutcome, WorkdirError> {
        if !self.active {
            return Ok(CleanupOutcome::AlreadyAbsent);
        }
        let outcome = remove_owned_root(
            &self.base,
            self.base_identity,
            &self.root,
            self.root_identity,
        )?;
        self.active = false;
        Ok(outcome)
    }

    /// Confirms every sandbox mount still belongs to this allocated run.
    pub(crate) fn verify_sandbox_mounts(&self) -> Result<(), WorkdirError> {
        let root = fs::symlink_metadata(&self.root)
            .map_err(|_| WorkdirError::new(WorkdirErrorKind::RootChanged))?;
        if root.file_type().is_symlink()
            || !root.is_dir()
            || Identity::from_metadata(&root) != self.root_identity
        {
            return Err(WorkdirError::new(WorkdirErrorKind::RootChanged));
        }
        for name in ["input", "package", "skills", "refs", "work", "out", "tmp"] {
            let mount = fs::symlink_metadata(self.root.join(name))
                .map_err(|_| WorkdirError::new(WorkdirErrorKind::RootChanged))?;
            if mount.file_type().is_symlink() || !mount.is_dir() {
                return Err(WorkdirError::new(WorkdirErrorKind::RootChanged));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        Materialization, WorkdirError, WorkdirErrorKind, WorkdirId, WorkdirManager,
        initialize_layout,
    };
    use crate::RunId;

    static NEXT_BASE: AtomicU64 = AtomicU64::new(0);

    struct TestBase(PathBuf);

    impl TestBase {
        fn new() -> Self {
            let parent = std::env::temp_dir();
            loop {
                let candidate = parent.join(format!(
                    "workflow-runtime-workdir-unit-{}-{}",
                    std::process::id(),
                    NEXT_BASE.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&candidate) {
                    Ok(()) => return Self(candidate),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("test base must be created: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestBase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn id(value: u8) -> WorkdirId {
        WorkdirId(format!("{value:032x}"))
    }

    fn run_id() -> RunId {
        RunId::new(String::from("unit-run")).expect("fixture run ID must be valid")
    }

    #[test]
    fn collision_preserves_existing_root_and_uses_next_id() {
        let base = TestBase::new();
        let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
        let collision = id(1);
        let fresh = id(2);
        let collision_root = base.path().join(collision.as_str());
        fs::create_dir(&collision_root).expect("colliding root must be created");
        fs::write(collision_root.join("sentinel"), b"keep").expect("sentinel must be written");
        let mut ids = [collision, fresh.clone()].into_iter();

        let workdir = manager
            .allocate_with(
                &run_id(),
                || Ok(ids.next().expect("deterministic ID must exist")),
                |root, id| initialize_layout(root, id, &Materialization::default()),
            )
            .expect("the second deterministic ID must allocate");

        assert_eq!(workdir.id(), &fresh);
        assert_eq!(
            fs::read(collision_root.join("sentinel")).expect("sentinel must survive"),
            b"keep"
        );
    }

    #[test]
    fn allocation_exhausts_after_exactly_eight_collisions() {
        let base = TestBase::new();
        let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
        let collision = id(3);
        let collision_root = base.path().join(collision.as_str());
        fs::create_dir(&collision_root).expect("colliding root must be created");
        fs::write(collision_root.join("sentinel"), b"keep").expect("sentinel must be written");
        let mut calls = 0_u8;

        let error = match manager.allocate_with(
            &run_id(),
            || {
                calls += 1;
                Ok(collision.clone())
            },
            |root, id| initialize_layout(root, id, &Materialization::default()),
        ) {
            Ok(_) => panic!("eight collisions must exhaust allocation"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WorkdirErrorKind::AllocationExhausted);
        assert_eq!(calls, 8);
        assert_eq!(
            fs::read(collision_root.join("sentinel")).expect("sentinel must survive"),
            b"keep"
        );
    }

    #[test]
    fn initialization_failure_removes_only_the_fresh_root() {
        use std::os::unix::fs::symlink;

        let base = TestBase::new();
        let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
        let candidate = id(4);
        let candidate_root = base.path().join(candidate.as_str());
        let sibling = base.path().join("sibling");
        let outside = base.path().join("outside-sentinel");
        fs::create_dir(&sibling).expect("sibling must be created");
        fs::write(sibling.join("sentinel"), b"sibling").expect("sibling sentinel must be written");
        fs::write(&outside, b"outside").expect("outside sentinel must be written");

        let error = match manager.allocate_with(
            &run_id(),
            || Ok(candidate.clone()),
            |root, _| {
                fs::create_dir(root.join("partial")).expect("partial layout must be created");
                symlink(&outside, root.join("outside-link"))
                    .expect("outside symlink must be created");
                Err(WorkdirError::with_source(
                    WorkdirErrorKind::InitializeLayout,
                    std::io::Error::other("injected initialization failure"),
                ))
            },
        ) {
            Ok(_) => panic!("injected initialization failure must fail allocation"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WorkdirErrorKind::InitializeLayout);
        assert!(!candidate_root.exists());
        assert_eq!(
            fs::read(sibling.join("sentinel")).expect("sibling sentinel must survive"),
            b"sibling"
        );
        assert_eq!(
            fs::read(outside).expect("outside sentinel must survive"),
            b"outside"
        );
    }

    #[test]
    fn rollback_failure_preserves_primary_and_rollback_errors() {
        use std::error::Error as _;

        let base = TestBase::new();
        let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
        let candidate = id(5);
        let displaced = base.path().join("displaced-root");

        let error = match manager.allocate_with(
            &run_id(),
            || Ok(candidate.clone()),
            |root, _| {
                fs::rename(root, &displaced).expect("fresh root must be displaced");
                fs::create_dir(root).expect("replacement root must be created");
                Err(WorkdirError::with_source(
                    WorkdirErrorKind::InitializeLayout,
                    std::io::Error::other("injected initialization failure"),
                ))
            },
        ) {
            Ok(_) => panic!("injected rollback failure must fail allocation"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WorkdirErrorKind::Rollback);
        let mut kinds = Vec::new();
        let mut source = error.source();
        while let Some(current) = source {
            if let Some(workdir_error) = current.downcast_ref::<WorkdirError>() {
                kinds.push(workdir_error.kind());
            }
            source = current.source();
        }
        assert_eq!(
            kinds,
            [
                WorkdirErrorKind::InitializeLayout,
                WorkdirErrorKind::RootChanged
            ]
        );
        assert!(displaced.exists());
        assert!(base.path().join(candidate.as_str()).exists());
    }

    #[test]
    fn missing_base_maps_to_inspect_base() {
        let fixture = TestBase::new();
        let error = match WorkdirManager::new(fixture.path().join("missing")) {
            Ok(_) => panic!("missing base must fail inspection"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WorkdirErrorKind::InspectBase);
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn injected_id_source_failure_maps_to_entropy() {
        let base = TestBase::new();
        let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
        let error = match manager.allocate_with(
            &run_id(),
            || {
                Err(WorkdirError::with_source(
                    WorkdirErrorKind::Entropy,
                    std::io::Error::other("injected entropy failure"),
                ))
            },
            |root, id| initialize_layout(root, id, &Materialization::default()),
        ) {
            Ok(_) => panic!("injected entropy failure must fail allocation"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WorkdirErrorKind::Entropy);
    }

    #[test]
    fn non_collision_root_failure_maps_to_create_root() {
        use std::os::unix::fs::PermissionsExt;

        let base = TestBase::new();
        let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o500))
            .expect("base permissions must be restricted");
        let error = match manager.allocate_with(
            &run_id(),
            || Ok(id(6)),
            |root, id| initialize_layout(root, id, &Materialization::default()),
        ) {
            Ok(_) => panic!("non-writable base must fail root creation"),
            Err(error) => error,
        };
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700))
            .expect("base permissions must be restored");

        assert_eq!(error.kind(), WorkdirErrorKind::CreateRoot);
    }

    #[test]
    fn existing_layout_entry_maps_to_initialize_layout() {
        let base = TestBase::new();
        let root = base.path().join("root");
        fs::create_dir(&root).expect("root must be created");
        fs::create_dir(root.join("work")).expect("conflicting work entry must be created");

        let error = initialize_layout(&root, &id(7), &Materialization::default())
            .expect_err("an existing layout entry must fail initialization");

        assert_eq!(error.kind(), WorkdirErrorKind::InitializeLayout);
    }

    #[test]
    fn manifest_rename_conflict_maps_to_publish_manifest() {
        let base = TestBase::new();
        let root = base.path().join("root");
        fs::create_dir(&root).expect("root must be created");
        fs::create_dir(root.join("manifest.json"))
            .expect("conflicting manifest directory must be created");

        let error = initialize_layout(&root, &id(8), &Materialization::default())
            .expect_err("manifest rename conflict must fail publication");

        assert_eq!(error.kind(), WorkdirErrorKind::PublishManifest);
    }

    #[test]
    fn every_error_kind_has_a_fixed_privacy_safe_message() {
        let cases = [
            (
                WorkdirErrorKind::InspectBase,
                "failed to inspect workdir base",
            ),
            (
                WorkdirErrorKind::BaseSymlink,
                "workdir base must not be a symlink",
            ),
            (
                WorkdirErrorKind::BaseNotDirectory,
                "workdir base must be a directory",
            ),
            (
                WorkdirErrorKind::BaseChanged,
                "workdir base identity changed",
            ),
            (
                WorkdirErrorKind::Entropy,
                "failed to obtain workdir entropy",
            ),
            (
                WorkdirErrorKind::CreateRoot,
                "failed to create workdir root",
            ),
            (
                WorkdirErrorKind::AllocationExhausted,
                "workdir allocation attempts exhausted",
            ),
            (
                WorkdirErrorKind::InitializeLayout,
                "failed to initialize workdir layout",
            ),
            (
                WorkdirErrorKind::PublishManifest,
                "failed to publish workdir manifest",
            ),
            (
                WorkdirErrorKind::Rollback,
                "failed to roll back workdir allocation",
            ),
            (
                WorkdirErrorKind::RootChanged,
                "workdir root identity changed",
            ),
            (WorkdirErrorKind::Cleanup, "failed to clean up workdir root"),
        ];
        let hostile = "../ run\0雪";
        let base = "/private/workdir/base";

        for (kind, message) in cases {
            let error = WorkdirError::new(kind);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
            assert!(!error.to_string().contains(hostile));
            assert!(!error.to_string().contains(base));
        }
    }
}
